//go:build linux

package ops

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The package operation record (PRIVILEGED §6, "Package operations"; the
// maintainer's condition 3): while an install, upgrade or remove runs, its
// instance holds an exclusive flock(2) on the record, which names the
// request id, when it started and the time it may run until. Whether an
// operation is in progress is decided by that lock, which the kernel
// releases when the instance ends however it ends — never by the record's
// contents alone, and never by dpkg's lock alone (which another program
// may hold, and which apt does not hold between its simulations and its
// run). The record is root's, 0600, a regular file with one link; anything
// else fails closed.

// maxRecordBytes bounds what is read from the record.
const maxRecordBytes = 4096

type pkgRecordData struct {
	RequestID string `json:"request_id"`
	Started   string `json:"started"`
	Until     string `json:"until"`
}

type pkgRecord struct{ f *os.File }

func (r *pkgRecord) release() {
	if r != nil && r.f != nil {
		_ = r.f.Close() // releases the lock
	}
}

// openRecord opens the record (creating it when create is set) and checks
// it is a private file of a trusted owner.
func (s *server) openRecord(create bool) (*os.File, error) {
	flags := os.O_RDONLY
	if create {
		flags = os.O_RDWR | os.O_CREATE
	}
	f, err := os.OpenFile(s.o.PkgRecord, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0o077 != 0 || !s.o.Trust.Owns(st.Uid) {
		_ = f.Close()
		return nil, errors.New("the package operation record is not a private regular file of root")
	}
	return f, nil
}

// holdRecord takes the record for this request, until killAt at the latest
// (released by its release, or by the instance's end), and refuses while
// another operation holds it.
func (s *server) holdRecord(killAt time.Time) (*pkgRecord, error) {
	f, err := s.openRecord(true)
	if err != nil {
		return nil, errf(protocol.CodeExecFailed, "the package operation record could not be used (%s); nothing was changed", err.Error())
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, s.inProgressErr()
		}
		return nil, errf(protocol.CodeExecFailed, "the package operation record could not be locked (%s); nothing was changed", err.Error())
	}
	b, _ := json.Marshal(pkgRecordData{RequestID: s.req.ID, Started: s.start.UTC().Format(time.RFC3339), Until: killAt.UTC().Format(time.RFC3339)})
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return nil, errf(protocol.CodeExecFailed, "the package operation record could not be written (%s); nothing was changed", err.Error())
	}
	if _, err := f.WriteAt(b, 0); err != nil {
		_ = f.Close()
		return nil, errf(protocol.CodeExecFailed, "the package operation record could not be written (%s); nothing was changed", err.Error())
	}
	return &pkgRecord{f: f}, nil
}

// notInProgress refuses while a package operation holds the record.
func (s *server) notInProgress() error {
	f, err := s.openRecord(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errf(protocol.CodeExecFailed, "the package operation record could not be used (%s)", err.Error())
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return s.inProgressErr()
		}
		return errf(protocol.CodeExecFailed, "the package operation record could not be locked (%s)", err.Error())
	}
	return nil
}

// inProgressErr names the operation that holds the record, from its
// contents, and the dpkg lock's holder when there is one.
func (s *server) inProgressErr() error {
	what := "details unavailable"
	if f, err := s.openRecord(false); err == nil {
		b, _ := io.ReadAll(io.LimitReader(f, maxRecordBytes))
		_ = f.Close()
		var r pkgRecordData
		if json.Unmarshal(b, &r) == nil && protocol.ValidID(r.RequestID) && validTime(r.Started) && validTime(r.Until) {
			what = fmt.Sprintf("request id %s, started %s, may run until %s", r.RequestID, r.Started, r.Until)
		}
	}
	msg := "package operation in progress (" + what + ")"
	if h, held, err := pkgLockHolder(s.dpkgLock()); err == nil && held {
		msg += "; the dpkg frontend lock is held by " + h
	}
	return errf(protocol.CodeExecFailed, "%s; nothing was changed; preview again after it ends", msg)
}

func validTime(s string) bool {
	_, err := time.Parse(time.RFC3339, s)
	return err == nil && len(s) <= 40
}

// pkgLockHolder names the dpkg frontend lock's holder.
func pkgLockHolder(path string) (holder string, held bool, err error) {
	h, held, err := pkg.LockHolder(path)
	return h.String(), held, err
}
