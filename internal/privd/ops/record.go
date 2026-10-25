//go:build linux

package ops

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The package operation record (PRIVILEGED §6, "Package operations"; the
// maintainer's condition 3): while an install, upgrade or remove runs, its
// instance holds an exclusive flock(2) on the record, which names the
// request id, when it started and the time it may run until. A power action
// holds it the same way while it waits for its time, and names itself, its
// action and that time in it (PRIVILEGED §6, "Power"). Whether an
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
	// Op, Action and ScheduledAt are set by a power action, which holds the
	// record while it waits for its time (PRIVILEGED §6, "Power").
	Op          string `json:"op,omitempty"`
	Action      string `json:"action,omitempty"`
	ScheduledAt string `json:"scheduled_at,omitempty"`
}

type pkgRecord struct{ f *os.File }

func (r *pkgRecord) release() {
	if r != nil && r.f != nil {
		_ = r.f.Close() // releases the lock
		r.f = nil
	}
}

// write replaces the record's contents.
func (r *pkgRecord) write(d *pkgRecordData) error {
	b, _ := json.Marshal(d)
	if err := r.f.Truncate(0); err != nil {
		return err
	}
	_, err := r.f.WriteAt(b, 0)
	return err
}

// intact reports whether the file at path is still the record this
// instance locked (same device and inode), so that the lock still means
// what it meant: nobody replaced or removed it meanwhile.
func (r *pkgRecord) intact(path string) bool {
	var held, now unix.Stat_t
	if r == nil || r.f == nil || unix.Fstat(int(r.f.Fd()), &held) != nil || unix.Lstat(path, &now) != nil {
		return false
	}
	return held.Dev == now.Dev && held.Ino == now.Ino && now.Mode&unix.S_IFMT == unix.S_IFREG
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
	return s.holdRecordAs(&pkgRecordData{RequestID: s.req.ID, Started: s.start.UTC().Format(time.RFC3339), Until: killAt.UTC().Format(time.RFC3339)})
}

// holdRecordAs takes the record with the contents d, and refuses while
// another operation holds it.
func (s *server) holdRecordAs(d *pkgRecordData) (*pkgRecord, error) {
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
	r := &pkgRecord{f: f}
	if err := r.write(d); err != nil {
		r.release()
		return nil, errf(protocol.CodeExecFailed, "the package operation record could not be written (%s); nothing was changed", err.Error())
	}
	return r, nil
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

// readRecord reads and checks the record's contents.
func readRecord(f *os.File) (pkgRecordData, bool) {
	b, _ := io.ReadAll(io.LimitReader(f, maxRecordBytes))
	var r pkgRecordData
	ok := json.Unmarshal(b, &r) == nil && protocol.ValidID(r.RequestID) && validTime(r.Started) && validTime(r.Until)
	if r.Op != "" {
		ok = ok && r.Op == protocol.OpPrivPower && slices.Contains(policy.PowerActions, r.Action) && validTime(r.ScheduledAt)
	}
	return r, ok
}

// inProgressErr names the operation that holds the record, from its
// contents (a package operation, or a power action waiting for its time),
// and the dpkg lock's holder when there is one.
func (s *server) inProgressErr() error {
	msg := "package operation in progress (details unavailable)"
	if f, err := s.openRecord(false); err == nil {
		r, ok := readRecord(f)
		_ = f.Close()
		switch {
		case ok && r.Op == protocol.OpPrivPower:
			msg = fmt.Sprintf("a %s is already scheduled for %s (request id %s); priv_power_cancel cancels it until then", r.Action, r.ScheduledAt, r.RequestID)
		case ok:
			msg = fmt.Sprintf("package operation in progress (request id %s, started %s, may run until %s)", r.RequestID, r.Started, r.Until)
		}
	}
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
