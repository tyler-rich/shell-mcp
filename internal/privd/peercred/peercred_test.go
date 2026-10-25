//go:build linux

package peercred_test

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/privd/peercred"
)

// connected returns one end of a connected AF_UNIX stream socket pair; the
// other end stays open until the test ends.
func connected(t *testing.T) int {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) })
	return fds[0]
}

// self is the test process's uid, gid and pid as SO_PEERCRED reports them.
func self() peercred.Cred {
	return peercred.Cred{PID: int32(os.Getpid()), UID: uint32(os.Getuid()), GID: uint32(os.Getgid())} //nolint:gosec // G115: Linux ids and pids fit
}

func TestPeerIsTheConnectingProcess(t *testing.T) {
	c, err := peercred.Peer(connected(t))
	if err != nil {
		t.Fatal(err)
	}
	if c != self() {
		t.Fatalf("cred %+v, want %+v", c, self())
	}
}

func TestAuthenticate(t *testing.T) {
	fd := connected(t)
	uid := self().UID
	if c, err := peercred.Authenticate(fd, uid); err != nil || c.UID != uid {
		t.Fatalf("right uid refused: %+v %v", c, err)
	}
	for _, other := range []uint32{uid + 1, 0, 4294967295} {
		if other == uid {
			continue
		}
		c, err := peercred.Authenticate(fd, other)
		if !errors.Is(err, peercred.ErrWrongPeer) {
			t.Fatalf("want uid %d: err %v", other, err)
		}
		if c.UID != uid {
			t.Fatalf("refusal must still report the peer: %+v", c)
		}
	}
}

func TestNotASocket(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if _, err := peercred.Authenticate(int(r.Fd()), self().UID); err == nil || errors.Is(err, peercred.ErrWrongPeer) {
		t.Fatalf("pipe: %v", err)
	}
}
