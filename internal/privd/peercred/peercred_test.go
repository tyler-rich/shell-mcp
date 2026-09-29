//go:build linux

package peercred_test

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/privd/peercred"
)

func pair(t *testing.T, typ int) (int, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) })
	return fds[0], fds[1]
}

func TestPeerIsTheConnectingProcess(t *testing.T) {
	a, _ := pair(t, unix.SOCK_STREAM)
	c, err := peercred.Peer(a)
	if err != nil {
		t.Fatal(err)
	}
	if c.UID != uint32(os.Getuid()) || c.GID != uint32(os.Getgid()) || c.PID != int32(os.Getpid()) {
		t.Fatalf("cred %+v, want uid %d gid %d pid %d", c, os.Getuid(), os.Getgid(), os.Getpid())
	}
}

func TestAuthenticate(t *testing.T) {
	a, _ := pair(t, unix.SOCK_STREAM)
	uid := uint32(os.Getuid())
	if c, err := peercred.Authenticate(a, uid); err != nil || c.UID != uid {
		t.Fatalf("right uid refused: %+v %v", c, err)
	}
	for _, other := range []uint32{uid + 1, 0, 4294967295} {
		if other == uid {
			continue
		}
		c, err := peercred.Authenticate(a, other)
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
	if _, err := peercred.Authenticate(int(r.Fd()), uint32(os.Getuid())); err == nil || errors.Is(err, peercred.ErrWrongPeer) {
		t.Fatalf("pipe: %v", err)
	}
}
