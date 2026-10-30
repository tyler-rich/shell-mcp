//go:build linux

package fsx

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// {path:read:fd} (POLICY §4, handoff N-22): ResolveReadFD resolves exactly
// as ResolveRead does (roots, deny list, final symlink, the chain rule and
// the owner-matched exception) and keeps the descriptor it checked, which
// must be a regular file. Every layout is invented.

// fdEnv is a gate FS for commands over <d>/x/w (closed, the test's uid
// trusted as the service account), with a deny rule for w/denied/**.
func fdEnv(t testing.TB, trusted func(uint32) bool) (fs *FS, root string) {
	t.Helper()
	e := newExecChainEnv(t)
	deny, err := pathx.NewMatcher([]string{e.root + "/denied/**"})
	must(t, err)
	fs = gateFSAt(t, e.root, trusted)
	fs.cfg.Deny = deny
	fs.cfg.OwnerMatchedReads = true
	return fs, e.root
}

// TestResolveReadFD: a regular file gives its open descriptor and real
// path; the descriptor is the file (same device and inode), read-only, and
// reads its content.
func TestResolveReadFD(t *testing.T) {
	fs, root := fdEnv(t, selfTrust)
	p := filepath.Join(root, "compose.yaml")
	putMode(t, p, "services: {}\n", 0o644)
	f, rp, err := fs.ResolveReadFD(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	want, err := ResolveReadString(fs, p)
	must(t, err)
	if rp != want || rp != p {
		t.Fatalf("real path %q, ResolveRead says %q", rp, want)
	}
	var a, b unix.Stat_t
	must(t, unix.Fstat(int(f.Fd()), &a))
	must(t, unix.Stat(p, &b))
	if a.Dev != b.Dev || a.Ino != b.Ino || a.Mode&unix.S_IFMT != unix.S_IFREG {
		t.Fatalf("descriptor %+v, file %+v", a, b)
	}
	fl, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	must(t, err)
	if fl&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatalf("access mode %#o, want read-only", fl&unix.O_ACCMODE)
	}
	got, err := io.ReadAll(f)
	if err != nil || string(got) != "services: {}\n" {
		t.Fatalf("read %q %v", got, err)
	}
}

// ResolveReadString is ResolveRead's path, for comparing the two forms.
func ResolveReadString(fs *FS, p string) (string, error) { return fs.ResolveRead(p) }

// TestResolveReadFDRefusesNonFiles: a directory is is_a_directory (a
// command given a directory as /dev/fd/N treats it as a symlink, and
// everything below it is still looked up by name); a FIFO, a socket and a
// device are path_denied; a final symlink, a deny-listed file and a path
// outside the roots are refused as ResolveRead refuses them. Nothing stays
// open.
func TestResolveReadFDRefusesNonFiles(t *testing.T) {
	fs, root := fdEnv(t, selfTrust)
	dir := filepath.Join(root, "d")
	mkdirMode(t, dir, 0o755)
	fifo := filepath.Join(root, "fifo")
	must(t, unix.Mkfifo(fifo, 0o644))
	sock := filepath.Join(root, "sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	must(t, err)
	defer func() { _ = l.Close() }()
	target := filepath.Join(root, "t")
	putMode(t, target, "t\n", 0o644)
	link := filepath.Join(root, "link")
	must(t, os.Symlink("t", link))
	mkdirMode(t, filepath.Join(root, "denied"), 0o755)
	denied := filepath.Join(root, "denied", "secret")
	putMode(t, denied, "DENIED\n", 0o644)

	before := openFDs(t)
	_, _, err = fs.ResolveReadFD(dir)
	wantCode(t, err, protocol.CodeIsADirectory)
	if !strings.Contains(err.Error(), "{path:read:fd}") || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory: the refusal does not say why: %v", err)
	}
	for name, p := range map[string]string{"FIFO": fifo, "socket": sock} {
		_, _, err := fs.ResolveReadFD(p)
		wantCode(t, err, protocol.CodePathDenied)
		if !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("%s: the refusal does not say why: %v", name, err)
		}
	}
	for name, p := range map[string]string{"final symlink": link, "denied": denied, "outside the roots": "/etc/hostname", "missing": filepath.Join(root, "missing")} {
		_, _, errFD := fs.ResolveReadFD(p)
		_, errStr := fs.ResolveRead(p)
		if errFD == nil || errStr == nil || errFD.Error() != errStr.Error() {
			t.Fatalf("%s: {path:read:fd} %v, {path:read} %v", name, errFD, errStr)
		}
	}
	if after := openFDs(t); after != before {
		t.Fatalf("%d descriptors open before, %d after", before, after)
	}
}

// TestResolveReadFDDevice: a character device (the null device, under a
// root made for it) is path_denied.
func TestResolveReadFDDevice(t *testing.T) {
	fs := gateFSAt(t, "/dev", func(uint32) bool { return true })
	fs.cfg.OwnerMatchedReads = true
	_, _, err := fs.ResolveReadFD("/dev/null")
	wantCode(t, err, protocol.CodePathDenied)
}

// TestResolveReadFDChainUnchanged: the descriptor form accepts exactly what
// {path:read} accepts: an open (group-writable or sticky) directory on the
// path refuses both with the same message, the owner-matched exception (a
// directory of one other account, here the test's uid left out of the
// trust) admits both.
func TestResolveReadFDChainUnchanged(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("needs an unprivileged uid")
	}
	fs, root := fdEnv(t, rootOnly)
	a := filepath.Join(root, "a")
	mkdirMode(t, a, 0o755)
	p := filepath.Join(a, "t")
	putMode(t, p, "t\n", 0o644)
	f, _, err := fs.ResolveReadFD(p)
	if err != nil {
		t.Fatalf("owner-matched: %v", err)
	}
	_ = f.Close()
	for _, mode := range []os.FileMode{0o775, 0o777, os.ModeSticky | 0o755} {
		must(t, os.Chmod(a, mode))
		_, _, errFD := fs.ResolveReadFD(p)
		_, errStr := fs.ResolveRead(p)
		wantCode(t, errFD, protocol.CodePathDenied)
		if errStr == nil || errFD.Error() != errStr.Error() {
			t.Fatalf("%v: {path:read:fd} %v, {path:read} %v", mode, errFD, errStr)
		}
	}
	must(t, os.Chmod(a, 0o755)) //nolint:gosec // G302: closed again
}

// TestResolveReadFDKeepsTheFile: the descriptor stays on the file the
// gate checked when the name is swapped afterwards, here for a symlink to
// a deny-listed file: what a command reopening /dev/fd/N reads.
func TestResolveReadFDKeepsTheFile(t *testing.T) {
	fs, root := fdEnv(t, selfTrust)
	p := filepath.Join(root, "t")
	putMode(t, p, "ORIGINAL\n", 0o644)
	mkdirMode(t, filepath.Join(root, "denied"), 0o755)
	putMode(t, filepath.Join(root, "denied", "secret"), "DENIED\n", 0o644)
	f, _, err := fs.ResolveReadFD(p)
	must(t, err)
	defer func() { _ = f.Close() }()
	must(t, os.Rename(p, p+".away"))
	must(t, os.Symlink("denied/secret", p))
	got, err := os.ReadFile("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	if err != nil || string(got) != "ORIGINAL\n" {
		t.Fatalf("reopened %q %v", got, err)
	}
}

// openFDs counts this process's open descriptors.
func openFDs(t testing.TB) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	return len(ents)
}

// FuzzResolveReadFD: for any path under a fixture tree (files, a
// directory, a FIFO, symlinks, a denied file), ResolveReadFD accepts
// exactly the paths ResolveRead accepts that are regular files, returns
// ResolveRead's real path and a descriptor on that very file, refuses the
// rest with ResolveRead's refusal when ResolveRead refuses, and leaves no
// descriptor open.
func FuzzResolveReadFD(f *testing.F) {
	fs, root := fdEnv(f, selfTrust)
	mkdirMode(f, filepath.Join(root, "d"), 0o755)
	putMode(f, filepath.Join(root, "d", "f"), "f\n", 0o644)
	putMode(f, filepath.Join(root, "t"), "t\n", 0o600)
	must(f, unix.Mkfifo(filepath.Join(root, "fifo"), 0o644))
	must(f, os.Symlink("t", filepath.Join(root, "link")))
	must(f, os.Symlink("d", filepath.Join(root, "dlink")))
	mkdirMode(f, filepath.Join(root, "denied"), 0o755)
	putMode(f, filepath.Join(root, "denied", "s"), "s\n", 0o644)
	for _, s := range []string{"t", "d", "d/f", "fifo", "link", "dlink/f", "denied/s", "missing", "", "../x", "d/../t", "/etc/hostname", "t/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, rel string) {
		p := rel
		if !strings.HasPrefix(rel, "/") {
			p = root + "/" + rel
		}
		before := openFDs(t)
		file, rp, errFD := fs.ResolveReadFD(p)
		want, errStr := fs.ResolveRead(p)
		switch {
		case errFD == nil:
			defer func() { _ = file.Close() }()
			var a, b unix.Stat_t
			if errStr != nil || rp != want || unix.Fstat(int(file.Fd()), &a) != nil || unix.Stat(want, &b) != nil ||
				a.Dev != b.Dev || a.Ino != b.Ino || a.Mode&unix.S_IFMT != unix.S_IFREG {
				t.Fatalf("%q: {path:read:fd} %q, {path:read} %q %v", p, rp, want, errStr)
			}
			return
		case errStr != nil && errFD.Error() != errStr.Error():
			t.Fatalf("%q: {path:read:fd} %v, {path:read} %v", p, errFD, errStr)
		case errStr == nil:
			if fi, err := os.Stat(want); err == nil && fi.Mode().IsRegular() {
				t.Fatalf("%q: a regular file refused: %v", p, errFD)
			}
		}
		if after := openFDs(t); after != before {
			t.Fatalf("%q: %d descriptors open before, %d after", p, before, after)
		}
	})
}
