//go:build linux

package setupx_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// self is the test process's own uid and gid: the owner the write helper
// can give a file without root.
func self() setupx.Owner {
	return setupx.Owner{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())} //nolint:gosec // G115: ids
}

// temps lists the install temp names left in dir.
func temps(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if setupx.IsTemp(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

func stat(t *testing.T, p string) (fs.FileMode, setupx.Owner) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return fi.Mode(), setupx.Owner{UID: st.Uid, GID: st.Gid}
}

// TestTempName: a temp name is the target's base name after a dot, then
// .shell-mcp- and 12 characters of a-z and 2-7, in the target's directory;
// the patterns sshd, systemd and polkit read never match it.
func TestTempName(t *testing.T) {
	n, err := setupx.TempName("/etc/ssh/sshd_config.d/60-shell-mcp.conf")
	if err != nil {
		t.Fatal(err)
	}
	dir, base := filepath.Split(n)
	if dir != "/etc/ssh/sshd_config.d/" || !strings.HasPrefix(base, ".60-shell-mcp.conf.shell-mcp-") || len(base) != len(".60-shell-mcp.conf.shell-mcp-")+12 {
		t.Fatalf("temp name %q", n)
	}
	if !setupx.IsTempFor(base, "60-shell-mcp.conf") || setupx.IsTempFor(base, "60-shell-mcp.rules") || !setupx.IsTemp(base) {
		t.Fatalf("%q is not recognised as the conf's temp name", base)
	}
	if strings.HasSuffix(base, ".conf") || strings.HasSuffix(base, ".rules") || strings.HasSuffix(base, ".socket") || strings.HasSuffix(base, ".service") {
		t.Fatalf("%q ends in a suffix a reader matches", base)
	}
	for _, s := range []string{"60-shell-mcp.conf", ".60-shell-mcp.conf.shell-mcp-ABCDEFGHIJKL", ".x.shell-mcp-abcdefghijk", ".x.shell-mcp-abcdefghijk1", ".x.shell-mcp-abcdefghijk8"} {
		if setupx.IsTemp(s) {
			t.Errorf("%q matched", s)
		}
	}
	m, _ := setupx.TempName("/etc/x")
	if m == n {
		t.Fatal("two temp names are equal")
	}
}

// TestWriteFile: a new file and a replaced one hold exactly the bytes,
// owner and mode, and no temp file is left.
func TestWriteFile(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "60-shell-mcp.conf")
	for _, c := range []struct {
		data string
		mode fs.FileMode
	}{{"Match User svc-shell\n", 0o644}, {"Match User other\n", 0o600}} {
		if err := setupx.WriteFile(p, []byte(c.data), c.mode, self()); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own file
		if err != nil || string(b) != c.data {
			t.Fatalf("content %q %v", b, err)
		}
		if mode, owner := stat(t, p); mode != c.mode || owner != self() {
			t.Fatalf("mode %v owner %v", mode, owner)
		}
		if l := temps(t, d); len(l) != 0 {
			t.Fatalf("temp files left: %v", l)
		}
	}
}

// TestWriteFileFailures: a failure at any step leaves no temp file. Before
// the rename the target keeps its old bytes and the error is not
// committed; after it the target is replaced and the error says so, for
// the journal to restore it.
func TestWriteFileFailures(t *testing.T) {
	committed := false
	for _, step := range setupx.WriteSteps {
		if step == setupx.CommittedFrom {
			committed = true
		}
		t.Run(step, func(t *testing.T) {
			d := t.TempDir()
			p := filepath.Join(d, "target")
			if err := os.WriteFile(p, []byte("old\n"), 0o644); err != nil { //nolint:gosec // G306: a test file
				t.Fatal(err)
			}
			err := setupx.WriteFileFailingAt(p, []byte("new\n"), 0o644, self(), step)
			var we *setupx.WriteError
			if !errors.As(err, &we) || we.Step != step || we.Committed != committed {
				t.Fatalf("error %v (%+v), want a WriteError at %s, committed %v", err, we, step, committed)
			}
			if l := temps(t, d); len(l) != 0 {
				t.Fatalf("temp files left: %v", l)
			}
			b, _ := os.ReadFile(p) //nolint:gosec // G304: the test's own file
			if want := map[bool]string{false: "old\n", true: "new\n"}[committed]; string(b) != want {
				t.Fatalf("target holds %q, want %q", b, want)
			}
		})
	}
}

// TestWriteFileRefuses: a relative or unclean path and a mode with type
// bits are refused before anything is created.
func TestWriteFileRefuses(t *testing.T) {
	d := t.TempDir()
	for _, p := range []string{"relative", d + "/a/../b"} {
		if err := setupx.WriteFile(p, nil, 0o644, self()); err == nil {
			t.Errorf("%q: written", p)
		}
	}
	if err := setupx.WriteFile(filepath.Join(d, "x"), nil, fs.ModeDir|0o755, self()); err == nil {
		t.Error("a directory mode: written")
	}
	if l := temps(t, d); len(l) != 0 {
		t.Fatalf("temp files left: %v", l)
	}
}

// TestWriteFileDoesNotFollowLinks: a symlink at the target is replaced by
// the file (rename), never written through.
func TestWriteFileDoesNotFollowLinks(t *testing.T) {
	d := t.TempDir()
	victim := filepath.Join(d, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "target")
	if err := os.Symlink(victim, p); err != nil {
		t.Fatal(err)
	}
	if err := setupx.WriteFile(p, []byte("new"), 0o644, self()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" { //nolint:gosec // G304: the test's own file
		t.Fatalf("written through the link: %q", b)
	}
	if mode, _ := stat(t, p); !mode.IsRegular() {
		t.Fatalf("target is %v", mode)
	}
}

// TestMkdir: owner and mode on the descriptor; an existing path refused.
func TestMkdir(t *testing.T) {
	p := filepath.Join(t.TempDir(), "authorized_keys.d")
	if err := setupx.Mkdir(p, 0o755, self()); err != nil {
		t.Fatal(err)
	}
	if mode, owner := stat(t, p); mode != fs.ModeDir|0o755 || owner != self() {
		t.Fatalf("mode %v owner %v", mode, owner)
	}
	if err := setupx.Mkdir(p, 0o755, self()); err == nil {
		t.Fatal("an existing directory: created again")
	}
}

// TestRemoveLeftovers: a killed run's temp files for the target are
// removed (regular, owned as expected); other targets' temp files and other
// names stay; a temp-looking name that is not a regular file is refused.
func TestRemoveLeftovers(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "60-shell-mcp.conf")
	mine := filepath.Join(d, ".60-shell-mcp.conf.shell-mcp-abcdefghijkl")
	other := filepath.Join(d, ".60-shell-mcp.rules.shell-mcp-abcdefghijkl")
	keep := filepath.Join(d, "50-other.conf")
	for _, p := range []string{mine, other, keep} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := setupx.RemoveLeftoversOwnedBy(target, self().UID)
	if err != nil || !slices.Equal(got, []string{mine}) {
		t.Fatalf("removed %v %v", got, err)
	}
	for _, p := range []string{other, keep} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("%s removed", p)
		}
	}
	if err := os.Mkdir(filepath.Join(d, ".60-shell-mcp.conf.shell-mcp-mnopqrstuvwx"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := setupx.RemoveLeftoversOwnedBy(target, self().UID); err == nil {
		t.Fatal("a directory with a temp name: no refusal")
	}
	if _, err := setupx.RemoveLeftovers(target); err == nil && os.Getuid() != 0 {
		t.Fatal("a temp file not owned by root: removed")
	}
}

// TestReadState: absent, a file with its bytes, owner and mode, a link not
// followed, and a file over the bound.
func TestReadState(t *testing.T) {
	d := t.TempDir()
	if s, err := setupx.ReadState(filepath.Join(d, "absent"), 10); err != nil || s.Exists {
		t.Fatalf("absent: %+v %v", s, err)
	}
	p := filepath.Join(d, "f")
	if err := os.WriteFile(p, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := setupx.ReadState(p, 10)
	if err != nil || !s.Same([]byte("abc"), 0o600, self()) {
		t.Fatalf("file: %+v %v", s, err)
	}
	if _, err := setupx.ReadState(p, 2); !errors.Is(err, setupx.ErrTooLarge) {
		t.Fatalf("over the bound: %v", err)
	}
	l := filepath.Join(d, "l")
	if err := os.Symlink(p, l); err != nil {
		t.Fatal(err)
	}
	if s, err := setupx.ReadState(l, 10); err != nil || s.Mode&fs.ModeSymlink == 0 || s.Data != nil {
		t.Fatalf("link: %+v %v", s, err)
	}
}
