//go:build linux

package fsx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// env is an invented layout: <d>/read (read root) containing config/
// (write root), secrets/ (denied), and <d>/outside (no root).
type env struct {
	d, read, write, outside, secrets string
	fs                               *FS
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		d:       d,
		read:    filepath.Join(d, "read"),
		write:   filepath.Join(d, "read", "config"),
		outside: filepath.Join(d, "outside"),
		secrets: filepath.Join(d, "read", "secrets"),
	}
	for _, p := range []string{e.write, e.outside, e.secrets} {
		must(t, os.MkdirAll(p, 0o750))
	}
	put(t, filepath.Join(e.read, "hello.txt"), "hello\nworld\n")
	put(t, filepath.Join(e.write, "app.yaml"), "key: value\n")
	put(t, filepath.Join(e.secrets, "token"), "TOPSECRET")
	put(t, filepath.Join(e.outside, "passwd"), "OUTSIDE")
	deny, err := pathx.NewMatcher([]string{e.secrets + "/**", "**/*.key"})
	must(t, err)
	prot, err := pathx.NewMatcher([]string{"**/.ssh", e.write + "/locked"})
	must(t, err)
	e.fs = New(&Config{
		ReadRoots:  []string{e.read},
		WriteRoots: []string{e.write},
		Deny:       deny,
		Protected:  prot,
		Limits:     Limits{MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxFindResults: 100, MaxFindDepth: 8, MaxDeleteEntries: 20},
	})
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func put(t *testing.T, p, s string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(p), 0o750))
	must(t, os.WriteFile(p, []byte(s), 0o600))
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("error %v (%T), want fsx code %s", err, err, code)
	}
	if fe.Code != code {
		t.Fatalf("code %s (%s), want %s", fe.Code, fe.Msg, code)
	}
}

func TestReadInsideRoot(t *testing.T) {
	e := newEnv(t)
	r, err := e.fs.ReadFile(filepath.Join(e.read, "hello.txt"), ReadOptions{MaxBytes: 1024})
	must(t, err)
	sum := sha256.Sum256([]byte("hello\nworld\n"))
	if r.Content != "hello\nworld\n" || r.Binary || r.Size != 12 || r.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("read %+v", r)
	}
	// Write roots are readable.
	if _, err := e.fs.ReadFile(filepath.Join(e.write, "app.yaml"), ReadOptions{MaxBytes: 10}); err != nil {
		t.Fatal(err)
	}
}

func TestUncleanAndOutside(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{e.read + "/../outside/passwd", e.read + "/./hello.txt", "read/hello.txt", e.read + "/hello.txt/"} {
		_, err := e.fs.ReadFile(p, ReadOptions{MaxBytes: 10})
		wantCode(t, err, protocol.CodeBadRequest)
	}
	_, err := e.fs.ReadFile(filepath.Join(e.outside, "passwd"), ReadOptions{MaxBytes: 10})
	wantCode(t, err, protocol.CodePathDenied)
	_, err = e.fs.ReadFile(filepath.Join(e.secrets, "token"), ReadOptions{MaxBytes: 10})
	wantCode(t, err, protocol.CodePathDenied)
	_, err = e.fs.ReadFile(filepath.Join(e.read, "missing"), ReadOptions{MaxBytes: 10})
	wantCode(t, err, protocol.CodeNotFound)
	_, err = e.fs.ReadFile(e.write, ReadOptions{MaxBytes: 10})
	wantCode(t, err, protocol.CodeIsADirectory)
}

func TestSymlinks(t *testing.T) {
	e := newEnv(t)
	// Intermediate symlink inside the root pointing outside it.
	must(t, os.Symlink(e.outside, filepath.Join(e.read, "escape")))
	_, err := e.fs.ReadFile(filepath.Join(e.read, "escape", "passwd"), ReadOptions{MaxBytes: 10})
	wantCode(t, err, protocol.CodePathDenied)
	// Intermediate symlink to a denied directory inside the root.
	must(t, os.Symlink(e.secrets, filepath.Join(e.read, "alias")))
	_, err = e.fs.ReadFile(filepath.Join(e.read, "alias", "token"), ReadOptions{MaxBytes: 10})
	wantCode(t, err, protocol.CodePathDenied)
	// Final-component symlinks: to a denied file, to an allowed file, outside.
	must(t, os.Symlink(filepath.Join(e.secrets, "token"), filepath.Join(e.read, "t1")))
	must(t, os.Symlink(filepath.Join(e.read, "hello.txt"), filepath.Join(e.read, "t2")))
	must(t, os.Symlink(filepath.Join(e.outside, "passwd"), filepath.Join(e.read, "t3")))
	for _, n := range []string{"t1", "t2", "t3"} {
		_, err = e.fs.ReadFile(filepath.Join(e.read, n), ReadOptions{MaxBytes: 10})
		wantCode(t, err, protocol.CodePathDenied)
	}
	// Stat reports a final symlink without following it.
	st, err := e.fs.Stat(filepath.Join(e.read, "t3"))
	must(t, err)
	if st.Type != "symlink" || st.LinkTarget != filepath.Join(e.outside, "passwd") {
		t.Fatalf("stat %+v", st)
	}
	// Writes through a final symlink are refused too.
	must(t, os.Symlink(filepath.Join(e.outside, "passwd"), filepath.Join(e.write, "link")))
	_, err = e.fs.WriteFile(filepath.Join(e.write, "link"), []byte("x"), WriteOptions{Create: true})
	wantCode(t, err, protocol.CodePathDenied)
	if b, _ := os.ReadFile(filepath.Join(e.outside, "passwd")); string(b) != "OUTSIDE" {
		t.Fatal("outside file changed")
	}
	// A relative intermediate symlink that stays inside the root and is not
	// denied is followed.
	must(t, os.Symlink("config", filepath.Join(e.read, "cfg")))
	if _, err = e.fs.ReadFile(filepath.Join(e.read, "cfg", "app.yaml"), ReadOptions{MaxBytes: 10}); err != nil {
		t.Fatalf("in-root intermediate symlink: %v", err)
	}
	// os.Root refuses absolute symlink targets even when they point back
	// inside the root.
	must(t, os.Symlink(e.write, filepath.Join(e.read, "cfgabs")))
	_, err = e.fs.ReadFile(filepath.Join(e.read, "cfgabs", "app.yaml"), ReadOptions{MaxBytes: 10})
	wantCode(t, err, protocol.CodePathDenied)
}

// TestSwapRace swaps a directory for a symlink to outside the root while
// reads and writes run, and asserts nothing outside is read or written.
func TestSwapRace(t *testing.T) {
	e := newEnv(t)
	sub := filepath.Join(e.write, "sub")
	stash := filepath.Join(e.write, "sub.real")
	must(t, os.MkdirAll(sub, 0o750))
	put(t, filepath.Join(sub, "f"), "INSIDE")
	outDir := filepath.Join(e.d, "outside-dir")
	must(t, os.MkdirAll(outDir, 0o750))
	put(t, filepath.Join(outDir, "f"), "OUTSIDE")
	link := filepath.Join(e.write, "sub.link")
	must(t, os.Symlink(outDir, link))

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			// sub is a directory → becomes a symlink to outside → back.
			_ = os.Rename(sub, stash)
			_ = os.Rename(link, sub)
			_ = os.Rename(sub, link)
			_ = os.Rename(stash, sub)
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	reads, writes := 0, 0
	for time.Now().Before(deadline) {
		r, err := e.fs.ReadFile(filepath.Join(sub, "f"), ReadOptions{MaxBytes: 64})
		if err == nil {
			reads++
			if strings.Contains(r.Content, "OUTSIDE") {
				stop.Store(true)
				wg.Wait()
				t.Fatal("read content from outside the root")
			}
		}
		if _, err := e.fs.WriteFile(filepath.Join(sub, "w"), []byte("W"), WriteOptions{Create: true}); err == nil {
			writes++
		}
	}
	stop.Store(true)
	wg.Wait()
	entries, err := os.ReadDir(outDir)
	must(t, err)
	if len(entries) != 1 {
		t.Fatalf("outside directory was written: %v", entries)
	}
	if b, _ := os.ReadFile(filepath.Join(outDir, "f")); string(b) != "OUTSIDE" { //nolint:gosec // G304: test fixture path
		t.Fatal("outside file changed")
	}
	t.Logf("%d successful reads, %d successful writes under the swap", reads, writes)
	if reads == 0 || writes == 0 {
		t.Fatalf("race test is vacuous: %d reads, %d writes succeeded", reads, writes)
	}
}

func TestWriteRules(t *testing.T) {
	e := newEnv(t)
	p := filepath.Join(e.write, "new.txt")
	w, err := e.fs.WriteFile(p, []byte("a\nb\n"), WriteOptions{Create: true})
	must(t, err)
	fi, _ := os.Stat(p)
	if !w.Created || !w.Verified || w.Mode != "0640" || fi.Mode().Perm() != 0o640 || w.LinesNew != 2 {
		t.Fatalf("write %+v mode %v", w, fi.Mode())
	}
	// Overwrite preserves mode; expected_sha256 guards.
	must(t, os.Chmod(p, 0o600))
	_, err = e.fs.WriteFile(p, []byte("c"), WriteOptions{Create: true, ExpectedSHA256: strings.Repeat("0", 64)})
	wantCode(t, err, protocol.CodeExists)
	w2, err := e.fs.WriteFile(p, []byte("c"), WriteOptions{Create: true, ExpectedSHA256: w.SHA256})
	must(t, err)
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 || w2.OldSHA256 != w.SHA256 || w2.Created {
		t.Fatalf("overwrite %+v mode %v", w2, fi.Mode())
	}
	// create=false needs an existing file.
	_, err = e.fs.WriteFile(filepath.Join(e.write, "absent"), []byte("x"), WriteOptions{Create: false})
	wantCode(t, err, protocol.CodeNotFound)
	// Outside write roots (a read root, outside, a denied path, protected paths).
	for _, q := range []string{filepath.Join(e.read, "x"), filepath.Join(e.outside, "x"), filepath.Join(e.write, "a.key"),
		filepath.Join(e.write, ".ssh", "authorized_keys"), filepath.Join(e.write, "locked")} {
		must(t, os.MkdirAll(filepath.Join(e.write, ".ssh"), 0o750))
		_, err = e.fs.WriteFile(q, []byte("x"), WriteOptions{Create: true})
		wantCode(t, err, protocol.CodePathDenied)
	}
	// Mode rules.
	for _, m := range []os.FileMode{0o4755, 0o2755, 0o1755, 0o646, 0o777} {
		m := m
		_, err = e.fs.WriteFile(filepath.Join(e.write, "m"), []byte("x"), WriteOptions{Create: true, Mode: &m})
		wantCode(t, err, protocol.CodePolicyDenied)
	}
	// An existing setuid file is not rewritten with its bits preserved.
	suid := filepath.Join(e.write, "suid")
	put(t, suid, "x")
	must(t, os.Chmod(suid, 0o755|os.ModeSetuid))
	_, err = e.fs.WriteFile(suid, []byte("y"), WriteOptions{Create: true})
	wantCode(t, err, protocol.CodePolicyDenied)
	// Size cap.
	e.fs.cfg.Limits.MaxWriteBytes = 4
	_, err = e.fs.WriteFile(p, []byte("12345"), WriteOptions{Create: true})
	wantCode(t, err, protocol.CodeTooLarge)
	// No temp files left behind.
	entries, _ := os.ReadDir(e.write)
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), ".shell-mcp-") {
			t.Fatalf("temp file left: %s", en.Name())
		}
	}
}

func TestReadBackFault(t *testing.T) {
	e := newEnv(t)
	e.fs.cfg.InjectReadBackFault = func(b []byte) []byte { return append(bytes.Clone(b), 'X') }
	_, err := e.fs.WriteFile(filepath.Join(e.write, "v.txt"), []byte("data"), WriteOptions{Create: true})
	wantCode(t, err, protocol.CodeVerifyFailed)
}

func TestPrivateKeyAndBinary(t *testing.T) {
	e := newEnv(t)
	// Invented, not key material.
	put(t, filepath.Join(e.read, "k.pem"), "x\n-----BEGIN OPENSSH PRIVATE KEY-----\ninvented\n-----END OPENSSH PRIVATE KEY-----\n")
	_, err := e.fs.ReadFile(filepath.Join(e.read, "k.pem"), ReadOptions{MaxBytes: 1024})
	wantCode(t, err, protocol.CodePathDenied)
	// Copying it is refused too.
	_, err = e.fs.Copy(filepath.Join(e.read, "k.pem"), filepath.Join(e.write, "k2"), false)
	wantCode(t, err, protocol.CodePathDenied)
	put(t, filepath.Join(e.read, "bin"), "ELF\x00\x01\x02")
	r, err := e.fs.ReadFile(filepath.Join(e.read, "bin"), ReadOptions{MaxBytes: 1024})
	must(t, err)
	if !r.Binary || r.Content != "" || r.Size != 6 || r.SHA256 == "" {
		t.Fatalf("binary %+v", r)
	}
	put(t, filepath.Join(e.read, "latin1"), "caf\xe9\n")
	if r, _ := e.fs.ReadFile(filepath.Join(e.read, "latin1"), ReadOptions{MaxBytes: 1024}); !r.Binary {
		t.Fatalf("invalid UTF-8 must be treated as binary: %+v", r)
	}
}

func TestReadWindows(t *testing.T) {
	e := newEnv(t)
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString("line ")
		sb.WriteString(strings.Repeat("x", i%7))
		sb.WriteString("\n")
	}
	p := filepath.Join(e.read, "log")
	put(t, p, sb.String())
	r, err := e.fs.ReadFile(p, ReadOptions{MaxBytes: 10})
	must(t, err)
	if len(r.Content) != 10 || !r.Truncated {
		t.Fatalf("max_bytes: %+v", r)
	}
	r, err = e.fs.ReadFile(p, ReadOptions{Offset: 5, MaxBytes: 3})
	must(t, err)
	if r.Content != sb.String()[5:8] || r.Offset != 5 {
		t.Fatalf("offset: %+v", r)
	}
	r, err = e.fs.ReadFile(p, ReadOptions{TailLines: 2, MaxBytes: 1024})
	must(t, err)
	lines := strings.Split(strings.TrimSuffix(sb.String(), "\n"), "\n")
	if r.Content != lines[98]+"\n"+lines[99]+"\n" {
		t.Fatalf("tail: %q", r.Content)
	}
	_, err = e.fs.ReadFile(p, ReadOptions{MaxBytes: 2 << 20})
	wantCode(t, err, protocol.CodeBadRequest)
	_, err = e.fs.ReadFile(p, ReadOptions{Offset: 1, TailLines: 1, MaxBytes: 10})
	wantCode(t, err, protocol.CodeBadRequest)
}

func TestListAndStat(t *testing.T) {
	e := newEnv(t)
	put(t, filepath.Join(e.read, ".hidden"), "h")
	put(t, filepath.Join(e.read, "x.key"), "k")
	l, err := e.fs.ListDir(e.read, false, 100)
	must(t, err)
	names := map[string]bool{}
	for _, en := range l.Entries {
		names[en.Name] = true
	}
	if !names["hello.txt"] || !names["config"] || names[".hidden"] || names["secrets"] || names["x.key"] {
		t.Fatalf("list %v", names)
	}
	l, err = e.fs.ListDir(e.read, true, 1)
	must(t, err)
	if len(l.Entries) != 1 || !l.Truncated {
		t.Fatalf("limit: %+v", l)
	}
	_, err = e.fs.ListDir(filepath.Join(e.read, "hello.txt"), false, 10)
	wantCode(t, err, protocol.CodeNotADirectory)
	st, err := e.fs.Stat(filepath.Join(e.read, "hello.txt"))
	must(t, err)
	if st.Type != "file" || st.Size != 12 || st.Mode != "0600" {
		t.Fatalf("stat %+v", st)
	}
	_, err = e.fs.Stat(filepath.Join(e.secrets, "token"))
	wantCode(t, err, protocol.CodePathDenied)
}

func TestFind(t *testing.T) {
	e := newEnv(t)
	put(t, filepath.Join(e.read, "a", "b", "c", "deep.log"), "x")
	put(t, filepath.Join(e.read, "a", "one.log"), "x")
	must(t, os.Symlink(e.outside, filepath.Join(e.read, "a", "out")))
	r, err := e.fs.Find(e.read, FindOptions{NameGlob: "*.log", MaxDepth: 8, Limit: 50})
	must(t, err)
	got := map[string]bool{}
	for _, en := range r.Entries {
		got[en.Path] = true
		if strings.HasPrefix(en.Path, e.outside) || strings.HasPrefix(en.Path, e.secrets) {
			t.Fatalf("find escaped or entered denied dir: %s", en.Path)
		}
	}
	if !got[filepath.Join(e.read, "a", "b", "c", "deep.log")] || !got[filepath.Join(e.read, "a", "one.log")] {
		t.Fatalf("find %v", got)
	}
	r, err = e.fs.Find(e.read, FindOptions{NameGlob: "*.log", MaxDepth: 2, Limit: 50})
	must(t, err)
	for _, en := range r.Entries {
		if strings.HasSuffix(en.Path, "deep.log") {
			t.Fatal("max_depth ignored")
		}
	}
	r, err = e.fs.Find(e.read, FindOptions{MaxDepth: 8, Limit: 2})
	must(t, err)
	if len(r.Entries) != 2 || !r.Truncated {
		t.Fatalf("limit: %+v", r)
	}
	r, err = e.fs.Find(e.read, FindOptions{Type: "symlink", MaxDepth: 8, Limit: 50})
	must(t, err)
	if len(r.Entries) != 1 || r.Entries[0].Type != "symlink" {
		t.Fatalf("type filter: %+v", r.Entries)
	}
	_, err = e.fs.Find(e.read, FindOptions{MaxDepth: 99, Limit: 5})
	wantCode(t, err, protocol.CodeBadRequest)
	_, err = e.fs.Find(e.read, FindOptions{NameGlob: "[", MaxDepth: 2, Limit: 5})
	wantCode(t, err, protocol.CodeBadRequest)
}

func TestMkdirCopyMoveChmod(t *testing.T) {
	e := newEnv(t)
	m, err := e.fs.Mkdir(filepath.Join(e.write, "x", "y"), nil, true)
	must(t, err)
	if fi, _ := os.Stat(filepath.Join(e.write, "x", "y")); !m.Created || !fi.IsDir() || fi.Mode().Perm() != 0o750 {
		t.Fatalf("mkdir %+v", m)
	}
	_, err = e.fs.Mkdir(filepath.Join(e.write, "x"), nil, false)
	wantCode(t, err, protocol.CodeExists)
	_, err = e.fs.Mkdir(filepath.Join(e.write, "p", "q"), nil, false)
	wantCode(t, err, protocol.CodeNotFound)
	_, err = e.fs.Mkdir(filepath.Join(e.write, "d", ".ssh"), nil, true)
	wantCode(t, err, protocol.CodePathDenied)

	c, err := e.fs.Copy(filepath.Join(e.read, "hello.txt"), filepath.Join(e.write, "hello.copy"), false)
	must(t, err)
	if b, _ := os.ReadFile(filepath.Join(e.write, "hello.copy")); string(b) != "hello\nworld\n" || !c.Verified {
		t.Fatalf("copy %+v", c)
	}
	_, err = e.fs.Copy(filepath.Join(e.read, "hello.txt"), filepath.Join(e.write, "hello.copy"), false)
	wantCode(t, err, protocol.CodeExists)
	_, err = e.fs.Copy(filepath.Join(e.secrets, "token"), filepath.Join(e.write, "t"), false)
	wantCode(t, err, protocol.CodePathDenied)
	_, err = e.fs.Copy(e.write, filepath.Join(e.write, "dircopy"), false)
	wantCode(t, err, protocol.CodeIsADirectory)

	mv, err := e.fs.Move(filepath.Join(e.write, "hello.copy"), filepath.Join(e.write, "x", "moved"), false)
	must(t, err)
	if _, err = os.Stat(filepath.Join(e.write, "x", "moved")); err != nil || mv.Type != "file" {
		t.Fatalf("move %+v %v", mv, err)
	}
	_, err = e.fs.Move(filepath.Join(e.read, "hello.txt"), filepath.Join(e.write, "h"), false)
	wantCode(t, err, protocol.CodePathDenied)
	put(t, filepath.Join(e.write, "a"), "a")
	put(t, filepath.Join(e.write, "b"), "b")
	_, err = e.fs.Move(filepath.Join(e.write, "a"), filepath.Join(e.write, "b"), false)
	wantCode(t, err, protocol.CodeExists)
	if _, err = e.fs.Move(filepath.Join(e.write, "a"), filepath.Join(e.write, "b"), true); err != nil {
		t.Fatal(err)
	}
	// A directory containing a denied entry cannot be moved (its contents
	// would become readable under another name) — here a *.key file.
	put(t, filepath.Join(e.write, "tree", "inner", "tls.key"), "k")
	_, err = e.fs.Move(filepath.Join(e.write, "tree"), filepath.Join(e.write, "tree2"), false)
	wantCode(t, err, protocol.CodePathDenied)

	ch, err := e.fs.Chmod(filepath.Join(e.write, "b"), 0o640)
	must(t, err)
	if fi, _ := os.Stat(filepath.Join(e.write, "b")); fi.Mode().Perm() != 0o640 || ch.OldMode != "0600" {
		t.Fatalf("chmod %+v", ch)
	}
	_, err = e.fs.Chmod(filepath.Join(e.write, "b"), 0o4755)
	wantCode(t, err, protocol.CodePolicyDenied)
	_, err = e.fs.Chmod(filepath.Join(e.read, "hello.txt"), 0o600)
	wantCode(t, err, protocol.CodePathDenied)
}

func TestDelete(t *testing.T) {
	e := newEnv(t)
	put(t, filepath.Join(e.write, "f"), "12345")
	pv, err := e.fs.DeletePreview(filepath.Join(e.write, "f"), false)
	must(t, err)
	if pv.Entries != 1 || pv.Bytes != 5 || pv.Deleted {
		t.Fatalf("preview %+v", pv)
	}
	if _, err = os.Stat(filepath.Join(e.write, "f")); err != nil {
		t.Fatal("preview deleted")
	}
	d, err := e.fs.Delete(filepath.Join(e.write, "f"), false)
	must(t, err)
	if !d.Deleted {
		t.Fatal("not deleted")
	}
	for i := 0; i < 5; i++ {
		put(t, filepath.Join(e.write, "tree", "sub", string(rune('a'+i))), "xx")
	}
	_, err = e.fs.Delete(filepath.Join(e.write, "tree"), false)
	wantCode(t, err, protocol.CodeBadRequest)
	pv, err = e.fs.DeletePreview(filepath.Join(e.write, "tree"), true)
	must(t, err)
	if pv.Entries != 7 || pv.Bytes != 10 || len(pv.First) != 7 {
		t.Fatalf("recursive preview %+v", pv)
	}
	_, err = e.fs.Delete(filepath.Join(e.write, "tree"), true)
	must(t, err)
	if _, err = os.Stat(filepath.Join(e.write, "tree")); !os.IsNotExist(err) {
		t.Fatal("tree still exists")
	}
	// Bounded.
	for i := 0; i < 25; i++ {
		put(t, filepath.Join(e.write, "big", string(rune('a'+i))), "x")
	}
	_, err = e.fs.Delete(filepath.Join(e.write, "big"), true)
	wantCode(t, err, protocol.CodeTooLarge)
	if n, _ := os.ReadDir(filepath.Join(e.write, "big")); len(n) != 25 {
		t.Fatal("over-limit delete removed entries")
	}
	// Refused: roots, symlinks, trees holding protected entries.
	_, err = e.fs.Delete(e.write, true)
	wantCode(t, err, protocol.CodePathDenied)
	must(t, os.Symlink(e.outside, filepath.Join(e.write, "l")))
	_, err = e.fs.Delete(filepath.Join(e.write, "l"), false)
	wantCode(t, err, protocol.CodePathDenied)
	put(t, filepath.Join(e.write, "home", ".ssh", "authorized_keys"), "k")
	_, err = e.fs.Delete(filepath.Join(e.write, "home"), true)
	wantCode(t, err, protocol.CodePathDenied)
	if _, err = os.Stat(filepath.Join(e.write, "home", ".ssh", "authorized_keys")); err != nil {
		t.Fatal("protected entry removed")
	}
	// Inner symlinks are removed, never followed.
	put(t, filepath.Join(e.write, "withlink", "x"), "x")
	must(t, os.Symlink(e.outside, filepath.Join(e.write, "withlink", "out")))
	_, err = e.fs.Delete(filepath.Join(e.write, "withlink"), true)
	must(t, err)
	if _, err := os.Stat(filepath.Join(e.outside, "passwd")); err != nil {
		t.Fatal("followed an inner symlink")
	}
}

func TestResolve(t *testing.T) {
	e := newEnv(t)
	p, err := e.fs.ResolveRead(filepath.Join(e.read, "hello.txt"))
	if err != nil || p != filepath.Join(e.read, "hello.txt") {
		t.Fatalf("ResolveRead %q %v", p, err)
	}
	_, err = e.fs.ResolveRead(filepath.Join(e.secrets, "token"))
	wantCode(t, err, protocol.CodePathDenied)
	must(t, os.Symlink(filepath.Join(e.read, "hello.txt"), filepath.Join(e.read, "hl")))
	_, err = e.fs.ResolveRead(filepath.Join(e.read, "hl"))
	wantCode(t, err, protocol.CodePathDenied)
	p, err = e.fs.ResolveWrite(filepath.Join(e.write, "new-out"))
	if err != nil || p != filepath.Join(e.write, "new-out") {
		t.Fatalf("ResolveWrite %q %v", p, err)
	}
	_, err = e.fs.ResolveWrite(filepath.Join(e.read, "x"))
	wantCode(t, err, protocol.CodePathDenied)
	p, err = e.fs.ResolveDir(e.write)
	if err != nil || p != e.write {
		t.Fatalf("ResolveDir %q %v", p, err)
	}
	_, err = e.fs.ResolveDir(filepath.Join(e.read, "hello.txt"))
	wantCode(t, err, protocol.CodeNotADirectory)
}

func TestParseMode(t *testing.T) {
	for s, want := range map[string]os.FileMode{"0640": 0o640, "640": 0o640, "0755": 0o755, "0000": 0} {
		if m, err := ParseMode(s); err != nil || m != want {
			t.Errorf("ParseMode(%q) = %v, %v", s, m, err)
		}
	}
	for _, s := range []string{"", "0", "999", "4755", "0647", "0777", "u+x", "07550", "0o644", "-644"} {
		if _, err := ParseMode(s); err == nil {
			t.Errorf("ParseMode(%q) accepted", s)
		}
	}
}
