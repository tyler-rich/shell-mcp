//go:build linux

package fsx

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Create-only commits: write_file with expect_absent, and copy and move
// without overwrite. A destination that appears after fsx looked for it, up
// to the commit itself, is never replaced: the operation answers exists and
// the other file is untouched. Fixtures are invented, under t.TempDir().

// windowRuns is how often the deterministic window test creates the
// destination just before the commit; concurrentRuns how often the
// concurrent test races a goroutine against the operation.
const (
	windowRuns     = 200
	concurrentRuns = 400
)

// createOnly is one create-only operation on dst. prepare runs before each
// attempt (a move needs a fresh source); srcLeft reports whether the source
// is still where it was (a refused move must not have moved it).
type createOnly struct {
	name    string
	prepare func(t *testing.T, i int)
	run     func(dst string, i int) error
	srcLeft func(t *testing.T, i int) bool
}

func createOnlyOps(e *env) []createOnly {
	copySrc := filepath.Join(e.write, "copy-src.txt")
	moveSrc := func(i int) string { return filepath.Join(e.write, fmt.Sprintf("move-src-%d.txt", i)) }
	moveDir := func(i int) string { return filepath.Join(e.write, fmt.Sprintf("move-dir-%d", i)) }
	return []createOnly{
		{
			name: "write_file expect_absent",
			run: func(dst string, _ int) error {
				_, err := e.fs.WriteFile(dst, []byte("approved\n"), WriteOptions{Create: true, ExpectAbsent: true})
				return err
			},
		},
		{
			name:    "copy without overwrite",
			prepare: func(t *testing.T, i int) { put(t, copySrc, "copied\n") },
			run: func(dst string, _ int) error {
				_, err := e.fs.Copy(copySrc, dst, false)
				return err
			},
		},
		{
			name:    "move file without overwrite",
			prepare: func(t *testing.T, i int) { put(t, moveSrc(i), "moved\n") },
			run: func(dst string, i int) error {
				_, err := e.fs.Move(moveSrc(i), dst, false)
				return err
			},
			srcLeft: func(t *testing.T, i int) bool { return read(t, moveSrc(i)) == "moved\n" },
		},
		{
			name: "move directory without overwrite",
			prepare: func(t *testing.T, i int) {
				put(t, filepath.Join(moveDir(i), "inner.txt"), "inner\n")
			},
			run: func(dst string, i int) error {
				_, err := e.fs.Move(moveDir(i), dst, false)
				return err
			},
			srcLeft: func(t *testing.T, i int) bool { return read(t, filepath.Join(moveDir(i), "inner.txt")) == "inner\n" },
		},
	}
}

// plant creates dst as the racing file (an empty directory for a directory
// move, the case rename(2) would otherwise replace), failing if it exists.
func plant(dst string, dir bool, i int) error {
	if dir {
		return os.Mkdir(dst, 0o750)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: test fixture
	if err != nil {
		return err
	}
	_, err = f.WriteString(racerContent(i))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func racerContent(i int) string { return fmt.Sprintf("racer %d\n", i) }

// planted reports whether dst still is what plant made.
func planted(t *testing.T, dst string, dir bool, i int) bool {
	t.Helper()
	if dir {
		ents, err := os.ReadDir(dst)
		return err == nil && len(ents) == 0
	}
	b, err := os.ReadFile(dst) //nolint:gosec // G304: test fixture
	return err == nil && string(b) == racerContent(i)
}

func TestExpectAbsentRules(t *testing.T) {
	e := newEnv(t)
	p := filepath.Join(e.write, "app.yaml")
	_, err := e.fs.WriteFile(p, []byte("x"), WriteOptions{Create: true, ExpectAbsent: true, ExpectedSHA256: strings.Repeat("0", 64)})
	wantCode(t, err, protocol.CodeBadRequest)
	_, err = e.fs.WriteFile(p, []byte("x"), WriteOptions{Create: true, ExpectAbsent: true})
	wantCode(t, err, protocol.CodeExists)
	if got := read(t, p); got != "key: value\n" {
		t.Fatalf("an existing file was changed: %q", got)
	}
	n := filepath.Join(e.write, "new.yaml")
	r, err := e.fs.WriteFile(n, []byte("new\n"), WriteOptions{Create: true, ExpectAbsent: true, Mode: new(os.FileMode(0o600))})
	must(t, err)
	if !r.Created || !r.Verified || r.Mode != "0600" || read(t, n) != "new\n" {
		t.Fatalf("create %+v", r)
	}
	// The commit leaves exactly one name for the new file.
	fi, err := os.Lstat(n)
	must(t, err)
	if nl := fi.Sys().(*syscall.Stat_t).Nlink; nl != 1 {
		t.Fatalf("new file has %d links", nl)
	}
	noTemp(t, e.write)
}

// TestCreateOnlyCommitWindow creates the destination at the last moment
// before each commit (InjectBeforeCommit), after every check fsx makes. The
// commit itself must refuse it.
func TestCreateOnlyCommitWindow(t *testing.T) {
	for _, op := range createOnlyOps(newEnv(t)) {
		t.Run(op.name, func(t *testing.T) {
			e := newEnv(t)
			op := findOp(t, createOnlyOps(e), op.name)
			dir := strings.Contains(op.name, "directory")
			for i := range windowRuns {
				if op.prepare != nil {
					op.prepare(t, i)
				}
				dst := filepath.Join(e.write, fmt.Sprintf("dst-%d", i))
				hooked := false
				e.fs.cfg.InjectBeforeCommit = func() {
					hooked = true
					if err := plant(dst, dir, i); err != nil {
						t.Errorf("plant: %v", err)
					}
				}
				err := op.run(dst, i)
				e.fs.cfg.InjectBeforeCommit = nil
				if !hooked {
					t.Fatalf("run %d: the commit hook never ran (%v)", i, err)
				}
				if !planted(t, dst, dir, i) {
					t.Fatalf("run %d: the file created before the commit was replaced (err %v)", i, err)
				}
				wantCode(t, err, protocol.CodeExists)
				if op.srcLeft != nil && !op.srcLeft(t, i) {
					t.Fatalf("run %d: a refused move moved its source", i)
				}
				noTemp(t, e.write)
			}
		})
	}
}

func findOp(t *testing.T, ops []createOnly, name string) createOnly {
	t.Helper()
	for _, o := range ops {
		if o.name == name {
			return o
		}
	}
	t.Fatalf("no op %q", name)
	return createOnly{}
}

// TestCreateOnlyConcurrentRace races a goroutine that creates the
// destination against the operation, with no hook: whoever creates the
// destination first keeps it. Both succeeding means one replaced the other.
func TestCreateOnlyConcurrentRace(t *testing.T) {
	for _, op := range createOnlyOps(newEnv(t)) {
		if strings.Contains(op.name, "directory") {
			continue // a racing mkdir cannot detect being replaced; the window test covers it
		}
		t.Run(op.name, func(t *testing.T) {
			e := newEnv(t)
			op := findOp(t, createOnlyOps(e), op.name)
			// The racer starts after a random delay of up to twice one
			// operation's duration, so it lands before, inside and after the
			// operation's window.
			spread := 2 * timeOp(t, e, op)
			racerFirst, opFirst := 0, 0
			for i := range concurrentRuns {
				if op.prepare != nil {
					op.prepare(t, i)
				}
				dst := filepath.Join(e.write, fmt.Sprintf("race-%d", i))
				delay := time.Duration(rand.Int64N(int64(spread) + 1)) //nolint:gosec // G404: test timing jitter
				racer := make(chan error, 1)
				go func() {
					time.Sleep(delay)
					racer <- plant(dst, false, i)
				}()
				err := op.run(dst, i)
				rerr := <-racer
				switch {
				case rerr == nil && err == nil:
					t.Fatalf("run %d: both the racer and the operation created the destination: one replaced the other", i)
				case rerr == nil:
					racerFirst++
					wantCode(t, err, protocol.CodeExists)
					if !planted(t, dst, false, i) {
						t.Fatalf("run %d: the racer's file was changed", i)
					}
					if op.srcLeft != nil && !op.srcLeft(t, i) {
						t.Fatalf("run %d: a refused move moved its source", i)
					}
				case errors.Is(rerr, fs.ErrExist):
					opFirst++
					must(t, err)
				default:
					t.Fatalf("run %d: racer: %v", i, rerr)
				}
				noTemp(t, e.write)
			}
			t.Logf("%d runs: racer first %d, operation first %d", concurrentRuns, racerFirst, opFirst)
			if racerFirst == 0 || opFirst == 0 {
				t.Fatalf("race test is vacuous: racer first %d, operation first %d", racerFirst, opFirst)
			}
		})
	}
}

// timeOp returns the median duration of a few uncontended runs of op.
func timeOp(t *testing.T, e *env, op createOnly) time.Duration {
	t.Helper()
	var ds []time.Duration
	for i := range 9 {
		if op.prepare != nil {
			op.prepare(t, 100000+i)
		}
		dst := filepath.Join(e.write, fmt.Sprintf("timing-%d", i))
		start := time.Now()
		must(t, op.run(dst, 100000+i))
		ds = append(ds, time.Since(start))
	}
	for i := range ds {
		for j := i + 1; j < len(ds); j++ {
			if ds[j] < ds[i] {
				ds[i], ds[j] = ds[j], ds[i]
			}
		}
	}
	return ds[len(ds)/2]
}

// TestNoReplaceUnsupported: a filesystem that cannot refuse an existing
// destination atomically (no hard links for write and copy, no
// RENAME_NOREPLACE for move) is refused, with nothing changed; there is no
// check-then-rename fallback. Operations that may replace are unaffected.
func TestNoReplaceUnsupported(t *testing.T) {
	e := newEnv(t)
	src := filepath.Join(e.write, "src.txt")
	put(t, src, "source\n")
	for _, errno := range []syscall.Errno{syscall.EINVAL, syscall.ENOSYS} {
		e.fs.cfg.InjectNoReplaceFault = func() error { return errno }
		dst := filepath.Join(e.write, "moved.txt")
		_, err := e.fs.Move(src, dst, false)
		wantCode(t, err, protocol.CodeBadRequest)
		if !strings.Contains(err.Error(), "RENAME_NOREPLACE") {
			t.Fatalf("%v: message does not name the filesystem limitation: %v", errno, err)
		}
		absent(t, dst)
		if read(t, src) != "source\n" {
			t.Fatal("the source moved")
		}
	}
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EOPNOTSUPP} {
		e.fs.cfg.InjectNoReplaceFault = func() error { return errno }
		n := filepath.Join(e.write, "created.txt")
		_, err := e.fs.WriteFile(n, []byte("x"), WriteOptions{Create: true, ExpectAbsent: true})
		wantCode(t, err, protocol.CodeBadRequest)
		if !strings.Contains(err.Error(), "hard link") {
			t.Fatalf("%v: message does not name the filesystem limitation: %v", errno, err)
		}
		absent(t, n)
		_, err = e.fs.Copy(src, n, false)
		wantCode(t, err, protocol.CodeBadRequest)
		absent(t, n)
		noTemp(t, e.write)
	}
	// Writes and moves that may replace never need the atomic refusal.
	e.fs.cfg.InjectNoReplaceFault = func() error { return syscall.EINVAL }
	_, err := e.fs.WriteFile(filepath.Join(e.write, "plain.txt"), []byte("plain\n"), WriteOptions{Create: true})
	must(t, err)
	_, err = e.fs.Move(src, filepath.Join(e.write, "app.yaml"), true)
	must(t, err)
}

func absent(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s exists (%v)", p, err)
	}
}
