//go:build linux

package fsx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Replacing commits (S4c-2, handoff P-9; POLICY §3 for the gate): a copy
// or move with overwrite binds the destination's content
// (expected_destination_sha256), and every commit that replaces a file in
// the helper (Config.VerifyReplaced), or a file whose content was bound in
// the gate, is an exchange checked afterwards, so a destination replaced or
// rewritten after the last check is exchanged back, never lost. The backup hook is told the
// hash fsx computed, and the results carry the new inode's owner. Fixtures
// are invented, under t.TempDir().

func hexSHA(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// helperEnv is newEnv with the helper's settings: verified replaces, and a
// backup hook recording what it was handed.
func helperEnv(t *testing.T) (*env, *[]*BackupSource) {
	t.Helper()
	e := newEnv(t)
	e.fs.cfg.VerifyReplaced = true
	var got []*BackupSource
	e.fs.cfg.Backup = func(src *BackupSource) error {
		b, err := readAllFile(src.File)
		if err != nil {
			return err
		}
		c := *src
		c.File = nil
		c.Path = src.Path + "\x00" + string(b) // what the backup read, for the test
		got = append(got, &c)
		return nil
	}
	return e, &got
}

func readAllFile(f *os.File) ([]byte, error) { return io.ReadAll(f) }

func TestCopyMoveExpectedDestination(t *testing.T) {
	type op func(e *env, src, dst string, overwrite bool, expected string) error
	ops := map[string]op{
		"copy": func(e *env, src, dst string, overwrite bool, expected string) error {
			_, err := e.fs.CopyExpecting(src, dst, overwrite, expected)
			return err
		},
		"move": func(e *env, src, dst string, overwrite bool, expected string) error {
			_, err := e.fs.MoveExpecting(src, dst, overwrite, expected)
			return err
		},
	}
	for name, run := range ops {
		t.Run(name, func(t *testing.T) {
			e, backups := helperEnv(t)
			src, dst := filepath.Join(e.write, "src.txt"), filepath.Join(e.write, "dst.txt")
			put(t, src, "new\n")
			put(t, dst, "approved old\n")
			// Another hash: exists, nothing changed, nothing backed up.
			wantCode(t, run(e, src, dst, true, hexSHA("something else")), protocol.CodeExists)
			if read(t, dst) != "approved old\n" || read(t, src) != "new\n" || len(*backups) != 0 {
				t.Fatalf("a refused %s changed something: dst %q, %d backups", name, read(t, dst), len(*backups))
			}
			// A malformed hash, or one without overwrite: bad_request.
			wantCode(t, run(e, src, dst, true, "ABC"), protocol.CodeBadRequest)
			wantCode(t, run(e, src, filepath.Join(e.write, "none.txt"), false, hexSHA("x")), protocol.CodeBadRequest)
			// The destination gone: not_found; a directory there: exists.
			wantCode(t, run(e, src, filepath.Join(e.write, "gone.txt"), true, hexSHA("x")), protocol.CodeNotFound)
			must(t, os.Mkdir(filepath.Join(e.write, "adir"), 0o750))
			wantCode(t, run(e, src, filepath.Join(e.write, "adir"), true, hexSHA("x")), protocol.CodeExists)
			// The right hash: replaced, and the backup was handed that hash and
			// read exactly that content.
			must(t, run(e, src, dst, true, hexSHA("approved old\n")))
			if read(t, dst) != "new\n" {
				t.Fatalf("dst %q", read(t, dst))
			}
			if len(*backups) != 1 || (*backups)[0].SHA256 != hexSHA("approved old\n") || !strings.HasSuffix((*backups)[0].Path, "\x00approved old\n") {
				t.Fatalf("backups %+v", *backups)
			}
		})
	}
}

// replaceOp is one operation that replaces dst with content it knows.
type replaceOp struct {
	name    string
	prepare func(t *testing.T, i int)
	run     func(dst string, i int) error
	srcLeft func(t *testing.T, i int) bool
}

func replaceOps(e *env, oldContent string) []replaceOp {
	src := filepath.Join(e.write, "repl-src.txt")
	moveSrc := func(i int) string { return filepath.Join(e.write, fmt.Sprintf("repl-move-%d.txt", i)) }
	return []replaceOp{
		{name: "write with expected_sha256", run: func(dst string, _ int) error {
			_, err := e.fs.WriteFile(dst, []byte("approved new\n"), WriteOptions{Create: true, ExpectedSHA256: hexSHA(oldContent)})
			return err
		}},
		{name: "copy with expected destination", prepare: func(t *testing.T, _ int) { put(t, src, "approved new\n") },
			run: func(dst string, _ int) error {
				_, err := e.fs.CopyExpecting(src, dst, true, hexSHA(oldContent))
				return err
			}},
		{name: "move with expected destination", prepare: func(t *testing.T, i int) { put(t, moveSrc(i), "approved new\n") },
			run: func(dst string, i int) error {
				_, err := e.fs.MoveExpecting(moveSrc(i), dst, true, hexSHA(oldContent))
				return err
			},
			srcLeft: func(t *testing.T, i int) bool { return read(t, moveSrc(i)) == "approved new\n" }},
	}
}

// replaceEnv is one configuration whose conditional replaces are verified:
// the helper's (Config.VerifyReplaced, with backups), or the gate's, where
// a write with expected_sha256, and a copy or move with
// expected_destination_sha256 (P-9), are verified replaces without the flag
// and without backups (POLICY §3).
type replaceEnv struct {
	name    string
	e       *env
	backups *[]*BackupSource // nil for the gate
}

func replaceEnvs(t *testing.T) []replaceEnv {
	t.Helper()
	h, backups := helperEnv(t)
	return []replaceEnv{{name: "helper", e: h, backups: backups}, {name: "gate", e: newEnv(t)}}
}

// TestVerifiedReplaceCommitWindow: the destination is replaced by another
// file, or rewritten in place, after every check and immediately before the
// commit. It is never lost: the operation answers exists and the racing
// content stays at the destination; a refused move leaves its source. In
// the helper and in the gate.
func TestVerifiedReplaceCommitWindow(t *testing.T) {
	t.Parallel()
	const old = "approved old\n"
	for _, how := range []string{"replaced", "rewritten"} {
		for _, re := range replaceEnvs(t) {
			e := re.e
			for _, op := range replaceOps(e, old) {
				for i := range windowRuns {
					dst := filepath.Join(e.write, fmt.Sprintf("win-%s-%d", how, i))
					put(t, dst, old)
					if op.prepare != nil {
						op.prepare(t, i)
					}
					racer := fmt.Sprintf("racer %d\n", i)
					e.fs.cfg.InjectBeforeCommit = func() {
						if how == "replaced" {
							tmp := dst + ".racer"
							put(t, tmp, racer)
							must(t, os.Rename(tmp, dst))
							return
						}
						time.Sleep(2 * time.Millisecond) // a new mtime, whatever the clock's granularity
						must(t, os.WriteFile(dst, []byte(racer), 0o600))
					}
					err := op.run(dst, i)
					e.fs.cfg.InjectBeforeCommit = nil
					if got := read(t, dst); got != racer {
						t.Fatalf("%s: %s, destination %s, run %d: the racing content was lost (op error %v): %q", re.name, op.name, how, i, err, got)
					}
					wantCode(t, err, protocol.CodeExists)
					if op.srcLeft != nil && !op.srcLeft(t, i) {
						t.Fatalf("%s: %s run %d: a refused move moved its source", re.name, op.name, i)
					}
				}
				t.Logf("%s: %s, destination %s before the commit: exists in %d of %d runs, the racing content kept", re.name, op.name, how, windowRuns, windowRuns)
			}
		}
	}
}

// TestVerifiedReplaceConcurrentRace: a goroutine replaces the destination
// (write a temp file, rename it over) after a random delay of up to twice
// the operation's measured duration. Whatever the order, the racer's
// content is never lost: it ends at the destination. In the helper, an
// operation that succeeds replaced the approved content only (its backup
// holds it). Every run is counted, and the test fails at the end if any
// run lost the racer's content or ended in an unexpected error.
func TestVerifiedReplaceConcurrentRace(t *testing.T) {
	t.Parallel()
	const old = "approved old\n"
	for _, re := range replaceEnvs(t) {
		e, backups := re.e, re.backups
		refusedFirst := []string{protocol.CodeExists, protocol.CodePathDenied}
		if backups != nil {
			refusedFirst = append(refusedFirst, protocol.CodeBackupFailed)
		}
		for _, op := range replaceOps(e, old) {
			// Measure the operation once.
			probe := filepath.Join(e.write, "race-probe")
			put(t, probe, old)
			if op.prepare != nil {
				op.prepare(t, 999999)
			}
			start := time.Now()
			must(t, op.run(probe, 999999))
			took := time.Since(start)
			first, wonOK, after, lost := 0, 0, 0, 0
			var unexpected []string
			for i := range concurrentRuns {
				dst := filepath.Join(e.write, fmt.Sprintf("race-%d", i))
				put(t, dst, old)
				if op.prepare != nil {
					op.prepare(t, i)
				}
				racer := fmt.Sprintf("racer %d\n", i)
				delay := time.Duration(rand.Int64N(int64(2*took) + 1)) //nolint:gosec // G404: test timing
				done := make(chan struct{})
				go func() {
					defer close(done)
					time.Sleep(delay)
					tmp := dst + ".racer"
					_ = os.WriteFile(tmp, []byte(racer), 0o600)
					_ = os.Rename(tmp, dst)
				}()
				nb := 0
				if backups != nil {
					nb = len(*backups)
				}
				err := op.run(dst, i)
				<-done
				if got := read(t, dst); got != racer {
					lost++
					continue
				}
				var fe *Error
				switch {
				case err == nil:
					wonOK++
					if backups != nil && (len(*backups) != nb+1 || !strings.HasSuffix((*backups)[nb].Path, "\x00"+old)) {
						t.Fatalf("%s: %s run %d: replaced something other than the approved content", re.name, op.name, i)
					}
				case !errors.As(err, &fe):
					unexpected = append(unexpected, err.Error())
				case slices.Contains(refusedFirst, fe.Code):
					first++ // the racer first: refused, nothing replaced
				case fe.Code == protocol.CodeVerifyFailed || fe.Code == protocol.CodeInternal && strings.Contains(fe.Msg, "could not be verified"):
					after++ // the racer after the commit, seen by the read-back or the move's own check
				default:
					unexpected = append(unexpected, err.Error())
				}
			}
			t.Logf("%s: %s: %d runs: succeeded, then the racer replaced it %d; the racer after the commit, reported %d; the racer first, refused %d; the racer's content lost %d; unexpected errors %d",
				re.name, op.name, concurrentRuns, wonOK, after, first, lost, len(unexpected))
			if lost != 0 || len(unexpected) != 0 {
				t.Errorf("%s: %s: the racer's content was lost in %d of %d runs; unexpected errors: %v", re.name, op.name, lost, concurrentRuns, unexpected)
			}
		}
	}
}

// TestVerifiedReplaceUnsupported: a filesystem without RENAME_EXCHANGE is
// refused with bad_request naming it, never replaced unchecked: in the
// helper, and for the gate's conditional replaces.
func TestVerifiedReplaceUnsupported(t *testing.T) {
	const old = "approved old\n"
	for _, re := range replaceEnvs(t) {
		e := re.e
		for _, op := range replaceOps(e, old) {
			for _, errno := range []error{syscall.EINVAL, syscall.ENOSYS} {
				dst := filepath.Join(e.write, "unsupported")
				put(t, dst, old)
				if op.prepare != nil {
					op.prepare(t, 0)
				}
				e.fs.cfg.InjectExchangeFault = func() error { return errno }
				err := op.run(dst, 0)
				e.fs.cfg.InjectExchangeFault = nil
				if got := read(t, dst); got != old {
					t.Fatalf("%s: %s: replaced unchecked (%v): %q", re.name, op.name, err, got)
				}
				wantCode(t, err, protocol.CodeBadRequest)
				if !strings.Contains(err.Error(), "RENAME_EXCHANGE") {
					t.Fatalf("%s: %s: %v", re.name, op.name, err)
				}
			}
		}
	}
	// The gate's unconditional replaces (a write without expected_sha256, a
	// copy or move with overwrite and no expected destination) keep
	// rename(2): they replace whatever is there, and need no exchange.
	g := newEnv(t)
	g.fs.cfg.InjectExchangeFault = func() error { return syscall.EINVAL }
	_, err := g.fs.WriteFile(filepath.Join(g.write, "app.yaml"), []byte("gate\n"), WriteOptions{Create: true})
	must(t, err)
	src, dst := filepath.Join(g.write, "u-src"), filepath.Join(g.write, "u-dst")
	put(t, src, "copied\n")
	put(t, dst, old)
	_, err = g.fs.Copy(src, dst, true)
	must(t, err)
	put(t, dst, old)
	_, err = g.fs.Move(src, dst, true)
	must(t, err)
	if got := read(t, dst); got != "copied\n" {
		t.Fatalf("unconditional gate replaces: dst %q", got)
	}
}

// TestBackupHandedTheHash: the backup hook gets the hash fsx computed of
// what it replaces. A file changed between that hash and the backup (a new
// size or mtime, or another inode) is refused by fsx before the hook runs;
// a change that keeps all three is the hook's to refuse, by content (the
// helper's store compares the hash; privd TestBackupBoundToPrecondition).
func TestBackupHandedTheHash(t *testing.T) {
	e, backups := helperEnv(t)
	p := filepath.Join(e.write, "app.yaml")
	_, err := e.fs.WriteFile(p, []byte("two\n"), WriteOptions{Create: true})
	must(t, err)
	if len(*backups) != 1 || (*backups)[0].SHA256 != hexSHA("key: value\n") {
		t.Fatalf("backups %+v", *backups)
	}
	e.fs.cfg.InjectBeforeBackup = func() { must(t, os.WriteFile(p, []byte("changed!\n"), 0o600)) }
	_, err = e.fs.WriteFile(p, []byte("three\n"), WriteOptions{Create: true, ExpectedSHA256: hexSHA("two\n")})
	wantCode(t, err, protocol.CodeBackupFailed)
	if len(*backups) != 1 || read(t, p) != "changed!\n" {
		t.Fatalf("the hook ran (%d backups) or the file changed: %q", len(*backups), read(t, p))
	}
	// Same size and mtime, other content: fsx hands the hook the hash of
	// what it checked, and the hook reads other bytes.
	fi, err := os.Stat(p)
	must(t, err)
	e.fs.cfg.InjectBeforeBackup = func() {
		must(t, os.WriteFile(p, []byte("CHANGED!\n"), 0o600))
		must(t, os.Chtimes(p, fi.ModTime(), fi.ModTime()))
	}
	_, err = e.fs.WriteFile(p, []byte("four\n"), WriteOptions{Create: true, ExpectedSHA256: hexSHA("changed!\n")})
	must(t, err) // this test's hook only records; the helper's store refuses
	if b := (*backups)[1]; b.SHA256 != hexSHA("changed!\n") || !strings.HasSuffix(b.Path, "\x00CHANGED!\n") {
		t.Fatalf("the hook was not handed the hash fsx computed before the change: %+v", b)
	}
}

// TestResultsCarryOwner: write, copy and mkdir results carry the new
// inode's owner and group, read from its descriptor.
func TestResultsCarryOwner(t *testing.T) {
	e := newEnv(t)
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: test ids fit
	w, err := e.fs.WriteFile(filepath.Join(e.write, "owned.txt"), []byte("x"), WriteOptions{Create: true})
	must(t, err)
	c, err := e.fs.Copy(filepath.Join(e.write, "owned.txt"), filepath.Join(e.write, "owned-copy.txt"), false)
	must(t, err)
	m, err := e.fs.Mkdir(filepath.Join(e.write, "owned-dir"), nil, false)
	must(t, err)
	if w.UID != uid || w.GID != gid || c.UID != uid || c.GID != gid || m.UID != uid || m.GID != gid {
		t.Fatalf("owners: write %d:%d copy %d:%d mkdir %d:%d, want %d:%d", w.UID, w.GID, c.UID, c.GID, m.UID, m.GID, uid, gid)
	}
	if st := statOf(t, filepath.Join(e.write, "owned.txt")); st.Uid != w.UID {
		t.Fatalf("on disk %d", st.Uid)
	}
}

// TestProbeExchange: on a filesystem with RENAME_EXCHANGE the probe passes
// and leaves nothing behind (check-policy runs it in each privileged write
// root).
func TestProbeExchange(t *testing.T) {
	d := t.TempDir()
	must(t, ProbeExchange(d))
	ents, err := os.ReadDir(d)
	must(t, err)
	if len(ents) != 0 {
		t.Fatalf("the probe left %v", ents)
	}
	if err := ProbeExchange(filepath.Join(d, "missing")); err == nil || errors.Is(err, ErrExchangeUnsupported) {
		t.Fatalf("a missing root: %v", err)
	}
}

// TestUnchangedSignal: fsx marks a refusal Unchanged only when it made no
// mutating system call, or undid the one it made; a failure after a commit
// never carries it.
func TestUnchangedSignal(t *testing.T) {
	e, _ := helperEnv(t)
	p := filepath.Join(e.write, "app.yaml")
	unchanged := func(err error) bool {
		var fe *Error
		return errors.As(err, &fe) && fe.Unchanged
	}
	// Exchanged back after a racer replaced the destination.
	e.fs.cfg.InjectBeforeCommit = func() { put(t, p+".r", "racer\n"); must(t, os.Rename(p+".r", p)) }
	_, err := e.fs.WriteFile(p, []byte("x\n"), WriteOptions{Create: true, ExpectedSHA256: hexSHA("key: value\n")})
	e.fs.cfg.InjectBeforeCommit = nil
	if !unchanged(err) {
		t.Fatalf("exchanged back: %v not marked unchanged", err)
	}
	// A create-only commit refused by link(2).
	n := filepath.Join(e.write, "new.yaml")
	e.fs.cfg.InjectBeforeCommit = func() { put(t, n, "planted\n") }
	_, err = e.fs.WriteFile(n, []byte("x\n"), WriteOptions{Create: true, ExpectAbsent: true})
	e.fs.cfg.InjectBeforeCommit = nil
	if !unchanged(err) {
		t.Fatalf("create-only refused: %v not marked unchanged", err)
	}
	// A changed file refused before its backup was written.
	e.fs.cfg.InjectBeforeBackup = func() { put(t, p, "changed again\n") }
	_, err = e.fs.WriteFile(p, []byte("y\n"), WriteOptions{Create: true})
	e.fs.cfg.InjectBeforeBackup = nil
	if !unchanged(err) {
		t.Fatalf("changed before the backup: %v not marked unchanged", err)
	}
	// After the commit: never.
	e.fs.cfg.InjectReadBackFault = func(b []byte) []byte { return append(b, 'x') }
	_, err = e.fs.WriteFile(p, []byte("z\n"), WriteOptions{Create: true})
	e.fs.cfg.InjectReadBackFault = nil
	if err == nil || unchanged(err) {
		t.Fatalf("a read-back failure after the commit: %v", err)
	}
}

// FuzzCheckExpectedDestination: expected_destination_sha256, which the
// gate's copy and move now take from the wire as the helper's do, is
// accepted exactly when it is empty, or 64 lowercase hex digits with
// overwrite; anything else is bad_request.
func FuzzCheckExpectedDestination(f *testing.F) {
	for _, s := range []string{"", "0", hexSHA("x"), hexSHA("x") + "0", "ABCDEF" + hexSHA("x")[6:], hexSHA("x")[:63] + "\n", hexSHA("x")[:63] + "é"} {
		f.Add(true, s)
		f.Add(false, s)
	}
	f.Fuzz(func(t *testing.T, overwrite bool, s string) {
		e := checkExpectedDestination(overwrite, s)
		want := s == "" || overwrite && previewSHA256RE.MatchString(s)
		if (e == nil) != want || e != nil && e.Code != protocol.CodeBadRequest {
			t.Fatalf("checkExpectedDestination(%v, %q) = %v, want accepted %v", overwrite, s, e, want)
		}
	})
}
