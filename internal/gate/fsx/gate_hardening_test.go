//go:build linux

package fsx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The gate's own versions of two gaps closed on the privileged side
// (handoff docs/handoff/S4C-PRIVILEGED.md N-11, N-18): its commands' paths
// under the chain rule, trusting root and the service account (the gate's
// own uid), and its moves staged in the destination's directory, so a
// replaced file never passes through the source's. Every layout is
// invented. An unprivileged test cannot make another account's directory,
// so another account is the test's own uid left out of the trust, or a
// group- or world-writable directory; e2e-host runs the real case.

// gateFSAt is an FS configured as the gate's (internal/gate/ops): no
// helper flag, the chain rule for commands' paths trusting trusted, and
// chmod's read-back.
func gateFSAt(t *testing.T, root string, trusted func(uint32) bool) *FS {
	t.Helper()
	empty, err := pathx.NewMatcher(nil)
	must(t, err)
	return New(&Config{
		WriteRoots:      []string{root},
		Deny:            empty,
		Protected:       empty,
		Limits:          Limits{MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxFindResults: 100, MaxFindDepth: 8, MaxDeleteEntries: 20},
		TrustedDirOwner: trusted,
		GuardExecPaths:  true,
		VerifyMetadata:  true,
	})
}

// selfTrust trusts root and the test's uid, which stands for the service
// account.
func selfTrust(u uint32) bool { return u == 0 || u == uint32(os.Getuid()) } //nolint:gosec // G115: test ids fit

// gateMoveEnv makes <d>/r (0755) with s and d beneath it, both 0755, and a
// gate FS over r.
func gateMoveEnv(t *testing.T) (fs *FS, sd, dd string) {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	must(t, err)
	root := filepath.Join(d, "r")
	sd, dd = filepath.Join(root, "s"), filepath.Join(root, "d")
	mkdirMode(t, root, 0o755)
	mkdirMode(t, sd, 0o755)
	mkdirMode(t, dd, 0o755)
	return gateFSAt(t, root, selfTrust), sd, dd
}

// TestGateExecChainWording: the gate's refusal under the chain rule says
// the command would look the path up itself, without "as root" (the gate
// runs commands as the service account); the helper's (Privileged) keeps
// it.
func TestGateExecChainWording(t *testing.T) {
	e := newExecChainEnv(t)
	file := filepath.Join(e.root, "t")
	putMode(t, file, "t\n", 0o644)
	must(t, os.Chmod(e.root, 0o777)) //nolint:gosec // G302: another account's write access, simulated

	defer func() { _ = os.Chmod(e.root, 0o755) }() //nolint:gosec // G302: closed again
	gate := gateFSAt(t, e.root, selfTrust)
	for name, err := range map[string]error{"read": second(gate.ResolveRead(file)), "write": second(gate.ResolveWrite(file)), "dir": second(gate.ResolveDir(e.root))} {
		wantCode(t, err, protocol.CodePathDenied)
		if strings.Contains(err.Error(), "as root") || !strings.Contains(err.Error(), "is not given to a command:") || !strings.Contains(err.Error(), e.root) {
			t.Fatalf("the gate's %s refusal: %v", name, err)
		}
	}
	e.fs.cfg.Privileged = true
	_, err := e.fs.ResolveRead(file)
	wantCode(t, err, protocol.CodePathDenied)
	if !strings.Contains(err.Error(), "is not given to a command as root:") {
		t.Fatalf("the helper's refusal: %v", err)
	}
}

func second(_ string, err error) error { return err }

// TestGateExecChainServiceAccount: the gate trusts root and its own
// account. A chain of directories the service account owns, neither group-
// nor world-writable, resolves; the same directories owned by another
// account (the test's uid left out of the trust) are open whatever their
// mode, and the refusal names the owner; a directory target the service
// account owns is closed.
func TestGateExecChainServiceAccount(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("needs an unprivileged uid")
	}
	e := newExecChainEnv(t)
	sub := filepath.Join(e.root, "a")
	mkdirMode(t, sub, 0o755)
	file := filepath.Join(sub, "t")
	putMode(t, file, "t\n", 0o600)
	gate := gateFSAt(t, e.root, selfTrust)
	for name, err := range map[string]error{"read": second(gate.ResolveRead(file)), "write": second(gate.ResolveWrite(file)),
		"new": second(gate.ResolveWrite(filepath.Join(sub, "new"))), "dir": second(gate.ResolveDir(sub))} {
		if err != nil {
			t.Fatalf("the service account's own chain, %s: %v", name, err)
		}
	}
	other := gateFSAt(t, e.root, func(u uint32) bool { return u == 0 })
	for name, err := range map[string]error{"read": second(other.ResolveRead(file)), "dir": second(other.ResolveDir(sub))} {
		wantCode(t, err, protocol.CodePathDenied)
		if !strings.Contains(err.Error(), fmt.Sprintf("owned by uid %d", os.Getuid())) {
			t.Fatalf("another account's directory, %s: the refusal does not name the owner: %v", name, err)
		}
	}
}

// moveModes are the gate's three commits: create-only, the unconditional
// overwrite (rename over whatever is there) and the verified replace
// (expected_destination_sha256).
var moveModes = []struct {
	name      string
	overwrite bool
	expected  bool
}{{"create-only", false, false}, {"overwrite", true, false}, {"verified overwrite", true, true}}

// TestGateMoveStagesInTheDestination: every gate move stages its source
// under .shell-mcp-move-<32 hex> in the destination's directory, the
// destination untouched until the commit, and afterwards nothing is left
// in either directory but the moved entry.
func TestGateMoveStagesInTheDestination(t *testing.T) {
	for _, mm := range moveModes {
		t.Run(mm.name, func(t *testing.T) {
			fs, sd, dd := gateMoveEnv(t)
			src, dst := filepath.Join(sd, "f.conf"), filepath.Join(dd, "f.conf")
			putMode(t, src, "new\n", 0o640)
			expected := ""
			if mm.overwrite {
				putMode(t, dst, "old\n", 0o640)
			}
			if mm.expected {
				expected = hexSHA("old\n")
			}
			called := 0
			fs.cfg.InjectAfterStage = func(tmp string) error {
				called++
				if !strings.HasPrefix(tmp, stagePrefix) || len(tmp) != len(stagePrefix)+32 {
					t.Errorf("staging name %q", tmp)
				}
				if read(t, filepath.Join(dd, tmp)) != "new\n" {
					t.Error("the staged entry is not the source")
				}
				if _, err := os.Lstat(src); err == nil {
					t.Error("the source is still under its name while staged")
				}
				if mm.overwrite && read(t, dst) != "old\n" {
					t.Error("the destination was replaced before the commit")
				}
				return nil
			}
			res, err := fs.MoveExpecting(src, dst, mm.overwrite, expected)
			must(t, err)
			if called != 1 {
				t.Fatalf("staged %d times, want 1", called)
			}
			if read(t, dst) != "new\n" || res.Replaced != mm.overwrite {
				t.Fatalf("not moved as asked: %+v", res)
			}
			if ents, _ := os.ReadDir(sd); len(ents) != 0 {
				t.Fatalf("the source's directory holds %d entries after the move", len(ents))
			}
			if ents, _ := os.ReadDir(dd); len(ents) != 1 {
				t.Fatalf("the destination's directory holds %d entries after the move", len(ents))
			}
		})
	}
}

// TestGateMoveSwapAfterCheck: the source's name is taken by another file
// after the gate checked it (before the stage), or the staged entry is
// exchanged for another (before the commit). What was staged goes back
// under the source's name, nothing reaches the destination, and the move
// is refused with exists, unchanged.
func TestGateMoveSwapAfterCheck(t *testing.T) {
	for _, when := range []string{"before the stage", "after the stage"} {
		for _, mm := range moveModes {
			t.Run(when+" "+mm.name, func(t *testing.T) {
				fs, sd, dd := gateMoveEnv(t)
				src, dst := filepath.Join(sd, "f.conf"), filepath.Join(dd, "f.conf")
				other := filepath.Join(sd, "other.conf")
				putMode(t, src, "checked\n", 0o640)
				putMode(t, other, "other\n", 0o640)
				expected := ""
				if mm.overwrite {
					putMode(t, dst, "old\n", 0o640)
				}
				if mm.expected {
					expected = hexSHA("old\n")
				}
				if when == "before the stage" {
					fs.cfg.InjectBeforeCommit = func() {
						must(t, unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, other, unix.RENAME_EXCHANGE))
					}
				} else {
					fs.cfg.InjectAfterStage = func(tmp string) error {
						return unix.Renameat2(unix.AT_FDCWD, filepath.Join(dd, tmp), unix.AT_FDCWD, other, unix.RENAME_EXCHANGE)
					}
				}
				_, err := fs.MoveExpecting(src, dst, mm.overwrite, expected)
				wantCode(t, err, protocol.CodeExists)
				wantUnchanged(t, err)
				if s := stagedIn(t, dd); len(s) != 0 {
					t.Fatalf("left staged: %v", s)
				}
				if mm.overwrite {
					if read(t, dst) != "old\n" {
						t.Fatal("the destination was replaced")
					}
				} else {
					gone(t, dst)
				}
				if read(t, src) != "other\n" || read(t, other) != "checked\n" {
					t.Fatal("what was staged was not put back under the source's name")
				}
			})
		}
	}
}

// TestGateMovePutBackTaken: when the source's name was taken again before
// what was staged could be put back, it goes into the source's directory
// under another staging name, which the refusal names (Error.SetAside,
// the gate's audit line) with the gate's documentation; it is not marked
// unchanged.
func TestGateMovePutBackTaken(t *testing.T) {
	fs, sd, dd := gateMoveEnv(t)
	src, dst := filepath.Join(sd, "f.conf"), filepath.Join(dd, "f.conf")
	other := filepath.Join(sd, "other.conf")
	putMode(t, src, "checked\n", 0o640)
	putMode(t, other, "other\n", 0o640)
	fs.cfg.InjectAfterStage = func(tmp string) error {
		must(t, unix.Renameat2(unix.AT_FDCWD, filepath.Join(dd, tmp), unix.AT_FDCWD, other, unix.RENAME_EXCHANGE))
		putMode(t, src, "taken\n", 0o640)
		return nil
	}
	_, err := fs.Move(src, dst, false)
	wantCode(t, err, protocol.CodeExists)
	var fe *Error
	if !asError(err, &fe) || fe.Unchanged || !strings.HasPrefix(filepath.Base(fe.SetAside), stagePrefix) || filepath.Dir(fe.SetAside) != sd ||
		!strings.Contains(fe.Msg, fe.SetAside) || !strings.Contains(fe.Msg, "policy documentation") || strings.Contains(fe.Msg, "helper") {
		t.Fatalf("the refusal does not name where it was put back, for the gate: %+v", fe)
	}
	if read(t, fe.SetAside) != "other\n" || read(t, src) != "taken\n" {
		t.Fatal("the put-back entry or the source's new file is wrong")
	}
	gone(t, dst)
}

// TestGateMoveStoppedAfterStage: a gate that stops between the stage and
// the commit (a timeout, the session closing) leaves the source under its
// staging name in the destination's directory; nothing is lost. Every gate
// operation on a path through such a name is refused, so is a move into or
// out of the directory that holds it, and a delete of a tree holding it;
// once it is moved back by hand, moves work again.
func TestGateMoveStoppedAfterStage(t *testing.T) {
	fs, sd, dd := gateMoveEnv(t)
	src, dst := filepath.Join(sd, "f.conf"), filepath.Join(dd, "f.conf")
	putMode(t, src, "precious\n", 0o640)
	stop := errors.New("the gate stopped here")
	fs.cfg.InjectAfterStage = func(string) error { return stop }
	_, err := fs.Move(src, dst, false)
	if !errors.Is(err, stop) {
		t.Fatalf("%v, want the stop", err)
	}
	fs.cfg.InjectAfterStage = nil
	s := stagedIn(t, dd)
	if len(s) != 1 {
		t.Fatalf("staged entries %v, want one", s)
	}
	staged := filepath.Join(dd, s[0])
	if read(t, staged) != "precious\n" {
		t.Fatal("the staged entry lost the source")
	}
	stranded := func(t *testing.T, what string, err error) {
		t.Helper()
		wantCode(t, err, protocol.CodePathDenied)
		var fe *Error
		if !asError(err, &fe) || !strings.Contains(fe.Msg, stagePrefix) || !strings.Contains(fe.Msg, "policy documentation") ||
			strings.Contains(fe.Msg, "helper") || strings.Contains(fe.Msg, "as root") {
			t.Fatalf("%s: the refusal does not name the staged entry for the gate: %v", what, err)
		}
	}
	other := filepath.Join(sd, "g.conf")
	putMode(t, other, "g\n", 0o640)
	_, err = fs.Move(other, filepath.Join(dd, "g.conf"), false)
	stranded(t, "a move into its directory", err)
	out := filepath.Join(dd, "h.conf")
	putMode(t, out, "h\n", 0o640)
	_, err = fs.Move(out, filepath.Join(sd, "h.conf"), false)
	stranded(t, "a move out of its directory", err)
	_, err = fs.ReadFile(staged, ReadOptions{MaxBytes: 1024})
	stranded(t, "read", err)
	_, err = fs.Stat(staged)
	stranded(t, "stat", err)
	_, err = fs.WriteFile(staged, []byte("x\n"), WriteOptions{Create: true})
	stranded(t, "write", err)
	_, err = fs.Chmod(staged, 0o600)
	stranded(t, "chmod", err)
	_, err = fs.Copy(staged, filepath.Join(sd, "copy.conf"), false)
	stranded(t, "copy", err)
	_, err = fs.Move(staged, filepath.Join(sd, "back.conf"), false)
	stranded(t, "move", err)
	_, err = fs.ResolveRead(staged)
	stranded(t, "a {path:read}", err)
	_, err = fs.PreviewDelete(staged, false)
	stranded(t, "delete_preview", err)
	_, err = fs.PreviewDelete(dd, true)
	stranded(t, "delete_preview of its tree", err)
	// A move of a tree that holds one.
	tree := filepath.Join(sd, "tree")
	mkdirMode(t, tree, 0o755)
	putMode(t, filepath.Join(tree, stagePrefix+strings.Repeat("0", 32)), "left\n", 0o640)
	_, err = fs.Move(tree, filepath.Join(sd, "tree2"), false)
	stranded(t, "a move of a tree holding one", err)
	must(t, os.RemoveAll(tree))
	if read(t, staged) != "precious\n" {
		t.Fatal("the staged entry changed")
	}
	must(t, os.Rename(staged, src))
	if _, err := fs.Move(src, dst, false); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if read(t, dst) != "precious\n" {
		t.Fatal("not moved after recovery")
	}
}

// TestGateMoveReplacedNeverInSource: a racer that can write the source's
// directory takes whatever appears under the source's name and is not the
// source (here: the replaced files, mode 0604) while the gate moves the
// source over a file in another directory, with and without
// expected_destination_sha256. The replaced file never appears there: it
// is exchanged out under the staging name in the destination's directory.
func TestGateMoveReplacedNeverInSource(t *testing.T) {
	for _, verified := range []bool{true, false} {
		t.Run(fmt.Sprintf("verified=%v", verified), func(t *testing.T) {
			fs, sd, dd := gateMoveEnv(t)
			src := filepath.Join(sd, "y")
			var stopped atomic.Bool
			var grabs atomic.Int64
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				var st unix.Stat_t
				for n := 0; !stopped.Load(); {
					if unix.Lstat(src, &st) != nil || st.Mode&0o777 != 0o604 {
						continue
					}
					if unix.Rename(src, fmt.Sprintf("%s.grab.%d", src, n)) == nil {
						n++
						grabs.Add(1)
					}
				}
			}()
			got := map[string]int{}
			for i := range 300 {
				dst := filepath.Join(dd, fmt.Sprintf("o%d", i))
				putMode(t, dst, "OLD\n", 0o604)
				putMode(t, src+".prep", "new\n", 0o640)
				must(t, os.Rename(src+".prep", src))
				expected := ""
				if verified {
					expected = hexSHA("OLD\n")
				}
				_, err := fs.MoveExpecting(src, dst, true, expected)
				var fe *Error
				switch {
				case err == nil:
					got["ok"]++
				case asError(err, &fe) && (fe.Code == protocol.CodeExists || fe.Code == protocol.CodeNotFound):
					got[fe.Code]++
				default:
					stopped.Store(true)
					wg.Wait()
					t.Fatalf("run %d: %v (the racer took %d replaced files)", i, err, grabs.Load())
				}
				_ = os.Remove(src)
			}
			stopped.Store(true)
			wg.Wait()
			if n := grabs.Load(); n != 0 {
				t.Fatalf("the racer took %d replaced files from the source's directory", n)
			}
			if s := stagedIn(t, dd); len(s) != 0 {
				t.Fatalf("left staged: %v", s)
			}
			t.Logf("moves %v; the racer took nothing", got)
		})
	}
}
