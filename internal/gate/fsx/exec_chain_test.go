//go:build linux

package fsx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The chain rule for root commands' paths (handoff
// docs/handoff/S4C-PRIVILEGED.md N-10; PRIVILEGED §6, "Commands"): with
// Config.GuardExecPaths (the helper), ResolveRead, ResolveWrite and
// ResolveDir return a path only when every directory from / to its parent is
// root's and neither group- nor world-writable, because the command looks
// the string up again itself. Every layout is invented. An unprivileged test
// cannot give a directory to another account, so "another account can write
// it" is a group- or world-writable directory, or an untrusted owner (the
// trust set without the test's uid); e2e-host runs the real case as root.

type execChainEnv struct {
	d, anc, root string
	fs           *FS
}

// newExecChainEnv makes <d>/x/w, a read and write root under its own
// ancestor <d>/x (both 0755), with the helper's settings.
func newExecChainEnv(t *testing.T) *execChainEnv {
	t.Helper()
	d := gatetest.SecureDir(t)
	e := &execChainEnv{d: d, anc: filepath.Join(d, "x"), root: filepath.Join(d, "x", "w")}
	mkdirMode(t, e.anc, 0o755)
	mkdirMode(t, e.root, 0o755)
	empty, err := pathx.NewMatcher(nil)
	must(t, err)
	trust := gatetest.Trust()
	e.fs = New(&Config{
		WriteRoots:      []string{e.root},
		Deny:            empty,
		Protected:       empty,
		Limits:          Limits{MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxFindResults: 100, MaxFindDepth: 8, MaxDeleteEntries: 20},
		TrustedDirOwner: trust.Owns,
		GuardExecPaths:  true,
	})
	return e
}

// resolveAll resolves p as each placeholder and cwd would be (ResolveDir
// only for a directory).
func (e *execChainEnv) resolveAll(p string, dir bool) map[string]error {
	errs := map[string]error{}
	_, errs["read"] = e.fs.ResolveRead(p)
	_, errs["write"] = e.fs.ResolveWrite(p)
	if dir {
		_, errs["dir"] = e.fs.ResolveDir(p)
	}
	return errs
}

// TestResolveExecChain: every level from / down to the parent, the root's
// own ancestors included, refuses when it is open; a closed chain resolves.
func TestResolveExecChain(t *testing.T) {
	for _, lvl := range []string{"ancestor", "root", "intermediate", "parent"} {
		// A sticky directory counts as open, writable or not.
		for _, mode := range []os.FileMode{0o775, 0o777, os.ModeSticky | 0o777, os.ModeSticky | 0o775, os.ModeSticky | 0o755} {
			t.Run(fmt.Sprintf("%s %v", lvl, mode), func(t *testing.T) {
				e := newExecChainEnv(t)
				a := filepath.Join(e.root, "a")
				b := filepath.Join(a, "b")
				mkdirMode(t, b, 0o755)
				must(t, os.Chmod(a, 0o755)) //nolint:gosec // G302: a directory, closed
				file := filepath.Join(b, "t")
				putMode(t, file, "t\n", 0o644)
				sub := filepath.Join(b, "c")
				mkdirMode(t, sub, 0o755)
				// Closed: everything resolves.
				for k, err := range e.resolveAll(file, false) {
					if err != nil {
						t.Fatalf("closed chain, %s: %v", k, err)
					}
				}
				for k, err := range e.resolveAll(sub, true) {
					if err != nil {
						t.Fatalf("closed chain, %s: %v", k, err)
					}
				}
				open := map[string]string{"ancestor": e.anc, "root": e.root, "intermediate": a, "parent": b}[lvl]
				must(t, os.Chmod(open, mode))
				defer func() { _ = os.Chmod(open, 0o755) }() //nolint:gosec // G302: a directory, closed again
				paths := []struct {
					p   string
					dir bool
				}{{file, false}, {filepath.Join(b, "new"), false}, {sub, true}}
				for _, c := range paths {
					for k, err := range e.resolveAll(c.p, c.dir) {
						if k == "read" && strings.HasSuffix(c.p, "/new") {
							continue // not found either way
						}
						wantCode(t, err, protocol.CodePathDenied)
						if !strings.Contains(err.Error(), open) || !strings.Contains(err.Error(), "(mode ") {
							t.Fatalf("%s %s: the refusal does not name %s and why: %v", k, c.p, open, err)
						}
					}
				}
				// The gate (no GuardExecPaths) resolves as before.
				gate := gateFS(t, e)
				if _, err := gate.ResolveRead(file); err != nil {
					t.Fatalf("the gate's resolution changed: %v", err)
				}
			})
		}
	}
}

// gateFS is e's layout with the gate's configuration (no GuardExecPaths).
func gateFS(t *testing.T, e *execChainEnv) *FS {
	t.Helper()
	empty, err := pathx.NewMatcher(nil)
	must(t, err)
	trust := gatetest.Trust()
	return New(&Config{
		WriteRoots: []string{e.root}, Deny: empty, Protected: empty,
		Limits:          Limits{MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxFindResults: 100, MaxFindDepth: 8, MaxDeleteEntries: 20},
		TrustedDirOwner: trust.Owns,
	})
}

// TestResolveExecChainRootItself: the root as a placeholder or a cwd has a
// chain of its own ancestors, and refuses when one is open; it is a
// directory target, so it refuses when it is open itself.
func TestResolveExecChainRootItself(t *testing.T) {
	e := newExecChainEnv(t)
	for k, err := range e.resolveAll(e.root, true) {
		if err != nil {
			t.Fatalf("closed chain, %s: %v", k, err)
		}
	}
	must(t, os.Chmod(e.anc, 0o777)) //nolint:gosec // G302: another account's write access, simulated
	for k, err := range e.resolveAll(e.root, true) {
		wantCode(t, err, protocol.CodePathDenied)
		if !strings.Contains(err.Error(), e.anc) {
			t.Fatalf("%s: the refusal does not name %s: %v", k, e.anc, err)
		}
	}
	must(t, os.Chmod(e.anc, 0o755)) //nolint:gosec // G302: a directory, closed again
	for _, mode := range []os.FileMode{0o777, os.ModeSticky | 0o755} {
		must(t, os.Chmod(e.root, mode))
		for k, err := range e.resolveAll(e.root, true) {
			wantCode(t, err, protocol.CodePathDenied)
			if !strings.Contains(err.Error(), e.root) {
				t.Fatalf("%s, root %v: the refusal does not name %s: %v", k, mode, e.root, err)
			}
		}
	}
}

// TestResolveExecDirTarget: a directory given to a command (a placeholder
// or the cwd) must be closed itself, besides its chain: the command works
// inside it. A file keeps the chain alone: its own mode does not matter.
func TestResolveExecDirTarget(t *testing.T) {
	for _, mode := range []os.FileMode{0o775, 0o777, os.ModeSticky | 0o777, os.ModeSticky | 0o755} {
		t.Run(mode.String(), func(t *testing.T) {
			e := newExecChainEnv(t)
			dir := filepath.Join(e.root, "d")
			mkdirMode(t, dir, 0o755)
			file := filepath.Join(e.root, "f")
			putMode(t, file, "f\n", 0o666)
			for k, err := range e.resolveAll(dir, true) {
				if err != nil {
					t.Fatalf("a closed directory, %s: %v", k, err)
				}
			}
			must(t, os.Chmod(dir, mode))
			for k, err := range e.resolveAll(dir, true) {
				wantCode(t, err, protocol.CodePathDenied)
				if !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "(mode ") {
					t.Fatalf("%s: the refusal does not name %s and why: %v", k, dir, err)
				}
			}
			for k, err := range e.resolveAll(file, false) {
				if err != nil {
					t.Fatalf("a file whose own mode is open, %s: %v", k, err)
				}
			}
			// The gate (no GuardExecPaths) resolves as before.
			if _, err := gateFS(t, e).ResolveDir(dir); err != nil {
				t.Fatalf("the gate's resolution changed: %v", err)
			}
		})
	}
}

// TestResolveExecChainOwner: a directory owned by an untrusted uid is open
// whatever its mode (its owner can change the mode): the test's own
// directories, once its uid is not trusted.
func TestResolveExecChainOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("needs an unprivileged uid")
	}
	e := newExecChainEnv(t)
	file := filepath.Join(e.root, "t")
	putMode(t, file, "t\n", 0o644)
	e.fs.cfg.TrustedDirOwner = func(uid uint32) bool { return uid == 0 }
	for k, err := range e.resolveAll(file, false) {
		wantCode(t, err, protocol.CodePathDenied)
		if !strings.Contains(err.Error(), fmt.Sprintf("uid %d", os.Getuid())) {
			t.Fatalf("%s: the refusal does not name the owner: %v", k, err)
		}
	}
}
