//go:build linux && shellmcp_confine_hook

package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The read-confinement layers one at a time (handoff N-12). A lookup is
// kept inside its root by three layers (locate.go, confineLayer): the
// parent held as an os.Root descriptor and the target opened from it
// (descriptor); the object opened being exactly the located one, by its
// real path (real path); and every real path inside the root and neither
// denied nor protected (checkReal). TestSwapRace shows the three together
// refuse a directory swapped for a symlink; it passes with any two of
// them removed, so on its own it cannot notice one going missing. Here the
// shellmcp_confine_hook test build turns off exactly one layer, swaps a
// path at a fixed point of the lookup, and requires the refusal to come
// from a named layer: the one that refuses first with every layer on, or,
// with that one off, the one that takes over. A layer removed from the
// code changes which layer refuses, or lets the read through, and a case
// here fails. Where no other layer takes over, the case shows that layer
// to be the last line. Layouts and contents are invented.

// layers are the cases' columns: every layer on, then each one off.
var layers = []confineLayer{layerNone, layerDescriptor, layerRealPath, layerCheckReal}

func layerName(l confineLayer) string {
	switch l {
	case layerDescriptor:
		return "descriptor"
	case layerRealPath:
		return "real path"
	case layerCheckReal:
		return "checkReal"
	}
	return "none"
}

// refusedBy names the layer whose refusal err is, from its message, or ""
// when err is no refusal of the three.
func refusedBy(err error) string {
	var fe *Error
	if !errors.As(err, &fe) {
		return ""
	}
	for _, m := range []struct{ layer, msg string }{
		{"descriptor", "path leaves its root or crosses a symlink"},
		{"descriptor", "a directory in the path is a symlink with an absolute target"},
		{"real path", "path changed while opening"},
		{"real path", "directory changed while opening"},
		{"checkReal", "path resolves outside its root"},
		{"checkReal", "path is denied by"},
		{"checkReal", "path is protected and never writable"},
	} {
		if strings.Contains(fe.Msg, m.msg) {
			return m.layer
		}
	}
	return ""
}

// swapForLink renames the directory or file p aside and puts a symlink to
// target (as written) in its place.
func swapForLink(t *testing.T, p, target string) {
	t.Helper()
	must(t, os.Rename(p, p+".real"))
	must(t, os.Symlink(target, p))
}

// once runs swap at the first time point is reached.
func once(point string, swap func()) func(build, at string) {
	var done atomic.Bool
	return func(build, at string) {
		if build != confineHookBuild {
			panic("confine hook called outside its test build")
		}
		if at == point && done.CompareAndSwap(false, true) {
			swap()
		}
	}
}

// confineCase is one swap, and for each layer turned off (layerNone: every
// layer on) the layer that must refuse it, or "read" when the operation
// must go through (and then never with content from outside the root, or
// denied, unless want says so with "escape").
type confineCase struct {
	name  string
	setup func(t *testing.T, e *env) (op func(fs *FS) (string, error), forbidden string)
	want  map[confineLayer]string
}

func runConfineCases(t *testing.T, cases []confineCase) {
	for _, c := range cases {
		for _, off := range layers {
			t.Run(c.name+"/off="+layerName(off), func(t *testing.T) {
				e := newEnv(t)
				op, forbidden := c.setup(t, e)
				e.fs.cfg.confineOff = off
				got, err := op(e.fs)
				e.fs.cfg.confineAt = nil
				want := c.want[off]
				switch {
				case want == "read" || want == "escape":
					if err != nil {
						t.Fatalf("refused (%v), want it to go through", err)
					}
					if (want == "escape") != strings.Contains(got, forbidden) {
						t.Fatalf("got %q; want %s", got, want)
					}
				case err == nil:
					t.Fatalf("went through with %q, want a refusal by %s", got, want)
				case refusedBy(err) != want:
					t.Fatalf("refused by %q (%v), want %s", refusedBy(err), err, want)
				}
				if forbidden != "" && want != "escape" && strings.Contains(got, forbidden) {
					t.Fatalf("read %q", got)
				}
			})
		}
	}
}

// read is a ReadFile of p returning its content.
func readOp(p string) func(fs *FS) (string, error) {
	return func(fs *FS) (string, error) {
		r, err := fs.ReadFile(p, ReadOptions{MaxBytes: 1024})
		return r.Content, err
	}
}

// listOp is a ListDir of p returning its names.
func listOp(p string) func(fs *FS) (string, error) {
	return func(fs *FS) (string, error) {
		r, err := fs.ListDir(p, true, 100)
		var names []string
		for _, en := range r.Entries {
			names = append(names, en.Name)
		}
		return strings.Join(names, " "), err
	}
}

// TestConfineLayersFileRead: a read of a file whose directory, or which
// itself, is swapped for a symlink out of the root or to a denied file in
// it, at each point of the lookup.
func TestConfineLayersFileRead(t *testing.T) {
	runConfineCases(t, []confineCase{
		{
			// The descriptor refuses; without it, the parent opened by its
			// path resolves outside the root and checkReal refuses: the
			// real-path check cannot see it (the parent's real path and the
			// file's agree). checkReal is the last line when the descriptor
			// is gone.
			name: "a directory swapped out of the root before the parent is opened",
			setup: func(t *testing.T, e *env) (func(*FS) (string, error), string) {
				sub := filepath.Join(e.read, "sub")
				put(t, filepath.Join(sub, "passwd"), "INSIDE")
				e.fs.cfg.confineAt = once("parent", func() { swapForLink(t, sub, "../outside") })
				return readOp(filepath.Join(sub, "passwd")), "OUTSIDE"
			},
			want: map[confineLayer]string{layerNone: "descriptor", layerDescriptor: "checkReal", layerRealPath: "descriptor", layerCheckReal: "descriptor"},
		},
		{
			// The held parent is the original directory, now under another
			// name, so the read finds the original file and the real-path
			// check refuses because the path changed; without that check the
			// original file is read, never the outside one. Without the
			// descriptor the file opened by its path is outside, and the
			// real-path check refuses before checkReal would.
			name: "a directory swapped out of the root after the parent is opened",
			setup: func(t *testing.T, e *env) (func(*FS) (string, error), string) {
				sub := filepath.Join(e.read, "sub")
				put(t, filepath.Join(sub, "passwd"), "INSIDE")
				e.fs.cfg.confineAt = once("target", func() { swapForLink(t, sub, "../outside") })
				return readOp(filepath.Join(sub, "passwd")), "OUTSIDE"
			},
			want: map[confineLayer]string{layerNone: "real path", layerDescriptor: "real path", layerRealPath: "read", layerCheckReal: "real path"},
		},
		{
			name: "the file swapped for a symlink out of the root after its lstat",
			setup: func(t *testing.T, e *env) (func(*FS) (string, error), string) {
				f := filepath.Join(e.read, "sub", "f")
				put(t, f, "INSIDE")
				e.fs.cfg.confineAt = once("open", func() { swapForLink(t, f, "../../outside/passwd") })
				return readOp(f), "OUTSIDE"
			},
			want: map[confineLayer]string{layerNone: "descriptor", layerDescriptor: "real path", layerRealPath: "descriptor", layerCheckReal: "descriptor"},
		},
		{
			// The descriptor is the parent's own os.Root, so it refuses a
			// final symlink that leaves the parent directory, inside the
			// root or not (the case above), and follows one to a sibling: it
			// does not refuse this one at all; the real-path check and
			// checkReal each do.
			name: "the file swapped for a symlink to a denied file beside it after its lstat",
			setup: func(t *testing.T, e *env) (func(*FS) (string, error), string) {
				f := filepath.Join(e.read, "sub", "f")
				put(t, f, "INSIDE")
				put(t, filepath.Join(e.read, "sub", "id.key"), "TOPSECRET")
				e.fs.cfg.confineAt = once("open", func() { swapForLink(t, f, "id.key") })
				return readOp(f), "TOPSECRET"
			},
			want: map[confineLayer]string{layerNone: "real path", layerDescriptor: "real path", layerRealPath: "checkReal", layerCheckReal: "real path"},
		},
		{
			// No race: a directory symlink that stays in the root is
			// followed by the descriptor, and the parent's real path and the
			// file's agree. checkReal alone refuses: it is the last line,
			// and without it the denied file is read.
			name: "a directory that is a symlink to a denied directory in the root",
			setup: func(t *testing.T, e *env) (func(*FS) (string, error), string) {
				must(t, os.Symlink("secrets", filepath.Join(e.read, "alias")))
				return readOp(filepath.Join(e.read, "alias", "token")), "TOPSECRET"
			},
			want: map[confineLayer]string{layerNone: "checkReal", layerDescriptor: "checkReal", layerRealPath: "checkReal", layerCheckReal: "escape"},
		},
	})
}

// TestConfineLayersDirectoryTarget: a listing of a directory swapped for a
// symlink after its lstat (the directory target, openDirRoot).
func TestConfineLayersDirectoryTarget(t *testing.T) {
	runConfineCases(t, []confineCase{
		{
			name: "the directory swapped for a symlink out of the root after its lstat",
			setup: func(t *testing.T, e *env) (func(*FS) (string, error), string) {
				sub := filepath.Join(e.read, "sub")
				put(t, filepath.Join(sub, "inside"), "INSIDE")
				e.fs.cfg.confineAt = once("open", func() { swapForLink(t, sub, "../outside") })
				return listOp(sub), "passwd"
			},
			want: map[confineLayer]string{layerNone: "descriptor", layerDescriptor: "real path", layerRealPath: "descriptor", layerCheckReal: "descriptor"},
		},
		{
			// The parent here is the root itself, so the descriptor follows a
			// symlink to a sibling directory.
			name: "the directory swapped for a symlink to a denied directory in the root after its lstat",
			setup: func(t *testing.T, e *env) (func(*FS) (string, error), string) {
				sub := filepath.Join(e.read, "sub")
				put(t, filepath.Join(sub, "inside"), "INSIDE")
				e.fs.cfg.confineAt = once("open", func() { swapForLink(t, sub, "secrets") })
				return listOp(sub), "token"
			},
			want: map[confineLayer]string{layerNone: "real path", layerDescriptor: "real path", layerRealPath: "checkReal", layerCheckReal: "real path"},
		},
	})
}

// TestConfineLayersWrite: writes through a directory swapped out of the
// write root before the lookup, and through a directory symlink to a
// protected directory in it. A write creates its file through the parent
// it holds, so only the descriptor and checkReal apply; for the protected
// directory checkReal is the last line, and without it the write lands
// there.
func TestConfineLayersWrite(t *testing.T) {
	writeOp := func(p string) func(fs *FS) (string, error) {
		return func(fs *FS) (string, error) {
			_, err := fs.WriteFile(p, []byte("W"), WriteOptions{Create: true})
			return "", err
		}
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, e *env) (target, landed string)
		want  map[confineLayer]string
	}{
		{
			name: "a directory swapped out of the root before the parent is opened",
			setup: func(t *testing.T, e *env) (string, string) {
				sub := filepath.Join(e.write, "sub")
				must(t, os.MkdirAll(sub, 0o750))
				e.fs.cfg.confineAt = once("parent", func() { swapForLink(t, sub, "../../outside") })
				return filepath.Join(sub, "w"), filepath.Join(e.outside, "w")
			},
			want: map[confineLayer]string{layerNone: "descriptor", layerDescriptor: "checkReal", layerRealPath: "descriptor", layerCheckReal: "descriptor"},
		},
		{
			name: "a directory that is a symlink to a protected directory in the root",
			setup: func(t *testing.T, e *env) (string, string) {
				must(t, os.MkdirAll(filepath.Join(e.write, "locked"), 0o750))
				must(t, os.Symlink("locked", filepath.Join(e.write, "lnk")))
				return filepath.Join(e.write, "lnk", "w"), filepath.Join(e.write, "locked", "w")
			},
			want: map[confineLayer]string{layerNone: "checkReal", layerDescriptor: "checkReal", layerRealPath: "checkReal", layerCheckReal: "escape"},
		},
	}
	for _, c := range cases {
		for _, off := range layers {
			t.Run(c.name+"/off="+layerName(off), func(t *testing.T) {
				e := newEnv(t)
				target, landed := c.setup(t, e)
				e.fs.cfg.confineOff = off
				_, err := writeOp(target)(e.fs)
				e.fs.cfg.confineAt = nil
				_, lerr := os.Lstat(landed)
				switch want := c.want[off]; {
				case want == "escape":
					if err != nil || lerr != nil {
						t.Fatalf("refused (%v) or not written (%v); this case shows checkReal is the last line", err, lerr)
					}
				case err == nil:
					t.Fatalf("written, want a refusal by %s", want)
				case refusedBy(err) != want:
					t.Fatalf("refused by %q (%v), want %s", refusedBy(err), err, want)
				case lerr == nil:
					t.Fatalf("refused, but %s was written", landed)
				}
			})
		}
	}
}

// TestConfineLayersSwapRace is TestSwapRace with each layer off in turn:
// nothing outside the root is ever read or written, and the refusals come
// from the layers still on (logged by layer). The symlink is relative:
// with an absolute one, a lookup by path that fails part-way through a swap
// would be explained by absoluteSymlink, whose message is the descriptor's.
func TestConfineLayersSwapRace(t *testing.T) {
	for _, off := range layers[1:] {
		t.Run("off="+layerName(off), func(t *testing.T) {
			e := newEnv(t)
			sub := filepath.Join(e.write, "sub")
			stash := filepath.Join(e.write, "sub.real")
			must(t, os.MkdirAll(sub, 0o750))
			put(t, filepath.Join(sub, "f"), "INSIDE")
			outDir := filepath.Join(e.d, "outside-dir")
			must(t, os.MkdirAll(outDir, 0o750))
			put(t, filepath.Join(outDir, "f"), "OUTSIDE")
			link := filepath.Join(e.write, "sub.link")
			must(t, os.Symlink("../../outside-dir", link))
			e.fs.cfg.confineOff = off

			var stop atomic.Bool
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !stop.Load() {
					_ = os.Rename(sub, stash)
					_ = os.Rename(link, sub)
					_ = os.Rename(sub, link)
					_ = os.Rename(stash, sub)
				}
			}()
			by := map[string]int{}
			reads, writes := 0, 0
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				r, err := e.fs.ReadFile(filepath.Join(sub, "f"), ReadOptions{MaxBytes: 64})
				switch {
				case err == nil:
					reads++
					if strings.Contains(r.Content, "OUTSIDE") {
						stop.Store(true)
						wg.Wait()
						t.Fatal("read content from outside the root")
					}
				default:
					by[refusedBy(err)]++
				}
				if _, err := e.fs.WriteFile(filepath.Join(sub, "w"), []byte("W"), WriteOptions{Create: true}); err == nil {
					writes++
				} else {
					by[refusedBy(err)]++
				}
			}
			stop.Store(true)
			wg.Wait()
			entries, err := os.ReadDir(outDir)
			must(t, err)
			if len(entries) != 1 {
				t.Fatalf("outside directory was written: %v", entries)
			}
			t.Logf("layer %s off: %d reads, %d writes; refusals by layer %v", layerName(off), reads, writes, by)
			if reads == 0 || writes == 0 {
				t.Fatalf("race test is vacuous: %d reads, %d writes succeeded", reads, writes)
			}
			if by[layerName(off)] != 0 {
				t.Fatalf("a refusal came from the layer turned off: %v", by)
			}
			if by["descriptor"]+by["real path"]+by["checkReal"] == 0 {
				t.Fatalf("no refusal from the layers still on: %v", by)
			}
		})
	}
}
