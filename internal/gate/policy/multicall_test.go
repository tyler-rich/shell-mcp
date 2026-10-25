//go:build linux

package policy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// Multi-call binaries, GNU coreutils' single-purpose programs and #!
// scripts as gate commands (S-MC). Every binary here is an invented
// fixture, never executed, built at run time from the markers the gate
// recognises (policy.MarkerForTesting), so that this test binary does not
// carry them itself.

func marker(kind string) string {
	m := policy.MarkerForTesting(kind)
	if m == "" {
		panic("no marker " + kind)
	}
	return m
}

// uutilsBody is an invented uutils multi-call binary.
func uutilsBody() string {
	return "invented multi-call body\x00" + marker("uutils") + " 0.0.0\x00(multi-call binary)\x00"
}

// uutils lays out an invented uutils install as Ubuntu 26.04 does: one
// binary hard-linked under its utilities' names in a directory of its own
// (cargo), and symlinks to those names in the system binary directory. It
// returns both directories.
func (f *fixture) uutils(t *testing.T, names ...string) (sys, cargo string) {
	t.Helper()
	return f.uutilsWith(t, uutilsBody(), names...)
}

func (f *fixture) uutilsWith(t *testing.T, body string, names ...string) (sys, cargo string) {
	t.Helper()
	sys = filepath.Join(f.dir, "sysbin")
	cargo = filepath.Join(f.dir, "cargo", "coreutils")
	gatetest.Mkdir(t, sys, 0o755)
	gatetest.Mkdir(t, cargo, 0o755)
	first := filepath.Join(cargo, "coreutils")
	gatetest.WriteFile(t, first, body, 0o755)
	for _, n := range names {
		if err := os.Link(first, filepath.Join(cargo, n)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(cargo, n), filepath.Join(sys, n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(first, filepath.Join(sys, "coreutils")); err != nil {
		t.Fatal(err)
	}
	f.opts.SystemBinDirs = []string{sys}
	return sys, cargo
}

// cmdPath declares one read command x at an absolute path.
func cmdPath(p string) string {
	return cmdPolicy("  - id: x\n    path: " + p + "\n    tier: read\n    templates: [[\"--version\"]]\n")
}

func warned(p *policy.Policy, subs ...string) bool {
	return slices.ContainsFunc(p.Warnings, func(w string) bool {
		for _, s := range subs {
			if !strings.Contains(w, s) {
				return false
			}
		}
		return true
	})
}

// TestUutilsApplet: the uutils multi-call binary runs as the name of the
// file it is executed by, so a command is judged by that name: chown, a
// utility on no list, is declarable although the same binary is env,
// timeout and chroot; those names, the multi-call entry point and a name
// that is not one of its utilities are refused, and so is a binary that is
// also reached under a listed name that is not one of its utilities.
func TestUutilsApplet(t *testing.T) {
	f := newFixture(t)
	sys, cargo := f.uutils(t, "chown", "stat", "env", "timeout", "chroot", "nice", "nohup", "stdbuf", "dd", "runcon")

	p := f.mustLoad(t, cmdPath(filepath.Join(sys, "chown")))
	c, _ := p.Command("x")
	if c.Applet != "chown" || c.Resolved != filepath.Join(cargo, "chown") {
		t.Fatalf("applet %q, resolved %q", c.Applet, c.Resolved)
	}
	f.mustLoad(t, cmdPath(filepath.Join(sys, "stat")))

	for _, n := range []string{"env", "timeout", "chroot", "nice", "nohup", "stdbuf", "dd", "runcon"} {
		f.mustFail(t, cmdPath(filepath.Join(sys, n)), "hard-denied")
	}
	f.mustFail(t, cmdPath(filepath.Join(sys, "coreutils")), "not one of its utilities")

	// A copy named after no utility: upstream uutils would run "mychown" as
	// chown (it matches a suffix); only exact names are accepted.
	gatetest.WriteFile(t, filepath.Join(f.bin, "mychown"), uutilsBody(), 0o755)
	f.mustFail(t, cmdPath(filepath.Join(f.bin, "mychown")), "not one of its utilities")
	// A copy under a utility's own name is that utility.
	gatetest.WriteFile(t, filepath.Join(f.bin, "chown"), uutilsBody(), 0o755)
	f.mustLoad(t, cmdPath(filepath.Join(f.bin, "chown")))

	// The same binary also reached as sh, which is not a uutils utility.
	if err := os.Link(filepath.Join(cargo, "coreutils"), filepath.Join(sys, "sh")); err != nil {
		t.Fatal(err)
	}
	f.mustFail(t, cmdPath(filepath.Join(sys, "chown")), `"sh"`)
}

// TestUutilsAppletCheckedByNameItRunsAs: a symlink with another name runs
// the utility of the file it resolves to, which is what the rules apply to,
// and check-policy says the names differ.
func TestUutilsAppletCheckedByNameItRunsAs(t *testing.T) {
	f := newFixture(t)
	_, cargo := f.uutils(t, "chown", "env")
	link := filepath.Join(f.bin, "owner-tool")
	if err := os.Symlink(filepath.Join(cargo, "chown"), link); err != nil {
		t.Fatal(err)
	}
	p := f.mustLoad(t, cmdPath(link))
	if c, _ := p.Command("x"); c.Applet != "chown" {
		t.Fatalf("applet %q", c.Applet)
	}
	if !warned(p, "commands[x]", `runs as "chown"`) {
		t.Fatalf("no name warning: %q", p.Warnings)
	}
	envLink := filepath.Join(f.bin, "report-tool")
	if err := os.Symlink(filepath.Join(cargo, "env"), envLink); err != nil {
		t.Fatal(err)
	}
	f.mustFail(t, cmdPath(envLink), "hard-denied")
}

// TestOtherMultiCallRefused: GNU coreutils built as one binary, BusyBox and
// toybox are refused by their content, under any name and with no listed
// name linking to them.
func TestOtherMultiCallRefused(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"invented\x00" + marker("gnu") + "\x00" + marker("gnu-multi") + "%s\x00", "multi-call"},
		{"invented\x00" + marker("busybox") + "1.0.0\x00", "BusyBox"},
		{"invented\x00" + marker("toybox") + "\x00", "toybox"},
		{"invented\x00" + marker("toybox-url") + "\x00", "toybox"},
	} {
		f := newFixture(t)
		f.sysBin(t)
		gatetest.WriteFile(t, filepath.Join(f.bin, "chown"), tc.body, 0o755)
		f.mustFail(t, cmdPath(filepath.Join(f.bin, "chown")), tc.want)
	}
}

// gnuNames are GNU coreutils' programs on POLICY §5's lists (F1, F2).
var gnuNames = []string{"env", "chroot", "nice", "nohup", "stdbuf", "timeout", "runcon", "dd"}

// TestGNUPrefixedNames (F1): Ubuntu installs GNU coreutils beside uutils
// under "gnu"-prefixed names, which are judged as the program they are,
// by name and by identity; a prefixed name that is not a GNU coreutils
// program is left alone.
func TestGNUPrefixedNames(t *testing.T) {
	for _, n := range gnuNames {
		f := newFixture(t)
		f.exe(t, "gnu"+n)
		f.mustFail(t, cmdAt("gnu"+n), "hard-denied")
	}
	f := newFixture(t)
	f.exe(t, "gnuchown")
	f.mustLoad(t, cmdAt("gnuchown"))
	f.exe(t, "gnupg") // "pg" is hard-denied, but is not a GNU coreutils program
	f.mustLoad(t, cmdAt("gnupg"))

	// A renamed copy of a prefixed system binary, by identity.
	f = newFixture(t)
	sys := f.sysBin(t)
	gatetest.WriteFile(t, filepath.Join(sys, "gnuenv"), "invented gnu env\n", 0o755)
	gatetest.WriteFile(t, filepath.Join(f.bin, "report-tool"), "invented gnu env\n", 0o755)
	f.mustFail(t, cmdAt("report-tool"), `"gnuenv"`)
}

// TestGNUContentNames (F1): a GNU coreutils single-purpose binary carries
// its program name as a string, so a renamed copy of a listed program is
// refused under any name; a GNU coreutils binary whose name is no GNU
// coreutils program is loaded with a warning, and uutils (which mentions
// GNU coreutils too) is judged as uutils.
func TestGNUContentNames(t *testing.T) {
	for _, n := range gnuNames {
		for _, mk := range []string{"gnu", "gnu-note"} {
			f := newFixture(t)
			f.sysBin(t)
			gatetest.WriteFile(t, filepath.Join(f.bin, "report-tool"), "invented\x00"+marker(mk)+"\x00"+n+"\x00more\x00", 0o755)
			f.mustFail(t, cmdAt("report-tool"), `"`+n+`"`)
		}
	}
	f := newFixture(t)
	f.sysBin(t)
	gatetest.WriteFile(t, filepath.Join(f.bin, "report-tool"), "invented\x00"+marker("gnu")+"\x00fchown\x00", 0o755)
	p := f.mustLoad(t, cmdAt("report-tool"))
	if !warned(p, "commands[a]", "GNU coreutils marker", `"report-tool"`) {
		t.Fatalf("no GNU warning: %q", p.Warnings)
	}
	for _, n := range []string{"chown", "gnuchown"} {
		gatetest.WriteFile(t, filepath.Join(f.bin, n), "invented\x00"+marker("gnu")+"\x00fchown\x00", 0o755)
		if p := f.mustLoad(t, cmdAt(n)); warned(p, "GNU coreutils marker") {
			t.Fatalf("%s warned: %q", n, p.Warnings)
		}
	}
	// A string that is only part of another is not the program's name.
	gatetest.WriteFile(t, filepath.Join(f.bin, "chown"), "invented\x00"+marker("gnu")+"\x00getenv\x00envs\x00", 0o755)
	f.mustLoad(t, cmdAt("chown"))

	f = newFixture(t)
	_, cargo := f.uutilsWith(t, uutilsBody()+marker("gnu")+"\x00env\x00", "chown")
	f.mustLoad(t, cmdPath(filepath.Join(cargo, "chown")))
}

// TestRunconHardDenied (F2): runcon runs another program, so it is in group
// 4 with the other launchers.
func TestRunconHardDenied(t *testing.T) {
	f := newFixture(t)
	f.exe(t, "runcon")
	f.mustFail(t, cmdAt("runcon"), "group 4")
}

// TestScriptInterpreter: a #! script runs its interpreter, which is judged
// as a command's binary is: a hard-denied interpreter (by name, by
// identity), one not owned by a trusted account or writable by others, a
// relative or missing one, a first line the kernel would cut, and scripts
// nested deeper than the kernel follows are refused; any other script is
// loaded, with a warning naming its interpreter.
func TestScriptInterpreter(t *testing.T) {
	f := newFixture(t)
	sys := f.sysBin(t)
	script := func(name, body string) string {
		p := filepath.Join(f.bin, name)
		gatetest.WriteFile(t, p, body, 0o755)
		return p
	}
	interp := filepath.Join(f.bin, "example-interp")
	gatetest.WriteFile(t, interp, "invented interpreter\n", 0o755)

	ok := script("renew", "#! "+interp+" -q\nrenew\n")
	p := f.mustLoad(t, cmdPath(ok))
	if c, _ := p.Command("x"); c.Interpreter != interp {
		t.Fatalf("interpreter %q", c.Interpreter)
	}
	if !warned(p, "commands[x]", "#! script", interp) {
		t.Fatalf("no script warning: %q", p.Warnings)
	}

	f.exe(t, "sh")
	f.mustFail(t, cmdPath(script("s-sh", "#!"+filepath.Join(f.bin, "sh")+"\n")), "hard-denied")
	f.exe(t, "env")
	f.mustFail(t, cmdPath(script("s-env", "#!"+filepath.Join(f.bin, "env")+" -S tool\n")), "hard-denied")
	b, _ := os.ReadFile(filepath.Join(sys, "bash")) //nolint:gosec // G304: the test's own fixture
	gatetest.WriteFile(t, filepath.Join(f.bin, "runner"), string(b), 0o755)
	f.mustFail(t, cmdPath(script("s-copy", "#!"+filepath.Join(f.bin, "runner")+"\n")), `"bash"`)
	f.mustFail(t, cmdPath(script("s-rel", "#!example-interp\n")), "absolute")
	f.mustFail(t, cmdPath(script("s-missing", "#!"+filepath.Join(f.bin, "missing")+"\n")), "cannot be resolved")
	f.mustFail(t, cmdPath(script("s-long", "#!"+interp+" "+strings.Repeat("a", 300))), "256 bytes")
	f.mustFail(t, cmdPath(script("s-empty", "#!   \n")), "interpreter")

	open := filepath.Join(f.bin, "open-interp")
	gatetest.WriteFile(t, open, "invented interpreter\n", 0o755)
	chmod(t, open, 0o775)
	f.mustFail(t, cmdPath(script("s-open", "#!"+open+"\n")), "writable")

	// Nested: the kernel follows "up to a limit of four recursions"
	// (execve(2)), so five scripts in a chain run and a sixth does not.
	prev := interp
	for i := range 5 {
		prev = script("nest"+string(rune('a'+i)), "#!"+prev+"\n")
	}
	f.mustLoad(t, cmdPath(prev))
	f.mustFail(t, cmdPath(script("nest-deep", "#!"+prev+"\n")), "nested")
}

// TestWrittenResolvedNameWarning: a program that acts on the name it is
// called by runs as the name it resolves to (argv[0] is the resolved
// path); check-policy says so when the names differ.
func TestWrittenResolvedNameWarning(t *testing.T) {
	f := newFixture(t)
	f.exe(t, "xz")
	if err := os.Symlink(filepath.Join(f.bin, "xz"), filepath.Join(f.bin, "unxz")); err != nil {
		t.Fatal(err)
	}
	p := f.mustLoad(t, cmdAt("unxz"))
	if !warned(p, "commands[a]", `runs as "xz"`, `"unxz"`) {
		t.Fatalf("no name warning: %q", p.Warnings)
	}
	other := filepath.Join(f.dir, "other")
	gatetest.Mkdir(t, other, 0o755)
	if err := os.Symlink(filepath.Join(f.bin, "xz"), filepath.Join(other, "xz")); err != nil {
		t.Fatal(err)
	}
	if p := f.mustLoad(t, cmdPath(filepath.Join(other, "xz"))); warned(p, "runs as") {
		t.Fatalf("same name warned: %q", p.Warnings)
	}
}

// TestRealCoreutils runs the rules above on this machine's own coreutils:
// on every image, chown is declarable and env, runcon and the GNU
// coreutils programs installed under prefixed names (Ubuntu 26.04) are
// not; where coreutils is uutils, its utilities are the table's.
func TestRealCoreutils(t *testing.T) {
	if _, err := os.Stat("/usr/bin/chown"); err != nil {
		t.Skip("no /usr/bin/chown")
	}
	f := newFixture(t)
	f.opts.SystemBinDirs = nil // the real system binary directories
	f.mustLoad(t, cmdPath("/usr/bin/chown"))
	f.mustFail(t, cmdPath("/usr/bin/env"), "hard-denied")
	for _, p := range []string{"/usr/bin/runcon", "/usr/bin/gnuenv", "/usr/sbin/gnuchroot", "/usr/bin/gnutimeout", "/usr/bin/gnunice",
		"/usr/bin/gnunohup", "/usr/bin/gnustdbuf", "/usr/bin/gnuruncon", "/usr/bin/gnudd"} {
		if _, err := os.Stat(p); err == nil {
			f.mustFail(t, cmdPath(p), "hard-denied")
		}
	}
	if _, err := os.Stat("/usr/bin/gnuchown"); err == nil {
		f.mustLoad(t, cmdPath("/usr/bin/gnuchown"))
	}
	if b, _ := os.ReadFile("/usr/bin/coreutils"); strings.Contains(string(b), marker("uutils")) {
		out, err := exec.CommandContext(t.Context(), "/usr/bin/coreutils", "--list").Output()
		if err != nil {
			t.Fatal(err)
		}
		list := strings.Fields(string(out))
		slices.Sort(list)
		if got := policy.UutilsApplets(); !slices.Equal(got, list) {
			t.Fatalf("the uutils table %q differs from this machine's coreutils --list %q", got, list)
		}
		c, _ := f.mustLoad(t, cmdPath("/usr/bin/chown")).Command("x")
		if c.Applet != "chown" {
			t.Fatalf("applet %q", c.Applet)
		}
		f.mustFail(t, cmdPath("/usr/bin/coreutils"), "not one of its utilities")
	}
}

// TestContentCacheSeesRewrite: the per-load content cache is keyed on the
// file's device, inode, size, modification and change time, so a binary
// rewritten in place under the same inode is identified again: with a new
// size, with the same size and a new modification time, and with its
// modification time put back (only the change time differs).
func TestContentCacheSeesRewrite(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.bin, "report-tool")
	plain := "invented plain binary\x00" + strings.Repeat("x", 64)
	gatetest.WriteFile(t, p, plain, 0o755)
	s := policy.NewIdentityScan([]string{f.bin})
	probe := func() policy.ContentKind {
		t.Helper()
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		c, err := s.Content(p, fi)
		if err != nil {
			t.Fatal(err)
		}
		return c.Kind
	}
	// rewrite replaces the content in place (same inode) and waits until
	// the change time has moved, the kernel's timestamps being one tick.
	rewrite := func(body string) {
		t.Helper()
		before, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		for range 200 {
			if err := os.WriteFile(p, []byte(body), 0o755); err != nil { //nolint:gosec // G306: the fixture binary already exists; its mode is kept
				t.Fatal(err)
			}
			after, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, after) {
				t.Fatal("the rewrite made a new inode")
			}
			if ctime(after) != ctime(before) {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("the change time never moved")
	}
	if k := probe(); k != policy.ContentPlain {
		t.Fatalf("plain file is %v", k)
	}

	// pad gives every rewrite the same size, which is not the plain file's.
	pad := func(s string) string { return s + strings.Repeat("y", 100-len(s)) }
	busy := pad("invented\x00" + policy.MarkerForTesting("busybox") + "1\x00")
	rewrite(busy) // another size than the plain file's
	if k := probe(); k != policy.ContentBusyBox {
		t.Errorf("after a rewrite with another size: %v", k)
	}

	same := pad("invented\x00" + policy.MarkerForTesting("toybox") + "\x00")
	rewrite(same) // the same size, a new modification time
	if k := probe(); k != policy.ContentToybox {
		t.Errorf("after a same-size rewrite: %v", k)
	}

	fi, _ := os.Stat(p)
	mtime := fi.ModTime()
	again := pad("invented\x00" + policy.MarkerForTesting("uutils") + "\x00")
	rewrite(again)
	if err := os.Chtimes(p, mtime, mtime); err != nil { // only the change time differs now
		t.Fatal(err)
	}
	if k := probe(); k != policy.ContentUutils {
		t.Errorf("after a same-size rewrite with the modification time put back: %v", k)
	}
}

func ctime(fi os.FileInfo) syscall.Timespec { return fi.Sys().(*syscall.Stat_t).Ctim }
