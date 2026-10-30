//go:build linux

package policy_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// Multi-call binaries, GNU coreutils' single-purpose programs, programs
// whose options run another program, and #! scripts as privileged commands
// (S-MC). Every binary here is an invented fixture, never executed, built
// at run time from the markers the policy recognises.

func marker(kind string) string {
	m := gpolicy.MarkerForTesting(kind)
	if m == "" {
		panic("no marker " + kind)
	}
	return m
}

func uutilsBody() string {
	return "invented multi-call body\x00" + marker("uutils") + " 0.0.0\x00(multi-call binary)\x00"
}

// uutils lays out an invented uutils install as Ubuntu 26.04 does: one
// binary hard-linked under its utilities' names in its own directory, and
// symlinks to them in the system binary directory. It returns that
// directory.
func (f *fixture) uutils(t *testing.T, names ...string) string {
	t.Helper()
	cargo := filepath.Join(f.dir, "cargo", "coreutils")
	gatetest.Mkdir(t, cargo, 0o755)
	first := filepath.Join(cargo, "coreutils")
	gatetest.WriteFile(t, first, uutilsBody(), 0o755)
	for _, n := range names {
		if err := os.Link(first, filepath.Join(cargo, n)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(cargo, n), filepath.Join(f.sysbin, n)); err != nil {
			t.Fatal(err)
		}
	}
	return cargo
}

func hasWarning(p *policy.Policy, subs ...string) bool {
	return slices.ContainsFunc(p.Warnings, func(w string) bool {
		for _, s := range subs {
			if !strings.Contains(w, s) {
				return false
			}
		}
		return true
	})
}

func reviewed(p *policy.Policy, kind string) bool {
	return slices.ContainsFunc(p.Acknowledged, func(fd policy.Finding) bool { return fd.Kind == kind && fd.Item == "x" })
}

// TestUutilsAppletPrivileged: the uutils multi-call binary is judged by the
// utility it runs as (the resolved file's name): chown is declarable, the
// worked example of PRIVILEGED §6; env, timeout and chroot are on the
// never list; dd needs an acknowledge, as a list B binary; sort, split
// and install with an action need one too; the entry point and a name that
// is not one of its utilities are refused.
func TestUutilsAppletPrivileged(t *testing.T) {
	f := newFixture(t)
	cargo := f.uutils(t, "chown", "env", "timeout", "chroot", "nice", "nohup", "stdbuf", "runcon", "dd", "sort", "split", "install")
	sys := func(n string) string { return filepath.Join(f.sysbin, n) }

	p := f.mustLoad(t, cmdWith(sys("chown"), "", `[["--no-dereference", "example-app:example-app", "/srv/app/data"]]`))
	c, _ := p.Command("x")
	if c.Applet != "chown" || c.Resolved != filepath.Join(cargo, "chown") {
		t.Fatalf("applet %q, resolved %q", c.Applet, c.Resolved)
	}
	for _, n := range []string{"env", "timeout", "chroot", "nice", "nohup", "stdbuf", "runcon"} {
		f.mustFail(t, cmdWith(sys(n), ack, "[[]]"), "never")
	}
	f.mustFail(t, cmdWith(sys("dd"), "", "[[]]"), "acknowledge")
	p = f.mustLoad(t, cmdWith(sys("dd"), ack, "[[]]"))
	if c, _ := p.Command("x"); c.ListB != 12 {
		t.Fatalf("dd list B group %d", c.ListB)
	}
	f.mustFail(t, cmdWith(sys("sort"), "", `[["--compress-program=gzip"]]`), "acknowledge")
	f.mustLoad(t, cmdWith(sys("sort"), "", `[["-u"]]`))
	f.mustFail(t, cmdWith(filepath.Join(cargo, "coreutils"), ack, "[[]]"), "not one of its utilities")
	gatetest.WriteFile(t, filepath.Join(f.bin, "mychown"), uutilsBody(), 0o755)
	f.mustFail(t, cmdWith(filepath.Join(f.bin, "mychown"), ack, "[[]]"), "not one of its utilities")
}

// TestOtherMultiCallPrivileged: GNU coreutils as one binary, BusyBox and
// toybox are refused by content under any name.
func TestOtherMultiCallPrivileged(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"invented\x00" + marker("gnu") + "\x00" + marker("gnu-multi") + "%s\x00", "multi-call"},
		{"invented\x00" + marker("busybox") + "1.0.0\x00", "BusyBox"},
		{"invented\x00" + marker("toybox") + "\x00", "toybox"},
	} {
		f := newFixture(t)
		p := f.exe(t, "chown", tc.body)
		f.mustFail(t, cmdWith(p, ack, "[[]]"), tc.want)
	}
}

// TestGNUCoreutilsPrivileged (F1): GNU coreutils' programs installed under
// "gnu"-prefixed names, or renamed copies that carry a listed program's
// name, are judged as that program.
func TestGNUCoreutilsPrivileged(t *testing.T) {
	for _, n := range []string{"env", "chroot", "nice", "nohup", "stdbuf", "timeout", "runcon"} {
		f := newFixture(t)
		f.mustFail(t, cmdWith(f.exe(t, "gnu"+n, "invented gnu "+n+"\n"), ack, "[[]]"), "never")
		f.mustFail(t, cmdWith(f.exe(t, "report-tool", "invented\x00"+marker("gnu")+"\x00"+n+"\x00"), ack, "[[]]"), "never")
	}
	f := newFixture(t)
	gnudd := f.exe(t, "gnudd", "invented gnu dd\n")
	f.mustFail(t, cmdWith(gnudd, "", "[[]]"), "acknowledge")
	if c, _ := f.mustLoad(t, cmdWith(gnudd, ack, "[[]]")).Command("x"); c.ListB != 12 {
		t.Fatalf("gnudd list B group %d", c.ListB)
	}
	f.mustFail(t, cmdWith(f.exe(t, "gnusort", "invented gnu sort\n"), "", `[["--compress-program=gzip"]]`), "acknowledge")
	f.mustLoad(t, cmdWith(f.exe(t, "gnuchown", "invented gnu chown\n"), "", "[[]]"))
	p := f.mustLoad(t, cmdWith(f.exe(t, "odd-tool", "invented\x00"+marker("gnu")+"\x00fchown\x00"), "", "[[]]"))
	if !hasWarning(p, "commands[x]", "GNU coreutils marker") {
		t.Fatalf("no GNU warning: %q", p.Warnings)
	}
}

// programActions are the coreutils options that run another program
// (F3), each with spellings that do and that do not reach it.
var programActions = []struct {
	program  string
	run, not []string
}{
	{"sort", []string{"--compress-program=gzip", "--compress-prog=gzip", "--com=gzip", "--compress-program"}, []string{"--check", "-c", "-u", "--compress-programs=x"}},
	{"split", []string{"--filter=cat", "--fil=cat", "--f=cat", "--filter"}, []string{"--lines=5", "-l", "--filters=x"}},
	{"install", []string{"--strip-program=strip", "--strip-prog=x", "--strip", "-s", "-Ds", "-sm"}, []string{"-m", "--suffix=x", "-D", "--mode=0755", "--"}},
}

// TestProgramActions (F3): sort, split and install with an option that
// runs another program need an acknowledge, as find with an action does,
// by written name, resolved name and identity; the same tokens on another
// program, and the programs' other options, do not.
func TestProgramActions(t *testing.T) {
	for _, pa := range programActions {
		for _, tok := range pa.run {
			if got := policy.ProgramAction(pa.program, []string{"x", tok, "y"}); got != tok {
				t.Errorf("%s %s: action %q", pa.program, tok, got)
			}
			if got := policy.ProgramAction("cat", []string{tok}); got != "" {
				t.Errorf("cat %s: action %q", tok, got)
			}
		}
		for _, tok := range pa.not {
			if got := policy.ProgramAction(pa.program, []string{tok}); got != "" {
				t.Errorf("%s %s: action %q", pa.program, tok, got)
			}
		}
		for _, way := range n13Ways {
			t.Run(pa.program+"/"+way, func(t *testing.T) {
				f := newFixture(t)
				p := f.declareAs(t, pa.program, way)
				tpl := `[["` + pa.run[0] + `", "{path:read}"]]`
				f.mustFail(t, cmdWith(p, "", tpl), "acknowledge")
				pol := f.mustLoad(t, cmdWith(p, ack, tpl))
				if !slices.Contains(findings(t, pol), policy.CommandFinding{Category: policy.FindingExec, Program: pa.program, Match: policy.MatchTemplate}) {
					t.Fatalf("findings %+v", findings(t, pol))
				}
				if !reviewed(pol, "program-action") {
					t.Fatalf("not reviewed: %+v", pol.Acknowledged)
				}
				f.mustLoad(t, cmdWith(p, "", `[["`+pa.not[0]+`", "{path:read}"]]`))
			})
		}
	}
}

// TestScriptInterpreterPrivileged: a #! script whose interpreter is on the
// never list is refused; one whose interpreter needs an acknowledge needs
// it; any other needs one too (handoff N-26) and is loaded with a warning
// naming its interpreter.
func TestScriptInterpreterPrivileged(t *testing.T) {
	f := newFixture(t)
	sh := f.exe(t, "sh", "invented shell\n")
	f.mustFail(t, cmdWith(f.exe(t, "renew", "#!"+sh+"\nrenew\n"), ack, "[[]]"), "never")
	nft := f.exe(t, "nft", "invented nft\n")
	rules := f.exe(t, "load-rules", "#!"+nft+" -f\nflush ruleset\n")
	f.mustFail(t, cmdWith(rules, "", "[[]]"), "acknowledge")
	if c, _ := f.mustLoad(t, cmdWith(rules, ack, "[[]]")).Command("x"); c.ListB != 13 || c.Interpreter != nft {
		t.Fatalf("list B %d, interpreter %q", c.ListB, c.Interpreter)
	}
	interp := f.exe(t, "example-interp", "invented interpreter\n")
	report := f.exe(t, "report", "#!"+interp+"\n")
	f.mustFail(t, cmdWith(report, "", "[[]]"), "acknowledge")
	p := f.mustLoad(t, cmdWith(report, ack, "[[]]"))
	if !hasWarning(p, "commands[x]", "#! script", interp) {
		t.Fatalf("no script warning: %q", p.Warnings)
	}
}

// TestWrittenResolvedNamePrivileged: check-policy says when a command runs
// as another name than the one written.
func TestWrittenResolvedNamePrivileged(t *testing.T) {
	f := newFixture(t)
	xz := f.exe(t, "xz", "invented xz\n")
	link := filepath.Join(f.bin, "unxz")
	if err := os.Symlink(xz, link); err != nil {
		t.Fatal(err)
	}
	p := f.mustLoad(t, cmdWith(link, "", "[[]]"))
	if !hasWarning(p, "commands[x]", `runs as "xz"`) {
		t.Fatalf("no name warning: %q", p.Warnings)
	}
}
