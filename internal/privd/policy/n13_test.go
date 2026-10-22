//go:build linux

package policy_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// N-13 (handoff docs/handoff/S4C-PRIVILEGED.md §2.1): privileged command
// templates whose program defeats a bound operation. Each program is
// recognised three ways: by the name the policy writes, by the name the
// path resolves to (a symlink with an innocent name), and by identity (an
// innocently named copy of a file in the system binary directories). Every
// binary here is an invented fixture and is never executed.

// n13Wrappers are the programs that run another program and joined a
// POLICY §5 group in S4c-9 (refused outright, as env and xargs are), with
// the group each joined.
var n13Wrappers = map[string]int{
	"systemd-run": 4, "systemd-cat": 4, "systemd-inhibit": 4, "systemd-socket-activate": 4,
	"run-parts": 4, "start-stop-daemon": 4, "taskset": 4, "chrt": 4, "prlimit": 4,
	"setarch": 4, "linux32": 4, "linux64": 4, "i386": 4, "x86_64": 4, "numactl": 4, "time": 4,
	"logsave": 4, "dbus-run-session": 4, "dbus-launch": 4, "ssh-agent": 4, "chronic": 4,
	"rlwrap": 4, "unbuffer": 4, "xvfb-run": 4, "fakeroot": 4, "faketime": 4, "daemonize": 4, "cgexec": 4,
	"perf": 5, "catchsegv": 5,
	"run0": 7, "machinectl": 7, "systemd-nspawn": 7, "bwrap": 7, "firejail": 7, "schroot": 7,
	"proot": 7, "lxc-attach": 7, "lxc-execute": 7,
	// Already in group 7 before S4c-9; listed so each is tested three ways.
	"nsenter": 7, "unshare": 7, "chroot": 7,
}

// n13BusClients can start units or call logind over D-Bus: refused
// outright, as systemctl is.
var n13BusClients = []string{"busctl", "dbus-send", "gdbus", "qdbus", "loginctl"}

// n13PackageTools bypass the package operations' binding: declarable only
// with an acknowledge.
var n13PackageTools = []string{"apt", "apt-get", "aptitude", "dpkg", "unattended-upgrade", "unattended-upgrades"}

// n13FindActions make find run, delete or write something: a find command
// whose template holds one is declarable only with an acknowledge.
var n13FindActions = []string{"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}

var n13Ways = []string{"written", "resolved", "identity"}

// declareAs returns a command path that is the program name, recognised the
// given way: a file of that name ("written"); an innocently named symlink to
// a file of that name ("resolved"); or an innocently named copy of a file of
// that name in the system binary directory ("identity").
func (f *fixture) declareAs(t *testing.T, name, way string) string {
	t.Helper()
	switch way {
	case "written":
		return f.exe(t, name, "written "+name+"\n")
	case "resolved":
		real := filepath.Join(f.dir, "real")
		gatetest.Mkdir(t, real, 0o755)
		target := filepath.Join(real, name)
		gatetest.WriteFile(t, target, "resolved "+name+"\n", 0o755)
		link := filepath.Join(f.bin, "tool-link")
		_ = os.Remove(link)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		return link
	case "identity":
		body := "system " + name + "\n"
		gatetest.WriteFile(t, filepath.Join(f.sysbin, name), body, 0o755)
		return f.exe(t, "tool-copy", body)
	}
	t.Fatalf("unknown way %q", way)
	return ""
}

func cmdWith(path, extra, templates string) string {
	return withCommand("  - id: x\n    path: " + path + "\n    tier: operator\n" + extra + "    templates: " + templates + "\n")
}

const ack = "    acknowledge: \"invented review note\"\n"

func findings(t *testing.T, p *policy.Policy) []policy.CommandFinding {
	t.Helper()
	c, ok := p.Command("x")
	if !ok {
		t.Fatal("command x missing")
	}
	return c.Findings
}

// TestN13WrappersRefused: every program-running wrapper is on the never
// list, by written name, resolved name and identity, acknowledged or not.
func TestN13WrappersRefused(t *testing.T) {
	for name := range n13Wrappers {
		for _, way := range n13Ways {
			t.Run(name+"/"+way, func(t *testing.T) {
				f := newFixture(t)
				p := f.declareAs(t, name, way)
				f.mustFail(t, cmdWith(p, "", "[[]]"), "never")
				f.mustFail(t, cmdWith(p, ack, "[[]]"), "never")
			})
		}
	}
}

// TestN13BusClientsRefused: D-Bus clients may not be commands, as systemctl
// may not, by written name, resolved name and identity.
func TestN13BusClientsRefused(t *testing.T) {
	for _, name := range n13BusClients {
		for _, way := range n13Ways {
			t.Run(name+"/"+way, func(t *testing.T) {
				f := newFixture(t)
				p := f.declareAs(t, name, way)
				f.mustFail(t, cmdWith(p, "", "[[]]"), "may not")
				f.mustFail(t, cmdWith(p, ack, "[[]]"), "may not")
			})
		}
	}
}

// TestN13BuiltinOpCopiesRefused: a renamed copy of systemctl, journalctl or
// git is refused by identity, as the names themselves are. A copy of a
// systemctl that the power names link to is refused as systemctl, not
// accepted as an acknowledged power binary.
func TestN13BuiltinOpCopiesRefused(t *testing.T) {
	for _, name := range []string{"systemctl", "journalctl", "git"} {
		for _, way := range n13Ways {
			t.Run(name+"/"+way, func(t *testing.T) {
				f := newFixture(t)
				p := f.declareAs(t, name, way)
				f.mustFail(t, cmdWith(p, ack, "[[]]"), "may not")
			})
		}
	}
	t.Run("systemctl behind the power names", func(t *testing.T) {
		f := newFixture(t)
		_ = os.Remove(filepath.Join(f.sysbin, "reboot"))
		gatetest.WriteFile(t, filepath.Join(f.sysbin, "systemctl"), "system manager\n", 0o755)
		for _, n := range []string{"reboot", "halt", "poweroff", "shutdown"} {
			if err := os.Symlink("systemctl", filepath.Join(f.sysbin, n)); err != nil {
				t.Fatal(err)
			}
		}
		p := f.exe(t, "maint-tool", "system manager\n")
		f.mustFail(t, cmdWith(p, ack, "[[]]"), "may not")
	})
}

// TestN13PackageToolsNeedAcknowledge: a package tool is declarable only
// with an acknowledge, recognised every way, and reported as a finding.
func TestN13PackageToolsNeedAcknowledge(t *testing.T) {
	for _, name := range n13PackageTools {
		for _, way := range n13Ways {
			t.Run(name+"/"+way, func(t *testing.T) {
				f := newFixture(t)
				p := f.declareAs(t, name, way)
				f.mustFail(t, cmdWith(p, "", "[[\"--version\"]]"), "acknowledge")
				pol := f.mustLoad(t, cmdWith(p, ack, "[[\"--version\"]]"))
				want := []policy.CommandFinding{{Category: "package", Program: name, Match: way}}
				if got := findings(t, pol); !slices.Equal(got, want) {
					t.Fatalf("findings %+v, want %+v", got, want)
				}
				if !slices.ContainsFunc(pol.Acknowledged, func(fd policy.Finding) bool {
					return fd.Kind == "package-tool" && fd.Item == "x" && strings.Contains(fd.Detail, name)
				}) {
					t.Fatalf("check-policy findings %+v", pol.Acknowledged)
				}
			})
		}
	}
}

// TestN13FindActionsNeedAcknowledge: find with any action that runs,
// deletes or writes needs an acknowledge, in any template and recognised
// every way; the action must be one of find's own arguments, not part of
// another; find without one is an ordinary command.
func TestN13FindActionsNeedAcknowledge(t *testing.T) {
	for _, action := range n13FindActions {
		for _, way := range n13Ways {
			t.Run(action+"/"+way, func(t *testing.T) {
				f := newFixture(t)
				p := f.declareAs(t, "find", way)
				tpl := `[["/srv", "-maxdepth", "1"], ["/srv", "-name", "x", "` + action + `"]]`
				f.mustFail(t, cmdWith(p, "", tpl), "acknowledge")
				pol := f.mustLoad(t, cmdWith(p, ack, tpl))
				want := []policy.CommandFinding{{Category: "exec", Program: "find", Match: "template"}}
				if got := findings(t, pol); !slices.Equal(got, want) {
					t.Fatalf("findings %+v, want %+v", got, want)
				}
				if !slices.ContainsFunc(pol.Acknowledged, func(fd policy.Finding) bool {
					return fd.Kind == "find-action" && fd.Item == "x" && strings.Contains(fd.Detail, action)
				}) {
					t.Fatalf("check-policy findings %+v", pol.Acknowledged)
				}
			})
		}
	}
	for _, way := range n13Ways {
		t.Run("no action/"+way, func(t *testing.T) {
			f := newFixture(t)
			p := f.declareAs(t, "find", way)
			for _, tpl := range []string{
				`[["/srv", "-maxdepth", "1", "-name", "x"]]`,
				`[["/srv", "-executable"], ["/srv", "-type", "f", "-newer", "/srv/stamp"]]`,
				`[["/srv/-exec"], ["/srv", "-name", "x-delete"], ["/srv", "-name", "-execx"], ["/srv", "-printf", "%p"]]`,
			} {
				pol := f.mustLoad(t, cmdWith(p, "", tpl))
				if got := findings(t, pol); len(got) != 0 {
					t.Fatalf("%s: findings %+v", tpl, got)
				}
			}
		})
	}
	// The same actions given to a program that is not find mean nothing.
	f := newFixture(t)
	pol := f.mustLoad(t, cmdWith("{BIN}/example-tool", "", `[["-exec", "-delete"]]`))
	if got := findings(t, pol); len(got) != 0 {
		t.Fatalf("example-tool: findings %+v", got)
	}
}

// TestN13PowerFinding: an acknowledged power binary is reported as a power
// finding, the way it was recognised.
func TestN13PowerFinding(t *testing.T) {
	for _, way := range n13Ways {
		t.Run(way, func(t *testing.T) {
			f := newFixture(t)
			p := f.declareAs(t, "shutdown", way)
			f.mustFail(t, cmdWith(p, "", "[[]]"), "acknowledge")
			pol := f.mustLoad(t, cmdWith(p, ack, "[[]]"))
			want := []policy.CommandFinding{{Category: "power", Program: "shutdown", Match: way}}
			if got := findings(t, pol); !slices.Equal(got, want) {
				t.Fatalf("findings %+v, want %+v", got, want)
			}
		})
	}
}

// TestN13OrdinaryCommand: an ordinary binary is not recognised as any of
// the above and carries no finding.
func TestN13OrdinaryCommand(t *testing.T) {
	f := newFixture(t)
	for _, name := range append(slices.Clone(n13PackageTools), n13BusClients...) {
		gatetest.WriteFile(t, filepath.Join(f.sysbin, name), "system "+name+"\n", 0o755)
	}
	gatetest.WriteFile(t, filepath.Join(f.sysbin, "find"), "system find\n", 0o755)
	for _, name := range []string{"example-tool", "dpkg-query", "apt-cache", "findmnt", "timedatectl"} {
		p := f.exe(t, name, "ordinary "+name+"\n")
		pol := f.mustLoad(t, cmdWith(p, "", `[["-exec"]]`))
		if got := findings(t, pol); len(got) != 0 {
			t.Fatalf("%s: findings %+v", name, got)
		}
	}
}
