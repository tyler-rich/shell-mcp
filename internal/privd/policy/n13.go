//go:build linux

package policy

import (
	"slices"
	"strings"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// Programs that defeat a bound operation (handoff N-13, S4c-9). A command
// runs exactly the argv its template allows, but some programs make that
// argv say nothing about what runs as root: they run another program (the
// launchers and privilege changers, POLICY §5 groups 4 and 7, refused
// outright), ask PID 1 or logind over D-Bus (refused outright, as systemctl
// is), change packages outside the package operations' binding to an
// approved transaction, power the host off outside priv_power's checks
// (POLICY §5 group 11), or, for find, run, delete or write through one of
// its actions. The last three are declarable only with an acknowledge, and
// are reported. Each program is recognised by the name the policy writes,
// the name its path resolves to, and by identity (POLICY §5's binary
// identity check, which the helper extends to these names).

// Class is how the privileged policy treats a command's program.
type Class int

// Classes, strongest first where a binary is several things at once.
const (
	// ClassNone: an ordinary program.
	ClassNone Class = iota
	// ClassNever: POLICY §5 groups 1–10 (PRIVILEGED §5.3 list A).
	ClassNever
	// ClassNotCommand: a built-in operation's binary or a D-Bus client.
	ClassNotCommand
	// ClassListB: POLICY §5 groups 11–13 (list B), with an acknowledge.
	ClassListB
	// ClassPackageTool: a package manager, with an acknowledge.
	ClassPackageTool
	// ClassFind: find, with an acknowledge when a template holds an action.
	ClassFind
	// ClassAction: sort, split or install, with an acknowledge when a
	// template holds an option that runs another program (S-MC, F3).
	ClassAction
)

// packageTools are the package managers a command could run outside the
// package operations' binding (PRIVILEGED §6, "Package operations").
var packageTools = []string{"apt", "apt-get", "aptitude", "dpkg", "unattended-upgrade", "unattended-upgrades"}

// findProgram is find, and findActions its arguments that run a program,
// delete, or write a file.
const findProgram = "find"

var findActions = []string{"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}

// Finding categories (CommandFinding.Category).
const (
	FindingPackage = "package"
	FindingPower   = "power"
	FindingExec    = "exec"
	// FindingScript: the command's program is a #! script (handoff N-26).
	FindingScript = "script"
)

// How a program was recognised (CommandFinding.Match).
const (
	MatchWritten  = "written"
	MatchResolved = "resolved"
	MatchIdentity = "identity"
	MatchTemplate = "template"
	// MatchScript: the program is a #! script, whatever its names.
	MatchScript = "script"
)

// powerGroup is POLICY §5's power group.
const powerGroup = 11

// helperScanNames are the names the helper's binary identity check adds to
// the gate's (hard-denied names, built-in operations, D-Bus clients).
func helperScanNames() []string {
	return append(append(slices.Clone(packageTools), findProgram), actionPrograms...)
}

// Classify returns a program base name's class, and for ClassNever and
// ClassListB its POLICY §5 group. A GNU coreutils program under Ubuntu's
// "gnu" prefix is that program (S-MC, F1).
func Classify(base string) (class Class, group int) {
	if class, group = classify(base); class == ClassNone {
		if rest, ok := gpolicy.GNUUnprefixed(base); ok {
			return classify(rest)
		}
	}
	return class, group
}

func classify(base string) (class Class, group int) {
	switch {
	case slices.Contains(packageTools, base):
		return ClassPackageTool, 0
	case base == findProgram:
		return ClassFind, 0
	case slices.Contains(actionPrograms, base):
		return ClassAction, 0
	case gpolicy.IsBuiltinOp(base) || gpolicy.IsBusClient(base):
		return ClassNotCommand, 0
	}
	if g, _, denied := gpolicy.HardDenied(base); denied {
		if g <= 10 {
			return ClassNever, g
		}
		return ClassListB, g
	}
	return ClassNone, 0
}

// FindAction returns the first token that is one of find's actions, or "".
// Tokens are compared whole: an action is one of find's own arguments,
// never part of another one (-executable, a name containing -exec).
func FindAction(tokens []string) string {
	for _, t := range tokens {
		if slices.Contains(findActions, t) {
			return t
		}
	}
	return ""
}

// actionPrograms are coreutils programs with an option that runs another
// program (S-MC, F3), and those options: GNU and uutils sort's
// --compress-program, split's --filter (GNU runs it through $SHELL -c), and
// install's --strip-program and -s/--strip, which run a stripping program.
// No other coreutils option runs a program (the programs that run one they
// are given, env, nice, nohup, stdbuf, timeout, chroot and runcon, are on
// POLICY §5's lists). Long options may be abbreviated (getopt_long, and
// clap's inferred long arguments in uutils), so a token is an action when
// its name, before any "=", is a prefix of the option, longer than "--";
// install's short options may be bundled, so any single-dash token holding
// an "s" is one. Like find's actions, the match errs on the safe side: an
// ambiguous abbreviation, or an "s" that is only another option's value,
// counts.
var actionPrograms = []string{"sort", "split", "install"}

var programActions = map[string]struct{ long, short string }{
	"sort":    {long: "--compress-program"},
	"split":   {long: "--filter"},
	"install": {long: "--strip-program", short: "s"},
}

// ProgramAction returns the first token that is one of program's options
// that run another program (sort, split, install), or "".
func ProgramAction(program string, tokens []string) string {
	a, ok := programActions[program]
	if !ok {
		return ""
	}
	for _, t := range tokens {
		if name, _, _ := strings.Cut(t, "="); strings.HasPrefix(t, "--") {
			if len(name) > 2 && strings.HasPrefix(a.long, name) {
				return t
			}
			continue
		}
		if a.short != "" && len(t) > 1 && t[0] == '-' && strings.ContainsAny(t[1:], a.short) {
			return t
		}
	}
	return ""
}

// recognised is a program a command's binary was recognised as.
type recognised struct {
	class Class
	group int
	name  string
	match string
}
