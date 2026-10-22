//go:build linux

package policy

import (
	"slices"

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
)

// How a program was recognised (CommandFinding.Match).
const (
	MatchWritten  = "written"
	MatchResolved = "resolved"
	MatchIdentity = "identity"
	MatchTemplate = "template"
)

// powerGroup is POLICY §5's power group.
const powerGroup = 11

// helperScanNames are the names the helper's binary identity check adds to
// the gate's (hard-denied names, built-in operations, D-Bus clients).
func helperScanNames() []string { return append(slices.Clone(packageTools), findProgram) }

// Classify returns a program base name's class, and for ClassNever and
// ClassListB its POLICY §5 group.
func Classify(base string) (Class, int) {
	switch {
	case slices.Contains(packageTools, base):
		return ClassPackageTool, 0
	case base == findProgram:
		return ClassFind, 0
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

// recognised is a program a command's binary was recognised as.
type recognised struct {
	class Class
	group int
	name  string
	match string
}
