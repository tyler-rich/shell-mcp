//go:build linux

package policy

// Class is how the privileged policy treats a command's program (handoff
// N-13). Stub: S4c-9 fills it in.
type Class int

// Classes.
const (
	ClassNone Class = iota
	ClassNever
	ClassNotCommand
	ClassListB
	ClassPackageTool
	ClassFind
)

// Classify returns a program base name's class. Stub.
func Classify(string) (Class, int) { return ClassNone, 0 }

// FindAction returns the first find action among tokens. Stub.
func FindAction([]string) string { return "" }
