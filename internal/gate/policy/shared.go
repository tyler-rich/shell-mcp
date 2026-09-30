package policy

import "slices"

// Exports shared with the privileged helper's policy (internal/privd/policy),
// which applies the gate's binary, root and deny rules to its own commands
// and roots (PRIVILEGED.md §4). None of them changes the gate's behaviour.

// HardDenied returns the POLICY §5 group (1–13) and group name that deny
// a binary base name, if any.
func HardDenied(base string) (group int, name string, denied bool) { return hardDenied(base) }

// BuiltinDeny returns the built-in read deny list (POLICY §3).
func BuiltinDeny() []string { return slices.Clone(builtinDeny) }

// BuiltinProtected returns the built-in protected set (POLICY §3), without
// the host's trust anchors that the gate adds at load time.
func BuiltinProtected() []string { return slices.Clone(builtinProtected) }

// IsBuiltinOp reports whether a binary base name may never be a policy
// command because its safe forms are built-in gate operations.
func IsBuiltinOp(base string) bool { return slices.Contains(builtinOps, base) }

// IsContainerCLI reports whether a binary base name needs
// `root_equivalent: true`.
func IsContainerCLI(base string) bool { return slices.Contains(containerCLIs, base) }

// CheckRoot applies POLICY §3 to one root: absolute and clean, not /, and
// not /proc, /sys, /dev, /run or inside one.
func CheckRoot(p string) error { return checkRoot(p) }

// ErrReason drops the path from a *fs.PathError (the caller already names
// it).
func ErrReason(err error) string { return errReason(err) }
