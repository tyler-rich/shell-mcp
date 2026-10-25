//go:build linux

package ops

import (
	"slices"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// helperReadFiles are single files the helper and the root commands it
// runs read after the sandbox is applied: owner and group names for
// listings, and the dynamic linker's cache. /proc/self is the helper's own
// /proc/<pid> (resolved when the rule is created), which fsx and the
// sandbox's own verification read.
var helperReadFiles = []string{"/proc/self", "/etc/passwd", "/etc/group", "/etc/ld.so.cache"}

// Rules computes the core unit's Landlock ruleset from the privileged
// policy (PRIVILEGED §5.1): read+execute on the system directories and on
// each declared command's binary; read on the read roots and the few files
// above; read+write (never execute) on the write roots, the persistence
// roots and the backup store; /dev/null and /dev/urandom. There is no
// socket grant, no syslog socket (the audit goes to stderr) and no TCP
// port, so from ABI 4 every TCP bind and connect is denied: the network is
// denied entirely, in addition to the unit's PrivateNetwork=yes and
// RestrictAddressFamilies=AF_UNIX.
func Rules(p *policy.Policy, backupDir string) sandbox.Rules {
	r := sandbox.Rules{DevNull: "/dev/null", DevURandom: "/dev/urandom"}
	r.ReadExec = gpolicy.DefaultReadExec()
	for i := range p.Commands {
		r.ReadExec = append(r.ReadExec, p.Commands[i].Resolved)
	}
	r.ReadOnly = append(append([]string(nil), helperReadFiles...), p.Paths.Read...)
	r.ReadWrite = append(p.Paths.WriteRoots(), backupDir)
	// A declared CAP_KILL must be able to reach processes outside the
	// helper's Landlock domain, so signals are then left unscoped (from ABI
	// 8); abstract Unix sockets stay scoped (maintainer decision, S1c).
	r.UnscopedSignals = slices.Contains(p.Capabilities, "CAP_KILL")
	return r
}

// ApplyLandlock applies Rules with the policy's sandbox.landlock mode,
// through the gate's sandbox (no_new_privs on every thread, Landlock at the
// kernel's exact ABI, the MPTCP seccomp filter, per-thread verification).
func ApplyLandlock(p *policy.Policy, backupDir string) (sandbox.Report, error) {
	if BypassBuild {
		return sandbox.Report{Mode: "bypassed (e2e test build)"}, nil
	}
	r := Rules(p, backupDir)
	return sandbox.ApplyRules(p.Landlock, &r)
}
