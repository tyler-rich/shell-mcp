//go:build linux

package execx

import "fmt"

// Credential is an account a root caller runs a command as
// (Spec.Credential): exactly this uid, this primary gid and these
// supplementary groups. The caller resolves them from /etc/passwd and
// /etc/group; Run checks only that they are not root's and are well formed.
type Credential struct {
	UID    uint32
	GID    uint32
	Groups []uint32 // the supplementary groups, exactly; may be empty
}

// MaxCredentialGroups bounds Credential.Groups.
const MaxCredentialGroups = 64

// CredentialError is Run's refusal of a Spec.Credential. It is returned
// before anything starts: no socketpair, no fork.
type CredentialError struct {
	// UID and EUID are the calling process's real and effective uid.
	UID, EUID int
	Reason    string
}

func (e *CredentialError) Error() string {
	return fmt.Sprintf("execx: Spec.Credential refused (caller uid %d, euid %d): %s", e.UID, e.EUID, e.Reason)
}

// Unwrap makes a refusal an ErrStart: the command never started.
func (e *CredentialError) Unwrap() error { return ErrStart }

// credentialRefusal says why c must not be used, or "".
func credentialRefusal(_ *Credential) string { return "" } // stub

// credentialSwitchRefusal is the trampoline's own check before it switches:
// it must run as uid 0, real and effective.
func credentialSwitchRefusal(_, _ int) string { return "" } // stub

// observedCreds is what the trampoline reads back after the switch.
type observedCreds struct {
	RUID, EUID, SUID int
	RGID, EGID, SGID int
	Groups           []int
	// Permitted and Effective are capget(2)'s sets of the calling thread.
	Permitted, Effective uint64
	// Threads is every thread's /proc/self/task/<tid>/status.
	Threads []threadCreds
}

// threadCreds is one thread's credentials from its status file.
type threadCreds struct {
	TID string
	// UID and GID are the real, effective, saved and filesystem ids.
	UID, GID [4]uint64
	Groups   []uint64
	// Prm, Eff and Amb are CapPrm, CapEff and CapAmb.
	Prm, Eff, Amb uint64
}

// credentialMismatch says how got differs from want, or "".
func credentialMismatch(_ *Credential, _ *observedCreds) string { return "" } // stub
