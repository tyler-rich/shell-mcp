//go:build linux

package execx

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

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

// Bounds on the trampoline's read-back of its own threads.
const (
	maxThreads      = 1024
	maxStatusBytes  = 64 << 10
	overflowID      = math.MaxUint32
	capVersion3Sets = 2 // capget(2) fills two __user_cap_data_struct for version 3
)

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

// checkCredential is Run's check of a Spec.Credential, before anything
// else: the calling process must run as uid 0, real and effective, and the
// credential must pass credentialRefusal.
func checkCredential(c *Credential) error {
	uid, euid := os.Getuid(), os.Geteuid()
	if uid != 0 || euid != 0 {
		return &CredentialError{UID: uid, EUID: euid, Reason: "the option is honoured only in a process running as uid 0, real and effective"}
	}
	if why := credentialRefusal(c); why != "" {
		return &CredentialError{UID: uid, EUID: euid, Reason: why}
	}
	return nil
}

// credentialRefusal says why c must not be used, or "": root's ids, the
// overflow id (setresuid(2) reads -1 as "unchanged"), group 0, a duplicate
// group, or more than MaxCredentialGroups groups.
func credentialRefusal(c *Credential) string {
	switch {
	case c.UID == 0:
		return "uid 0 is root's"
	case c.GID == 0:
		return "gid 0 is root's"
	case c.UID == overflowID:
		return "uid 4294967295 is the overflow id"
	case c.GID == overflowID:
		return "gid 4294967295 is the overflow id"
	case len(c.Groups) > MaxCredentialGroups:
		return fmt.Sprintf("%d supplementary groups, at most %d", len(c.Groups), MaxCredentialGroups)
	}
	seen := make(map[uint32]bool, len(c.Groups))
	for _, g := range c.Groups {
		switch {
		case g == 0:
			return "group 0 is root's"
		case g == overflowID:
			return "group 4294967295 is the overflow id"
		case seen[g]:
			return fmt.Sprintf("group %d twice", g)
		}
		seen[g] = true
	}
	return ""
}

// credentialSwitchRefusal is the trampoline's own check before it switches:
// it must run as uid 0, real and effective, whatever Run checked.
func credentialSwitchRefusal(uid, euid int) string {
	if uid != 0 || euid != 0 {
		return fmt.Sprintf("a credential to switch to, but not running as uid 0 (uid %d, euid %d)", uid, euid)
	}
	return ""
}

// observedCreds is what the trampoline reads back after the switch.
type observedCreds struct {
	RUID, EUID, SUID uint64
	RGID, EGID, SGID uint64
	Groups           []uint64
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

// sameSet reports whether a and b hold the same ids (the kernel keeps the
// group list sorted; the caller's order does not matter).
func sameSet(a []uint64, want []uint32) bool {
	if len(a) != len(want) {
		return false
	}
	x := slices.Clone(a)
	slices.Sort(x)
	w := make([]uint64, len(want))
	for i, g := range want {
		w[i] = uint64(g)
	}
	slices.Sort(w)
	return slices.Equal(x, w)
}

// credentialMismatch says how got differs from want, or "": the real,
// effective and saved uid and gid, the group list, the calling thread's
// permitted and effective capabilities, and for every thread its four uids
// and gids, its groups and its permitted, effective and ambient sets.
func credentialMismatch(want *Credential, got *observedCreds) string {
	u, g := uint64(want.UID), uint64(want.GID)
	switch {
	case got.RUID != u || got.EUID != u || got.SUID != u:
		return fmt.Sprintf("uid after the switch: real %d, effective %d, saved %d; want %d", got.RUID, got.EUID, got.SUID, u)
	case got.RGID != g || got.EGID != g || got.SGID != g:
		return fmt.Sprintf("gid after the switch: real %d, effective %d, saved %d; want %d", got.RGID, got.EGID, got.SGID, g)
	case !sameSet(got.Groups, want.Groups):
		return fmt.Sprintf("supplementary groups after the switch: %v, want %v", got.Groups, want.Groups)
	case got.Permitted != 0 || got.Effective != 0:
		return fmt.Sprintf("capabilities left after the switch: permitted %#x, effective %#x", got.Permitted, got.Effective)
	case len(got.Threads) == 0:
		return "no thread's credentials could be read back"
	}
	for i := range got.Threads {
		th := &got.Threads[i]
		for i := range 4 {
			if th.UID[i] != uint64(want.UID) || th.GID[i] != uint64(want.GID) {
				return fmt.Sprintf("thread %s kept other ids: Uid %v, Gid %v", th.TID, th.UID, th.GID)
			}
		}
		if !sameSet(th.Groups, want.Groups) {
			return fmt.Sprintf("thread %s kept other groups: %v", th.TID, th.Groups)
		}
		if th.Prm != 0 || th.Eff != 0 || th.Amb != 0 {
			return fmt.Sprintf("thread %s kept capabilities: permitted %#x, effective %#x, ambient %#x", th.TID, th.Prm, th.Eff, th.Amb)
		}
	}
	return ""
}

var errThreadStatus = errors.New("malformed thread status")

// parseThreadStatus reads the credential lines of a task's status file
// (proc_pid_status(5)): Uid and Gid with four ids each, Groups, and the
// hexadecimal CapPrm, CapEff and CapAmb. Each must appear exactly once, and
// the file is bounded by maxStatusBytes.
func parseThreadStatus(tid string, b []byte) (threadCreds, error) {
	th := threadCreds{TID: tid}
	if len(b) > maxStatusBytes {
		return th, errThreadStatus
	}
	seen := map[string]bool{}
	ids := func(v string, n int) ([]uint64, bool) {
		f := strings.Fields(v)
		if n >= 0 && len(f) != n {
			return nil, false
		}
		out := make([]uint64, 0, len(f))
		for _, s := range f {
			x, err := strconv.ParseUint(s, 10, 32)
			if err != nil {
				return nil, false
			}
			out = append(out, x)
		}
		return out, true
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), maxStatusBytes)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		switch k {
		case "Uid", "Gid", "Groups", "CapPrm", "CapEff", "CapAmb":
		default:
			continue
		}
		if seen[k] {
			return th, errThreadStatus
		}
		seen[k] = true
		switch k {
		case "Uid", "Gid":
			x, ok := ids(v, 4)
			if !ok {
				return th, errThreadStatus
			}
			if k == "Uid" {
				th.UID = [4]uint64(x)
			} else {
				th.GID = [4]uint64(x)
			}
		case "Groups":
			x, ok := ids(v, -1)
			if !ok || len(x) > MaxCredentialGroups+1 {
				return th, errThreadStatus
			}
			if len(x) > 0 {
				th.Groups = x
			}
		default:
			s := strings.TrimSpace(v)
			x, err := strconv.ParseUint(s, 16, 64)
			if err != nil || len(s) != 16 {
				return th, errThreadStatus
			}
			switch k {
			case "CapPrm":
				th.Prm = x
			case "CapEff":
				th.Eff = x
			default:
				th.Amb = x
			}
		}
	}
	if sc.Err() != nil || len(seen) != 6 {
		return th, errThreadStatus
	}
	return th, nil
}

// liveCreds reads this process's credentials back: getresuid(2),
// getresgid(2), getgroups(2) and capget(2) for the calling thread, and
// every thread's status file.
func liveCreds() (*observedCreds, error) {
	o := &observedCreds{}
	r, e, s := unix.Getresuid()
	o.RUID, o.EUID, o.SUID = id64(r), id64(e), id64(s)
	r, e, s = unix.Getresgid()
	o.RGID, o.EGID, o.SGID = id64(r), id64(e), id64(s)
	g, err := unix.Getgroups()
	if err != nil {
		return nil, fmt.Errorf("getgroups: %w", err)
	}
	for _, x := range g {
		o.Groups = append(o.Groups, id64(x))
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var d [capVersion3Sets]unix.CapUserData
	if err = unix.Capget(&hdr, &d[0]); err != nil {
		return nil, fmt.Errorf("capget: %w", err)
	}
	o.Permitted = uint64(d[1].Permitted)<<32 | uint64(d[0].Permitted)
	o.Effective = uint64(d[1].Effective)<<32 | uint64(d[0].Effective)
	dir, err := os.Open("/proc/self/task")
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	tids, err := dir.Readdirnames(maxThreads + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(tids) > maxThreads {
		return nil, fmt.Errorf("more than %d threads", maxThreads)
	}
	for _, tid := range tids {
		f, err := os.Open("/proc/self/task/" + tid + "/status") //nolint:gosec // G304: a task directory of this process
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(f, maxStatusBytes+1))
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		th, err := parseThreadStatus(tid, b)
		if err != nil {
			return nil, fmt.Errorf("thread %s: %w", tid, err)
		}
		o.Threads = append(o.Threads, th)
	}
	return o, nil
}

// becomeAccount switches the trampoline to c, after every check of
// trampolineRefusal has passed as root, and returns why it refuses to run
// the command, or "". ppid is the parent the trampoline checked (Run).
//
// The order is setgroups(2), setgid(2), setuid(2): the first two need
// CAP_SETGID, which setuid(2) to a non-zero uid drops. As root, setgid and
// setuid set the real, effective and saved ids (setuid(2), setgid(2)); when
// all of them become non-zero the kernel clears the permitted, effective
// and ambient capability sets, unless SECBIT_KEEP_CAPS is set
// (capabilities(7)), which the verification below would catch. setIDs
// makes the three calls on every thread of the process, through
// AllThreadsSyscall as syscall.Setgroups, Setgid and Setuid do in a binary
// without cgo (which these binaries are), with the ids as uint32, never
// narrowed through int; unix.Setgroups would change only the calling
// thread.
//
// The kernel clears the parent-death signal when the effective or
// filesystem ids change (PR_SET_PDEATHSIG(2const)), so it is set again,
// and the parent checked to be the one that started the trampoline (else
// it died during the switch, and the signal would never come). Then
// no_new_privs is set. Both are per-thread attributes of the calling
// thread, which is the one that execve(2)s: the trampoline runs in init,
// where the runtime keeps the main goroutine on the main thread.
func becomeAccount(c *Credential, ppid int) string {
	if why := credentialSwitchRefusal(unix.Getuid(), unix.Geteuid()); why != "" {
		return why
	}
	if why := credentialRefusal(c); why != "" {
		return why
	}
	if step, err := setIDs(c); err != nil {
		return fmt.Sprintf("%s: %v", step, err)
	}
	o, err := liveCreds()
	if err != nil {
		return fmt.Sprintf("cannot read the credentials back: %v", err)
	}
	if why := credentialMismatch(c, o); why != "" {
		return why
	}
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return fmt.Sprintf("PR_SET_PDEATHSIG: %v", err)
	}
	if unix.Getppid() != ppid {
		return "the parent process exited during the switch"
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Sprintf("PR_SET_NO_NEW_PRIVS: %v", err)
	}
	return ""
}

// id64 is an id the os and unix packages return as an int, widened; a
// negative one (none is) is the overflow id, which never matches.
func id64(v int) uint64 {
	if v < 0 {
		return overflowID
	}
	return uint64(v)
}
