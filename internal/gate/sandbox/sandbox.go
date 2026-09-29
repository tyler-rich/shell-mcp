//go:build linux

// Package sandbox computes the gate's Landlock ruleset from the policy
// (docs/POLICY.md §4a) and applies it, with no_new_privs, to every thread of
// the process before the request is read (D-019). Children inherit it.
//
// The ruleset is built for exactly the ABI the kernel supports and applied
// without go-landlock's best-effort mode: best-effort can silently fall back
// to enforcing nothing when a rule cannot be downgraded. The gate makes the
// best-effort decision itself (Plan) and reports it.
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/audit"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// ABI levels that matter to the gate.
const (
	// ABIFSFull governs file truncation as well as the V1/V2 rights, so
	// read-only roots cannot be truncated.
	ABIFSFull = 3
	// ABINet governs TCP bind and connect.
	ABINet = 4
	// ABIScope scopes signals and abstract Unix sockets to the domain.
	// Scoping arrived in ABI 6, but below ABI 8 go-landlock restricts each
	// thread separately (psx), which gives every thread its own domain: with
	// scoping on, the gate could not signal a child started from another
	// thread (seen on CI at ABI 7: exec timeouts could not kill). Scoping is
	// therefore handled only from ABI 8, where LANDLOCK_RESTRICT_SELF_TSYNC
	// gives the whole process one domain.
	ABIScope = 8
	// ABIUnixSocket governs connect(2)/sendmsg(2) on pathname Unix sockets
	// (LANDLOCK_ACCESS_FS_RESOLVE_UNIX).
	ABIUnixSocket = 9
	// ABIHighest is the highest ABI go-landlock v0.10.1 knows (landlock.V10).
	ABIHighest = 10
	// RequiredMinABI is what `landlock: required` needs for every policy:
	// the network rule (no TCP bind; connect only to listed ports) is always
	// present, and it needs ABINet. Filesystem rules need ABIFSFull ≤ ABINet.
	RequiredMinABI = ABINet
)

// ErrUnavailable means `landlock: required` cannot be satisfied.
var ErrUnavailable = errors.New("landlock cannot enforce every rule this policy needs")

// Rules is the ruleset computed from a policy, before it is trimmed to the
// kernel's ABI.
type Rules struct {
	ReadExec       []string // read + execute
	ReadOnly       []string // read
	ReadWrite      []string // read + write (no execute)
	DevNull        string   // read + write + truncate, the single file
	DevURandom     string   // read, the single file
	UnixSocketDirs []string // connect to pathname sockets beneath (ABI >= 9)
	SyslogSocket   string   // the audit socket; its real directory is granted
	TCPConnect     []uint16
}

// Enforcement is the per-class status.
type Enforcement struct {
	FS         bool `json:"fs"`
	Net        bool `json:"net"`
	UnixSocket bool `json:"unix_socket"`
	Scope      bool `json:"scope"`
}

// Report describes the sandbox for hello and check-policy.
type Report struct {
	Mode              string      `json:"mode"`
	KernelABI         int         `json:"kernel_abi"`
	EffectiveABI      int         `json:"effective_abi"`
	RequiredMinABI    int         `json:"required_min_abi"`
	Applied           bool        `json:"applied"`
	NoNewPrivs        bool        `json:"no_new_privs"`
	Enforced          Enforcement `json:"enforced"`
	NotEnforced       []string    `json:"not_enforced"`
	UnixSocketControl string      `json:"unix_socket_control"`
	TCPConnectPorts   []uint16    `json:"tcp_connect_ports"`
	ExtraFiles        []string    `json:"extra_files"`
	// MPTCP says how Multipath TCP sockets are handled: Landlock cannot
	// govern them, so a seccomp filter makes them unavailable.
	MPTCP string `json:"mptcp"`
}

// Journal directories granted read when the policy configures journal.
var journalDirs = []string{"/var/log/journal", "/run/log/journal"}

// dbusSocketDir holds the system bus socket, granted (ABI >= 9) when the
// policy configures any service feature: services.status (service_status,
// service_list, and {unit} placeholders) or services.control. systemctl
// reaches systemd through the system bus.
const dbusSocketDir = "/run/dbus"

// Compute derives the ruleset from the policy (POLICY §4a). Pathname Unix
// sockets are granted on the directory that holds them, which the kernel
// accepts for every file type; the helper's directory holds only helper
// sockets, the bus directory only the bus socket.
func Compute(p *policy.Policy) Rules {
	r := Rules{DevNull: "/dev/null", DevURandom: "/dev/urandom"}
	r.ReadExec = append(policy.DefaultReadExec(), p.Sandbox.SystemReadExec...)
	r.ReadOnly = append([]string{"/etc", "/proc"}, p.Paths.Read...)
	if len(p.Journal.Units) > 0 {
		r.ReadOnly = append(r.ReadOnly, journalDirs...)
	}
	r.ReadWrite = append([]string(nil), p.Paths.Write...)
	if len(p.Services.Status) > 0 || len(p.Services.ControlUnits) > 0 {
		r.UnixSocketDirs = append(r.UnixSocketDirs, dbusSocketDir)
	}
	r.SyslogSocket = audit.DevLog
	if p.Privileged.Enabled {
		for _, s := range []string{p.Privileged.Socket, p.Privileged.BroadSocket} {
			if d := path.Dir(s); s != "" && !slices.Contains(r.UnixSocketDirs, d) {
				r.UnixSocketDirs = append(r.UnixSocketDirs, d)
			}
		}
	}
	r.TCPConnect = append([]uint16(nil), p.Sandbox.TCPConnectPorts...)
	return r
}

// SocketDir returns the directory that really holds the Unix socket at p
// (after following symlinks: /dev/log is a symlink into journald's
// directory on systemd hosts), or false when p is missing or not a socket.
// Landlock checks the resolved socket, so the grant is on that directory,
// following the directory form used for every socket grant.
func SocketDir(p string) (string, bool) {
	rp, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", false
	}
	fi, err := os.Lstat(rp)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return "", false
	}
	return filepath.Dir(rp), true
}

// rawKernelABI is landlock_create_ruleset(NULL, 0, VERSION), 0 if unavailable.
func rawKernelABI() int {
	v, err := llsys.LandlockGetABIVersion()
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// KernelABI returns the running kernel's Landlock ABI (0 if unavailable),
// downgraded to 5 when the signal-scoping erratum is not fixed, exactly as
// go-landlock does, and capped at ABIHighest.
func KernelABI() int {
	v := rawKernelABI()
	if v >= 6 {
		errata, err := llsys.LandlockGetErrata()
		if err != nil {
			errata = 0
		}
		if errata&0x2 == 0 {
			v = 5
		}
	}
	return min(v, ABIHighest)
}

// Plan decides what the sandbox enforces for the policy at the given ABI.
// With `landlock: required` and abi < RequiredMinABI it returns
// ErrUnavailable. Plan changes nothing.
func Plan(p *policy.Policy, abi int) (Report, error) {
	return PlanRules(p.Sandbox.Landlock, Compute(p), abi)
}

// PlanRules is Plan for a ruleset computed elsewhere (the privileged
// helper computes its own from the privileged policy).
func PlanRules(mode policy.LandlockMode, rules Rules, abi int) (Report, error) {
	eff := min(abi, ABIHighest)
	r := Report{
		Mode:            string(mode),
		KernelABI:       abi,
		EffectiveABI:    eff,
		RequiredMinABI:  RequiredMinABI,
		TCPConnectPorts: append([]uint16{}, rules.TCPConnect...),
		ExtraFiles:      []string{"/dev/null (read, write, truncate)", "/dev/urandom (read)"},
		MPTCP:           MPTCPStatus,
		Enforced: Enforcement{
			FS:         eff >= ABIFSFull,
			Net:        eff >= ABINet,
			UnixSocket: eff >= ABIUnixSocket,
			Scope:      eff >= ABIScope,
		},
		NotEnforced: []string{},
	}
	for _, c := range []struct {
		name string
		on   bool
	}{{"fs", r.Enforced.FS}, {"net", r.Enforced.Net}, {"unix_socket", r.Enforced.UnixSocket}, {"scope", r.Enforced.Scope}} {
		if !c.on {
			r.NotEnforced = append(r.NotEnforced, c.name)
		}
	}
	if r.Enforced.UnixSocket {
		r.UnixSocketControl = "landlock"
	} else {
		r.UnixSocketControl = "file permissions and the helper's peer-UID check (kernel ABI below 9)"
	}
	if mode == policy.LandlockRequired && eff < RequiredMinABI {
		return r, fmt.Errorf("%w: kernel Landlock ABI %d, policy needs %d (set sandbox.landlock: best-effort to run with reduced enforcement)",
			ErrUnavailable, abi, RequiredMinABI)
	}
	return r, nil
}

// Access rights.
const (
	rightsReadExec  = llsys.AccessFSExecute | llsys.AccessFSReadFile | llsys.AccessFSReadDir
	rightsRead      = llsys.AccessFSReadFile | llsys.AccessFSReadDir
	rightsReadWrite = llsys.AccessFSReadFile | llsys.AccessFSReadDir | llsys.AccessFSWriteFile |
		llsys.AccessFSRemoveDir | llsys.AccessFSRemoveFile | llsys.AccessFSMakeDir | llsys.AccessFSMakeReg |
		llsys.AccessFSMakeSock | llsys.AccessFSMakeFifo | llsys.AccessFSMakeSym | llsys.AccessFSTruncate |
		llsys.AccessFSRefer // no execute, no device nodes, no ioctl
	rightsDevNull  = llsys.AccessFSReadFile | llsys.AccessFSWriteFile | llsys.AccessFSTruncate
	rightsURandom  = llsys.AccessFSReadFile
	rightsUnixSock = llsys.AccessFSResolveUnix
	// rightsFile are the rights the kernel accepts on a non-directory.
	rightsFile = llsys.AccessFSExecute | llsys.AccessFSWriteFile | llsys.AccessFSReadFile |
		llsys.AccessFSTruncate | llsys.AccessFSIoctlDev
)

// handledFS is the filesystem rights each ABI can restrict (go-landlock's
// abiInfos table).
func handledFS(abi int) landlock.AccessFSSet {
	switch {
	case abi >= 9:
		return (1 << 17) - 1
	case abi >= 5:
		return (1 << 16) - 1
	case abi >= 3:
		return (1 << 15) - 1
	case abi == 2:
		return (1 << 14) - 1
	case abi == 1:
		return (1 << 13) - 1
	}
	return 0
}

// build returns the config and rules for exactly this ABI. UDP (ABI 10) is
// deliberately not handled: POLICY §4a defines TCP rules only, and handling
// UDP would deny DNS to every command.
func build(r *Rules, abi int) (landlock.Config, []landlock.Rule, error) {
	fs := handledFS(abi)
	var net landlock.AccessNetSet
	if abi >= ABINet {
		net = llsys.AccessNetBindTCP | llsys.AccessNetConnectTCP
	}
	var scoped landlock.ScopedSet
	if abi >= ABIScope {
		scoped = llsys.ScopeAbstractUnixSocket | llsys.ScopeSignal
	}
	cfg, err := landlock.NewConfig(fs, net, scoped)
	if err != nil {
		return landlock.Config{}, nil, err
	}
	var rules []landlock.Rule
	add := func(access landlock.AccessFSSet, paths ...string) {
		for _, pth := range paths {
			a := access & fs
			fi, err := os.Stat(pth)
			if err != nil {
				continue // missing: nothing to grant
			}
			if !fi.IsDir() {
				a &= rightsFile
			}
			if a == 0 {
				continue
			}
			rules = append(rules, landlock.PathAccess(a, pth).IgnoreIfMissing())
		}
	}
	add(rightsReadExec, r.ReadExec...)
	add(rightsRead, r.ReadOnly...)
	add(rightsReadWrite, r.ReadWrite...)
	add(rightsDevNull, r.DevNull)
	add(rightsURandom, r.DevURandom)
	add(rightsUnixSock, r.UnixSocketDirs...)
	if d, ok := SocketDir(r.SyslogSocket); r.SyslogSocket != "" && ok {
		add(rightsUnixSock, d) // the audit line (ABI >= 9 governs it)
	}
	if abi >= ABINet {
		for _, port := range r.TCPConnect {
			rules = append(rules, landlock.ConnectTCP(port))
		}
	}
	return *cfg, rules, nil
}

// Apply sets no_new_privs and applies the Landlock ruleset to every thread,
// then verifies NoNewPrivs on every thread. It is irreversible.
//
// All-thread application: no_new_privs is set with go-landlock's
// AllThreadsPrctl, which with CGO_ENABLED=0 is syscall.AllThreadsSyscall
// through libcap/psx. The ruleset is applied by go-landlock to every
// thread: on ABI < 8 with psx (landlock_restrict_self on each thread), on
// ABI >= 8 with LANDLOCK_RESTRICT_SELF_TSYNC.
func Apply(p *policy.Policy) (Report, error) {
	rules := Compute(p)
	return ApplyRules(p.Sandbox.Landlock, &rules)
}

// ApplyRules is Apply for a ruleset computed elsewhere: the privileged
// helper applies one computed from its own policy (no TCP rule, so every
// TCP bind and connect is denied from ABI 4), with the same all-thread
// mechanism, MPTCP filter and verification.
func ApplyRules(mode policy.LandlockMode, rules *Rules) (Report, error) {
	abi := KernelABI()
	r, err := PlanRules(mode, *rules, abi)
	r.KernelABI = rawKernelABI()
	if err != nil {
		return r, err
	}
	if err := llsys.AllThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return r, fmt.Errorf("%w: prctl(PR_SET_NO_NEW_PRIVS): %w", ErrUnavailable, err)
	}
	if abi >= 1 {
		cfg, ll, err := build(rules, abi)
		if err != nil {
			return r, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		if err := cfg.Restrict(ll...); err != nil {
			return r, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		r.Applied = true
	}
	// Landlock cannot govern MPTCP; make it unavailable (seccomp.go).
	if err := applySeccomp(); err != nil {
		if mode == policy.LandlockRequired {
			return r, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		r.MPTCP = "not blocked: seccomp is unavailable"
	}
	if err := allThreadsNoNewPrivs(r.MPTCP == MPTCPStatus); err != nil {
		return r, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	r.NoNewPrivs = true
	return r, nil
}

// allThreadsNoNewPrivs checks /proc/self/task/*/status: NoNewPrivs is 1,
// and (when the MPTCP filter was installed) Seccomp is 2 (filter mode).
func allThreadsNoNewPrivs(wantSeccomp bool) error {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return fmt.Errorf("cannot list threads: %w", err)
	}
	if len(tasks) == 0 {
		return errors.New("no threads listed")
	}
	for _, t := range tasks {
		b, err := os.ReadFile("/proc/self/task/" + t.Name() + "/status")
		if err != nil {
			continue // thread exited
		}
		nnp, filtered := false, false
		for _, line := range strings.Split(string(b), "\n") {
			k, v, found := strings.Cut(line, ":")
			switch {
			case found && k == "NoNewPrivs":
				nnp = strings.TrimSpace(v) == "1"
			case found && k == "Seccomp":
				filtered = strings.TrimSpace(v) == "2"
			}
		}
		if !nnp {
			return fmt.Errorf("thread %s does not have NoNewPrivs set", t.Name())
		}
		if wantSeccomp && !filtered {
			return fmt.Errorf("thread %s has no seccomp filter", t.Name())
		}
	}
	return nil
}
