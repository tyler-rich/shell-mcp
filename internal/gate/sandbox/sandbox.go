//go:build linux

// Package sandbox computes the gate's Landlock ruleset from the policy
// (docs/POLICY.md §4a) and applies it, with no_new_privs, to every thread of
// the process before the request is read (D-019). Children inherit it.
package sandbox

import (
	"errors"

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
	ABIScope = 6
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
}

// Compute derives the ruleset from the policy.
func Compute(p *policy.Policy) Rules { return Rules{} }

// KernelABI returns the running kernel's Landlock ABI (0 if unavailable),
// downgraded to 5 when the signal-scoping erratum is not fixed, exactly as
// go-landlock does, and capped at ABIHighest.
func KernelABI() int { return 0 }

// Plan decides what the sandbox enforces for the policy at the given ABI.
// With `landlock: required` and abi < RequiredMinABI it returns
// ErrUnavailable. Plan changes nothing.
func Plan(p *policy.Policy, abi int) (Report, error) { return Report{}, errors.New("not implemented") }

// Apply sets no_new_privs and applies the Landlock ruleset to every thread,
// then verifies NoNewPrivs on every thread. It is irreversible.
func Apply(p *policy.Policy) (Report, error) { return Report{}, errors.New("not implemented") }
