//go:build linux

package setup

import (
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// ScanResult is the owner scan's outcome: the first entry owned by one of
// the ids (Hit, empty when none), the directories walked, the filesystems
// skipped (pseudo and network, "mount point (type)"), and for a narrowed
// scan the local filesystems it did not cover.
type ScanResult struct {
	Hit        string
	Walked     []string
	Skipped    []string
	NotCovered []string
}

// Host is what shell-mcp-gate install reads and changes beyond
// setupx.Host. The only production implementation is NewHost's.
type Host interface {
	setupx.Host
	// LoadPolicy loads the gate policy as serve would, with home as the
	// service account's home in the protected set.
	LoadPolicy(path, home string) (*policy.Policy, error)
	// CheckSandbox is the kernel's Landlock ABI and the sandbox plan's
	// refusal for p (nil when serve could apply it).
	CheckSandbox(p *policy.Policy) (abi int, err error)
	// MemTotal is the host's memory in bytes (/proc/meminfo).
	MemTotal() (uint64, error)
	// OwnerScan walks the local filesystems (or only paths, when given)
	// for an entry owned by one of uids or gids.
	OwnerScan(uids, gids []uint32, paths []string) (ScanResult, error)
	// RunAs runs the installed gate binary with args as the account cred
	// (execx's credential option), with RLIMIT_DATA memoryMB.
	RunAs(cred *execx.Credential, memoryMB int, args ...string) (setupx.Output, error)
}

type host struct {
	*setupx.System
}

// NewHost is the real host.
func NewHost() (Host, error) { var stub0 Host; var stub1 error; return stub0, stub1 }

func (h *host) LoadPolicy(path, home string) (*policy.Policy, error) {
	var stub0 *policy.Policy
	var stub1 error
	return stub0, stub1
}

func (h *host) CheckSandbox(p *policy.Policy) (int, error) {
	var stub0 int
	var stub1 error
	return stub0, stub1
}

func (h *host) MemTotal() (uint64, error) { var stub0 uint64; var stub1 error; return stub0, stub1 }

// parseMemTotal reads MemTotal (kB) from /proc/meminfo.
func parseMemTotal(b []byte) (uint64, error) { var stub0 uint64; var stub1 error; return stub0, stub1 }

func (h *host) OwnerScan(uids, gids []uint32, paths []string) (ScanResult, error) {
	var stub0 ScanResult
	var stub1 error
	return stub0, stub1
}

// checkPolicyTimeout bounds check-policy as the account.
const checkPolicyTimeout = 5 * time.Minute

// RunAs is the one place that sets execx's credential option (TARGET-SETUP
// §12.1 step 4; a call-site test in execx enforces it): the installed gate
// binary, an empty environment, as the account.
func (h *host) RunAs(cred *execx.Credential, memoryMB int, args ...string) (setupx.Output, error) {
	var stub0 setupx.Output
	var stub1 error
	return stub0, stub1
}
