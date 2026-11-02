//go:build linux

package setup

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
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
	// CredentialSupported says whether this binary can run check-policy as
	// the account (execx.CredentialSupported): not in a build with cgo.
	CredentialSupported() error
	// RunAs runs the installed gate binary with args as the account cred
	// (execx's credential option), with RLIMIT_DATA memoryMB.
	RunAs(cred *execx.Credential, memoryMB int, args ...string) (setupx.Output, error)
}

type host struct {
	*setupx.System
}

// NewHost is the real host.
func NewHost() (Host, error) {
	s, err := setupx.NewSystem()
	if err != nil {
		return nil, err
	}
	return &host{s}, nil
}

func (h *host) LoadPolicy(path, home string) (*policy.Policy, error) {
	exe, _ := h.Executable()
	return policy.Load(path, &policy.LoadOptions{Trust: policy.RootTrust(), GateExecutable: exe, ServiceHome: home})
}

func (h *host) CredentialSupported() error { return execx.CredentialSupported() }

func (h *host) CheckSandbox(p *policy.Policy) (int, error) {
	abi := sandbox.KernelABI()
	_, err := sandbox.Plan(p, abi)
	return abi, err
}

func (h *host) MemTotal() (uint64, error) {
	b, err := setupx.ReadState("/proc/meminfo", 1<<20)
	if err != nil {
		return 0, err
	}
	return parseMemTotal(b.Data)
}

// parseMemTotal reads MemTotal (kB) from /proc/meminfo.
func parseMemTotal(b []byte) (uint64, error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			f := strings.Fields(v)
			if len(f) == 2 && f[1] == "kB" {
				n, err := strconv.ParseUint(f[0], 10, 64)
				if err == nil && n < 1<<44 {
					return n << 10, nil
				}
			}
			break
		}
	}
	return 0, fmt.Errorf("no MemTotal in /proc/meminfo")
}

func (h *host) OwnerScan(uids, gids []uint32, paths []string) (ScanResult, error) {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ScanResult{}, err
	}
	mounts, err := ParseMountinfo(b)
	if err != nil {
		return ScanResult{}, err
	}
	return ownerScan(mounts, uids, gids, paths)
}

// checkPolicyTimeout bounds check-policy as the account.
const checkPolicyTimeout = 5 * time.Minute

// RunAs is the one place that sets execx's credential option (TARGET-SETUP
// §12.1 step 4; a call-site test in execx enforces it): the installed gate
// binary, an empty environment, as the account.
func (h *host) RunAs(cred *execx.Credential, memoryMB int, args ...string) (setupx.Output, error) {
	exe, _ := h.Executable()
	r, err := execx.Run(context.Background(), &execx.Spec{Path: GatePath, Args: args, Env: []string{}, Dir: "/", Timeout: checkPolicyTimeout,
		MaxOutput: 4 << 20, MaxMemoryMB: memoryMB, Trampoline: exe, Credential: cred})
	if err != nil {
		return setupx.Output{}, err
	}
	out := setupx.Output{Stdout: r.Stdout, Stderr: r.Stderr, Exit: -1, Signal: r.Signal, TimedOut: r.TimedOut}
	if r.ExitCode != nil {
		out.Exit = *r.ExitCode
	}
	if r.StdoutTruncated || r.StderrTruncated {
		return out, setupx.ErrOutputCut
	}
	return out, nil
}
