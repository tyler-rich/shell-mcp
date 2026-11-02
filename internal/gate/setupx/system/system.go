//go:build linux

// Package system is the install commands' real host: setupx's Host on the
// running system, its programs run through execx. It is a package of its
// own so that setupx's file helpers carry no execx: execx's init() makes any
// binary that links it an exec trampoline, and the server (shell-mcp init)
// uses those helpers but must never link execx (D-003).
package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// Bounds of a program run.
const (
	// programOutput caps each stream; sshd -T prints about 10 KiB.
	programOutput = 4 << 20
	// programMemoryMB is each program's RLIMIT_DATA.
	programMemoryMB = 1024
)

// System is the real host.
type System struct {
	setupx.Disk
	exe    string
	mu     sync.Mutex
	chains map[string]error
}

// NewSystem returns the real host, with the running binary resolved (the
// trampoline of every program it runs). The temp files it removes after a
// killed run are root's.
func NewSystem() (*System, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot resolve own path: %w", err)
	}
	return &System{Disk: setupx.Disk{TempOwner: 0}, exe: exe, chains: map[string]error{}}, nil
}

// Euid implements setupx.Host.
func (s *System) Euid() int { return os.Geteuid() }

// LookupEnv implements setupx.Host.
func (s *System) LookupEnv(name string) (string, bool) { return os.LookupEnv(name) }

// Executable implements setupx.Host.
func (s *System) Executable() (string, error) { return s.exe, nil }

// CheckChain implements setupx.Host.
func (s *System) CheckChain(path string) error {
	_, err := policy.CheckChain(policy.RootTrust(), path)
	return err
}

// checked is CheckChain, once per path for the run.
func (s *System) checked(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err, ok := s.chains[path]; ok {
		return err
	}
	err := s.CheckChain(path)
	s.chains[path] = err
	return err
}

// Run implements setupx.Host: through execx, with the running binary as the
// trampoline, an empty environment, stdin /dev/null, the program's timeout,
// a memory limit and capped output that must be complete.
func (s *System) Run(prog string, args ...string) (setupx.Output, error) {
	timeout, ok := setupx.ProgramTimeout(prog)
	if !ok {
		return setupx.Output{}, fmt.Errorf("%w: %s is not one of the installer's programs", setupx.ErrProgram, prog)
	}
	for _, p := range []string{s.exe, prog} {
		if err := s.checked(p); err != nil {
			return setupx.Output{}, fmt.Errorf("%w: %s: %w", setupx.ErrProgram, p, err)
		}
	}
	r, err := execx.Run(context.Background(), &execx.Spec{Path: prog, Args: args, Env: []string{}, Dir: "/", Timeout: timeout,
		MaxOutput: programOutput, MaxMemoryMB: programMemoryMB, Trampoline: s.exe})
	if err != nil {
		return setupx.Output{}, err
	}
	out := setupx.Output{Stdout: r.Stdout, Stderr: r.Stderr, Exit: -1, Signal: r.Signal, TimedOut: r.TimedOut}
	if r.ExitCode != nil {
		out.Exit = *r.ExitCode
	}
	if r.StdoutTruncated || r.StderrTruncated || r.OutputCeilingHit {
		return out, fmt.Errorf("%s: %w", prog, setupx.ErrOutputCut)
	}
	return out, nil
}

// Accounts implements setupx.Host.
func (s *System) Accounts() (*setupx.Accounts, error) {
	pw, err := setupx.ReadState("/etc/passwd", setupx.MaxDatabaseBytes)
	if err != nil {
		return nil, err
	}
	gr, err := setupx.ReadState("/etc/group", setupx.MaxDatabaseBytes)
	if err != nil {
		return nil, err
	}
	if !pw.IsRegular() || !gr.IsRegular() {
		return nil, fmt.Errorf("%w: /etc/passwd and /etc/group must be regular files", setupx.ErrDatabase)
	}
	users, err := setupx.ParsePasswd(pw.Data)
	if err != nil {
		return nil, err
	}
	groups, err := setupx.ParseGroup(gr.Data)
	if err != nil {
		return nil, err
	}
	return &setupx.Accounts{Users: users, Groups: groups}, nil
}

// SystemdRunning implements setupx.Host.
func (s *System) SystemdRunning() bool {
	fi, err := os.Lstat("/run/systemd/system")
	return err == nil && fi.IsDir()
}
