//go:build linux

package setupx

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
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
	exe    string
	mu     sync.Mutex
	chains map[string]error
}

// NewSystem returns the real host, with the running binary resolved (the
// trampoline of every program it runs).
func NewSystem() (*System, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot resolve own path: %w", err)
	}
	return &System{exe: exe, chains: map[string]error{}}, nil
}

// Euid implements Host.
func (s *System) Euid() int { return os.Geteuid() }

// LookupEnv implements Host.
func (s *System) LookupEnv(name string) (string, bool) { return os.LookupEnv(name) }

// Executable implements Host.
func (s *System) Executable() (string, error) { return s.exe, nil }

// CheckChain implements Host.
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

// State implements Host.
func (s *System) State(path string, limit int64) (FileState, error) { return ReadState(path, limit) }

// ReadDir implements Host.
func (s *System) ReadDir(path string) ([]string, error) {
	ents, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(ents))
	for i, e := range ents {
		out[i] = e.Name()
	}
	return out, nil
}

// WriteFile implements Host.
func (s *System) WriteFile(path string, data []byte, mode fs.FileMode, owner Owner) error {
	return WriteFile(path, data, mode, owner)
}

// Mkdir implements Host.
func (s *System) Mkdir(path string, mode fs.FileMode, owner Owner) error {
	return Mkdir(path, mode, owner)
}

// Remove implements Host.
func (s *System) Remove(path string) error { return Remove(path) }

// RemoveLeftovers implements Host.
func (s *System) RemoveLeftovers(target string) ([]string, error) { return RemoveLeftovers(target) }

// ErrProgram is a program that is not on the list, or whose path or the
// trampoline's fails the chain check.
var ErrProgram = errors.New("program refused")

// ErrOutputCut is a program whose output reached the cap.
var ErrOutputCut = errors.New("the program's output was cut at its cap")

// Run implements Host: through execx, with the running binary as the
// trampoline, an empty environment, stdin /dev/null, the program's timeout,
// a memory limit and capped output that must be complete.
func (s *System) Run(prog string, args ...string) (Output, error) {
	timeout, ok := programTimeouts[prog]
	if !ok {
		return Output{}, fmt.Errorf("%w: %s is not one of the installer's programs", ErrProgram, prog)
	}
	for _, p := range []string{s.exe, prog} {
		if err := s.checked(p); err != nil {
			return Output{}, fmt.Errorf("%w: %s: %w", ErrProgram, p, err)
		}
	}
	r, err := execx.Run(context.Background(), &execx.Spec{Path: prog, Args: args, Env: []string{}, Dir: "/", Timeout: timeout,
		MaxOutput: programOutput, MaxMemoryMB: programMemoryMB, Trampoline: s.exe})
	if err != nil {
		return Output{}, err
	}
	out := Output{Stdout: r.Stdout, Stderr: r.Stderr, Exit: -1, Signal: r.Signal, TimedOut: r.TimedOut}
	if r.ExitCode != nil {
		out.Exit = *r.ExitCode
	}
	if r.StdoutTruncated || r.StderrTruncated || r.OutputCeilingHit {
		return out, fmt.Errorf("%s: %w", prog, ErrOutputCut)
	}
	return out, nil
}

// Accounts implements Host.
func (s *System) Accounts() (*Accounts, error) {
	pw, err := ReadState("/etc/passwd", MaxDatabaseBytes)
	if err != nil {
		return nil, err
	}
	gr, err := ReadState("/etc/group", MaxDatabaseBytes)
	if err != nil {
		return nil, err
	}
	if !pw.IsRegular() || !gr.IsRegular() {
		return nil, fmt.Errorf("%w: /etc/passwd and /etc/group must be regular files", ErrDatabase)
	}
	users, err := ParsePasswd(pw.Data)
	if err != nil {
		return nil, err
	}
	groups, err := ParseGroup(gr.Data)
	if err != nil {
		return nil, err
	}
	return &Accounts{Users: users, Groups: groups}, nil
}

// SystemdRunning implements Host.
func (s *System) SystemdRunning() bool {
	fi, err := os.Lstat("/run/systemd/system")
	return err == nil && fi.IsDir()
}
