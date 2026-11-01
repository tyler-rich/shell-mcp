//go:build linux

package setupx

import (
	"errors"

	"io/fs"

	"sync"
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
func NewSystem() (*System, error) { var stub0 *System; var stub1 error; return stub0, stub1 }

// Euid implements Host.
func (s *System) Euid() int { var stub0 int; return stub0 }

// LookupEnv implements Host.
func (s *System) LookupEnv(name string) (string, bool) {
	var stub0 string
	var stub1 bool
	return stub0, stub1
}

// Executable implements Host.
func (s *System) Executable() (string, error) { var stub0 string; var stub1 error; return stub0, stub1 }

// CheckChain implements Host.
func (s *System) CheckChain(path string) error { var stub0 error; return stub0 }

// checked is CheckChain, once per path for the run.
func (s *System) checked(path string) error { var stub0 error; return stub0 }

// State implements Host.
func (s *System) State(path string, limit int64) (FileState, error) {
	var stub0 FileState
	var stub1 error
	return stub0, stub1
}

// ReadDir implements Host.
func (s *System) ReadDir(path string) ([]string, error) {
	var stub0 []string
	var stub1 error
	return stub0, stub1
}

// WriteFile implements Host.
func (s *System) WriteFile(path string, data []byte, mode fs.FileMode, owner Owner) error {
	var stub0 error
	return stub0
}

// Mkdir implements Host.
func (s *System) Mkdir(path string, mode fs.FileMode, owner Owner) error {
	var stub0 error
	return stub0
}

// Remove implements Host.
func (s *System) Remove(path string) error { var stub0 error; return stub0 }

// RemoveLeftovers implements Host.
func (s *System) RemoveLeftovers(target string) ([]string, error) {
	var stub0 []string
	var stub1 error
	return stub0, stub1
}

// ErrProgram is a program that is not on the list, or whose path or the
// trampoline's fails the chain check.
var ErrProgram = errors.New("program refused")

// ErrOutputCut is a program whose output reached the cap.
var ErrOutputCut = errors.New("the program's output was cut at its cap")

// Run implements Host: through execx, with the running binary as the
// trampoline, an empty environment, stdin /dev/null, the program's timeout,
// a memory limit and capped output that must be complete.
func (s *System) Run(prog string, args ...string) (Output, error) {
	var stub0 Output
	var stub1 error
	return stub0, stub1
}

// Accounts implements Host.
func (s *System) Accounts() (*Accounts, error) {
	var stub0 *Accounts
	var stub1 error
	return stub0, stub1
}

// SystemdRunning implements Host.
func (s *System) SystemdRunning() bool { var stub0 bool; return stub0 }
