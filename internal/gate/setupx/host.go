//go:build linux

package setupx

import (
	"errors"
	"io/fs"
	"slices"
	"time"
)

// The programs the installers may run (TARGET-SETUP §12.4), by absolute
// path, each with its timeout. On Debian 13, Ubuntu 24.04 and 26.04 none is
// a multi-call binary (shadow-utils, OpenSSH, systemd).
const (
	Groupadd       = "/usr/sbin/groupadd"
	Useradd        = "/usr/sbin/useradd"
	Usermod        = "/usr/sbin/usermod"
	Sshd           = "/usr/sbin/sshd"
	Systemctl      = "/usr/bin/systemctl"
	SystemdAnalyze = "/usr/bin/systemd-analyze"
)

var programTimeouts = map[string]time.Duration{
	Groupadd: 60 * time.Second, Useradd: 120 * time.Second, Usermod: 60 * time.Second, Sshd: 30 * time.Second,
	Systemctl: 120 * time.Second, SystemdAnalyze: 120 * time.Second,
}

// Programs is every program an installer may run, sorted.
func Programs() []string {
	out := make([]string, 0, len(programTimeouts))
	for p := range programTimeouts {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// IsProgram reports whether prog is one of Programs.
func IsProgram(prog string) bool {
	_, ok := programTimeouts[prog]
	return ok
}

// ProgramTimeout is prog's timeout, if it is one of Programs.
func ProgramTimeout(prog string) (time.Duration, bool) {
	t, ok := programTimeouts[prog]
	return t, ok
}

// ErrProgram is a program that is not on the list, or whose path or the
// trampoline's fails the chain check.
var ErrProgram = errors.New("program refused")

// ErrOutputCut is a program whose output reached the cap.
var ErrOutputCut = errors.New("the program's output was cut at its cap")

// Output is a program's result. Exit is -1 when it ended by a signal or
// timed out.
type Output struct {
	Stdout, Stderr []byte
	Exit           int
	Signal         string
	TimedOut       bool
}

// OK reports exit status 0.
func (o *Output) OK() bool { return o.Exit == 0 && o.Signal == "" && !o.TimedOut }

// Files is what a run reads and changes on the filesystem, through the write
// helper. Disk is the real one; tests use setuptest.Fake.
type Files interface {
	// State reads path without following a link (ReadState).
	State(path string, limit int64) (FileState, error)
	// WriteFile, Mkdir and Remove change the filesystem (the write helper).
	WriteFile(path string, data []byte, mode fs.FileMode, owner Owner) error
	Mkdir(path string, mode fs.FileMode, owner Owner) error
	Remove(path string) error
	// RemoveLeftovers removes a killed run's temp files for target.
	RemoveLeftovers(target string) ([]string, error)
}

// Host is everything an installer reads and changes on the host. The only
// production implementation is system.System; tests use setuptest.Fake. No
// flag or variable chooses another.
type Host interface {
	Files
	// Euid is the effective uid; LookupEnv reads the environment.
	Euid() int
	LookupEnv(name string) (string, bool)
	// Executable is the running binary, resolved.
	Executable() (string, error)
	// CheckChain requires path and every directory above it to be
	// root-owned and not group- or world-writable (policy.CheckChain with
	// root-only trust).
	CheckChain(path string) error
	// ReadDir lists a directory's names.
	ReadDir(path string) ([]string, error)
	// Run runs one of Programs with exactly args and an empty environment.
	Run(prog string, args ...string) (Output, error)
	// Accounts reads /etc/passwd and /etc/group.
	Accounts() (*Accounts, error)
	// SystemdRunning reports whether systemd runs as PID 1
	// (/run/systemd/system is a directory, sd_booted(3)).
	SystemdRunning() bool
}
