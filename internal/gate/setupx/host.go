//go:build linux

package setupx

import (
	"io/fs"

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
func Programs() []string { var stub0 []string; return stub0 }

// IsProgram reports whether prog is one of Programs.
func IsProgram(prog string) bool { var stub0 bool; return stub0 }

// Output is a program's result. Exit is -1 when it ended by a signal or
// timed out.
type Output struct {
	Stdout, Stderr []byte
	Exit           int
	Signal         string
	TimedOut       bool
}

// OK reports exit status 0.
func (o *Output) OK() bool { var stub0 bool; return stub0 }

// Host is everything an installer reads and changes on the host. The only
// production implementation is System; tests use setuptest.Fake. No flag or
// variable chooses another.
type Host interface {
	// Euid is the effective uid; LookupEnv reads the environment.
	Euid() int
	LookupEnv(name string) (string, bool)
	// Executable is the running binary, resolved.
	Executable() (string, error)
	// CheckChain requires path and every directory above it to be
	// root-owned and not group- or world-writable (policy.CheckChain with
	// root-only trust).
	CheckChain(path string) error
	// State reads path without following a link (ReadState).
	State(path string, limit int64) (FileState, error)
	// ReadDir lists a directory's names.
	ReadDir(path string) ([]string, error)
	// WriteFile, Mkdir and Remove change the filesystem (the write helper).
	WriteFile(path string, data []byte, mode fs.FileMode, owner Owner) error
	Mkdir(path string, mode fs.FileMode, owner Owner) error
	Remove(path string) error
	// RemoveLeftovers removes a killed run's temp files for target.
	RemoveLeftovers(target string) ([]string, error)
	// Run runs one of Programs with exactly args and an empty environment.
	Run(prog string, args ...string) (Output, error)
	// Accounts reads /etc/passwd and /etc/group.
	Accounts() (*Accounts, error)
	// SystemdRunning reports whether systemd runs as PID 1
	// (/run/systemd/system is a directory, sd_booted(3)).
	SystemdRunning() bool
}
