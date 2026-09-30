//go:build linux

// Package pkg implements the apt operations the privileged helper runs in
// its broad unit (docs/PRIVILEGED.md §5.2, §6): the fixed apt-get argv for
// each operation, package-name validation (Debian Policy §5.6.1), the
// parser for a simulated transaction (apt-get -s), and a runner that waits
// — bounded — for a held dpkg or lists lock.
//
// There is never a free-form apt argument: every option is fixed here, and
// package names (already checked against the policy's allow-lists by the
// caller) are validated again and passed only after "--", which ends
// apt-get's option parsing (apt-pkg/contrib/cmndline.cc, apt 3.0.3 and
// 3.1.16).
package pkg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
)

// Op is an apt operation.
type Op string

// Operations.
const (
	OpUpdate  Op = "update"
	OpInstall Op = "install"
	OpUpgrade Op = "upgrade"
	OpRemove  Op = "remove"
)

// Bounds.
const (
	// MaxNames bounds the package names of one install or remove.
	MaxNames = 20
	// MaxChanges bounds the entries a parsed simulation keeps.
	MaxChanges = 5000
	maxName    = 128
)

// common are the options of every operation that changes packages:
// quiet, non-interactive, existing configuration files kept on upgrade
// (--force-confold), dpkg without a pseudo-terminal, and never an
// automatic removal of other packages.
var common = []string{"-q", "-y", "-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Use-Pty=0", "-o", "APT::Get::AutomaticRemove=false"}

// Args returns apt-get's arguments (after argv[0]) for op. simulate adds
// -s: the same transaction, simulated, without locking (apt-get(8)).
// install and remove take 1..MaxNames valid names; update and upgrade none;
// update is never simulated (it has no transaction to preview).
func Args(op Op, simulate bool, names []string) ([]string, error) {
	switch op {
	case OpUpdate, OpUpgrade:
		if len(names) != 0 {
			return nil, fmt.Errorf("%s takes no package names", op)
		}
	case OpInstall, OpRemove:
		if err := checkNames(op, names); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown apt operation %q", op)
	}
	if op == OpUpdate {
		if simulate {
			return nil, errors.New("update cannot be simulated")
		}
		return []string{"-q", "update"}, nil
	}
	args := slices.Clone(common)
	switch op {
	case OpInstall, OpUpgrade:
		args = append(args, "--no-install-recommends")
	case OpRemove:
		// Never a purge of configuration files in v1 (PRIVILEGED §6).
		args = append(args, "-o", "APT::Get::Purge=false")
	}
	if simulate {
		args = append(args, "-s")
	}
	args = append(args, string(op))
	if len(names) > 0 {
		args = append(append(args, "--"), names...)
	}
	return args, nil
}

func checkNames(op Op, names []string) error {
	if len(names) == 0 || len(names) > MaxNames {
		return fmt.Errorf("%s takes 1..%d package names", op, MaxNames)
	}
	for i, n := range names {
		switch {
		case !ValidName(n):
			return fmt.Errorf("%q is not a Debian package name", n)
		case op == OpInstall && strings.HasSuffix(n, "-"), op == OpRemove && strings.HasSuffix(n, "+"):
			// apt-get reads a trailing "-" on install as a removal and a
			// trailing "+" on remove as an installation.
			return fmt.Errorf("%q would change the operation's direction", n)
		case slices.Contains(names[:i], n):
			return fmt.Errorf("duplicate package %q", n)
		}
	}
	return nil
}

// nameRE is Debian Policy §5.6.1: lower-case letters, digits, "+", "-" and
// ".", at least two characters, starting with an alphanumeric.
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

// ValidName reports whether n is a Debian package name of at most 128
// bytes.
func ValidName(n string) bool { return len(n) <= maxName && nameRE.MatchString(n) }

// Env is the exact environment of every apt-get run: the helper's fixed
// command environment (POLICY §4) plus DEBIAN_FRONTEND=noninteractive.
func Env(home string) []string {
	return append(execx.Environment(home), "DEBIAN_FRONTEND=noninteractive")
}

// Version is a package to be installed.
type Version struct{ Name, Version string }

// Upgrade is an installed package whose version changes.
type Upgrade struct{ Name, From, To string }

// Removal is a package to be removed (Purge: with its configuration).
type Removal struct {
	Name, Version string
	Purge         bool
}

// Simulation is a parsed simulated transaction. Unparsed counts lines that
// looked like changes but did not parse, and changes past MaxChanges.
type Simulation struct {
	Install  []Version
	Upgrade  []Upgrade
	Remove   []Removal
	Unparsed int
}

// The lines pkgSimulate prints (apt-pkg/algorithms.cc, apt 3.0.3 and
// 3.1.16): "Inst <name> [<current>] (<candidate> <release>)" unpacks a new
// or changed version (with "[<current>]" only when one is installed),
// "Remv|Purg <name> [<current>]" removes, and "Conf …" configures (not a
// change of its own). Anything may follow: broken-dependency notes.
var (
	instRE    = regexp.MustCompile(`^Inst ([^\s\[\]()]+)(?: \[([^\s\[\]()]+)\])? \(([^\s\[\]()]+) `)
	removeRE  = regexp.MustCompile(`^(Remv|Purg) ([^\s\[\]()]+)(?: \[([^\s\[\]()]+)\])?(?: |$)`)
	versionRE = regexp.MustCompile(`^[A-Za-z0-9.+~:-]{1,128}$`)
	archRE    = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

// ParseSimulation parses apt-get -s output (host data: every name and
// version is validated, and at most MaxChanges entries are kept).
func ParseSimulation(out []byte) Simulation {
	var s Simulation
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		kind, _, _ := strings.Cut(line, " ")
		if kind != "Inst" && kind != "Remv" && kind != "Purg" {
			continue
		}
		ok := false
		if n < MaxChanges {
			if kind == "Inst" {
				ok = s.addInst(line)
			} else {
				ok = s.addRemove(line)
			}
		}
		if ok {
			n++
		} else {
			s.Unparsed++
		}
	}
	return s
}

func (s *Simulation) addInst(line string) bool {
	m := instRE.FindStringSubmatch(line)
	if len(m) != 4 || !validQualified(m[1]) || !versionRE.MatchString(m[3]) || (m[2] != "" && !versionRE.MatchString(m[2])) {
		return false
	}
	if m[2] == "" {
		s.Install = append(s.Install, Version{Name: m[1], Version: m[3]})
	} else {
		s.Upgrade = append(s.Upgrade, Upgrade{Name: m[1], From: m[2], To: m[3]})
	}
	return true
}

func (s *Simulation) addRemove(line string) bool {
	m := removeRE.FindStringSubmatch(line)
	if len(m) != 4 || m[3] == "" || !validQualified(m[2]) || !versionRE.MatchString(m[3]) {
		return false
	}
	s.Remove = append(s.Remove, Removal{Name: m[2], Version: m[3], Purge: m[1] == "Purg"})
	return true
}

// validQualified accepts a package name with an optional ":<arch>" (apt
// prints the architecture for packages that are not native).
func validQualified(s string) bool {
	name, arch, qualified := strings.Cut(s, ":")
	return ValidName(name) && (!qualified || archRE.MatchString(arch))
}

// lockMessages are apt's refusals when another process holds the dpkg
// frontend or administration lock, or the package lists lock
// (apt-pkg/contrib/fileutl.cc, apt-pkg/deb/debsystem.cc, apt-pkg/acquire.cc;
// untranslated under LC_ALL=C.UTF-8). apt refuses before changing anything.
var lockMessages = [][]byte{
	[]byte("Could not get lock "),
	[]byte("Unable to acquire the dpkg frontend lock"),
	[]byte("Unable to lock the administration directory"),
	[]byte("Unable to lock directory "),
}

// LockHeld reports whether stderr says a lock was held.
func LockHeld(stderr []byte) bool {
	for _, m := range lockMessages {
		if bytes.Contains(stderr, m) {
			return true
		}
	}
	return false
}

// ErrLockHeld is returned by Run when the lock was still held after
// LockWait.
var ErrLockHeld = errors.New("the package database is locked by another process")

// DefaultRetry is the pause between attempts while a lock is held.
const DefaultRetry = 2 * time.Second

// Runner runs apt-get through the helper's exec engine (execve, new
// process group, output caps, SIGTERM→SIGKILL at the deadline).
type Runner struct {
	AptGet    string
	Env       []string
	MaxOutput int
	// LockWait bounds how long a held lock is waited for.
	LockWait time.Duration
	// Retry is the pause between attempts (0 means DefaultRetry).
	Retry time.Duration
}

// Result is apt-get's last run, how many runs there were and how long a
// held lock was waited for.
type Result struct {
	execx.Result
	LockWait time.Duration
	Attempts int
}

// Run runs apt-get with args, all attempts within timeout. When apt-get
// fails because a lock is held, it is run again after Retry, until
// LockWait has passed; the result is then wrapped in ErrLockHeld.
func (r *Runner) Run(ctx context.Context, timeout time.Duration, args []string) (Result, error) {
	retry := r.Retry
	if retry <= 0 {
		retry = DefaultRetry
	}
	start := time.Now()
	deadline := start.Add(timeout)
	var res Result
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return res, fmt.Errorf("%w (waited %v)", ErrLockHeld, res.LockWait.Round(time.Second))
		}
		er, err := execx.Run(ctx, &execx.Spec{Path: r.AptGet, Args: args, Env: r.Env, Dir: "/", Timeout: remaining, MaxOutput: r.MaxOutput})
		if err != nil {
			return res, err
		}
		res.Result = er
		res.Attempts++
		if er.ExitCode == nil || *er.ExitCode == 0 || !LockHeld(er.Stderr) {
			return res, nil
		}
		res.LockWait = time.Since(start)
		if res.LockWait+retry > r.LockWait || time.Until(deadline) <= retry {
			return res, fmt.Errorf("%w (waited %v)", ErrLockHeld, res.LockWait.Round(time.Second))
		}
		t := time.NewTimer(retry)
		select {
		case <-ctx.Done():
			t.Stop()
			return res, ctx.Err()
		case <-t.C:
		}
		res.LockWait = time.Since(start)
	}
}
