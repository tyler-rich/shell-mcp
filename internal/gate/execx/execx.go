//go:build linux

// Package execx is the gate's (and the helper's) execve engine: an absolute
// path, an exact argv and environment, a new process group with
// Pdeathsig=SIGKILL, per-child rlimits, bounded stdin, capped output on two
// pipes, and SIGTERM→SIGKILL on the process group at the timeout. It never
// uses a shell or a PATH search, and it inherits nothing from the caller's
// environment.
package execx

import (
	"context"
	"errors"
	"time"
)

// Defaults.
const (
	DefaultLookahead   = 64 << 10 // bytes kept past the cap so redaction sees secrets straddling it
	DefaultHardCeiling = 64 << 20 // bytes drained per stream before the group is killed
	DefaultKillGrace   = 2 * time.Second
	// ChildNofile is the RLIMIT_NOFILE applied to every child.
	ChildNofile = 1024
	// ChildExtraTasks bounds how many tasks a child and its descendants may
	// add to the service user's count (RLIMIT_NPROC = current + this).
	ChildExtraTasks = 256
)

// Spec describes one process.
type Spec struct {
	Path        string   // absolute, already resolved
	Args        []string // argv[1:]; argv[0] is always Path
	Env         []string // the exact environment
	Dir         string   // working directory (real path); "" means "/"
	Stdin       []byte   // nil means /dev/null
	Timeout     time.Duration
	MaxOutput   int           // per stream
	Lookahead   int           // 0 means DefaultLookahead
	HardCeiling int64         // 0 means DefaultHardCeiling
	KillGrace   time.Duration // 0 means DefaultKillGrace
}

// Result reports what happened. Stdout and Stderr hold at most
// MaxOutput+Lookahead bytes; the caller redacts and cuts them to MaxOutput.
type Result struct {
	ExitCode         *int
	Signal           string
	TimedOut         bool
	Stdout           []byte
	Stderr           []byte
	StdoutTruncated  bool
	StderrTruncated  bool
	OutputCeilingHit bool
	Duration         time.Duration
}

// ErrStart is returned (wrapped) when the process could not be started.
var ErrStart = errors.New("process could not be started")

// Environment returns the exact child environment (POLICY §4).
func Environment(home string) []string { return nil }

// Run starts the process and waits for it. The error is non-nil only if
// the process could not be started; everything after that is in Result.
func Run(ctx context.Context, s Spec) (Result, error) {
	return Result{}, errors.New("not implemented")
}
