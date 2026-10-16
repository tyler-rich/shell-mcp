//go:build linux

package execx

import (
	"context"
	"time"
)

// RunWithStartDelay is Run with the parent paused for d right after the
// child started: whatever the parent does to the child after that point
// reaches it only after the child has run for d.
func RunWithStartDelay(ctx context.Context, spec *Spec, d time.Duration) (Result, error) {
	return run(ctx, spec, &hooks{afterStart: func() { time.Sleep(d) }})
}

// UserTasks is userTasks, for the rlimit tests' expected bound.
var UserTasks = userTasks
