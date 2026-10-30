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

// UserTasksIn is userTasksIn, for the task-count tests.
var UserTasksIn = userTasksIn

// RunWithProcDir is Run counting the user's tasks under procDir instead of
// /proc.
func RunWithProcDir(ctx context.Context, spec *Spec, procDir string) (Result, error) {
	return run(ctx, spec, &hooks{procDir: procDir})
}
