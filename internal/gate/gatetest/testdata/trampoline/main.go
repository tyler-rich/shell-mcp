//go:build linux

// Command trampoline is the exec trampoline alone, for tests; never
// shipped. It imports execx, whose init runs the trampoline when the binary
// is started as one, and it is built like the release gate and helper
// (CGO_ENABLED=0, no race detector): a race-built test binary as the
// trampoline carries ThreadSanitizer, which may map memory after the child
// limits are lowered and abort under the memory limit (handoff N-30).
// Started any other way, it exits 2.
package main

import (
	"fmt"
	"os"

	_ "github.com/tyler-rich/shell-mcp/internal/gate/execx"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "trampoline: a test exec trampoline only")
	os.Exit(2)
}
