//go:build !linux && !windows

package main

import "io"

// isTerminal fails closed where no terminal check is implemented: the
// enrolment command then refuses to show a seed.
func isTerminal(io.Writer) bool { return false }
