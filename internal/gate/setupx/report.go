package setupx

import (
	"io"
)

// Report prints the human lines (TARGET-SETUP §12.4) in check-policy's
// style: "ok   ", "WARN ", "FAIL ", "REVIEW ", "NOTE " and a continuation
// indent.
type Report struct {
	W        io.Writer
	Failures int
	Warnings int
}

func (r *Report) line(tag, format string, a ...any) {}

// OK prints an ok line.
func (r *Report) OK(format string, a ...any) {}

// Warn prints a WARN line.
func (r *Report) Warn(format string, a ...any) {}

// Fail prints a FAIL line; the run refuses.
func (r *Report) Fail(format string, a ...any) {}

// Review prints a REVIEW line.
func (r *Report) Review(format string, a ...any) {}

// Note prints a NOTE line.
func (r *Report) Note(format string, a ...any) {}

// Info prints an indented line.
func (r *Report) Info(format string, a ...any) {}

// Block prints text indented, one line per line, for a file's content or a
// diff.
func (r *Report) Block(text string) {}
