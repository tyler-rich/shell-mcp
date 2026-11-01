package setupx

import (
	"fmt"
	"io"
	"strings"
)

// Report prints the human lines (TARGET-SETUP §12.4) in check-policy's
// style: "ok   ", "WARN ", "FAIL ", "REVIEW ", "NOTE " and a continuation
// indent.
type Report struct {
	W        io.Writer
	Failures int
	Warnings int
}

func (r *Report) line(tag, format string, a ...any) {
	_, _ = fmt.Fprintf(r.W, tag+format+"\n", a...)
}

// OK prints an ok line.
func (r *Report) OK(format string, a ...any) { r.line("ok   ", format, a...) }

// Warn prints a WARN line.
func (r *Report) Warn(format string, a ...any) { r.Warnings++; r.line("WARN ", format, a...) }

// Fail prints a FAIL line; the run refuses.
func (r *Report) Fail(format string, a ...any) { r.Failures++; r.line("FAIL ", format, a...) }

// Review prints a REVIEW line.
func (r *Report) Review(format string, a ...any) { r.line("REVIEW ", format, a...) }

// Note prints a NOTE line.
func (r *Report) Note(format string, a ...any) { r.line("NOTE ", format, a...) }

// Info prints an indented line.
func (r *Report) Info(format string, a ...any) { r.line("     ", format, a...) }

// Block prints text indented, one line per line, for a file's content or a
// diff.
func (r *Report) Block(text string) {
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		_, _ = fmt.Fprintf(r.W, "     | %s\n", l)
	}
}
