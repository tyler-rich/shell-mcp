package tools

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// Shared pieces of the read tools (docs/TOOLS.md, read tier). Server-side
// checks reject clearly bad input early with validation_error and never
// clean it up; the gate re-validates everything against its policy.
//
// Schema maxima are static, so the catalogue is the same for every
// deployment: where TOOLS.md bounds a value by a server setting or a
// policy limit, the schema states the highest value that setting can take
// and the check (here, or the gate's) applies the configured one.

const (
	// maxTimeoutCeiling is the highest SHELL_MCP_MAX_TIMEOUT (seconds).
	maxTimeoutCeiling = 3600
	// maxOutputCeiling is the highest SHELL_MCP_MAX_OUTPUT_BYTES, and the
	// highest policy max_output_bytes and max_read_bytes.
	maxOutputCeiling = 4 << 20
	// defaultMaxOutput is SHELL_MCP_MAX_OUTPUT_BYTES' default.
	defaultMaxOutput = 262144
	// defaultMaxTimeout is SHELL_MCP_MAX_TIMEOUT's default.
	defaultMaxTimeout = 300 * time.Second
	// maxFilter bounds name filters (the gate's own bound).
	maxFilter = 256
	// maxRelativeSeconds is ten years, the bound on relative times.
	maxRelativeSeconds = 10 * 365 * 24 * 3600
	// maxSafeInt bounds offsets: integers up to it travel exactly in JSON.
	maxSafeInt = 1 << 53
)

// Input patterns (informational in the schema; the checks below decide).
const (
	pathPattern    = `^/[^\x00]*$`
	filterPattern  = `^[^\x00]*$`
	globPattern    = `^[^/\x00]*$`
	unitPattern    = `^[A-Za-z0-9:_.\\@][A-Za-z0-9:_.\\@-]{0,249}\.(service|socket|target|timer|mount|automount|path|slice|scope|swap|device)$`
	userPattern    = `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,30}\$?$`
	commandPattern = `^[a-z0-9][a-z0-9-]{0,62}$`
	argPattern     = `^[^\x00\n\r]*$`
	withinPattern  = `^[1-9][0-9]{0,6}[smhdw]$`
	timePattern    = `^(-[1-9][0-9]{0,6}[smhdw]|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2}))$`
)

var (
	unitRE    = regexp.MustCompile(unitPattern)
	userRE    = regexp.MustCompile(userPattern)
	commandRE = regexp.MustCompile(commandPattern)
	withinRE  = regexp.MustCompile(`^([1-9]\d{0,6})([smhdw])$`)
)

var unitSeconds = map[string]int64{"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}

// Common optional inputs on tools that run a process (TOOLS.md).
type timeoutArg struct {
	TimeoutSeconds *int `json:"timeout_seconds,omitzero" jsonschema:"Time budget in seconds (1 to the server's maximum, at most 3600). Default: the server's default timeout. The gate clamps it to its policy's limit."`
}

type outputArg struct {
	MaxOutputBytes *int `json:"max_output_bytes,omitzero" jsonschema:"Most bytes of output returned (1 to the server's maximum output size, at most 4194304). Default: the server's maximum. Longer output is cut and flagged as truncated."`
}

// --- Schema helpers -----------------------------------------------------

func prop(s *jsonschema.Schema, name string) *jsonschema.Schema {
	p := s.Properties[name]
	if p == nil {
		panic("tools: schema has no property " + name)
	}
	return p
}

// intIn bounds an integer property; an optional (pointer) integer is still
// typed "integer", since null is not accepted.
func intIn(s *jsonschema.Schema, name string, lo, hi float64) {
	p := prop(s, name)
	p.Type, p.Types = "integer", nil
	p.Minimum, p.Maximum = &lo, &hi
}

func strIn(s *jsonschema.Schema, name, pattern string, maxLen int) {
	p := prop(s, name)
	p.Pattern, p.MaxLength = pattern, &maxLen
}

func enumIn(s *jsonschema.Schema, name string, vals ...string) {
	p := prop(s, name)
	p.Enum = make([]any, len(vals))
	for i, v := range vals {
		p.Enum[i] = v
	}
	p.MaxLength = new(16)
	p.Pattern = "^(" + strings.Join(vals, "|") + ")$"
}

// boundCommon bounds target and whichever common inputs the schema has.
func boundCommon(s *jsonschema.Schema) {
	boundTarget(s)
	if s.Properties["timeout_seconds"] != nil {
		intIn(s, "timeout_seconds", 1, maxTimeoutCeiling)
	}
	if s.Properties["max_output_bytes"] != nil {
		intIn(s, "max_output_bytes", 1, maxOutputCeiling)
	}
}

// --- Validation helpers ---------------------------------------------------

func invalid(format string, a ...any) *envelope.Error {
	return envelope.Errorf(envelope.CodeValidationError, format, a...)
}

// checkPath: absolute and already clean (POLICY §3); never cleaned here.
func checkPath(field, p string) *envelope.Error {
	if err := pathx.CheckClean(p); err != nil {
		return invalid("%s must be an absolute, clean path (no . or .. components, no repeated or trailing /, no NUL, at most 4096 bytes): %v", field, err)
	}
	return nil
}

func checkOptPath(field, p string) *envelope.Error {
	if p == "" {
		return nil
	}
	return checkPath(field, p)
}

// checkCount: an optional count, when given, is 1..hi.
func checkCount(field string, v *int, hi int) *envelope.Error {
	if v != nil && (*v < 1 || *v > hi) {
		return invalid("%s must be 1..%d", field, hi)
	}
	return nil
}

func checkUnit(u string) *envelope.Error {
	if len(u) > 256 || !unitRE.MatchString(u) {
		return invalid("unit must be an exact unit name with a type suffix, such as example-app.service (no globs, no leading -)")
	}
	return nil
}

func checkFilter(field, v string) *envelope.Error {
	if len(v) > maxFilter || strings.ContainsRune(v, 0) {
		return invalid("%s must be at most %d bytes without NUL", field, maxFilter)
	}
	return nil
}

// relativeSeconds parses N<s|m|h|d|w> of at most ten years.
func relativeSeconds(v string) (int64, bool) {
	m := withinRE.FindStringSubmatch(v)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	secs := n * unitSeconds[m[2]]
	return secs, secs <= maxRelativeSeconds
}

// journalTime parses since/until: RFC 3339 with a zone, or -N<unit> of at
// most ten years before now. It returns the instant.
func journalTime(v string, now time.Time) (time.Time, bool) {
	if strings.HasPrefix(v, "-") {
		secs, ok := relativeSeconds(v[1:])
		return now.Add(-time.Duration(secs) * time.Second), ok
	}
	if len(v) > 64 || !strings.Contains(v, "T") {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v)
	return t, err == nil && t.Unix() >= 0
}

// --- Budget, limits, redaction --------------------------------------------

func (d *Deps) maxTimeout() time.Duration {
	if d.MaxTimeout > 0 {
		return d.MaxTimeout
	}
	return defaultMaxTimeout
}

func (d *Deps) maxOutput() int {
	if d.MaxOutputBytes > 0 {
		return d.MaxOutputBytes
	}
	return defaultMaxOutput
}

func (d *Deps) redactor() *redact.Redactor {
	if d.Redactor != nil {
		return d.Redactor
	}
	return redact.New(nil)
}

// timeoutFor is the request's budget: timeout_seconds within
// SHELL_MCP_MAX_TIMEOUT, or the server's default.
func (d *Deps) timeoutFor(a timeoutArg) (time.Duration, *envelope.Error) {
	if a.TimeoutSeconds == nil {
		return d.budget(), nil
	}
	maxS := int(d.maxTimeout() / time.Second)
	if *a.TimeoutSeconds < 1 || *a.TimeoutSeconds > maxS {
		return 0, invalid("timeout_seconds must be 1..%d (SHELL_MCP_MAX_TIMEOUT)", maxS)
	}
	return time.Duration(*a.TimeoutSeconds) * time.Second, nil
}

// outputLimit is what may be returned per output stream: max_output_bytes
// within SHELL_MCP_MAX_OUTPUT_BYTES, or that maximum.
func (d *Deps) outputLimit(a outputArg) (int, *envelope.Error) {
	limit := d.maxOutput()
	if a.MaxOutputBytes == nil {
		return limit, nil
	}
	if *a.MaxOutputBytes < 1 || *a.MaxOutputBytes > limit {
		return 0, invalid("max_output_bytes must be 1..%d (SHELL_MCP_MAX_OUTPUT_BYTES)", limit)
	}
	return *a.MaxOutputBytes, nil
}

// fetch resolves the target, sends one gate request and decodes the data
// strictly. On success every string in the data and every warning has
// been through the server's redaction (the built-in rules and
// SHELL_MCP_REDACT_PATTERNS): everything there came from the host.
func fetch[T any](ctx context.Context, d *Deps, target, op string, args any, budget time.Duration) envelope.Envelope[T] {
	t, e := d.resolve(target)
	if e != nil {
		return envelope.Failure[T](target, e)
	}
	resp, e := d.call(ctx, t.Name, op, args, budget)
	if e != nil {
		return envelope.Failure[T](t.Name, e)
	}
	env := envelope.FromGate[T](t.Name, resp)
	if env.OK {
		r := d.redactor()
		redactStrings(r, reflect.ValueOf(env.Data))
		for i, w := range env.Warnings {
			env.Warnings[i] = r.String(w)
		}
	}
	return env
}

// redactStrings redacts every settable string reachable from v.
func redactStrings(r *redact.Redactor, v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			redactStrings(r, v.Elem())
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				redactStrings(r, v.Field(i))
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			redactStrings(r, v.Index(i))
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(r.String(v.String()))
		}
	default:
	}
}

// capText cuts *s to at most limit bytes: redacted before the cut and
// again after it (redact.Truncate), and never inside a UTF-8 sequence. It
// reports whether anything was cut.
func capText(r *redact.Redactor, s *string, limit int) bool {
	out, cut := r.Truncate([]byte(*s), limit)
	if cut {
		for len(out) > 0 && !utf8.Valid(out) {
			out = out[:len(out)-1]
		}
	}
	*s = string(out)
	return cut
}

// fitList drops trailing entries of *list until whole (the data that holds
// the list) encodes to at most limit bytes. It reports whether it dropped
// any.
func fitList[E any](whole any, list *[]E, limit int) bool {
	if encodedSize(whole) <= limit {
		return false
	}
	full := *list
	lo, hi := 0, len(full)
	for lo < hi {
		mid := (lo + hi + 1) / 2
		*list = full[:mid]
		if encodedSize(whole) <= limit {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	*list = full[:lo]
	return true
}

func encodedSize(v any) int {
	b, err := stdjson.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// truncated is a summary suffix.
func truncated(cut bool) string {
	if cut {
		return ", truncated"
	}
	return ""
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
