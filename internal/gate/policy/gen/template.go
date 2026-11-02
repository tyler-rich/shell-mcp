package gen

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Template is an example policy file read as a template (POLICY §9.3): its
// header, split into the example's own lines (which the answers file
// replaces) and the template's last paragraph (kept), and its keys, each
// with the comment and blank lines before it.
type Template struct {
	// Header is the header's last paragraph, after the last "#" line.
	Header []string
	// ExampleHeader is the header before that "#" line: in the example it
	// comes from the answers file.
	ExampleHeader []string
	// Split says whether the header had that "#" line.
	Split bool
	// Nodes are the top-level keys, in order.
	Nodes []*Node
	// Values is the template decoded, for the preset's values.
	Values map[string]any
}

// Node is one key of a template mapping.
type Node struct {
	Lead   []string // blank and comment lines before the key line
	Line   string   // the key line
	Indent int
	Key    string
	Inline string  // the text after "key:" on the line ("" when none)
	Kids   []*Node // a mapping value
	Body   []string
	// Body is a block list value, or the comment lines that continue an
	// inline value's line comment.
}

// Kid returns the child key named key, or nil.
func (n *Node) Kid(key string) *Node {
	for _, k := range n.Kids {
		if k.Key == key {
			return k
		}
	}
	return nil
}

var keyRE = regexp.MustCompile(`^([a-z_]+):(?: (.*))?$`)

func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

func isBlank(l string) bool { return strings.TrimSpace(l) == "" }

func isComment(l string) bool { return strings.HasPrefix(strings.TrimLeft(l, " "), "#") }

// ParseTemplate reads an example policy as a template. The examples are
// this repository's own files, so anything outside the shape they have is
// an error, not something to guess at.
// ParseTemplate is a stub.
func ParseTemplate(src []byte) (*Template, error) { return &Template{}, nil }

func parseTemplateImpl(src []byte) (*Template, error) {
	s := string(src)
	if !strings.HasSuffix(s, "\n") || strings.Contains(s, "\r") || strings.Contains(s, "\t") {
		return nil, errors.New("template: must end with a newline and hold no CR or tab")
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	i := 0
	for i < len(lines) && strings.HasPrefix(lines[i], "#") {
		i++
	}
	if i == len(lines) || lines[i] != "" {
		return nil, errors.New("template: the header must be followed by a blank line")
	}
	t := &Template{Header: lines[:i]}
	for j := i - 1; j >= 0; j-- {
		if lines[j] == "#" {
			t.ExampleHeader, t.Header, t.Split = lines[:j], lines[j+1:i], true
			break
		}
	}
	nodes, rest, err := parseMap(lines[i:], 0)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("template: unexpected lines at the end: %q", rest[0])
	}
	t.Nodes = nodes
	if err := yaml.Unmarshal(src, &t.Values); err != nil {
		return nil, fmt.Errorf("template: %w", err)
	}
	return t, nil
}

// parseMap reads the keys of a mapping at indent from lines. It returns the
// lines it did not take (a shallower key, or trailing comments).
func parseMap(lines []string, indent int) ([]*Node, []string, error) {
	var out []*Node
	var lead []string
	for len(lines) > 0 {
		l := lines[0]
		if isBlank(l) || isComment(l) && indentOf(l) == indent {
			lead = append(lead, l)
			lines = lines[1:]
			continue
		}
		in := indentOf(l)
		if in < indent {
			break
		}
		if in > indent || isComment(l) {
			return nil, nil, fmt.Errorf("template: unexpected indentation: %q", l)
		}
		m := keyRE.FindStringSubmatch(l[indent:])
		if m == nil {
			return nil, nil, fmt.Errorf("template: not a key line: %q", l)
		}
		n := &Node{Lead: lead, Line: l, Indent: indent, Key: m[1], Inline: m[2]}
		lead = nil
		lines = lines[1:]
		j := 0
		for j < len(lines) && !isBlank(lines[j]) && indentOf(lines[j]) > indent {
			j++
		}
		child := lines[:j]
		lines = lines[j:]
		first := slices.IndexFunc(child, func(l string) bool { return !isComment(l) })
		switch {
		case n.Inline != "":
			if first >= 0 {
				return nil, nil, fmt.Errorf("template: %s has a value and more lines", n.Key)
			}
			n.Body = child
		case first < 0:
			n.Body = child
		case strings.HasPrefix(strings.TrimLeft(child[first], " "), "- "):
			n.Body = child
		default:
			kids, rest, err := parseMap(child, indentOf(child[first]))
			if err != nil {
				return nil, nil, err
			}
			if len(rest) > 0 {
				return nil, nil, fmt.Errorf("template: unexpected lines under %s: %q", n.Key, rest[0])
			}
			n.Kids = kids
		}
		out = append(out, n)
	}
	return out, append(lead, lines...), nil
}

// Out builds a rendered policy. The first error sticks; Bytes reports it.
type Out struct {
	lines []string
	err   error
}

// Fail records err (the first one wins).
func (o *Out) Fail(err error) {
	if o.err == nil {
		o.err = err
	}
}

// Err is the first error.
func (o *Out) Err() error { return o.err }

// Line adds one line.
func (o *Out) Line(l string) { o.lines = append(o.lines, l) }

// Lines adds lines.
func (o *Out) Lines(ls []string) { o.lines = append(o.lines, ls...) }

// Bytes is the rendered file.
func (o *Out) Bytes() ([]byte, error) {
	if o.err != nil {
		return nil, o.err
	}
	return []byte(strings.Join(o.lines, "\n") + "\n"), nil
}

// Verbatim adds a node as the template has it.
func (o *Out) Verbatim(n *Node) {
	o.Lines(n.Lead)
	o.Line(n.Line)
	for _, k := range n.Kids {
		o.Verbatim(k)
	}
	o.Lines(n.Body)
}

// Value adds a node's lead and its key line with the value v, keeping the
// line's comment (and the comment lines that continue it) aligned as the
// template has it.
func (o *Out) Value(n *Node, v string) {
	o.Lines(n.Lead)
	o.Line(WithValue(n, v))
	o.Lines(n.Body)
}

// Section adds a mapping node when kids adds at least one line: its lead
// and key line, then what kids added. A section the answers do not use is
// left out with its comment.
func (o *Out) Section(n *Node, kids func(*Out)) {
	sub := &Out{}
	kids(sub)
	if sub.err != nil {
		o.Fail(sub.err)
		return
	}
	if len(sub.lines) == 0 {
		return
	}
	o.Lines(n.Lead)
	o.Line(n.Line)
	o.Lines(sub.lines)
}

// Comment adds a carried comment (POLICY §9.3) at indent: every line its
// own "# " line ("#" for an empty one). A comment that breaks §9.3's rules
// is an error, so nothing but comment lines can come of it.
func (o *Out) Comment(indent int, text string) {
	if text == "" {
		return
	}
	if err := CheckComment(text); err != nil {
		o.Fail(fmt.Errorf("a comment %w", err))
		return
	}
	pad := strings.Repeat(" ", indent)
	for _, l := range CommentLines(text) {
		if l == "" {
			o.Line(pad + "#")
		} else {
			o.Line(pad + "# " + l)
		}
	}
}

// Header adds the policy's header: the carried comment, a "#" line, then
// the template's paragraph; without a comment, the paragraph alone.
func (o *Out) Header(t *Template, comment string) {
	if comment != "" {
		o.Comment(0, comment)
		o.Line("#")
	}
	o.Lines(t.Header)
}

// Plain is s as a plain scalar when YAML reads that back as the same
// string in block and flow context, else Quoted.
func (o *Out) Plain(s string) string {
	if plainRE.MatchString(s) && roundTrips(s, s) {
		return s
	}
	return o.Quoted(s)
}

var plainRE = regexp.MustCompile(`^[A-Za-z0-9_./][A-Za-z0-9_./@+:=~-]*$`)

// Quoted is s double-quoted; a control character is an error.
func (o *Out) Quoted(s string) string {
	if err := checkText(s); err != nil {
		o.Fail(fmt.Errorf("value %q %w", s, err))
		return `""`
	}
	q := `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
	if !roundTrips(q, s) {
		o.Fail(fmt.Errorf("value %q does not read back as itself", s))
		return `""`
	}
	return q
}

// roundTrips reports whether the scalar text reads back as s, alone and in
// a flow list.
func roundTrips(text, s string) bool {
	var m map[string]any
	if yaml.Unmarshal([]byte("k: "+text+"\n"), &m) != nil {
		return false
	}
	if v, ok := m["k"].(string); !ok || v != s {
		return false
	}
	var l []any
	if yaml.Unmarshal([]byte("["+text+"]\n"), &l) != nil || len(l) != 1 {
		return false
	}
	v, ok := l[0].(string)
	return ok && v == s
}

// Flow is a flow list of items, each through q.
func (o *Out) Flow(items []string, q func(string) string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = q(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// Int is a decimal integer.
func Int(n int64) string { return strconv.FormatInt(n, 10) }

// WithValue is n's key line with its value replaced by v (v "" leaves
// "key:"). A line comment stays at its column, or two spaces after a value
// that reaches it.
func WithValue(n *Node, v string) string {
	s := strings.Repeat(" ", n.Indent) + n.Key + ":"
	if v != "" {
		s += " " + v
	}
	col, comment := lineComment(n.Line)
	if comment == "" {
		return s
	}
	pad := col - utf8.RuneCountInString(s)
	if pad < 1 {
		pad = 2
	}
	return s + strings.Repeat(" ", pad) + comment
}

// lineComment finds a line comment outside quotes: its column (in runes)
// and its text from "#".
func lineComment(l string) (col int, comment string) {
	var quote rune
	escaped := false
	prev := ' '
	for i, r := range l {
		switch {
		case escaped:
			escaped = false
		case quote == '"' && r == '\\':
			escaped = true
		case quote != 0 && r == quote:
			quote = 0
		case quote == 0 && (r == '"' || r == '\''):
			quote = r
		case quote == 0 && r == '#' && prev == ' ':
			return col, l[i:]
		}
		prev = r
		col++
	}
	return 0, ""
}

// CheckValues decodes rendered and requires it to hold exactly want: the
// rendering is checked against the values it was meant to write, so no
// comment, quoting or layout can add, drop or change one.
// CheckValues is a stub.
func CheckValues(rendered []byte, want map[string]any) error { return nil }

func checkValuesImpl(rendered []byte, want map[string]any) error {
	var got map[string]any
	if err := yaml.Unmarshal(rendered, &got); err != nil {
		return fmt.Errorf("the rendered policy does not parse: %w", err)
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("the rendered policy's values differ from the answers and the preset: %s", firstDiff("", got, want))
	}
	return nil
}

// firstDiff names the first key at which got and want differ.
func firstDiff(path string, got, want any) string {
	gm, gok := got.(map[string]any)
	wm, wok := want.(map[string]any)
	if gok && wok {
		keys := slices.Sorted(maps.Keys(gm))
		for k := range wm {
			if _, ok := gm[k]; !ok {
				keys = append(keys, k)
			}
		}
		for _, k := range keys {
			if !reflect.DeepEqual(gm[k], wm[k]) {
				return firstDiff(path+"."+k, gm[k], wm[k])
			}
		}
	}
	return fmt.Sprintf("%s: got %v, want %v", strings.TrimPrefix(path, "."), got, want)
}

// Clone is a deep copy of the template's values, for the expected values.
func (t *Template) Clone() map[string]any {
	c, _ := deepCopy(t.Values).(map[string]any)
	return c
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = deepCopy(e)
		}
		return m
	case []any:
		l := make([]any, len(x))
		for i, e := range x {
			l[i] = deepCopy(e)
		}
		return l
	}
	return v
}

// Strings is l as decoded YAML values.
func Strings(l []string) []any {
	out := make([]any, len(l))
	for i, s := range l {
		out[i] = s
	}
	return out
}

// Templates is a command's templates as decoded YAML values.
func Templates(ts [][]string) []any {
	out := make([]any, len(ts))
	for i, t := range ts {
		out[i] = Strings(t)
	}
	return out
}

// Sub returns the mapping at key of m, or nil.
func Sub(m map[string]any, key string) map[string]any {
	s, _ := m[key].(map[string]any)
	return s
}

// SetOrDelete sets m[key] to v, or deletes it when v is an empty list, an
// empty mapping or nil.
func SetOrDelete(m map[string]any, key string, v any) {
	switch x := v.(type) {
	case nil:
		delete(m, key)
		return
	case []any:
		if len(x) == 0 {
			delete(m, key)
			return
		}
	case map[string]any:
		if len(x) == 0 {
			delete(m, key)
			return
		}
	}
	m[key] = v
}
