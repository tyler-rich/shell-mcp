// Package gitx parses the output of the fixed git invocations the gate
// runs, and decides which repository-local configuration the gate accepts.
// Formats were checked against git 2.47.3 (Debian 13) and the 2.53
// documentation (Ubuntu 26.04 LTS).
package gitx

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Bounds.
const (
	maxRecords = 1 << 20
	maxField   = 64 << 10
)

var errFormat = errors.New("unexpected git output")

func bad(what string) error { return fmt.Errorf("%s: %w", what, errFormat) }

// Status is `git status --porcelain=v2 --branch -z`.
type Status struct {
	OID      string
	Branch   string
	Upstream string
	Ahead    int
	Behind   int
	Entries  []Entry
}

// Entry is one status entry. Kind is changed, renamed, unmerged, untracked
// or ignored; XY is empty for the last two.
type Entry struct {
	Kind     string `json:"kind"`
	XY       string `json:"xy"`
	Path     string `json:"path"`
	OrigPath string `json:"orig_path,omitempty"`
}

// ParseStatus parses NUL-separated porcelain v2 records. Unknown "# "
// headers are ignored (the format says parsers must); at most maxEntries
// entries are kept and the rest are reported as truncated.
func ParseStatus(b []byte, maxEntries int) (st Status, truncated bool, err error) {
	recs := bytes.Split(bytes.TrimSuffix(b, []byte{0}), []byte{0})
	if len(b) == 0 {
		recs = nil
	}
	if len(recs) > maxRecords {
		return Status{}, false, bad("status: too many records")
	}
	for i := 0; i < len(recs); i++ {
		r := string(recs[i])
		if len(r) > maxField {
			return Status{}, false, bad("status: record too long")
		}
		if h, ok := strings.CutPrefix(r, "# "); ok {
			k, v, _ := strings.Cut(h, " ")
			switch k {
			case "branch.oid":
				if v != "(initial)" {
					st.OID = v
				}
			case "branch.head":
				st.Branch = v
			case "branch.upstream":
				st.Upstream = v
			case "branch.ab":
				a, bh, ok := strings.Cut(v, " ")
				ah, e1 := strconv.Atoi(strings.TrimPrefix(a, "+"))
				bb, e2 := strconv.Atoi(strings.TrimPrefix(bh, "-"))
				if !ok || e1 != nil || e2 != nil || !strings.HasPrefix(a, "+") || !strings.HasPrefix(bh, "-") || ah < 0 || bb < 0 {
					return Status{}, false, bad("status: branch.ab")
				}
				st.Ahead, st.Behind = ah, bb
			}
			continue
		}
		var e Entry
		switch {
		case strings.HasPrefix(r, "1 "):
			f := strings.SplitN(r, " ", 9)
			if len(f) != 9 || len(f[1]) != 2 || f[8] == "" {
				return Status{}, false, bad("status: changed entry")
			}
			e = Entry{Kind: "changed", XY: f[1], Path: f[8]}
		case strings.HasPrefix(r, "2 "):
			f := strings.SplitN(r, " ", 10)
			if len(f) != 10 || len(f[1]) != 2 || f[9] == "" || i+1 >= len(recs) || len(recs[i+1]) == 0 {
				return Status{}, false, bad("status: renamed entry")
			}
			i++
			e = Entry{Kind: "renamed", XY: f[1], Path: f[9], OrigPath: string(recs[i])}
		case strings.HasPrefix(r, "u "):
			f := strings.SplitN(r, " ", 11)
			if len(f) != 11 || len(f[1]) != 2 || f[10] == "" {
				return Status{}, false, bad("status: unmerged entry")
			}
			e = Entry{Kind: "unmerged", XY: f[1], Path: f[10]}
		case strings.HasPrefix(r, "? ") && len(r) > 2:
			e = Entry{Kind: "untracked", Path: r[2:]}
		case strings.HasPrefix(r, "! ") && len(r) > 2:
			e = Entry{Kind: "ignored", Path: r[2:]}
		default:
			return Status{}, false, bad("status: unknown record")
		}
		if len(st.Entries) == maxEntries {
			truncated = true
			continue
		}
		st.Entries = append(st.Entries, e)
	}
	return st, truncated, nil
}

// Commit is one log entry.
type Commit struct {
	Hash    string `json:"hash"`
	Author  string `json:"author"`
	Date    string `json:"date"`
	Subject string `json:"subject"`
}

// LogFormat is the --format the gate passes to git log: four fields
// separated by US (0x1f), records terminated by RS (0x1e).
const LogFormat = "%H%x1f%an%x1f%aI%x1f%s%x1e"

// ParseLog parses records written with LogFormat (git adds a newline after
// each record).
func ParseLog(b []byte) ([]Commit, error) {
	out := []Commit{}
	for _, rec := range strings.Split(string(b), "\x1e") {
		rec = strings.TrimPrefix(rec, "\n")
		if rec == "" || rec == "\n" {
			continue
		}
		f := strings.Split(rec, "\x1f")
		if len(f) != 4 || (len(f[0]) != 40 && len(f[0]) != 64) || strings.Trim(f[0], "0123456789abcdef") != "" {
			return nil, bad("log record")
		}
		if len(out) == maxRecords {
			return nil, bad("log: too many records")
		}
		out = append(out, Commit{Hash: f[0], Author: f[1], Date: f[2], Subject: f[3]})
	}
	return out, nil
}

// Unquote decodes a path as git prints it with core.quotePath: bare, or
// double-quoted with C escapes (\a \b \t \n \v \f \r \" \\ and three-digit
// octal bytes).
func Unquote(s string) (string, error) {
	if !strings.HasPrefix(s, `"`) {
		return s, nil
	}
	if len(s) < 2 || !strings.HasSuffix(s, `"`) {
		return "", bad("quoted path")
	}
	in := s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c == '"' {
			return "", bad("quoted path")
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(in) {
			return "", bad("quoted path")
		}
		switch e := in[i]; e {
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'v':
			b.WriteByte('\v')
		case 'f':
			b.WriteByte('\f')
		case 'r':
			b.WriteByte('\r')
		case '"', '\\':
			b.WriteByte(e)
		case '0', '1', '2', '3':
			if i+2 >= len(in) {
				return "", bad("quoted path")
			}
			v, err := strconv.ParseUint(in[i:i+3], 8, 8)
			if err != nil {
				return "", bad("quoted path")
			}
			b.WriteByte(byte(v))
			i += 2
		default:
			return "", bad("quoted path")
		}
	}
	return b.String(), nil
}

// ParseClean parses `git clean -n -d` (run with LC_ALL=C.UTF-8, so the
// messages are untranslated): "Would remove <path>" and "Would skip
// repository <path>" lines.
func ParseClean(b []byte) (remove, skipped []string, err error) {
	remove, skipped = []string{}, []string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		var dst *[]string
		var p string
		if v, ok := strings.CutPrefix(line, "Would remove "); ok {
			dst, p = &remove, v
		} else if v, ok := strings.CutPrefix(line, "Would skip repository "); ok {
			dst, p = &skipped, v
		} else {
			return nil, nil, bad("clean line")
		}
		u, err := Unquote(p)
		if err != nil || u == "" {
			return nil, nil, bad("clean path")
		}
		if len(remove)+len(skipped) == maxRecords {
			return nil, nil, bad("clean: too many entries")
		}
		*dst = append(*dst, u)
	}
	return remove, skipped, nil
}

// KV is one configuration entry, as `git config --list -z` prints it:
// section and variable names lowercased, subsections verbatim. HasValue
// is false for a key written without "=" (git's implicit true).
type KV struct {
	Key      string
	Value    string
	HasValue bool
}

// ParseConfig parses `git config --list -z`: "key\nvalue\0" entries, or
// "key\0" for a key without a value.
func ParseConfig(b []byte) ([]KV, error) {
	if len(b) == 0 {
		return nil, nil
	}
	if b[len(b)-1] != 0 {
		return nil, bad("config: missing terminator")
	}
	var out []KV
	for _, e := range bytes.Split(b[:len(b)-1], []byte{0}) {
		k, v, has := bytes.Cut(e, []byte{'\n'})
		if len(k) == 0 || !utf8.Valid(k) {
			return nil, bad("config key")
		}
		if len(out) == maxRecords {
			return nil, bad("config: too many entries")
		}
		out = append(out, KV{Key: string(k), Value: string(v), HasValue: has})
	}
	return out, nil
}

// The repository-local configuration the gate accepts (POLICY §7): keys
// that git uses only as data for the gate's fixed commands, each with the
// values git itself accepts for it. Verified against git 2.47.3 and 2.55.0
// (documentation and source). None of these keys can name a program, a
// path git executes or reads configuration from, a URL, a proxy,
// credentials, an include, a filter, a hook, an editor, a pager, a signing
// program, or another git directory or work tree. Everything else —
// filters (so Git LFS), textconv and external diff drivers, url.*.insteadOf,
// include and includeIf, core.askPass/editor/pager/worktree, http.*,
// credential.*, gpg.*, other remotes, extensions, maintenance.*, gc.* other
// than gc.auto — is refused. Values are checked because a malformed value
// can crash git (a valueless remote.<name>.tagOpt segfaults) or make it die
// part-way through an operation (gc.auto after a fast-forward in 2.55).

// valueRule checks one entry's value.
type valueRule func(kv *KV) bool

func isBool(kv *KV) bool {
	if !kv.HasValue {
		return true // "key" alone is true
	}
	switch strings.ToLower(kv.Value) {
	case "", "true", "false", "yes", "no", "on", "off":
		return true
	}
	_, err := strconv.Atoi(kv.Value)
	return err == nil
}

func boolOr(words ...string) valueRule {
	return func(kv *KV) bool {
		return isBool(kv) || (kv.HasValue && slices.Contains(words, strings.ToLower(kv.Value)))
	}
}

func oneOf(words ...string) valueRule {
	return func(kv *KV) bool { return kv.HasValue && slices.Contains(words, kv.Value) }
}

func hasValue(kv *KV) bool { return kv.HasValue }

func isInt(kv *KV) bool {
	_, err := strconv.Atoi(kv.Value)
	return kv.HasValue && err == nil
}

// gcAutoRE is git_config_int's syntax: a decimal with an optional k/m/g
// unit.
var gcAutoRE = regexp.MustCompile(`^-?\d{1,18}[kKmMgG]?$`)

func isGCAuto(kv *KV) bool { return kv.HasValue && gcAutoRE.MatchString(kv.Value) }

// colorBool is git_config_colorbool: never, always, auto or a boolean.
func colorBool(kv *KV) bool { return boolOr("never", "always", "auto")(kv) }

// colorWords are the names and attributes git's color_parse accepts.
var colorWords = map[string]bool{
	"normal": true, "default": true, "reset": true,
	"black": true, "red": true, "green": true, "yellow": true, "blue": true, "magenta": true, "cyan": true, "white": true,
	"bold": true, "dim": true, "ul": true, "blink": true, "reverse": true, "italic": true, "strike": true,
}

var hexColorRE = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// colorSpec is a conservative subset of git's color_parse: at most eight
// whitespace-separated words, each a color name (optionally "bright"), a
// 0..255 number, #rgb/#rrggbb, or an attribute (optionally "no"/"no-").
func colorSpec(kv *KV) bool {
	if !kv.HasValue {
		return false // color_parse needs a value
	}
	words := strings.Fields(strings.ToLower(kv.Value))
	if len(words) > 8 {
		return false
	}
	for _, w := range words {
		if n, err := strconv.Atoi(w); err == nil {
			if n < -1 || n > 255 {
				return false
			}
			continue
		}
		base := strings.TrimPrefix(w, "bright")
		attr := strings.TrimPrefix(strings.TrimPrefix(w, "no-"), "no")
		if !colorWords[w] && !colorWords[base] && !colorWords[attr] && !hexColorRE.MatchString(w) {
			return false
		}
	}
	return true
}

// exactRules are keys allowed by exact name.
var exactRules = map[string]valueRule{
	// Written by git init/clone.
	"core.repositoryformatversion": isInt,
	"core.filemode":                isBool,
	"core.bare":                    isBool,
	"core.logallrefupdates":        boolOr("always"),
	"core.ignorecase":              isBool,
	"core.precomposeunicode":       isBool,
	"core.symlinks":                isBool,
	"remote.origin.url":            hasValue,
	"remote.origin.fetch":          hasValue,
	// Identity: used only as the reflog ident; the gate never commits.
	"user.name":  hasValue,
	"user.email": hasValue,
	// Line endings: built-in conversions of file content, no program.
	"core.autocrlf": boolOr("input"),
	"core.eol":      oneOf("lf", "crlf", "native"),
	"core.safecrlf": boolOr("warn"),
	// Pull strategy: the gate's `pull --ff-only --no-rebase` overrides both
	// (git never reads them for that command line).
	"pull.rebase": boolOr("merges", "m", "interactive", "i"),
	"pull.ff":     boolOr("only"),
	// Read only by init/clone and `remote show`.
	"init.defaultbranch": hasValue,
	// Pruning deletes stale remote-tracking refs only.
	"fetch.prune":         isBool,
	"remote.origin.prune": isBool,
	// Only these two strings do anything; a valueless tagOpt crashes git.
	"remote.origin.tagopt": oneOf("--tags", "--no-tags"),
	// Auto-gc threshold (a number); gc.autoDetach and maintenance.* stay out.
	"gc.auto": isGCAuto,
}

// ruleFor returns the rule for key, or nil when the key is not allowed.
func ruleFor(key string) valueRule {
	if r, ok := exactRules[key]; ok {
		return r
	}
	first, last := strings.IndexByte(key, '.'), strings.LastIndexByte(key, '.')
	if first < 0 {
		return nil
	}
	section, sub, name := key[:first], "", key[last+1:]
	if last > first {
		sub = key[first+1 : last]
	}
	switch section {
	case "branch":
		// branch.<name>.remote/merge/rebase; rebase is overridden like
		// pull.rebase.
		if sub == "" {
			return nil
		}
		switch name {
		case "remote", "merge":
			return hasValue
		case "rebase":
			return boolOr("merges", "m", "interactive", "i")
		}
	case "advice":
		// Every advice.* key is a boolean hint switch (output on stderr).
		if sub == "" {
			return isBool
		}
	case "color":
		// color.<cmd> is a color boolean, color.<cmd>.<slot> a color.
		// color.blame.* is left out: blame is never run and
		// highlightRecent is a list of colors and dates.
		switch {
		case sub == "" && name != "blame":
			return colorBool
		case sub != "" && sub != "blame" && !strings.Contains(sub, "."):
			return colorSpec
		}
	}
	return nil
}

// CheckConfig returns the first key that is not allowed or whose value git
// would not accept, or ok.
func CheckConfig(kvs []KV) (badKey string, ok bool) {
	for i := range kvs {
		r := ruleFor(kvs[i].Key)
		if r == nil || !r(&kvs[i]) {
			return kvs[i].Key, false
		}
	}
	return "", true
}

// Value returns the last value of key (git's "last one wins").
func Value(kvs []KV, key string) (string, bool) {
	v, ok := "", false
	for _, kv := range kvs {
		if kv.Key == key {
			v, ok = kv.Value, true
		}
	}
	return v, ok
}

// RemovalHint returns the git command an operator runs in the repository
// to remove a refused key: the whole "section.subsection" for a key with a
// subsection (a filter, diff or merge driver, a url rewrite, another
// remote), otherwise every value of the key.
func RemovalHint(key string) string {
	first, last := strings.IndexByte(key, '.'), strings.LastIndexByte(key, '.')
	if first > 0 && last > first {
		return "git config --remove-section " + key[:last]
	}
	return "git config --unset-all " + key
}
