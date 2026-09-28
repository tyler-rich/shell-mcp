// Package gitx parses the output of the fixed git invocations the gate
// runs, and decides which repository-local configuration the gate accepts.
// Formats were checked against git 2.47.3 (Debian 13) and the 2.53
// documentation (Ubuntu 26.04 LTS).
package gitx

import (
	"bytes"
	"errors"
	"fmt"
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
// section and variable names lowercased, subsections verbatim.
type KV struct {
	Key   string
	Value string
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
		k, v, _ := bytes.Cut(e, []byte{'\n'})
		if len(k) == 0 || !utf8.Valid(k) {
			return nil, bad("config key")
		}
		if len(out) == maxRecords {
			return nil, bad("config: too many entries")
		}
		out = append(out, KV{Key: string(k), Value: string(v)})
	}
	return out, nil
}

// allowedKeys are the repository-local keys the gate accepts: the inert
// ones `git init` and `git clone` write. Everything else — filters,
// textconv and external diff drivers, url.*.insteadOf, include and
// includeIf, core.askPass, core.worktree, http.*, credential.*, other
// remotes, extensions — is refused, because repository-local configuration
// can make git run commands or talk to another host.
var allowedKeys = map[string]bool{
	"core.repositoryformatversion": true, "core.filemode": true, "core.bare": true, "core.logallrefupdates": true,
	"core.ignorecase": true, "core.precomposeunicode": true, "core.symlinks": true,
	"remote.origin.url": true, "remote.origin.fetch": true,
}

// CheckConfig returns the first key outside the allowlist, or ok.
// branch.<name>.remote and branch.<name>.merge are allowed for any
// non-empty branch name.
func CheckConfig(kvs []KV) (badKey string, ok bool) {
	for _, kv := range kvs {
		k := kv.Key
		if allowedKeys[k] {
			continue
		}
		if rest, found := strings.CutPrefix(k, "branch."); found {
			if name, found := strings.CutSuffix(rest, ".remote"); found && name != "" {
				continue
			}
			if name, found := strings.CutSuffix(rest, ".merge"); found && name != "" {
				continue
			}
		}
		return k, false
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
