// Command doccheck checks that every relative link, anchor and section
// reference in the live documents resolves: the S5b read-through, scripted
// (handoff §4.H). Run from the repository's root:
//
//	go run ./scripts/doccheck
//
// A link's file must exist, and its anchor must be one of GitHub's heading
// slugs in that file. A section reference "§N" must be a numbered heading
// of the document it names: the name before it (POLICY, docs/POLICY.md, a
// link to it), the one before a list's first reference ("§3 and §7"), or
// else the document it is in. Code blocks and code spans are not checked,
// nor the history (ARCHIVE, CHANGELOG, the handoffs), whose references are
// to what the documents said then.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// docs are the live documents.
var docs = []string{
	"README.md", "deploy/README.md", "deploy/caddy/README.md",
	"docs/ARCHITECTURE.md", "docs/CLIENTS.md", "docs/POLICY.md", "docs/PRIVILEGED.md",
	"docs/SECURITY.md", "docs/TARGET-SETUP.md", "docs/TOOLS.md",
}

// named are the documents a reference can name, by the name the documents
// use for them.
var named = map[string]string{
	"ARCHITECTURE": "docs/ARCHITECTURE.md", "CLIENTS": "docs/CLIENTS.md", "POLICY": "docs/POLICY.md",
	"PRIVILEGED": "docs/PRIVILEGED.md", "SECURITY": "docs/SECURITY.md", "TARGET-SETUP": "docs/TARGET-SETUP.md",
	"TOOLS": "docs/TOOLS.md", "ARCHIVE": "docs/ARCHIVE.md", "plan": "plan.md",
}

// unchecked are names whose sections are not checked (another document's
// numbering than the one named, or a document chosen by context).
var unchecked = map[string]bool{"handoff": true}

func main() {
	problems, err := check(os.DirFS("."), docs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "doccheck:", err)
		os.Exit(1)
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "doccheck: %d link(s) or reference(s) do not resolve\n", len(problems))
		os.Exit(1)
	}
	fmt.Printf("doccheck: every link, anchor and section reference in %d documents resolves\n", len(docs))
}

// doc is a document's prose lines (code removed) and what links can reach.
type doc struct {
	lines    []string
	slugs    map[string]bool
	sections map[string]bool
}

var (
	headingRE    = regexp.MustCompile(`^(#{1,6})\s+(.*?)\s*#*\s*$`)
	headingNumRE = regexp.MustCompile(`^§?(\d+[a-z]?(?:\.\d+)*)(?:[.\s]|$)`)
	fenceRE      = regexp.MustCompile("^\\s*(```|~~~)")
	codeRE       = regexp.MustCompile("`[^`]*`")
	linkRE       = regexp.MustCompile(`!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)
)

func load(fsys fs.FS, p string, cache map[string]*doc) (*doc, error) {
	if d, ok := cache[p]; ok {
		return d, nil
	}
	b, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	d := &doc{slugs: map[string]bool{}, sections: map[string]bool{}}
	seen := map[string]int{}
	fenced := false
	for _, line := range strings.Split(string(b), "\n") {
		if fenceRE.MatchString(line) {
			fenced = !fenced
			d.lines = append(d.lines, "")
			continue
		}
		if fenced {
			d.lines = append(d.lines, "")
			continue
		}
		d.lines = append(d.lines, line)
		m := headingRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		s := slug(m[2])
		if n := seen[s]; n > 0 {
			d.slugs[fmt.Sprintf("%s-%d", s, n)] = true
		} else {
			d.slugs[s] = true
		}
		seen[s]++
		if sm := headingNumRE.FindStringSubmatch(m[2]); sm != nil {
			d.sections[sm[1]] = true
		}
	}
	cache[p] = d
	return d, nil
}

// check returns one line per link, anchor or section reference in paths
// that does not resolve.
func check(fsys fs.FS, paths []string) ([]string, error) {
	cache := map[string]*doc{}
	var problems []string
	for _, p := range paths {
		d, err := load(fsys, p, cache)
		if err != nil {
			return nil, err
		}
		for i, line := range d.lines {
			at := fmt.Sprintf("%s:%d: ", p, i+1)
			prose := codeRE.ReplaceAllStringFunc(line, func(s string) string { return strings.Repeat(" ", len(s)) })
			for _, m := range linkRE.FindAllStringSubmatch(prose, -1) {
				if msg := checkLink(fsys, p, m[1], d, cache); msg != "" {
					problems = append(problems, at+msg)
				}
			}
			for _, r := range refs(line) {
				target := p
				if r.doc != "" {
					target = named[r.doc]
				}
				td, err := load(fsys, target, cache)
				name := r.doc
				if name != "" {
					name += " "
				}
				switch {
				case errors.Is(err, fs.ErrNotExist):
					problems = append(problems, at+name+"§"+r.section+": "+target+" does not exist")
				case err != nil:
					return nil, err
				case !td.sections[r.section]:
					problems = append(problems, at+name+"§"+r.section+": no such section in "+target)
				}
			}
		}
	}
	return problems, nil
}

func checkLink(fsys fs.FS, from, target string, d *doc, cache map[string]*doc) string {
	if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
		return ""
	}
	file, anchor, _ := strings.Cut(target, "#")
	td := d
	if file != "" {
		p := path.Clean(path.Join(path.Dir(from), file))
		if _, err := fs.Stat(fsys, strings.TrimSuffix(p, "/")); err != nil {
			return target + ": no such file"
		}
		if anchor == "" {
			return ""
		}
		if !strings.HasSuffix(p, ".md") {
			return target + ": an anchor in a file that is not Markdown"
		}
		var err error
		if td, err = load(fsys, p, cache); err != nil {
			return target + ": " + err.Error()
		}
	}
	if anchor != "" && !td.slugs[anchor] {
		return target + ": no heading with that anchor"
	}
	return ""
}

// slug is GitHub's anchor for a heading: lower case, everything but
// letters, digits, spaces, hyphens and underscores removed, spaces made
// hyphens.
func slug(h string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(h) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return strings.ToLower(b.String())
}

// ref is one section reference: the document it names ("" for the one it
// is in) and the section number.
type ref struct {
	doc     string
	section string
}

var (
	refRE      = regexp.MustCompile(`§(\d+[a-z]?(?:\.\d+)*)`)
	linkEndRE  = regexp.MustCompile(`\]\(([^)\s]+)\)$`)
	lastWordRE = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_./-]*)$`)
	listRE     = regexp.MustCompile(`(,|\band|\bor|/|–)$`)
)

// refs returns the section references of one line of prose.
func refs(line string) []ref {
	var out []ref
	prev, prevEnd, prevSkip := "", -1, false
	for _, m := range refRE.FindAllStringSubmatchIndex(line, -1) {
		before := strings.TrimRight(strings.ReplaceAll(line[:m[0]], "`", ""), " \t")
		name, known, other := "", false, false
		switch {
		case linkEndRE.MatchString(before):
			// A link to anything but a named document is another document.
			name, known = docName(linkEndRE.FindStringSubmatch(before)[1])
			other = !known
		case lastWordRE.MatchString(before):
			name, known = docName(lastWordRE.FindStringSubmatch(before)[1])
			other = !known && name != ""
		}
		switch {
		case other:
			// Another document's numbering ("handoff", Debian Policy, a path):
			// not checked, and neither is a list that continues it.
			prev, prevEnd, prevSkip = "", m[1], true
			continue
		case known:
		case prevEnd >= 0 && listRE.MatchString(strings.TrimRight(strings.TrimSuffix(before, "("), " ")) &&
			!strings.ContainsAny(line[prevEnd:m[0]], ";.:"):
			if prevSkip {
				prevEnd = m[1]
				continue
			}
			name = prev
		}
		out = append(out, ref{doc: name, section: line[m[2]:m[3]]})
		prev, prevEnd, prevSkip = name, m[1], false
	}
	return out
}

// docName is the document a word or a link target names: its base name
// without .md, when it is one of the named documents. Another document (a
// path, a capitalised name such as Debian Policy, "handoff") is returned
// unknown with its name, not checked; any other word unknown and empty.
func docName(w string) (string, bool) {
	w, _, _ = strings.Cut(w, "#")
	base := strings.TrimSuffix(path.Base(w), ".md")
	if _, ok := named[base]; ok {
		return base, true
	}
	first, _ := utf8.DecodeRuneInString(base)
	if unchecked[base] || strings.Contains(w, "/") || strings.HasSuffix(w, ".md") || unicode.IsUpper(first) {
		return base, false
	}
	return "", false
}
