package main

// The command check (-commands <dir>): every command line of README's quick
// start and of CLIENTS §3.2's recipe that runs shell-mcp, shell-mcp-gate or
// shell-mcp-privd names a subcommand that exists and only flags that its
// real --help shows, using the binaries in <dir> (the ones the gate built).
// Placeholders (<…>) stay as written: they are neither subcommands nor
// flags.
//
// A command runs a binary when the binary is its first word (a path or a
// bare name), when it is `docker run … <image> …` with the image the docs
// name ("$IMAGE" or ghcr.io/tyler-rich/shell-mcp…, whose entrypoint is
// shell-mcp), or `docker exec …`/`docker compose exec …` with an absolute
// path to a binary. Its subcommand is the words after the binary up to the
// first flag or placeholder; each must exist (--help exits 0) and be named
// in the binary's or its parent's --help, since a parent that sees --help
// prints its own usage for an unknown word. Code blocks are read whole,
// prose through its code spans. A code block of flags alone (the flags a
// step adds to the previous command) is checked against the section's
// previous code-block command; a code span of flags alone, against every
// command of the section.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// commandSections are where the commands are: a file and the heading that
// opens the section (it ends at the next heading of the same or a higher
// level).
var commandSections = []struct{ file, heading string }{
	{"README.md", "## Quick start"},
	{"docs/CLIENTS.md", "### 3.2 Setting it up"},
}

// binaries are the programs whose commands are checked.
var binaries = map[string]bool{"shell-mcp": true, "shell-mcp-gate": true, "shell-mcp-privd": true}

// helpFunc runs bin with args and returns its combined output and exit code.
type helpFunc func(bin string, args []string) (string, int, error)

// runBinaries returns a helpFunc that runs the binaries in dir.
func runBinaries(dir string) helpFunc {
	return func(bin string, args []string) (string, int, error) {
		if !binaries[bin] {
			return "", 0, fmt.Errorf("not a checked binary: %s", bin)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// bin is one of the three names above, joined to the directory the
		// caller gave: an absolute or relative path, never a PATH lookup.
		cmd := exec.CommandContext(ctx, filepath.Join(dir, bin), args...) //nolint:gosec // G204: a fixed binary name, and argv only (no shell)
		cmd.Env = []string{"LC_ALL=C"}
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), ee.ExitCode(), nil
		}
		if err != nil {
			return "", 0, fmt.Errorf("%s: %w", bin, err)
		}
		return string(out), 0, nil
	}
}

// command is one command line: its words and where it starts.
type command struct {
	at    string
	text  string
	words []string
}

// invocation is a command that runs a checked binary.
type invocation struct {
	command
	bin   string
	sub   []string
	flags []string
}

var (
	spanRE = regexp.MustCompile("`([^`]+)`")
	fdRE   = regexp.MustCompile(`^(\d+|&)$`)
)

// sectionLines returns the lines of the section opened by heading in b,
// and the 1-based line number of its first line.
func sectionLines(b []byte, heading string) (section []string, first int, err error) {
	lines := strings.Split(string(b), "\n")
	level := len(heading) - len(strings.TrimLeft(heading, "#"))
	for i, l := range lines {
		if strings.TrimRight(l, " \r") != heading && !strings.HasPrefix(l, heading+" ") {
			continue
		}
		end := len(lines)
		fenced := false
		for j := i + 1; j < len(lines); j++ {
			if fenceRE.MatchString(lines[j]) {
				fenced = !fenced
				continue
			}
			if m := headingRE.FindStringSubmatch(lines[j]); !fenced && m != nil && len(m[1]) <= level {
				end = j
				break
			}
		}
		return lines[i:end], i + 1, nil
	}
	return nil, 0, fmt.Errorf("no heading %q", heading)
}

// sectionCommands splits a section into the commands of its code blocks and
// of its prose's code spans. A block is a flag continuation when its first
// word is a flag; a span is a fragment when its first word is a flag.
type piece struct {
	command
	block    bool
	fragment bool
}

func sectionCommands(file string, lines []string, first int) []piece {
	var out []piece
	fenced := false
	var cur []string
	start := 0
	flush := func() {
		joined := []string{}
		lineAt := []int{}
		buf := ""
		bufAt := 0
		for k, l := range cur {
			t := strings.TrimSpace(l)
			if buf == "" {
				bufAt = start + k
			}
			if strings.HasSuffix(t, `\`) {
				buf += strings.TrimSpace(strings.TrimSuffix(t, `\`)) + " "
				continue
			}
			buf += t
			joined = append(joined, buf)
			lineAt = append(lineAt, bufAt)
			buf = ""
		}
		if buf != "" {
			joined = append(joined, buf)
			lineAt = append(lineAt, bufAt)
		}
		for k, j := range joined {
			for _, words := range splitCommands(j) {
				if len(words) == 0 {
					continue
				}
				out = append(out, piece{command: command{at: fmt.Sprintf("%s:%d", file, lineAt[k]), text: j, words: words},
					block: true, fragment: strings.HasPrefix(words[0], "-")})
			}
		}
		cur = nil
	}
	for i, l := range lines {
		if fenceRE.MatchString(l) {
			if fenced {
				flush()
			}
			fenced = !fenced
			start = first + i + 1
			continue
		}
		if fenced {
			cur = append(cur, l)
			continue
		}
		for _, m := range spanRE.FindAllStringSubmatch(l, -1) {
			for _, words := range splitCommands(m[1]) {
				if len(words) == 0 {
					continue
				}
				out = append(out, piece{command: command{at: fmt.Sprintf("%s:%d", file, first+i), text: m[1], words: words},
					fragment: strings.HasPrefix(words[0], "--")})
			}
		}
	}
	return out
}

// splitCommands splits a shell line into its commands' words: quotes
// removed, a placeholder <…> kept as part of its word (spaces and all),
// a comment dropped, a redirection and its target dropped, and a new
// command after |, ||, && and ;.
func splitCommands(s string) [][]string {
	var cmds [][]string
	var words []string
	var w strings.Builder
	inWord := false
	skipNext := false
	end := func() {
		if inWord {
			if skipNext {
				skipNext = false
			} else {
				words = append(words, w.String())
			}
		}
		w.Reset()
		inWord = false
	}
	next := func() {
		end()
		cmds = append(cmds, words)
		words = nil
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				j = len(s) - i - 1
			}
			w.WriteString(s[i+1 : i+1+j])
			inWord = true
			i += j + 1
		case c == '"':
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.ContainsRune(`"\$`+"`", rune(s[i+1])) {
					i++
				}
				w.WriteByte(s[i])
			}
			inWord = true
		case c == '\\' && i+1 < len(s):
			i++
			w.WriteByte(s[i])
			inWord = true
		case c == '<':
			j := strings.IndexByte(s[i:], '>')
			if j < 0 {
				j = len(s) - i - 1
			}
			w.WriteString(s[i : i+j+1])
			inWord = true
			i += j
		case c == '>':
			// A redirection: drop a file descriptor number or & before it,
			// then its target (&N here, or the next word).
			if inWord && fdRE.MatchString(w.String()) {
				w.Reset()
				inWord = false
			}
			end()
			for i+1 < len(s) && s[i+1] == '>' {
				i++
			}
			if i+1 < len(s) && s[i+1] == '&' {
				for i+1 < len(s) && s[i+1] != ' ' && s[i+1] != '\t' {
					i++
				}
			} else {
				skipNext = true
			}
		case c == '|' || c == ';' || (c == '&' && i+1 < len(s) && s[i+1] == '&'):
			next()
			if i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '&') {
				i++
			}
		case c == '#' && !inWord:
			next()
			return nonEmpty(cmds)
		case c == ' ' || c == '\t':
			end()
		default:
			w.WriteByte(c)
			inWord = true
		}
	}
	next()
	return nonEmpty(cmds)
}

func nonEmpty(cmds [][]string) [][]string {
	out := cmds[:0]
	for _, c := range cmds {
		if len(c) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// imageRef reports whether a word names the server's image as the docs do.
func imageRef(w string) bool {
	return w == "$IMAGE" || strings.HasPrefix(w, "ghcr.io/tyler-rich/shell-mcp:") || strings.HasPrefix(w, "ghcr.io/tyler-rich/shell-mcp@")
}

// invoke returns the invocation a command makes of a checked binary, if any.
func invoke(c command) (invocation, bool) {
	w := c.words
	at := -1
	bin := ""
	switch {
	case binaries[path.Base(w[0])] && (w[0] == path.Base(w[0]) || strings.HasPrefix(w[0], "/")):
		at, bin = 0, path.Base(w[0])
	case w[0] == "docker" && len(w) > 1 && w[1] == "run":
		for i := 2; i < len(w); i++ {
			if imageRef(w[i]) {
				at, bin = i, "shell-mcp"
				break
			}
		}
	case w[0] == "docker" && len(w) > 1 && (w[1] == "exec" || w[1] == "compose" && len(w) > 2 && w[2] == "exec"):
		for i := 2; i < len(w); i++ {
			if strings.HasPrefix(w[i], "/") && binaries[path.Base(w[i])] {
				at, bin = i, path.Base(w[i])
				break
			}
		}
	}
	if at < 0 {
		return invocation{}, false
	}
	inv := invocation{command: c, bin: bin}
	rest := w[at+1:]
	i := 0
	for ; i < len(rest) && !strings.HasPrefix(rest[i], "-") && !strings.HasPrefix(rest[i], "<"); i++ {
		inv.sub = append(inv.sub, rest[i])
	}
	inv.flags = flagsOf(rest[i:])
	return inv, true
}

// flagsOf returns the flags among words: each word that starts with - and is
// more than "-" (the value of --out -), without its =value.
func flagsOf(words []string) []string {
	var out []string
	for _, w := range words {
		if len(w) < 2 || w[0] != '-' || w == "--" {
			continue
		}
		if k := strings.IndexByte(w, '='); k > 0 {
			w = w[:k]
		}
		switch w {
		case "-h", "-help", "--help":
			continue
		}
		out = append(out, w)
	}
	return out
}

// helpHas reports whether a --help text shows the flag (as a word: --dir
// is not --dir-x) or the command word.
func helpHas(help, word string) bool {
	return regexp.MustCompile(`(^|[^\w-])` + regexp.QuoteMeta(word) + `($|[^\w-])`).MatchString(help)
}

func show(c command) string {
	const limit = 110
	t := c.text
	if len(t) > limit {
		t = t[:limit] + "…"
	}
	return "`" + t + "`"
}

// checkCommands returns one problem per subcommand or flag that the
// binaries' --help does not show, and a line for each command it checked.
func checkCommands(fsys fs.FS, help helpFunc) (problems, checked []string, _ error) {
	type res struct {
		out  string
		code int
	}
	cache := map[string]res{}
	run := func(bin string, args ...string) (res, error) {
		k := bin + "\x00" + strings.Join(args, "\x00")
		if r, ok := cache[k]; ok {
			return r, nil
		}
		out, code, err := help(bin, args)
		if err != nil {
			return res{}, err
		}
		cache[k] = res{out, code}
		return cache[k], nil
	}
	for _, s := range commandSections {
		b, err := fs.ReadFile(fsys, s.file)
		if err != nil {
			return nil, nil, err
		}
		lines, first, err := sectionLines(b, s.heading)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", s.file, err)
		}
		var last *invocation
		var helps []string
		var fragments []piece
		for _, p := range sectionCommands(s.file, lines, first) {
			if p.fragment {
				if !p.block {
					fragments = append(fragments, p)
					continue
				}
				if last == nil {
					problems = append(problems, fmt.Sprintf("%s: %s: flags with no command before them in the section", p.at, show(p.command)))
					continue
				}
				h, err := run(last.bin, append(append([]string{}, last.sub...), "--help")...)
				if err != nil {
					return nil, nil, err
				}
				checked = append(checked, fmt.Sprintf("%s: %s, more flags: %s", p.at, strings.Join(append([]string{last.bin}, last.sub...), " "), strings.Join(flagsOf(p.words), " ")))
				for _, f := range flagsOf(p.words) {
					if !helpHas(h.out, f) {
						problems = append(problems, fmt.Sprintf("%s: %s: %s is not a flag of %#q (its --help)", p.at, show(p.command), f, strings.Join(append([]string{last.bin}, last.sub...), " ")))
					}
				}
				continue
			}
			inv, ok := invoke(p.command)
			if !ok {
				continue
			}
			name := strings.Join(append([]string{inv.bin}, inv.sub...), " ")
			checked = append(checked, fmt.Sprintf("%s: %s %s", p.at, name, strings.Join(inv.flags, " ")))
			h, err := run(inv.bin, append(append([]string{}, inv.sub...), "--help")...)
			if err != nil {
				return nil, nil, err
			}
			if h.code != 0 {
				problems = append(problems, fmt.Sprintf("%s: %s: `%s --help` exits %d: no such subcommand", p.at, show(p.command), name, h.code))
				continue
			}
			subOK := true
			for i, w := range inv.sub {
				root, err := run(inv.bin, "--help")
				if err != nil {
					return nil, nil, err
				}
				parent, err := run(inv.bin, append(append([]string{}, inv.sub[:i]...), "--help")...)
				if err != nil {
					return nil, nil, err
				}
				if !helpHas(root.out, w) && !helpHas(parent.out, w) {
					problems = append(problems, fmt.Sprintf("%s: %s: %q is not a subcommand of %#q (its --help)", p.at, show(p.command), w, strings.Join(append([]string{inv.bin}, inv.sub[:i]...), " ")))
					subOK = false
					break
				}
			}
			if !subOK {
				continue
			}
			for _, f := range inv.flags {
				if !helpHas(h.out, f) {
					problems = append(problems, fmt.Sprintf("%s: %s: %s is not a flag of %#q (its --help)", p.at, show(p.command), f, name))
				}
			}
			helps = append(helps, h.out)
			if p.block {
				l := inv
				last = &l
			}
		}
		// A code span of flags alone, in prose: the flags of some command of
		// the section.
		for _, p := range fragments {
			checked = append(checked, fmt.Sprintf("%s: flags %s", p.at, strings.Join(flagsOf(p.words), " ")))
			if len(helps) == 0 {
				problems = append(problems, fmt.Sprintf("%s: %s: flags in a section with no command", p.at, show(p.command)))
				continue
			}
			for _, f := range flagsOf(p.words) {
				if !strings.HasPrefix(f, "--") {
					continue
				}
				found := false
				for _, h := range helps {
					if helpHas(h, f) {
						found = true
						break
					}
				}
				if !found {
					problems = append(problems, fmt.Sprintf("%s: %s: %s is a flag of no command in %s's section (their --help)", p.at, show(p.command), f, s.file))
				}
			}
		}
	}
	return problems, checked, nil
}
