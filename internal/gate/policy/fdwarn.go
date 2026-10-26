package policy

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// {path:read:fd} warnings (POLICY §4, handoff N-22). A command given the
// gate's descriptor as /dev/fd/N gains only when it reads the file through
// it. The programs below were measured (Debian 13 with GNU coreutils 9.7,
// Ubuntu 26.04 with uutils 0.10.0; S6-2, ARCHIVE §14) to give wrong
// results, or no gain, with one: some act on the /dev/fd/N symlink itself
// unless told to follow it, some read the link back to the real path and
// look that up again, and some resolve paths named in the file from
// /dev/fd/. check-policy warns about each, recognised by the name as
// written, as resolved and canonical (as the GTFOBins warning is). A flag
// that makes the program follow the link counts only as a whole token,
// so the match errs on the side of warning.

// fdRule is one program's measured behaviour with a descriptor.
type fdRule struct {
	// follow are whole tokens that make the program act on the file the
	// link names; any of them silences the warning.
	follow []string
	// wrong, when set, decides from the template's tokens whether the
	// program gets it wrong (follow is checked first); nil means always.
	wrong func(tokens []string) bool
	// why completes "<program> …".
	why string
}

var fdRules = map[string]fdRule{
	"stat": {follow: []string{"-L", "--dereference"},
		why: "reports the /dev/fd/N link itself, not the file, without -L (--dereference)"},
	"du": {follow: []string{"-L", "--dereference", "-D", "-H", "--dereference-args"},
		why: "reports the /dev/fd/N link itself, not the file, without -L, -D or -H (--dereference, --dereference-args)"},
	"file": {follow: []string{"-L", "--dereference"},
		why: "describes the /dev/fd/N link itself, not the file, without -L (--dereference)"},
	"ls": {follow: []string{"-L", "-H", "--dereference", "--dereference-command-line"},
		why: "lists the /dev/fd/N link itself, not the file, without -L or -H (--dereference, --dereference-command-line)"},
	"find": {follow: []string{"-H", "-L"},
		why: "does not descend into or test the file, only the /dev/fd/N link, without a leading -H or -L"},
	"cp": {follow: []string{"-L", "--dereference"}, wrong: anyToken("-P", "-d", "-a", "-r", "-R", "--no-dereference", "--archive", "--recursive"),
		why: "copies the /dev/fd/N link, which names the real path, not the file, with -P, -d, -a, -r or -R (--no-dereference, --archive, --recursive)"},
	"tar": {follow: []string{"-h", "--dereference"}, wrong: tarMember,
		why: "archives the /dev/fd/N link, not the file, when it is a member to add rather than the archive (-f) and -h (--dereference) is not given"},
	"findmnt": {why: "reads the /dev/fd/N link back to the real path and looks the real path up again, so the descriptor gains nothing"},
	"nginx":   {why: "resolves relative paths in the file (include, and the prefix) from /dev/fd/, not from the file's directory"},
	"docker": {wrong: anyToken("compose"),
		why: "compose resolves relative paths in the file from /dev/fd/ and names the project fd; with --project-directory it still reads every file the compose file names by path"},
	"docker-compose": {why: "resolves relative paths in the file from /dev/fd/ and names the project fd; with --project-directory it still reads every file the compose file names by path"},
}

func anyToken(names ...string) func([]string) bool {
	return func(tokens []string) bool {
		return slices.ContainsFunc(tokens, func(t string) bool { return slices.Contains(names, t) })
	}
}

// tarCluster is a bundle of tar's single-letter options, with or without
// the leading dash (the old style takes the first argument without one).
var tarCluster = regexp.MustCompile(`^-?[A-Za-z]+$`)

// tarMember reports whether a {path:read:fd} is a member for tar to add
// rather than the archive: the archive follows -f, --file or a bundle
// ending in f ("-czf", or "tf" as the first argument), and an h in such a
// bundle is -h.
func tarMember(tokens []string) bool {
	bundle := func(i int) bool {
		t := tokens[i]
		return tarCluster.MatchString(t) && !strings.HasPrefix(t, "--") && (strings.HasPrefix(t, "-") || i == 0)
	}
	for i, t := range tokens {
		if bundle(i) && strings.ContainsRune(strings.TrimPrefix(t, "-"), 'h') {
			return false
		}
	}
	for i, t := range tokens {
		if t != fdToken {
			continue
		}
		archive := i > 0 && (tokens[i-1] == "-f" || tokens[i-1] == "--file" || bundle(i-1) && strings.HasSuffix(tokens[i-1], "f"))
		if !archive {
			return true
		}
	}
	return false
}

const fdToken = "{path:read:fd}" //nolint:gosec // G101: a placeholder name, not a credential

// DescriptorWarning is check-policy's warning for the command at field
// whose template (its tokens as written) passes a {path:read:fd} to a
// program, the first of names (as written, then as resolved) that is
// measured to give wrong results, or no gain, with a descriptor; "" when
// none applies.
func DescriptorWarning(field string, tokens []string, names ...string) string {
	if !slices.Contains(tokens, fdToken) {
		return ""
	}
	for _, name := range names {
		r, ok := fdRules[name]
		if !ok {
			continue
		}
		if slices.ContainsFunc(tokens, func(t string) bool { return slices.Contains(r.follow, t) }) || r.wrong != nil && !r.wrong(tokens) {
			return ""
		}
		return fmt.Sprintf("%s: %s given a {path:read:fd} %s (POLICY §4)", field, name, r.why)
	}
	return ""
}
