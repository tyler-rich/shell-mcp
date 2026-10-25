//go:build linux

package ops_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gitx"
	"github.com/tyler-rich/shell-mcp/internal/gate/ops"
)

// Every configuration key and hook event the installed git knows that could
// make it run a program is covered by the gate (handoff N-20, POLICY §7):
// git's own list of keys (`git help --config`) is filtered with
// gitx.ProgramKeyName, and each match must be in gitx.ProgramKeys, either
// forced on the gate's command line (every -c value present in ops.GitArgs),
// overridden by environment variables (present in ops.GitEnv), disabled for
// every hook event, or listed with the reason it cannot run; and every hook
// event in the installed githooks(5) must be disabled with
// hook.<event>.enabled=false. A git that adds a hook event or a key the rule
// recognises fails here until gitx's table covers it.

// programKeyGaps returns what table does not cover, for git's keys and hook
// events, the gate's -c values and its environment. A key whose name holds
// a part the repository chooses (<driver>, <name>, <url>, *) can never be
// forced with -c, so unless it is forced for each of git's fixed values
// (gpg.<format>.program) or per hook event, it must be marked as covered by
// the closed repository chain (Chain).
func programKeyGaps(table []gitx.ProgramKey, keys, events, cvals, env []string) []string {
	var gaps []string
	for _, k := range keys {
		if !gitx.ProgramKeyName(k) {
			continue
		}
		var e *gitx.ProgramKey
		for i := range table {
			if strings.EqualFold(table[i].Key, k) {
				e = &table[i]
			}
		}
		if e == nil {
			gaps = append(gaps, k+": names a program or command to run, and gitx.ProgramKeys neither covers it nor says why it cannot run")
			continue
		}
		for _, a := range e.Args {
			if !slices.Contains(cvals, a) {
				gaps = append(gaps, k+": -c "+a+" is not on the gate's command line")
			}
		}
		for _, v := range e.Env {
			if !slices.Contains(env, v) {
				gaps = append(gaps, k+": "+v+" is not in the gate's environment")
			}
		}
		if len(e.Args) == 0 && len(e.Env) == 0 && !e.PerEvent && e.Why == "" {
			gaps = append(gaps, k+": gitx.ProgramKeys lists it without an override or a reason")
		}
		if (strings.Contains(k, "<") || strings.Contains(k, "*")) && len(e.Args) == 0 && !e.PerEvent && !e.Chain {
			gaps = append(gaps, k+": its name holds a part the repository chooses, which no -c can override, and gitx.ProgramKeys does not mark it as covered by the closed repository chain")
		}
	}
	for _, ev := range events {
		if !slices.Contains(cvals, "hook."+ev+".enabled=false") {
			gaps = append(gaps, "hook event "+ev+": hook."+ev+".enabled=false is not on the gate's command line")
		}
	}
	return gaps
}

// gateCValues returns the -c values of the gate's git argv.
func gateCValues() []string {
	var out []string
	a := ops.GitArgs("/srv/app/deploy", "", "status")
	for i := 0; i+1 < len(a); i++ {
		if a[i] == "-c" {
			out = append(out, a[i+1])
			i++
		}
	}
	return out
}

// installedGit runs the installed git (ops.GitPath) with no configuration.
func installedGit(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), ops.GitPath, args...) //nolint:gosec // G204: the fixed git binary, fixed arguments
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + cmd.Dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C.UTF-8"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}

// hookHeadingRE is a subsection heading of githooks(5) as roff: .SS "name",
// with each hyphen escaped.
var hookHeadingRE = regexp.MustCompile(`^\.SS "([a-z0-9\\-]+)"\s*$`)

// installedHookEvents reads the hook events from the installed git's
// githooks(5), under `git --man-path` (git-man; gzip-compressed or not).
func installedHookEvents(t *testing.T) []string {
	t.Helper()
	dir := strings.TrimSpace(installedGit(t, "--man-path"))
	var r io.Reader
	for _, name := range []string{"githooks.5.gz", "githooks.5"} {
		b, err := os.ReadFile(filepath.Join(dir, "man5", name)) //nolint:gosec // G304: the installed git's own manual page
		if err != nil {
			continue
		}
		r = bytes.NewReader(b)
		if strings.HasSuffix(name, ".gz") {
			if r, err = gzip.NewReader(r); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		break
	}
	if r == nil {
		t.Fatalf("githooks(5) is not under %s/man5: this git's hook events cannot be listed (install git's manual pages, git-man)", dir)
	}
	var events []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if m := hookHeadingRE.FindStringSubmatch(sc.Text()); m != nil {
			events = append(events, strings.ReplaceAll(m[1], `\-`, "-"))
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

// TestGitProgramKeysCovered: see the file comment.
func TestGitProgramKeysCovered(t *testing.T) {
	t.Parallel()
	ver := strings.TrimSpace(installedGit(t, "version"))
	keys := strings.Fields(installedGit(t, "help", "--config"))
	events := installedHookEvents(t)
	// A list this short is not git's whole list: the check would pass
	// vacuously.
	if len(keys) < 500 || len(events) < 20 {
		t.Fatalf("%s: %d configuration keys and %d hook events; that is not the whole list", ver, len(keys), len(events))
	}
	if gaps := programKeyGaps(gitx.ProgramKeys, keys, events, gateCValues(), ops.GitEnv("/home/svc", "/srv/app/deploy")); len(gaps) > 0 {
		t.Fatalf("%s: what could run a program is not covered by the gate's git argv or environment:\n%s", ver, strings.Join(gaps, "\n"))
	}
	matched := 0
	for _, k := range keys {
		if gitx.ProgramKeyName(k) {
			matched++
		}
	}
	t.Logf("%s: %d configuration keys, %d naming a program, %d hook events: all covered", ver, len(keys), matched, len(events))
}

// TestGitProgramKeyGapsFound: the check fails for what a future git could
// add, a hook event and a program-running key the gate does not cover, and
// for a table entry whose override is missing from the gate's argv.
func TestGitProgramKeyGapsFound(t *testing.T) {
	t.Parallel()
	cvals, env := gateCValues(), ops.GitEnv("/home/svc", "/srv/app/deploy")
	if g := programKeyGaps(gitx.ProgramKeys, []string{"core.editor", "user.name", "filter.<driver>.clean"}, gitx.HookEvents, cvals, env); len(g) != 0 {
		t.Fatalf("covered keys reported: %q", g)
	}
	for _, c := range []struct {
		keys, events, cvals []string
		want                string
	}{
		{[]string{"core.newEditor"}, nil, cvals, "core.newEditor"},
		{[]string{"merge.<driver>.newCommand"}, nil, cvals, "merge.<driver>.newCommand"},
		{[]string{"fetch.uploadHelper"}, nil, cvals, "fetch.uploadHelper"},
		{nil, append(slices.Clone(gitx.HookEvents), "post-new-event"), cvals, "hook event post-new-event"},
		{[]string{"core.editor"}, nil, slices.DeleteFunc(slices.Clone(cvals), func(v string) bool { return v == "core.editor=/bin/false" }), "-c core.editor=/bin/false"},
	} {
		if g := programKeyGaps(gitx.ProgramKeys, c.keys, c.events, c.cvals, env); len(g) != 1 || !strings.Contains(g[0], c.want) {
			t.Fatalf("keys %q events %d: gaps %q, want one naming %s", c.keys, len(c.events), g, c.want)
		}
	}
	noEnv := slices.DeleteFunc(slices.Clone(env), func(v string) bool { return v == "GIT_PROXY_COMMAND=" })
	if g := programKeyGaps(gitx.ProgramKeys, []string{"core.gitProxy"}, nil, cvals, noEnv); len(g) != 1 || !strings.Contains(g[0], "GIT_PROXY_COMMAND") {
		t.Fatalf("a missing variable: gaps %q", g)
	}
	// A key the repository names, not marked as covered by the closed
	// repository chain.
	noChain := slices.Clone(gitx.ProgramKeys)
	for i := range noChain {
		if noChain[i].Key == "remote.<name>.vcs" {
			noChain[i].Chain = false
		}
	}
	if g := programKeyGaps(noChain, []string{"remote.<name>.vcs"}, nil, cvals, env); len(g) != 1 || !strings.Contains(g[0], "closed repository chain") {
		t.Fatalf("a repository-named key without Chain: gaps %q", g)
	}
}

// submoduleKeyGaps returns what table does not cover among git's keys that
// can make a command enter a submodule (gitx.SubmoduleKeyName; handoff
// N-23): a key the table does not list, a -c value not on the gate's
// command line, and an entry with neither an override, a flag nor a
// reason. A key whose name the repository chooses can never be forced with
// -c, so it needs the flag that beats it or the reason it is never read.
func submoduleKeyGaps(table []gitx.SubmoduleKey, keys, cvals []string) []string {
	var gaps []string
	for _, k := range keys {
		if !gitx.SubmoduleKeyName(k) {
			continue
		}
		i := slices.IndexFunc(table, func(e gitx.SubmoduleKey) bool { return strings.EqualFold(e.Key, k) })
		if i < 0 {
			gaps = append(gaps, k+": can make a command enter a submodule, and gitx.SubmoduleKeys neither covers it nor says why it cannot")
			continue
		}
		e := &table[i]
		for _, a := range e.Args {
			if !slices.Contains(cvals, a) {
				gaps = append(gaps, k+": -c "+a+" is not on the gate's command line")
			}
		}
		if len(e.Args) == 0 && e.Flag == "" && e.Why == "" {
			gaps = append(gaps, k+": gitx.SubmoduleKeys lists it without an override, a flag or a reason")
		}
	}
	return gaps
}

// TestGitSubmoduleKeysCovered: every key the installed git knows that can
// make a command enter a submodule is covered by gitx.SubmoduleKeys, and
// every -c value of the table is on the gate's command line.
func TestGitSubmoduleKeysCovered(t *testing.T) {
	t.Parallel()
	ver := strings.TrimSpace(installedGit(t, "version"))
	keys := strings.Fields(installedGit(t, "help", "--config"))
	matched := 0
	for _, k := range keys {
		if gitx.SubmoduleKeyName(k) {
			matched++
		}
	}
	// git 2.47 and later know at least these many; fewer is not the whole list.
	if len(keys) < 500 || matched < 18 {
		t.Fatalf("%s: %d configuration keys, %d about submodules; that is not the whole list", ver, len(keys), matched)
	}
	if gaps := submoduleKeyGaps(gitx.SubmoduleKeys, keys, gateCValues()); len(gaps) > 0 {
		t.Fatalf("%s: what could make git enter a submodule is not covered by the gate's git argv:\n%s", ver, strings.Join(gaps, "\n"))
	}
	t.Logf("%s: %d configuration keys, %d about submodules: all covered", ver, len(keys), matched)
}

// TestGitSubmoduleKeyGapsFound: the check fails for a key a future git
// could add and for a table override missing from the gate's argv.
func TestGitSubmoduleKeyGapsFound(t *testing.T) {
	t.Parallel()
	var cvals []string
	for _, k := range gitx.SubmoduleKeys {
		cvals = append(cvals, k.Args...)
	}
	if g := submoduleKeyGaps(gitx.SubmoduleKeys, []string{"submodule.recurse", "diff.ignoreSubmodules", "core.editor"}, cvals); len(g) != 0 {
		t.Fatalf("covered keys reported: %q", g)
	}
	for _, c := range []struct {
		keys, cvals []string
		want        string
	}{
		{[]string{"status.newSubmoduleMode"}, cvals, "status.newSubmoduleMode"},
		{[]string{"submodule.<name>.newSetting"}, cvals, "submodule.<name>.newSetting"},
		{[]string{"submodule.recurse"}, slices.DeleteFunc(slices.Clone(cvals), func(v string) bool { return v == "submodule.recurse=false" }), "-c submodule.recurse=false"},
	} {
		if g := submoduleKeyGaps(gitx.SubmoduleKeys, c.keys, c.cvals); len(g) != 1 || !strings.Contains(g[0], c.want) {
			t.Fatalf("keys %q: gaps %q, want one naming %s", c.keys, g, c.want)
		}
	}
	empty := slices.Clone(gitx.SubmoduleKeys)
	for i := range empty {
		if empty[i].Key == "submodule.fetchJobs" {
			empty[i].Why = ""
		}
	}
	if g := submoduleKeyGaps(empty, []string{"submodule.fetchJobs"}, cvals); len(g) != 1 || !strings.Contains(g[0], "without an override") {
		t.Fatalf("an entry without an override, a flag or a reason: gaps %q", g)
	}
}
