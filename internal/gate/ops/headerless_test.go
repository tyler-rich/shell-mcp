//go:build linux

package ops_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// Headerless key text (handoff N-35): output whose slice the source cut
// before redaction (journalctl -n, a command that prints a range of its
// input, a diff hunk) could begin inside a private key's body, without the
// BEGIN line the output redaction needs. Keys are generated for each run
// (RSA 2048, PKCS #8: 26 body lines); every name and path is invented.

// rsaKeyLines returns a newly generated key as lines: BEGIN, body, END.
func rsaKeyLines(t *testing.T) []string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))), "\n")
}

// bodyLeaks returns the key's body lines that out holds.
func bodyLeaks(out string, key []string) []string {
	var hit []string
	for _, l := range key[1 : len(key)-1] {
		if strings.Contains(out, l) {
			hit = append(hit, l)
		}
	}
	return hit
}

func journalLine(i int, msg string) string {
	return fmt.Sprintf("2026-10-30T10:%02d:%02d+00:00 target-a example-app[4242]: %s", i/60, i%60, msg)
}

// TestJournalHeaderlessKey: a service that logged a key line by line (one
// journal entry per line); journalctl -n windows that start inside the body
// (12 lines, the reproduction's window) and one that holds the BEGIN line
// (100) show no body line; a window that also ends inside the body (the
// journal holds no END yet) shows none either; the ordinary lines around
// the key, and a certificate logged whole, are unchanged.
func TestJournalHeaderlessKey(t *testing.T) {
	f := newFixture(t, "read")
	f.fakeSystemd(t, "read")
	key := rsaKeyLines(t)
	journal := filepath.Join(f.dir, "fakesys.log.journal")
	var j strings.Builder
	entries := append(append([]string{"starting"}, key...), "listening on :8080")
	for i, l := range entries {
		j.WriteString(journalLine(i, l) + "\n")
	}
	gatetest.WriteFile(t, journal, j.String(), 0o644)
	var d struct {
		Output string `json:"output"`
	}
	for _, n := range []int{12, 100, 2, 1} {
		f.ok("journal", m{"unit": "example-app.service", "lines": n}, &d)
		if leaks := bodyLeaks(d.Output, key); len(leaks) != 0 {
			t.Fatalf("lines=%d: %d body lines shown:\n%s", n, len(leaks), d.Output)
		}
		if !strings.HasSuffix(d.Output, journalLine(len(entries)-1, "listening on :8080")+"\n") {
			t.Fatalf("lines=%d: the last ordinary line changed:\n%s", n, d.Output)
		}
	}
	f.ok("journal", m{"unit": "example-app.service", "lines": 100}, &d)
	if !strings.HasPrefix(d.Output, journalLine(0, "starting")+"\n") {
		t.Fatalf("the first ordinary line changed:\n%s", d.Output)
	}
	// The key's END was not logged (yet): a window wholly inside the body.
	j.Reset()
	for i, l := range append([]string{"starting"}, key[:15]...) {
		j.WriteString(journalLine(i, l) + "\n")
	}
	gatetest.WriteFile(t, journal, j.String(), 0o644)
	for _, n := range []int{5, 1} {
		f.ok("journal", m{"unit": "example-app.service", "lines": n}, &d)
		if leaks := bodyLeaks(d.Output, key); len(leaks) != 0 {
			t.Fatalf("lines=%d without END: %d body lines shown:\n%s", n, len(leaks), d.Output)
		}
		if got := strings.Count(d.Output, "\n"); got != n {
			t.Fatalf("lines=%d: %d lines returned:\n%s", n, got, d.Output)
		}
	}
	// A certificate logged whole is ordinary output.
	cert, _ := selfSigned(t, "app.example.test", 30)
	j.Reset()
	for i, l := range strings.Split(strings.TrimSpace(cert), "\n") {
		j.WriteString(journalLine(i, l) + "\n")
	}
	gatetest.WriteFile(t, journal, j.String(), 0o644)
	f.ok("journal", m{"unit": "example-app.service", "lines": 100}, &d)
	if d.Output != j.String() {
		t.Fatalf("certificate changed:\n%s\nwant\n%s", d.Output, j.String())
	}
}

// keyCommands are this file's commands: a range command (tail) and a
// whole-file one (the probe's cat), by path and by descriptor, without and
// with reads_private_keys.
const keyCommands = `  - id: log-tail
    path: /usr/bin/tail
    tier: read
    templates: [["-n", "{int:1-1000}", "--", "{path:read}"]]
  - id: log-tail-fd
    path: /usr/bin/tail
    tier: read
    templates: [["-n", "{int:1-1000}", "--", "{path:read:fd}"]]
  - id: key-cat
    path: {BIN}/probe
    tier: read
    templates: [["cat", "{path:read}"], ["cat", "{path:read:fd}"]]
  - id: key-cat-allowed
    path: {BIN}/probe
    tier: read
    reads_private_keys: true
    templates: [["cat", "{path:read}"], ["cat", "{path:read:fd}"]]
  - id: log-tail-allowed
    path: /usr/bin/tail
    tier: read
    reads_private_keys: true
    templates: [["-n", "{int:1-1000}", "--", "{path:read}"]]
`

func keyFixture(t *testing.T) (f *fixture, dir string) {
	t.Helper()
	f = newFixture(t, "read")
	f.rawPolicy(strings.NewReplacer("{TIER}", "read", "{PRIV}", "").Replace(basePolicy + keyCommands))
	dir = filepath.Join(f.read, "tls")
	gatetest.Mkdir(t, dir, 0o755)
	return f, dir
}

type keyExec struct {
	Stdout   string `json:"stdout"`
	ExitCode *int   `json:"exit_code"`
}

// TestExecKeyInputRefused: a {path:read} or {path:read:fd} naming a file
// that holds a private key anywhere (a key file, a key past 64 KiB of log)
// is refused (path_denied) by exec_preview and exec alike, and nothing
// runs; a file without one runs as before, its output unchanged.
func TestExecKeyInputRefused(t *testing.T) {
	f, dir := keyFixture(t)
	key := rsaKeyLines(t)
	keyFile := filepath.Join(dir, "service.key")
	gatetest.WriteFile(t, keyFile, strings.Join(key, "\n")+"\n", 0o644)
	late := filepath.Join(dir, "late.log")
	gatetest.WriteFile(t, late, strings.Repeat("ordinary log line\n", 6000)+strings.Join(key, "\n")+"\n", 0o644)
	for _, req := range []m{
		{"command_id": "log-tail", "args": []string{"-n", "10", "--", keyFile}},
		{"command_id": "log-tail", "args": []string{"-n", "10", "--", late}},
		{"command_id": "log-tail-fd", "args": []string{"-n", "10", "--", keyFile}},
		{"command_id": "key-cat", "args": []string{"cat", keyFile}},
		{"command_id": "key-cat", "args": []string{"cat", late}},
	} {
		for _, op := range []string{"exec_preview", "exec"} {
			r := f.call(op, req)
			if r.OK || r.Error == nil || r.Error.Code != "path_denied" || !strings.Contains(r.Error.Message, "private key") ||
				!strings.Contains(r.Error.Message, "reads_private_keys") {
				t.Fatalf("%s %v: %+v %s, want path_denied naming the key and reads_private_keys", op, req["args"], r.Error, r.Data)
			}
			if leaks := bodyLeaks(string(r.Data), key); len(leaks) != 0 {
				t.Fatalf("%s %v: body shown", op, req["args"])
			}
		}
	}
	plain := filepath.Join(dir, "app.log")
	gatetest.WriteFile(t, plain, "one\ntwo\nthree\n", 0o644)
	var d keyExec
	f.ok("exec", m{"command_id": "log-tail", "args": []string{"-n", "2", "--", plain}}, &d)
	if d.Stdout != "two\nthree\n" {
		t.Fatalf("ordinary tail: %q", d.Stdout)
	}
}

// TestExecKeyInputOptIn: with reads_private_keys the same file is accepted
// and the command runs; its output is still redacted, with the width
// heuristic too: a whole key is masked, a range of it shows no body line,
// and a file of body lines with no header (which the search does not count
// as a key) shows none either.
func TestExecKeyInputOptIn(t *testing.T) {
	f, dir := keyFixture(t)
	key := rsaKeyLines(t)
	keyFile := filepath.Join(dir, "service.key")
	gatetest.WriteFile(t, keyFile, strings.Join(key, "\n")+"\n", 0o644)
	bare := filepath.Join(dir, "bare.txt")
	gatetest.WriteFile(t, bare, strings.Join(key[3:12], "\n")+"\n", 0o644)
	var d keyExec
	for _, req := range []m{
		{"command_id": "key-cat-allowed", "args": []string{"cat", keyFile}},
		{"command_id": "log-tail-allowed", "args": []string{"-n", "10", "--", keyFile}},
		{"command_id": "log-tail-allowed", "args": []string{"-n", "5", "--", bare}},
		{"command_id": "key-cat-allowed", "args": []string{"cat", bare}},
	} {
		f.ok("exec_preview", req, nil)
		f.ok("exec", req, &d)
		if d.ExitCode == nil || *d.ExitCode != 0 {
			t.Fatalf("%v: exit %v", req, d.ExitCode)
		}
		if leaks := bodyLeaks(d.Stdout, key); len(leaks) != 0 || !strings.Contains(d.Stdout, "[REDACTED]") {
			t.Fatalf("%v: %d body lines shown:\n%s", req["args"], len(leaks), d.Stdout)
		}
	}
	var s struct {
		Commands []struct {
			ID               string `json:"id"`
			ReadsPrivateKeys bool   `json:"reads_private_keys"`
		} `json:"commands"`
	}
	f.ok("policy", m{}, &s)
	got := map[string]bool{}
	for _, c := range s.Commands {
		got[c.ID] = c.ReadsPrivateKeys
	}
	if !got["key-cat-allowed"] || !got["log-tail-allowed"] || got["key-cat"] || got["log-tail"] {
		t.Fatalf("policy summary reads_private_keys: %v", got)
	}
}

// TestExecKeyInputLargeFile: a file above the 256 MiB the search covers is
// not searched; the command runs and its output gets the width heuristic,
// so a range that ends inside a key's body (no END) shows no body line.
func TestExecKeyInputLargeFile(t *testing.T) {
	f, dir := keyFixture(t)
	key := rsaKeyLines(t)
	big := filepath.Join(dir, "big.log")
	gatetest.WriteFile(t, big, "", 0o644)
	tail := []byte(strings.Join(key[:20], "\n") + "\n")
	file, err := os.OpenFile(big, os.O_WRONLY, 0) //nolint:gosec // G304: the test's own file
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(tail, 256<<20+1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	var d keyExec
	f.ok("exec", m{"command_id": "log-tail", "args": []string{"-n", "8", "--", big}}, &d)
	if leaks := bodyLeaks(d.Stdout, key); len(leaks) != 0 {
		t.Fatalf("%d body lines shown:\n%s", len(leaks), d.Stdout)
	}
	if strings.Count(d.Stdout, "\n") != 8 {
		t.Fatalf("lines: %q", d.Stdout)
	}
}

// keyRepo commits an invented key file (and a renamed-later and a
// deleted-later one) to the fixture repository.
func keyRepo(t *testing.T, g *gitFixture, files ...string) map[string][]string {
	t.Helper()
	keys := map[string][]string{}
	for _, name := range files {
		k := rsaKeyLines(t)
		keys[name] = k
		p := filepath.Join(g.repo, name)
		gatetest.Mkdir(t, filepath.Dir(p), 0o755)
		gatetest.WriteFile(t, p, strings.Join(k, "\n")+"\n", 0o644)
		gatetest.Git(t, g.repo, "add", "--", name)
	}
	gatetest.Git(t, g.repo, "-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-q", "-m", "keys")
	return keys
}

// changeLine rewrites line i of the key file name with another key's line.
func changeLine(t *testing.T, g *gitFixture, name string, key []string, i int) []string {
	t.Helper()
	mod := append([]string{}, key...)
	mod[i] = rsaKeyLines(t)[i]
	gatetest.WriteFile(t, filepath.Join(g.repo, name), strings.Join(mod, "\n")+"\n", 0o644)
	return mod
}

type diffData struct {
	Diff      string `json:"diff"`
	Truncated bool   `json:"truncated"`
}

func excludedLine(name string) string {
	return fmt.Sprintf("[REDACTED] %q: holds a private key; its changes are not shown\n", name)
}

// TestGitDiffKeyFileExcluded: a changed file that holds a private key on
// either side of the diff is left out of the patch and named in a mask
// line, in the work-tree and the staged diff: one changed body line (the
// hunk's context, and the hunk header git fills from the line before the
// hunk, are body lines), a deleted key, an added one, a renamed one and a
// name with glob characters and a space. The other files' changes are
// shown as before.
func TestGitDiffKeyFileExcluded(t *testing.T) {
	g := newGitFixture(t, "read")
	odd := "tls/odd [1] *.pem"
	keys := keyRepo(t, g, "tls/service.key", "tls/old.key", "tls/gone.key", odd)
	mod := changeLine(t, g, "tls/service.key", keys["tls/service.key"], 14)
	changeLine(t, g, odd, keys[odd], 5)
	if err := os.Remove(filepath.Join(g.repo, "tls", "gone.key")); err != nil {
		t.Fatal(err)
	}
	gatetest.WriteFile(t, filepath.Join(g.repo, "app.conf"), "port=9090\n", 0o644)
	leaks := func(diff string) []string {
		var all []string
		for _, k := range keys {
			all = append(all, bodyLeaks(diff, k)...)
		}
		return append(all, bodyLeaks(diff, mod)...)
	}
	var d diffData
	g.ok("git_diff", m{"repo": g.repo}, &d)
	if l := leaks(d.Diff); len(l) != 0 || strings.Contains(d.Diff, "@@ -12,7") {
		t.Fatalf("work-tree diff shows %d body lines:\n%s", len(l), d.Diff)
	}
	for _, name := range []string{"tls/service.key", "tls/gone.key", odd} {
		if !strings.Contains(d.Diff, excludedLine(name)) {
			t.Fatalf("work-tree diff does not name %q:\n%s", name, d.Diff)
		}
	}
	if !strings.Contains(d.Diff, "+port=9090") || strings.Contains(d.Diff, excludedLine("tls/old.key")) {
		t.Fatalf("work-tree diff: other changes wrong:\n%s", d.Diff)
	}

	// Staged: the same changes, a rename, and a new key.
	gatetest.Git(t, g.repo, "add", "-A")
	gatetest.Git(t, g.repo, "mv", "tls/old.key", "tls/renamed.key")
	added := rsaKeyLines(t)
	gatetest.WriteFile(t, filepath.Join(g.repo, "tls", "new.key"), strings.Join(added, "\n")+"\n", 0o644)
	gatetest.Git(t, g.repo, "add", "tls/new.key")
	keys["tls/new.key"] = added
	g.ok("git_diff", m{"repo": g.repo, "staged": true}, &d)
	if l := leaks(d.Diff); len(l) != 0 {
		t.Fatalf("staged diff shows %d body lines:\n%s", len(l), d.Diff)
	}
	for _, name := range []string{"tls/service.key", "tls/gone.key", odd, "tls/old.key", "tls/renamed.key", "tls/new.key"} {
		if !strings.Contains(d.Diff, excludedLine(name)) {
			t.Fatalf("staged diff does not name %q:\n%s", name, d.Diff)
		}
	}
	if !strings.Contains(d.Diff, "+port=9090") {
		t.Fatalf("staged diff lost app.conf:\n%s", d.Diff)
	}
}

// TestGitDiffKeyFileUnbornHead: in a repository with no commit yet, a
// staged key is left out of the staged diff.
func TestGitDiffKeyFileUnbornHead(t *testing.T) {
	g := newGitFixture(t, "read")
	gatetest.Git(t, g.repo, "checkout", "-q", "--orphan", "fresh")
	gatetest.Git(t, g.repo, "rm", "-q", "-r", "--cached", ".")
	key := rsaKeyLines(t)
	gatetest.WriteFile(t, filepath.Join(g.repo, "first.key"), strings.Join(key, "\n")+"\n", 0o644)
	gatetest.Git(t, g.repo, "add", "first.key", "app.conf")
	var d diffData
	g.ok("git_diff", m{"repo": g.repo, "staged": true}, &d)
	if l := bodyLeaks(d.Diff, key); len(l) != 0 || !strings.Contains(d.Diff, excludedLine("first.key")) || !strings.Contains(d.Diff, "+port=8080") {
		t.Fatalf("staged diff on an unborn branch:\n%s", d.Diff)
	}
}
