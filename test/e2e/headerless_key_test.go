//go:build e2e && linux

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Headerless key text end to end (handoff N-35), through the real server
// (read-only profile), sshd and gate with the read policy: a service that
// logged a private key line by line, read with journal windows that begin
// inside its body, and a committed key file with one changed body line in
// the read repository, whose diff leaves the file out. The keys are
// generated for each run (RSA 2048, PKCS #8); every name and path is
// invented.

const diffKeyName = "tls/service.key"

var diffKey, diffKeyMod []string

// pemLines returns a newly generated key as lines: BEGIN, body, END.
func pemLines() ([]string, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))), "\n"), nil
}

func shownBody(out string, keys ...[]string) []string {
	var hit []string
	for _, k := range keys {
		for _, l := range k[1 : len(k)-1] {
			if strings.Contains(out, l) {
				hit = append(hit, l)
			}
		}
	}
	return hit
}

// TestReadToolJournalHeaderlessKey: the key is logged by a transient unit
// the read policy lists (cat of the key file: journald stores each line of
// its stdout as an entry), followed by an ordinary line; shell_get_journal
// with 12 lines (a window that begins inside the body) and with 100 (one
// that holds the BEGIN line) shows no body line and keeps the ordinary
// line.
func TestReadToolJournalHeaderlessKey(t *testing.T) {
	server(t)
	key, err := pemLines()
	if err != nil {
		t.Fatal(err)
	}
	marker := "example-keylog listening " + randomHex(8)
	src := filepath.Join(t.TempDir(), "keylog.txt")
	if err := os.WriteFile(src, []byte(strings.Join(key, "\n")+"\n"+marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	//nolint:gosec // G204: fixed argv; the file is this run's fixture
	if out, err := exec.CommandContext(ctx, "systemd-run", "--quiet", "--wait", "--collect", "--unit=example-keylog.service",
		"/usr/bin/cat", src).CombinedOutput(); err != nil {
		t.Fatalf("systemd-run: %v: %s", err, out)
	}
	for i := 0; ; i++ {
		out, _ := exec.CommandContext(ctx, "journalctl", "--no-pager", "-u", "example-keylog.service", "-o", "cat").Output()
		if strings.Contains(string(out), marker) {
			break
		}
		if i == 50 {
			t.Fatal("the journal lines did not appear")
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, n := range []int{12, 100} {
		d := okData(t, callTool(t, "shell_get_journal", map[string]any{"unit": "example-keylog.service", "since": "-1h", "lines": n}))
		out, _ := d["output"].(string)
		if hit := shownBody(out, key); len(hit) != 0 {
			t.Fatalf("lines=%d: %d body lines shown:\n%s", n, len(hit), out)
		}
		if !strings.Contains(out, marker) {
			t.Fatalf("lines=%d: the ordinary line is missing:\n%s", n, out)
		}
	}
}

// TestReadToolGitDiffKeyFile: the key file's change (one body line, whose
// hunk's context lines and header are body lines too) is left out of
// shell_get_git_diff and named in a mask line; the repository's other
// change is shown.
func TestReadToolGitDiffKeyFile(t *testing.T) {
	server(t)
	d := okData(t, callTool(t, "shell_get_git_diff", map[string]any{"repo": readRepo}))
	diff, _ := d["diff"].(string)
	if hit := shownBody(diff, diffKey, diffKeyMod); len(hit) != 0 {
		t.Fatalf("%d body lines shown:\n%s", len(hit), diff)
	}
	if want := fmt.Sprintf("[REDACTED] %q: holds a private key; its changes are not shown\n", diffKeyName); !strings.Contains(diff, want) {
		t.Fatalf("the key file is not named:\n%s", diff)
	}
	if !strings.Contains(diff, "+version: 2") {
		t.Fatalf("the other change is missing:\n%s", diff)
	}
}
