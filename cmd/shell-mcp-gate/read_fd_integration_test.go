//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// fdIntegrationCommand gives the probe a {path:read:fd} (handoff N-22):
// read it, write through it, or read it after a pause.
const fdIntegrationCommand = `  - id: probe-fd
    path: {BIN}/probe
    tier: read
    templates: [["cat", "{path:read:fd}"], ["write", "{path:read:fd}"], ["sleep-cat", "{enum:2s}", "{path:read:fd}"]]
`

// TestIntegrationSandboxPathReadFD: the real gate, inside its Landlock
// domain, passes a {path:read:fd} as /dev/fd/4, and the command's reopen
// of it is checked against the file where it is, as any open is:
//   - a file under a read root is read;
//   - "read-only" is the gate's descriptor only: the command's reopen for
//     writing is governed by the roots, so a file under a write root is
//     written and one under a read root only is not (EACCES);
//   - a file renamed out of every root after the gate opened it cannot be
//     reopened (EACCES), while one renamed within the root is read.
func TestIntegrationSandboxPathReadFD(t *testing.T) {
	needABI(t, 1)
	g := newGate(t)
	g.rawPolicy(strings.NewReplacer("{TIER}", "destructive", "{MODE}", defaultMode(), "{PORTS}", "").Replace(integrationPolicy) + fdIntegrationCommand)
	run := func(args ...string) string {
		t.Helper()
		r := g.want(g.call("exec", m{"command_id": "probe-fd", "args": args}), "")
		var d execOut
		if err := json.Unmarshal(r.Data, &d); err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(d.Stdout)
	}

	inRead := filepath.Join(g.read, "fd.txt")
	gatetest.WriteFile(t, inRead, "IN-ROOT", 0o644)
	if out := run("cat", inRead); out != "READ:IN-ROOT" {
		t.Fatalf("read through /dev/fd/4: %q", out)
	}

	t.Run("writes follow the roots", func(t *testing.T) {
		inWrite := filepath.Join(g.write, "fd.txt")
		gatetest.WriteFile(t, inWrite, "before", 0o644)
		if out := run("write", inWrite); out != "WROTE" {
			t.Fatalf("under the write root: %q", out)
		}
		if b, _ := os.ReadFile(inWrite); string(b) != "probe" { //nolint:gosec // G304: the test's own fixture
			t.Fatalf("under the write root: content %q", b)
		}
		if out := run("write", inRead); out != "EACCES" {
			t.Fatalf("under a read root only: %q", out)
		}
		if b, _ := os.ReadFile(inRead); string(b) != "IN-ROOT" { //nolint:gosec // G304: the test's own fixture
			t.Fatalf("under a read root only: content %q", b)
		}
	})

	for _, c := range []struct{ name, to, want string }{
		{"renamed within the root", filepath.Join(g.read, "moved.txt"), "READ:ORIGINAL"},
		{"renamed out of every root", filepath.Join(g.outside, "moved.txt"), "EACCES"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := filepath.Join(g.read, "t.txt")
			gatetest.WriteFile(t, f, "ORIGINAL", 0o644)
			a, _ := json.Marshal(m{"command_id": "probe-fd", "args": []string{"sleep-cat", "2s", f}})
			cmd := exec.CommandContext(t.Context(), harness(t), "serve", "--policy", g.pol, "--principal", "test") //nolint:gosec // G204: the test's own harness
			cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, g.env...)
			cmd.Stdin = strings.NewReader(fmt.Sprintf(`{"v":%d,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"exec","args":%s,"timeout_ms":10000}`+"\n", protocol.Version, a))
			var out bytes.Buffer
			cmd.Stdout = &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if !waitForArgv(g.probe, "sleep-cat", 5*time.Second) {
				_ = cmd.Wait()
				t.Fatalf("the command did not start: %q", out.String())
			}
			if err := os.Rename(f, c.to); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
			var r struct {
				OK   bool `json:"ok"`
				Data struct {
					Stdout string `json:"stdout"`
				} `json:"data"`
			}
			if json.Unmarshal(out.Bytes(), &r) != nil || !r.OK || strings.TrimSpace(r.Data.Stdout) != c.want {
				t.Fatalf("got %q, want stdout %q", out.String(), c.want)
			}
		})
	}
}

// waitForArgv waits until a process runs bin with word among its
// arguments.
func waitForArgv(bin, word string, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		ents, _ := os.ReadDir("/proc")
		for _, e := range ents {
			b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
			if err == nil && bytes.HasPrefix(b, []byte(bin+"\x00")) && bytes.Contains(b, []byte("\x00"+word+"\x00")) {
				return true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
