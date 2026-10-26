//go:build e2e && linux

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// {path:read:fd} end to end (POLICY §4, handoff N-22): the real gate as the
// service account (svc-shell), with Landlock, passes the descriptor it
// resolved as /dev/fd/4. setup.sh declares /etc/shell-mcp/gate-fd.yaml
// over the hardening layout (/srv/e2e-gate, write root
// /srv/e2e-gate/work): probe-fd (cat, procattrs, write and a delayed cat
// of a {path:read:fd}) and probe-cat (cat of a {path:read}). Every path
// and name is an invented fixture.

const fdPolicy = "/etc/shell-mcp/gate-fd.yaml"

// fdExec previews probe-fd under the descriptor policy and runs it with
// the preview's hash (an invalid one when the preview is refused).
func fdExec(t *testing.T, args []string) (preview, run response) {
	t.Helper()
	req := map[string]any{"command_id": "probe-fd", "args": args}
	preview, _ = gatePolicyAt(t, fdPolicy, svcShell, "read", "exec_preview", req)
	hash := strings.Repeat("0", 64)
	if preview.OK {
		var p struct {
			PreviewSHA256 string `json:"preview_sha256"`
		}
		if err := json.Unmarshal(preview.Data, &p); err != nil {
			t.Fatalf("previewed %s: %v", preview.Data, err)
		}
		hash = p.PreviewSHA256
	}
	req["expected_preview_sha256"] = hash
	run, _ = gatePolicyAt(t, fdPolicy, svcShell, "read", "exec", req)
	return preview, run
}

// TestGateExecPathReadFD: the command reopens /dev/fd/4 under the gate's
// Landlock ruleset and reads the file; it holds that one descriptor; the
// preview shows it; a directory is refused.
func TestGateExecPathReadFD(t *testing.T) {
	dir := hardRoot + "/fd"
	ownDir(t, dir, 0, 0, 0o755)
	f := dir + "/app.conf"
	ownFile(t, f, "key: value\n", svcShell, 0o644)
	pr, r := fdExec(t, []string{"cat", f})
	if out := stdoutOf(t, &r); !pr.OK || out != "READ:key: value\n\n" {
		t.Fatalf("preview %+v %s, ran %q", pr.Error, pr.Data, out)
	}
	var p struct {
		Argv []string `json:"argv"`
		Fds  []struct {
			FD   int    `json:"fd"`
			Path string `json:"path"`
		} `json:"fds"`
	}
	if err := json.Unmarshal(pr.Data, &p); err != nil || len(p.Argv) != 3 || p.Argv[2] != "/dev/fd/4" || len(p.Fds) != 1 || p.Fds[0].FD != 4 || p.Fds[0].Path != f {
		t.Fatalf("preview %s", pr.Data)
	}
	_, r = fdExec(t, []string{"procattrs", f})
	var held []string
	for _, l := range strings.Split(stdoutOf(t, &r), "\n") {
		if v, ok := strings.CutPrefix(l, "fds="); ok {
			for _, x := range strings.Split(v, ",") {
				if x != "" && !strings.HasPrefix(x, "3:100000:/sys/fs/cgroup/") {
					held = append(held, x)
				}
			}
		}
	}
	if len(held) != 1 || held[0] != "4:100000:"+f {
		t.Fatalf("the command holds %v, want only 4 on %s", held, f)
	}
	pr, r = fdExec(t, []string{"cat", dir})
	if pr.code() != "is_a_directory" || r.code() != "is_a_directory" {
		t.Fatalf("a directory: preview %s %+v, exec %s", pr.code(), pr.Error, r.code())
	}
}

// TestGateExecPathReadFDWritable: "read-only" describes the gate's
// descriptor. A command reopening /dev/fd/4 gets a new open, governed by
// the file's permissions and the gate's Landlock roots as for {path:read}:
// a file the service account may write, under a write root, is written; one
// under a read root only, or one it may not write, is not.
func TestGateExecPathReadFDWritable(t *testing.T) {
	w := hardWork + "/fdw"
	ownDir(t, w, svcShell, svcShell, 0o755)
	writable := w + "/t"
	ownFile(t, writable, "before\n", svcShell, 0o644)
	others := w + "/others"
	ownFile(t, others, "before\n", exampleApp, 0o644)
	ro := hardRoot + "/fdro"
	ownDir(t, ro, 0, 0, 0o755)
	readOnly := ro + "/t"
	ownFile(t, readOnly, "before\n", svcShell, 0o644)
	for _, c := range []struct {
		name, path, out, content string
	}{
		{"under a write root, the service account's", writable, "WROTE\n", "probe"},
		{"under a read root only", readOnly, "EACCES\n", "before\n"},
		{"under a write root, another account's 0644", others, "EACCES\n", "before\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, r := fdExec(t, []string{"write", c.path})
			if out := stdoutOf(t, &r); out != c.out {
				t.Fatalf("write through /dev/fd/4: %q, want %q", out, c.out)
			}
			fileIs(t, c.path, c.content)
		})
	}
}

// TestGateExecPathReadFDRenamedOut: a file renamed out of the read roots
// after the gate opened it cannot be reopened through /dev/fd/4 (Landlock
// checks the file where it now is); renamed within the roots, it is read.
func TestGateExecPathReadFDRenamedOut(t *testing.T) {
	dir := hardRoot + "/fdmv"
	ownDir(t, dir, 0, 0, 0o755)
	outside := "/srv/e2e-fd-outside"
	ownDir(t, outside, 0, 0, 0o755)
	for _, c := range []struct {
		name, to, want string
	}{
		{"within the read root", dir + "/moved", "READ:ORIGINAL\n\n"},
		{"out of the read roots", outside + "/moved", "EACCES\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := dir + "/t"
			ownFile(t, f, "ORIGINAL\n", svcShell, 0o644)
			_ = os.Remove(c.to)
			done := make(chan []byte, 1)
			as := cred(t, svcShell)
			go func() { done <- runGateLine(fdPolicy, as, fdExecLine([]string{"sleep-cat", "3s", f})) }()
			if !waitForProcess("sleep-cat", 10*time.Second) {
				t.Fatal("the command did not start")
			}
			if err := os.Rename(f, c.to); err != nil {
				t.Fatal(err)
			}
			var r response
			out := <-done
			if err := json.Unmarshal(out, &r); err != nil {
				t.Fatalf("gate: %q: %v", out, err)
			}
			if got := stdoutOf(t, &r); got != c.want {
				t.Fatalf("read %q, want %q", got, c.want)
			}
		})
	}
}

// TestGateExecOwnerMatchedReadFDRace: the twin of
// TestGateExecOwnerMatchedReadRace with {path:read:fd}. example-app swaps
// its target, or a directory above it, for a symlink to a file only the
// service account can read, to a denied file, or to root's file; the
// command reads the file the gate opened, or the request is refused, in
// every round, while the string form (the existing test) reaches them.
func TestGateExecOwnerMatchedReadFDRace(t *testing.T) {
	vault := hardWork + "/vault-read-fd"
	ownDir(t, vault, svcShell, svcShell, 0o700)
	ownFile(t, vault+"/t", "SERVICE-ONLY\n", svcShell, 0o600)
	denied := hardWork + "/denied"
	ownDir(t, denied, svcShell, svcShell, 0o755)
	ownFile(t, denied+"/t", "DENIED\n", svcShell, 0o644)
	rootVault := hardWork + "/root-only-fd"
	ownDir(t, rootVault, 0, 0, 0o700)
	rootFile(t, rootVault+"/t", "ROOT-ONLY\n", 0o600)
	race := hardRoot + "/race-fd"
	for _, c := range []struct {
		name, target, swap, to string
	}{
		{"the target, to the service account's file", "t", "t", vault + "/t"},
		{"the target, to a denied file", "t", "t", denied + "/t"},
		{"a directory above the target, to the service account's directory", "sub/t", "sub", vault},
		{"the target, to root's file", "t", "t", rootVault + "/t"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ownDir(t, race, exampleApp, exampleApp, 0o755)
			if err := os.Mkdir(race+"/sub", 0o700); err != nil {
				t.Fatal(err)
			}
			setDir(t, race+"/sub", exampleApp, exampleApp, 0o755)
			ownFile(t, race+"/t", "decoy\n", exampleApp, 0o644)
			ownFile(t, race+"/sub/t", "decoy\n", exampleApp, 0o644)
			stop := startRacer(t, "SWAPS", "E2E_CLIENT=swap", "E2E_SWAP_NAME="+filepath.Join(race, c.swap),
				"E2E_SWAP_ALT="+filepath.Join(race, c.swap+".alt"), "E2E_SWAP_TO="+c.to)
			target := filepath.Join(race, c.target)
			got := map[string]int{}
			for i := range 60 {
				pr, er := fdExec(t, []string{"cat", target})
				out := ""
				if er.OK {
					var d struct {
						Stdout string `json:"stdout"`
					}
					_ = json.Unmarshal(er.Data, &d)
					out = d.Stdout
				}
				switch {
				case strings.Contains(string(pr.Data)+string(er.Data), "SERVICE-ONLY") || strings.Contains(string(pr.Data)+string(er.Data), "DENIED") ||
					strings.Contains(string(pr.Data)+string(er.Data), "ROOT-ONLY"):
					stop()
					t.Fatalf("run %d: the command read through the swap: %s", i, er.Data)
				case out == "READ:decoy\n\n":
					got["decoy"]++
				case er.OK:
					got["not read: "+strings.TrimSpace(out)]++
				default:
					got[er.code()]++
				}
			}
			n := stop()
			if n == 0 {
				t.Fatal("the racer did not swap")
			}
			if got["decoy"] == 0 {
				t.Fatalf("no request read the file: %v", got)
			}
			t.Logf("reads %v; the racer made %d exchanges", got, n)
		})
	}
}

// TestGateProtocolVersions: the real gate answers a version 1 request (a
// 0.1.0 server's) with protocol_mismatch in version 1's frame, naming the
// server as the side to upgrade, and a version 3 request in its own
// version, naming the gate.
func TestGateProtocolVersions(t *testing.T) {
	for _, c := range []struct {
		v, frame int
		want     string
	}{
		{1, 1, "upgrade the server (shell-mcp)"},
		{3, 2, "upgrade shell-mcp-gate and shell-mcp-privd on this host"},
	} {
		line := fmt.Sprintf(`{"v":%d,"id":%q,"ceiling":"read","op":"hello","args":{},"timeout_ms":30000}`+"\n", c.v, newID())
		var r response
		out := runGateLine(fdPolicy, cred(t, svcShell), line)
		if err := json.Unmarshal(out, &r); err != nil || r.V != c.frame || r.code() != "protocol_mismatch" || !strings.Contains(r.Error.Message, c.want) {
			t.Fatalf("v%d: %q", c.v, out)
		}
	}
}

// fdExecLine is an exec request line under the descriptor policy, without
// a preview hash (a read command).
func fdExecLine(args []string) string {
	a, _ := json.Marshal(map[string]any{"command_id": "probe-fd", "args": args})
	return fmt.Sprintf(`{"v":%d,"id":%q,"ceiling":"read","op":"exec","args":%s,"timeout_ms":30000}`+"\n", protocol.Version, newID(), a)
}

// runGateLine runs the installed gate with credentials c on one raw
// request line and returns its output (or the error as text); it never
// calls t, so it may run in a goroutine.
func runGateLine(policy string, c *syscall.Credential, line string) []byte {
	cmd := exec.Command(gateBin, "serve", "--policy", policy, "--principal", "e2e") //nolint:gosec,noctx // G204: the installed gate with one of setup.sh's policies; bounded by the request's timeout
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: c}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = "/"
	cmd.Stdin = strings.NewReader(line)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return []byte(fmt.Sprintf("gate: %v: %s", err, out.String()))
	}
	return out.Bytes()
}

// waitForProcess waits until a process whose command line holds word runs.
func waitForProcess(word string, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		ents, _ := os.ReadDir("/proc")
		for _, e := range ents {
			b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
			if err == nil && bytes.Contains(b, []byte(word)) && !bytes.Contains(b, []byte("e2e.test")) {
				return true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
