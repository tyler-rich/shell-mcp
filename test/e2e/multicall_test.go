//go:build e2e && linux

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// Multi-call binaries, GNU coreutils' single-purpose programs, programs
// whose options run another program, and #! scripts as commands (S-MC), on
// this runner's own coreutils: on Ubuntu 26.04 the uutils multi-call binary
// (/usr/bin/chown a symlink to /usr/lib/cargo/bin/coreutils/chown, one of
// its hard links) and GNU coreutils beside it under "gnu"-prefixed names
// (/usr/bin/gnuchown, /usr/bin/gnuenv, …). setup.sh declares
// /etc/shell-mcp/gate-multicall.yaml and the privileged variant
// privileged-multicall.yaml; the tests write the other policies and
// fixtures (/usr/local/bin/e2e-mc-*) themselves, and remove them. Every
// name and path is an invented fixture.

const (
	mcGatePolicy = "/etc/shell-mcp/gate-multicall.yaml"
	mcPolicyDir  = "/etc/shell-mcp/e2e-mc"
	mcOwned      = chainRoot + "/mc-owned"
)

// runAs runs a command as uid and returns its output, whatever its exit
// status (check-policy exits 1 for any FAIL); a failure to start is fatal.
func runAs(t *testing.T, uid uint32, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: fixed test commands
	if uid != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, uid)}
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	if err == nil || errors.As(err, &ee) {
		return out.String()
	}
	t.Fatalf("%s %v: %v", name, args, err)
	return ""
}

// TestMulticallRunnerLayout: the runner's coreutils are laid out as the
// other tests here expect, and the gate's table of uutils utilities is
// this uutils' own list.
func TestMulticallRunnerLayout(t *testing.T) {
	r, err := filepath.EvalSymlinks("/usr/bin/chown")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(r)
	if err != nil {
		t.Fatal(err)
	}
	if r == "/usr/bin/chown" || !bytes.Contains(b, []byte(gpolicy.MarkerForTesting("uutils"))) {
		t.Fatalf("/usr/bin/chown resolves to %s, not the uutils multi-call binary", r)
	}
	for _, p := range []string{"/usr/bin/gnuchown", "/usr/bin/gnuenv", "/usr/sbin/gnuchroot"} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("GNU coreutils' %s: %v", p, err)
		}
	}
	list := strings.Fields(run(t, "/usr/bin/coreutils", "--list"))
	slices.Sort(list)
	if got := gpolicy.UutilsApplets(); !slices.Equal(got, list) {
		t.Fatalf("the uutils table %q differs from this runner's coreutils --list %q", got, list)
	}
}

// mcFixture makes root's fixtures under /usr/local/bin: a renamed copy of
// GNU env and of GNU chown, an alias of GNU chown, and three #! scripts.
func mcFixture(t *testing.T) {
	t.Helper()
	cp := func(src, dst string) {
		in, err := os.Open(src) //nolint:gosec // G304: the runner's own binaries
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = in.Close() }()
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) //nolint:gosec // G302,G304: a fixed fixture path; an executable copy
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, in); err != nil {
			t.Fatal(err)
		}
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
	}
	cp("/usr/bin/gnuenv", "/usr/local/bin/e2e-mc-renamed-env")
	cp("/usr/bin/gnuchown", "/usr/local/bin/e2e-mc-renamed-chown")
	_ = os.Remove("/usr/local/bin/e2e-mc-alias")
	if err := os.Symlink("/usr/bin/gnuchown", "/usr/local/bin/e2e-mc-alias"); err != nil {
		t.Fatal(err)
	}
	rootFile(t, "/usr/local/bin/e2e-mc-sh-script", "#!/bin/sh\necho invented\n", 0o755)
	rootFile(t, "/usr/local/bin/e2e-mc-env-script", "#!/usr/bin/env bash\necho invented\n", 0o755)
	rootFile(t, "/usr/local/bin/e2e-mc-probe-script", "#!/usr/local/bin/example-probe\n", 0o755)
	t.Cleanup(func() {
		for _, n := range []string{"renamed-env", "renamed-chown", "alias", "sh-script", "env-script", "probe-script"} {
			_ = os.Remove("/usr/local/bin/e2e-mc-" + n)
		}
	})
}

// mcCase is one command, the template it is declared with, and what the
// gate's and the helper's check-policy say: "" for accepted, otherwise a
// FAIL line's text; the helper's with and without an acknowledge.
type mcCase struct {
	name, path, tpl     string
	gate, priv, privAck string
	gateNote, privNote  string // a line accepted policies must also print
}

func mcCases() []mcCase {
	refused := func(name, path string) mcCase {
		return mcCase{name: name, path: path, tpl: `[["--version"]]`, gate: "hard-denied", priv: "never", privAck: "never"}
	}
	cases := []mcCase{
		{name: "uutils-chown", path: "/usr/bin/chown", tpl: `[["--version"]]`,
			gateNote: "is the uutils multi-call binary; it runs as chown", privNote: "[uutils applet chown]"},
		{name: "uutils-stat", path: "/usr/bin/stat", tpl: `[["--version"]]`, privNote: "[uutils applet stat]"},
		{name: "uutils-entry", path: "/usr/bin/coreutils", tpl: `[["--version"]]`, gate: "not one of its utilities", priv: "not one of its utilities", privAck: "not one of its utilities"},
		{name: "uutils-dd", path: "/usr/bin/dd", tpl: `[["--version"]]`, gate: "hard-denied", priv: "acknowledge"},
		{name: "gnu-dd", path: "/usr/bin/gnudd", tpl: `[["--version"]]`, gate: "hard-denied", priv: "acknowledge"},
		{name: "gnu-chown", path: "/usr/bin/gnuchown", tpl: `[["--version"]]`},
		{name: "gnu-renamed-env", path: "/usr/local/bin/e2e-mc-renamed-env", tpl: `[["--version"]]`, gate: "hard-denied", priv: "never", privAck: "never"},
		{name: "gnu-renamed-chown", path: "/usr/local/bin/e2e-mc-renamed-chown", tpl: `[["--version"]]`,
			gateNote: "GNU coreutils marker", privNote: "GNU coreutils marker"},
		{name: "gnu-alias", path: "/usr/local/bin/e2e-mc-alias", tpl: `[["--version"]]`, gateNote: `runs as "gnuchown"`, privNote: `runs as "gnuchown"`},
		{name: "script-sh", path: "/usr/local/bin/e2e-mc-sh-script", tpl: `[[]]`, gate: "hard-denied", priv: "never", privAck: "never"},
		{name: "script-env", path: "/usr/local/bin/e2e-mc-env-script", tpl: `[[]]`, gate: "hard-denied", priv: "never", privAck: "never"},
		{name: "script-probe", path: "/usr/local/bin/e2e-mc-probe-script", tpl: `[[]]`,
			gateNote: "is a #! script run by /usr/local/bin/example-probe", privNote: "[#! script run by /usr/local/bin/example-probe]"},
		// F3: the gate has no rule for these options (POLICY §5); the helper
		// needs an acknowledge for each.
		{name: "sort-compress", path: "/usr/bin/sort", tpl: `[["--compress-program=gzip", "/etc/hostname"]]`, priv: "acknowledge"},
		{name: "gnusort-compress", path: "/usr/bin/gnusort", tpl: `[["--compress-program=gzip", "/etc/hostname"]]`, priv: "acknowledge"},
		{name: "sort-plain", path: "/usr/bin/sort", tpl: `[["-u", "/etc/hostname"]]`},
		{name: "split-filter", path: "/usr/bin/split", tpl: `[["--filter=cat", "/etc/hostname"]]`, priv: "acknowledge"},
		{name: "install-strip", path: "/usr/bin/install", tpl: `[["-s", "/etc/hostname", "/srv/e2e-priv-exec/root/x"]]`, priv: "acknowledge"},
	}
	for _, n := range []string{"env", "timeout", "chroot", "nice", "nohup", "stdbuf", "runcon"} {
		cases = append(cases, refused("uutils-"+n, "/usr/bin/"+n))
	}
	for _, p := range []string{"/usr/bin/gnuenv", "/usr/sbin/gnuchroot", "/usr/bin/gnutimeout", "/usr/bin/gnunice",
		"/usr/bin/gnunohup", "/usr/bin/gnustdbuf", "/usr/bin/gnuruncon"} {
		cases = append(cases, refused("gnu-"+filepath.Base(p), p))
	}
	return cases
}

// failLine returns the check-policy line that refuses command x, or "".
func failLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "FAIL") && strings.Contains(l, "commands[x]") {
			return l
		}
	}
	return ""
}

func wantCheck(t *testing.T, who, out, want, note string) {
	t.Helper()
	l := failLine(out)
	switch {
	case want == "" && l != "":
		t.Fatalf("%s refused it:\n%s", who, out)
	case want != "" && !strings.Contains(l, want):
		t.Fatalf("%s: want a FAIL line for commands[x] containing %q:\n%s", who, want, out)
	case want == "" && note != "" && !strings.Contains(out, note):
		t.Fatalf("%s: want %q:\n%s", who, note, out)
	}
}

// TestMulticallCheckPolicy: the real gate's and helper's check-policy, on
// this runner's binaries, refuse and accept each case as S-MC decides.
func TestMulticallCheckPolicy(t *testing.T) {
	mcFixture(t)
	if err := os.MkdirAll(mcPolicyDir, 0o755); err != nil { //nolint:gosec // G301: root's policy directory, as /etc/shell-mcp
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(mcPolicyDir) })
	for _, c := range mcCases() {
		t.Run(c.name, func(t *testing.T) {
			cmd := fmt.Sprintf("commands:\n  - id: x\n    path: %s\n    tier: read\n%%s    templates: %s\n", c.path, c.tpl)
			gp := filepath.Join(mcPolicyDir, c.name+"-gate.yaml")
			rootFile(t, gp, "version: 1\nmax_tier: read\npaths:\n  read: [/srv/e2e-gate]\n"+fmt.Sprintf(cmd, ""), 0o644)
			out := runAs(t, svcShell, gateBin, "check-policy", "--policy", gp)
			wantCheck(t, "gate", out, c.gate, c.gateNote)

			privHead := "version: 1\nclient_uid: 4200001\nsocket_group: svc-shell-priv\nmax_tier: operator\npaths:\n  write: [/srv/e2e-priv-exec/root]\n" +
				"owners:\n  users: [root]\n  groups: [root]\nmodes:\n  max: \"0755\"\n"
			pp := filepath.Join(mcPolicyDir, c.name+"-priv.yaml")
			rootFile(t, pp, privHead+fmt.Sprintf(cmd, ""), 0o600)
			out = runAs(t, 0, privdBin, "check-policy", "--policy", pp)
			wantCheck(t, "helper", out, c.priv, c.privNote)
			if c.priv == "acknowledge" || c.privAck != "" {
				rootFile(t, pp, privHead+fmt.Sprintf(cmd, "    acknowledge: \"e2e: invented review note\"\n"), 0o600)
				out = runAs(t, 0, privdBin, "check-policy", "--policy", pp)
				wantCheck(t, "helper, acknowledged", out, c.privAck, "")
			}
		})
	}
}

// TestMulticallGateExec: the gate runs uutils' chown and stat, under its
// sandbox, as the utilities the policy names.
func TestMulticallGateExec(t *testing.T) {
	r, _ := gatePolicyAt(t, mcGatePolicy, svcShell, "read", "exec_preview", map[string]any{"command_id": "mc-chown-version", "args": []string{"--version"}})
	if !r.OK {
		t.Fatalf("preview refused: %+v", r.Error)
	}
	if !strings.Contains(string(r.Data), `"/usr/lib/cargo/bin/coreutils/chown"`) {
		t.Fatalf("preview's argv[0] is not the resolved utility: %s", r.Data)
	}
	r, _ = gatePolicyAt(t, mcGatePolicy, svcShell, "read", "exec", map[string]any{"command_id": "mc-chown-version", "args": []string{"--version"}})
	if out := stdoutOf(t, &r); !strings.HasPrefix(out, "chown (uutils coreutils)") {
		t.Fatalf("ran as %q", out)
	}
	r, _ = gatePolicyAt(t, mcGatePolicy, svcShell, "read", "exec", map[string]any{"command_id": "mc-stat-owner", "args": []string{"--format=%U", "/srv/e2e-gate"}})
	if out := stdoutOf(t, &r); out != "root\n" {
		t.Fatalf("stat said %q", out)
	}
}

// TestMulticallHelperExec: PRIVILEGED §6's worked chown example, declared
// on uutils' /usr/bin/chown, runs in the core unit (its sandbox and
// Landlock) as chown and re-owns the one path it names; Ubuntu's
// check that uutils runs under its own name (/proc/self/exe) passes there.
func TestMulticallHelperExec(t *testing.T) {
	installPolicy(t, "privileged-multicall.yaml")
	_, r := chainExec(t, "core", "mc-chown-version", []string{"--version"}, "")
	if out := stdoutOf(t, &r); !strings.HasPrefix(out, "chown (uutils coreutils)") {
		t.Fatalf("ran as %q", out)
	}
	rootFile(t, mcOwned, "invented\n", 0o644)
	t.Cleanup(func() { _ = os.Remove(mcOwned) })
	_, r = chainExec(t, "core", "mc-chown", []string{"--no-dereference", "example-app:example-app", mcOwned}, "")
	var d struct {
		ExitCode int    `json:"exit_code"`
		Stderr   string `json:"stderr"`
	}
	if out := stdoutOf(t, &r); out != "" || json.Unmarshal(r.Data, &d) != nil || d.ExitCode != 0 {
		t.Fatalf("chown: stdout %q, %+v", out, d)
	}
	if _, uid, gid, _ := statOwner(t, mcOwned); uid != exampleApp || gid != exampleApp {
		t.Fatalf("%s is %d:%d, want example-app's", mcOwned, uid, gid)
	}
}
