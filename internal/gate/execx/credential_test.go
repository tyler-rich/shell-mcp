//go:build linux

package execx_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// requireRootEnv makes the root-only tests fail instead of skip: set by
// scripts/setup-check (as the container's root) and e2e-host (as root), so
// that they cannot pass there merely by skipping.
const requireRootEnv = "SHELL_MCP_REQUIRE_ROOT_TESTS"

// requireRoot skips a test that needs a root test process, unless
// requireRootEnv is 1, which turns the skip into a failure.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() == 0 && os.Geteuid() == 0 {
		return
	}
	if os.Getenv(requireRootEnv) == "1" {
		t.Fatalf("%s=1 but the test process runs as uid %d (euid %d); the credential tests must run as root", requireRootEnv, os.Getuid(), os.Geteuid())
	}
	t.Skipf("needs a root test process (uid %d); runs in scripts/setup-check and e2e-host", os.Getuid())
}

// The account the credential tests switch to: ids from the documented test
// range (test/e2e/setup.sh) that no file needs; nothing creates them.
const (
	credUID    = 4200006
	credGID    = 4200007
	credGroup1 = 4200008
	credGroup2 = 4200009
)

// openProbe is the probe in a directory any account may search, so that the
// command can still be executed after the switch.
func openProbe(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "execx-cred")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // G302: the account must reach the probe
		t.Fatal(err)
	}
	for p := d; p != "/"; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm()&0o001 == 0 {
			t.Fatalf("%s is not searchable by other accounts; the credential tests need a TMPDIR they can reach (TMPDIR=/tmp)", p)
		}
	}
	return gatetest.BuildProbe(t, d, "probe", "/nonexistent")
}

func credRun(t *testing.T, p string, cred *execx.Credential, args ...string) execx.Result {
	t.Helper()
	r, err := execx.Run(context.Background(), &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: args, Env: execx.Environment("/nonexistent-home"),
		Timeout: 10 * time.Second, MaxOutput: 1 << 20, Trampoline: gatetest.Trampoline(t), Credential: cred})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.ExitCode == nil || *r.ExitCode != 0 {
		t.Fatalf("%v: exit %v signal %q, stderr %s", args, r.ExitCode, r.Signal, r.Stderr)
	}
	return r
}

// status parses the probe's "creds" lines into field → value.
func status(out []byte) map[string]string {
	m := map[string]string{}
	for _, l := range lines(out) {
		k, v, _ := strings.Cut(l, ":")
		m[k] = strings.Join(strings.Fields(v), " ")
	}
	return m
}

// TestCredentialRefusedWhenNotRoot: in a process that is not uid 0, a
// credential is refused with a CredentialError naming the option and the
// caller's uid, before anything starts. The trampoline path does not exist
// and the command would write a file: neither is ever reached.
func TestCredentialRefusedWhenNotRoot(t *testing.T) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("runs as a non-root test process; the root tests cover the root caller")
	}
	marker := filepath.Join(t.TempDir(), "ran")
	_, err := execx.Run(context.Background(), &execx.Spec{MaxMemoryMB: testMemoryMB, Path: probePath(t), Args: []string{"write", marker},
		Timeout: 10 * time.Second, MaxOutput: 1 << 20, Trampoline: "/nonexistent/trampoline",
		Credential: &execx.Credential{UID: credUID, GID: credGID}})
	var ce *execx.CredentialError
	if !errors.As(err, &ce) {
		t.Fatalf("Run: %v, want a CredentialError", err)
	}
	if !errors.Is(err, execx.ErrStart) || ce.UID != os.Getuid() || ce.EUID != os.Geteuid() {
		t.Fatalf("refusal %+v", ce)
	}
	if msg := err.Error(); !strings.Contains(msg, "Spec.Credential") || !strings.Contains(msg, "uid 0") {
		t.Fatalf("message %q must name the option and that it needs uid 0", msg)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the command ran: %v", err)
	}
}

// TestCredentialSwitch: the command runs with exactly the account's real,
// effective, saved and filesystem uid and gid and exactly its groups (none
// of the root test process's own, group 0 among them), no permitted,
// effective or ambient capability, no_new_privs set, and SIGKILL as its
// parent-death signal again (the kernel clears it on the switch).
func TestCredentialSwitch(t *testing.T) {
	requireRoot(t)
	p := openProbe(t)
	cred := &execx.Credential{UID: credUID, GID: credGID, Groups: []uint32{credGroup2, credGroup1}}
	got := status(credRun(t, p, cred, "creds").Stdout)
	for k, want := range map[string]string{
		"Uid": "4200006 4200006 4200006 4200006", "Gid": "4200007 4200007 4200007 4200007", "Groups": "4200008 4200009",
		"CapPrm": "0000000000000000", "CapEff": "0000000000000000", "CapAmb": "0000000000000000", "NoNewPrivs": "1",
	} {
		if got[k] != want {
			t.Errorf("%s: %q, want %q", k, got[k], want)
		}
	}
	a := procAttrs(credRun(t, p, cred, "procattrs").Stdout)
	if a["pdeathsig"] != "9" || a["pdeathsig_thread"] != "main" || a["pgid_is_pid"] != "true" {
		t.Errorf("attributes after the switch %v", a)
	}
	if extra := extraFDs(a["fds"]); len(extra) > 0 {
		t.Errorf("the command has descriptors it was not given: %v", extra)
	}
}

// TestCredentialNoGroups: an empty group list leaves the command in no
// supplementary group at all.
func TestCredentialNoGroups(t *testing.T) {
	requireRoot(t)
	got := status(credRun(t, openProbe(t), &execx.Credential{UID: credUID, GID: credGID}, "creds").Stdout)
	if got["Groups"] != "" || got["Uid"] != "4200006 4200006 4200006 4200006" {
		t.Fatalf("creds %v", got)
	}
}

// TestCredentialNPROC: the command's RLIMIT_NPROC counts the account's
// tasks (none here) plus ChildExtraTasks, as for any command of a non-root
// process; root's exemption does not carry over.
func TestCredentialNPROC(t *testing.T) {
	requireRoot(t)
	r := credRun(t, openProbe(t), &execx.Credential{UID: credUID, GID: credGID}, "rlimits")
	got := map[string]string{}
	for _, l := range lines(r.Stdout) {
		k, v, _ := strings.Cut(l, "=")
		got[k] = v
	}
	if got["nproc"] != "256/256" || got["core"] != "0/0" || got["nofile"] != "1024/1024" {
		t.Fatalf("rlimits %v, want nproc 256/256 (the account's 0 tasks + %d)", got, execx.ChildExtraTasks)
	}
}

// TestCredentialRefusedValuesAsRoot: as root too, a credential of root's
// ids or with a bad group list is refused before anything starts.
func TestCredentialRefusedValuesAsRoot(t *testing.T) {
	requireRoot(t)
	for _, c := range []*execx.Credential{
		{UID: 0, GID: credGID}, {UID: credUID, GID: 0}, {UID: credUID, GID: credGID, Groups: []uint32{0}},
		{UID: credUID, GID: credGID, Groups: []uint32{credGroup1, credGroup1}},
	} {
		marker := filepath.Join(t.TempDir(), "ran")
		_, err := execx.Run(context.Background(), &execx.Spec{MaxMemoryMB: testMemoryMB, Path: probePath(t), Args: []string{"write", marker},
			Timeout: 10 * time.Second, MaxOutput: 1 << 20, Trampoline: "/nonexistent/trampoline", Credential: c})
		var ce *execx.CredentialError
		if !errors.As(err, &ce) {
			t.Fatalf("%+v: %v, want a CredentialError", c, err)
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%+v: the command ran", c)
		}
	}
}

// TestNilCredentialAsRoot: without a credential a root caller's command
// still runs as root, as before (the helper's commands).
func TestNilCredentialAsRoot(t *testing.T) {
	requireRoot(t)
	got := status(credRun(t, openProbe(t), nil, "creds").Stdout)
	if got["Uid"] != "0 0 0 0" {
		t.Fatalf("creds %v", got)
	}
}
