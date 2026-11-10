//go:build e2e && linux

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// The install commands on the runner (handoff §3.8, TARGET-SETUP §12). The
// file sorts last so that what it changes on this disposable VM (the
// helper's units, the runner's own sshd drop-in) is changed after every
// other test, and each test restores it in a cleanup registered before its
// first change.

// The test account (setup.sh's documented test id range, distinct from
// every other e2e account) and its invented policy.
const (
	installUser       = "svc-install"
	installUID        = 4200005
	installTestPolicy = "/etc/shell-mcp/e2e-install.yaml"
	installRoot       = "/srv/e2e-install"
	runnerDropIns     = "/etc/ssh/sshd_config.d"
	runnerDropIn      = runnerDropIns + "/60-shell-mcp.conf"
	runnerKeysDir     = "/etc/ssh/authorized_keys.d"
	runnerKeys        = runnerKeysDir + "/" + installUser
	installSlice      = "/etc/systemd/system/user-4200005.slice.d"
)

// runCode runs a command and returns its combined output and exit code.
func runCode(t *testing.T, name string, args ...string) (output string, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // G204: fixed test commands
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	}
	t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	return "", -1
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func dirNames(t *testing.T, d string) []string {
	t.Helper()
	ents, err := os.ReadDir(d)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// effective is sshd -T -C's value of key for spec, from the runner's own
// configuration.
func effective(t *testing.T, spec, key string) string {
	t.Helper()
	out := run(t, "/usr/sbin/sshd", "-T", "-C", spec)
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, " "); ok && k == key {
			return v
		}
	}
	return ""
}

// TestInstallGateOnRunnerSSHD: shell-mcp-gate install for the svc-install
// account against the runner VM's own sshd (handoff §7 Q3): it writes only
// the drop-in and that account's keys file (and the slice drop-in), the
// Match block reaches no other account, the account logs in with the key
// and reaches the gate, a second run changes nothing, the audit lines are in
// the journal, and afterwards the runner's sshd_config.d and
// authorized_keys.d are as they were and no value of the block remains.
func TestInstallGateOnRunnerSSHD(t *testing.T) {
	for _, p := range []string{runnerDropIn, runnerKeys} {
		if exists(p) {
			t.Fatalf("refusing to start: %s exists on this runner, and the test may not overwrite it", p)
		}
	}
	dropInsBefore := dirNames(t, runnerDropIns)
	keysDirBefore := exists(runnerKeysDir)
	keysBefore := dirNames(t, runnerKeysDir)
	other := "user=svc-shell,host=client.example.test,addr=127.0.0.1"
	otherKeysFile := effective(t, other, "authorizedkeysfile")
	// The runner's sshd as found; when neither unit is active the test
	// starts ssh.service (approved under handoff §7 Q3) and stops it again in
	// a cleanup that runs even on failure, then checks it is back as found.
	active := func(u string) bool { _, code := runCode(t, "systemctl", "is-active", "--quiet", u); return code == 0 }
	serviceBefore, socketBefore := active("ssh.service"), active("ssh.socket")
	if !serviceBefore && !socketBefore {
		t.Cleanup(func() {
			if out, code := runCode(t, "systemctl", "stop", "ssh.service"); code != 0 {
				t.Errorf("cleanup: stop ssh.service: %s", out)
			}
			if active("ssh.service") || active("ssh.socket") {
				t.Error("cleanup: the runner's ssh units are not back as found (neither active)")
			}
		})
		run(t, "systemctl", "start", "ssh.service")
	}

	run(t, "install", "-o", "root", "-g", "root", "-m", "0755", "-d", installRoot)
	pol := "version: 1\nmax_tier: read\nsandbox:\n  landlock: required\npaths:\n  read: [" + installRoot + "]\njournal:\n  units: [example-app.service]\n"
	if err := os.WriteFile(installTestPolicy, []byte(pol), 0o644); err != nil { //nolint:gosec // G306: a gate policy is root:root 0644
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spk, _ := ssh.NewPublicKey(pub)
	keyFile := filepath.Join(t.TempDir(), "ssh_key.pub")
	if err = os.WriteFile(keyFile, ssh.MarshalAuthorizedKey(spk), 0o644); err != nil { //nolint:gosec // G306: a public key
		t.Fatal(err)
	}

	// The cleanup, registered before the first write: both files (and the
	// keys directory if this test created it), the slice drop-in, the
	// reload, and the check that nothing of the block remains.
	t.Cleanup(func() {
		for _, p := range []string{runnerDropIn, runnerKeys, filepath.Join(installSlice, "50-shell-mcp.conf")} {
			if rerr := os.Remove(p); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				t.Errorf("cleanup: %v", rerr)
			}
		}
		for _, d := range []string{installSlice, runnerKeysDir} {
			if d == runnerKeysDir && keysDirBefore {
				continue
			}
			if rerr := os.Remove(d); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				t.Errorf("cleanup: %v", rerr)
			}
		}
		_, _ = runCode(t, "systemctl", "daemon-reload")
		if _, code := runCode(t, "systemctl", "is-active", "--quiet", "ssh.service"); code == 0 {
			if out, code := runCode(t, "systemctl", "reload", "ssh.service"); code != 0 {
				t.Errorf("cleanup: reload ssh.service: %s", out)
			}
		}
		if got := dirNames(t, runnerDropIns); !slices.Equal(got, dropInsBefore) {
			t.Errorf("cleanup: %s holds %v, before the test %v", runnerDropIns, got, dropInsBefore)
		}
		if got := dirNames(t, runnerKeysDir); exists(runnerKeysDir) != keysDirBefore || !slices.Equal(got, keysBefore) {
			t.Errorf("cleanup: %s is not as it was (%v, before %v)", runnerKeysDir, got, keysBefore)
		}
		spec := "user=" + installUser + ",host=client.example.test,addr=127.0.0.1"
		for _, k := range []string{"authorizedkeysfile", "authenticationmethods", "maxsessions"} {
			if v := effective(t, spec, k); v == map[string]string{"authorizedkeysfile": runnerKeysDir + "/%u", "authenticationmethods": "publickey", "maxsessions": "8"}[k] {
				t.Errorf("cleanup: sshd -T -C %s still shows %s %s", spec, k, v)
			}
		}
	})

	start := time.Now()
	args := []string{"install", "--policy", installTestPolicy, "--principal", "e2e-install", "--from", "127.0.0.1", "--key", keyFile,
		"--user", installUser, "--uid", "4200005", "--gid", "4200005", "--home", "/var/lib/" + installUser,
		"--owner-scan-paths", "/etc,/home,/srv,/var/lib"}
	out, code := runCode(t, gateBin, args...)
	t.Logf("install:\n%s", out)
	if code != 0 {
		t.Fatalf("install exit %d", code)
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(readFile(t, "/etc/ssh/ssh_host_ed25519_key.pub")))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "SHELL_MCP_TARGET_HOST_KEYS=ssh-ed25519 "+ssh.FingerprintSHA256(hostKey)+"\n") || !strings.Contains(out, "WARN owner scan narrowed") {
		t.Fatal("install did not print the runner's pin or the narrowed-scan WARN")
	}
	// The slice drop-in in force.
	if s := run(t, "systemctl", "show", "-p", "MemoryMax", "-p", "MemorySwapMax", "user-4200005.slice"); !strings.Contains(s, "MemoryMax=4294967296") || !strings.Contains(s, "MemorySwapMax=0") {
		t.Fatalf("slice: %s", s)
	}
	// The block reaches only svc-install.
	if got := effective(t, other, "authorizedkeysfile"); got != otherKeysFile {
		t.Fatalf("svc-shell's authorizedkeysfile changed: %q, before %q", got, otherKeysFile)
	}
	// A login with the key reaches the gate as the account.
	signer, _ := ssh.NewSignerFromKey(priv)
	c, err := sshx.New(&config.Target{Name: "runner", Host: "127.0.0.1", Port: 22, User: installUser,
		HostKeys: []config.HostKey{{Type: hostKey.Type(), Fingerprint: ssh.FingerprintSHA256(hostKey)}}, Key: config.PrivateKeyFromSigner(signer)},
		sshx.Options{ConnectTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	r, err := hello(t, c)
	if err != nil || r.Gate == nil || r.Gate.Principal != "e2e-install" {
		t.Fatalf("hello over the runner's sshd: %+v %v", r, err)
	}
	// Again: nothing to do.
	if out, code := runCode(t, gateBin, args...); code != 0 || !strings.Contains(out, "nothing to do: every item unchanged") {
		t.Fatalf("second run %d:\n%s", code, out)
	}
	// The audit lines, in the journal under the gate's tag.
	findJournal(t, "shell-mcp-gate", start, `"event":"install"`, `"object":"key"`, `"user":"svc-install"`)
	findJournal(t, "shell-mcp-gate", start, `"event":"install"`, `"object":"owner_scan"`, `"owner_scan":"narrowed"`)
}

func fileHash(t *testing.T, p string) string {
	t.Helper()
	s := sha256.Sum256([]byte(readFile(t, p)))
	return hex.EncodeToString(s[:])
}

// TestPrivdInstallOnRunner: shell-mcp-privd install with the runner's
// systemd: setup.sh's units (written by units --out) are found unchanged; a
// policy edit gives helper_policy_mismatch until install --accept with the
// new hash, which restarts the changed socket and serves again; a policy
// that drops the broad unit disables its socket and removes the pair; and
// the installed policy is restored, broad pair included, afterwards.
func TestPrivdInstallOnRunner(t *testing.T) {
	orig := readFile(t, privPolicy)
	origHash := fileHash(t, privPolicy)
	privd := func(args ...string) (string, int) {
		return runCode(t, privdBin, append([]string{"install", "--policy", privPolicy}, args...)...)
	}
	restore := func() {
		if err := os.WriteFile(privPolicy, []byte(orig), 0o600); err != nil {
			t.Errorf("restore: %v", err)
			return
		}
		if out, code := privd("--gate-policy", gatePolicy, "--accept", origHash); code != 0 {
			t.Errorf("restore: install exit %d:\n%s", code, out)
		}
	}
	t.Cleanup(restore)
	start := time.Now()

	// Without --accept it stops for review, also for the installed policy.
	if out, code := privd("--gate-policy", gatePolicy); code != 3 || !strings.Contains(out, "--accept "+origHash) {
		t.Fatalf("review stop: exit %d:\n%s", code, out)
	}
	// setup.sh's units are exactly install's.
	if out, code := privd("--gate-policy", gatePolicy, "--accept", origHash); code != 0 || !strings.Contains(out, "nothing to do: every item unchanged") {
		t.Fatalf("over setup.sh's units: exit %d:\n%s", code, out)
	}

	// An edit: refused until installed.
	if err := os.WriteFile(privPolicy, []byte(orig+"# edited by the install test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantGate(t, svcShell, "priv_stat", map[string]any{"path": "/etc/example-app"}, "helper_policy_mismatch")
	out, code := privd("--gate-policy", gatePolicy, "--accept", fileHash(t, privPolicy))
	t.Logf("install after an edit:\n%s", out)
	if code != 0 || !strings.Contains(out, "ran systemctl restart shell-mcp-privd.socket") {
		t.Fatalf("install after the edit: exit %d", code)
	}
	if !regexp.MustCompile(`(ok   |WARN )systemd-analyze security shell-mcp-privd@.service: \d\.\d`).MatchString(out) {
		t.Error("install printed no exposure level for the core unit")
	}
	mustGate(t, "priv_stat", map[string]any{"path": "/etc/example-app"}, nil)

	// A policy without the broad unit: its socket disabled, the pair removed.
	core := "version: 1\nclient_uid: 4200001\nsocket_group: svc-shell-priv\nmax_tier: read\nsandbox:\n  landlock: required\npaths:\n  read: [/etc/example-app]\n"
	if err := os.WriteFile(privPolicy, []byte(core), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code = privd("--accept", fileHash(t, privPolicy))
	t.Logf("install of a core-only policy:\n%s", out)
	if code != 0 || !strings.Contains(out, "ran systemctl disable --now shell-mcp-privd-broad.socket") {
		t.Fatalf("install of a core-only policy: exit %d", code)
	}
	for _, p := range []string{"/etc/systemd/system/shell-mcp-privd-broad.socket", "/etc/systemd/system/shell-mcp-privd-broad@.service"} {
		if exists(p) {
			t.Errorf("%s left in place", p)
		}
	}
	// systemd keeps a stopped socket's node (RemoveOnStop= is off by
	// default, systemd.socket(5)): install leaves it and says so, and
	// nothing listens on it.
	if !strings.Contains(out, "NOTE "+broadSocket+" stays as a file node") {
		t.Error("install did not say that the stopped broad socket's node stays")
	}
	if _, code := runCode(t, "systemctl", "is-active", "--quiet", "shell-mcp-privd-broad.socket"); code == 0 {
		t.Error("the broad socket is still active")
	}
	if c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(t.Context(), "unix", broadSocket); err == nil {
		_ = c.Close()
		t.Error("something still listens on the broad socket")
	}
	if _, code := runCode(t, "systemctl", "is-enabled", "--quiet", "shell-mcp-privd-broad.socket"); code == 0 {
		t.Error("the broad socket is still enabled")
	}
	mustGate(t, "priv_stat", map[string]any{"path": "/etc/example-app"}, nil)
	findJournal(t, "shell-mcp-privd", start, `"event":"install"`, `"action":"remove"`, `"unit":"shell-mcp-privd-broad.socket"`)
	findJournal(t, "shell-mcp-privd", start, `"event":"install"`, `"action":"review"`)

	// Restored: the broad pair back and enabled, the e2e policy serving.
	restore()
	if !exists(broadSocket) {
		t.Fatal("the broad socket was not restored")
	}
	if out, code := privd("--gate-policy", gatePolicy, "--accept", origHash); code != 0 || !strings.Contains(out, "nothing to do") {
		t.Fatalf("after the restore: exit %d:\n%s", code, out)
	}
	mustGate(t, "priv_stat", map[string]any{"path": "/etc/example-app"}, nil)
}
