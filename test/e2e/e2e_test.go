//go:build e2e && linux

// Package e2e runs the gate and the privileged helper against a real
// systemd, journald and polkit on a disposable machine prepared by
// setup.sh: the GitHub-hosted runner VM (CI job "e2e-host") or the local
// systemd test container (local.sh). It is built only with -tags e2e and
// runs as root; the gate itself always runs as the invented service
// account.
//
// Every restriction is tested two-sided: a control shows the action works
// without the restriction, then the restricted case fails. With
// E2E_REQUIRE_ALL set (the CI job), nothing may skip.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Fixed paths on the machine (setup.sh) and invented test ids.
const (
	gateBin     = "/usr/local/bin/shell-mcp-gate"
	privdBin    = "/usr/local/libexec/shell-mcp-privd"
	probeBin    = "/usr/local/bin/example-probe"
	gatePolicy  = "/etc/shell-mcp/gate.yaml"
	privPolicy  = "/etc/shell-mcp/privileged.yaml"
	socketPath  = "/run/shell-mcp/privd.sock"
	broadSocket = "/run/shell-mcp/privd-broad.sock"
	repoDir     = "/srv/e2e-apt"
	backupDir   = "/var/lib/shell-mcp/backups"
	svcShell    = 4200001
	socketGroup = 4200002
	svcOther    = 4200003
	exampleApp  = 4200004
)

// bin is the directory with the test binaries and policy variants.
func bin() string {
	if b := os.Getenv("E2E_BIN"); b != "" {
		return b
	}
	return "/opt/e2e-bin"
}

func TestMain(m *testing.M) {
	if os.Getenv("E2E_CLIENT") != "" {
		os.Exit(client())
	}
	if os.Getuid() != 0 {
		fmt.Println("the e2e tests run as root on a disposable systemd machine prepared by test/e2e/setup.sh")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// client is this binary run as another user: it connects to the helper's
// socket (E2E_SOCKET, default the core unit's) and either sends stdin and
// prints everything the helper writes ("send"), or holds the connection
// open without sending ("hold").
func client() int {
	sock := os.Getenv("E2E_SOCKET")
	if sock == "" {
		sock = socketPath
	}
	c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", sock)
	if err != nil {
		fmt.Println("DIAL:", err)
		return 3
	}
	defer func() { _ = c.Close() }()
	if os.Getenv("E2E_CLIENT") == "hold" {
		time.Sleep(20 * time.Second)
		return 0
	}
	in, _ := io.ReadAll(os.Stdin)
	if _, err := c.Write(in); err != nil {
		fmt.Println("WRITE:", err)
		return 3
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	out, _ := io.ReadAll(c)
	_, _ = os.Stdout.Write(out)
	return 0
}

// need skips (or, under E2E_REQUIRE_ALL, fails) when a precondition of
// this machine is missing.
func need(t *testing.T, ok bool, reason string) {
	t.Helper()
	if ok {
		return
	}
	if os.Getenv("E2E_REQUIRE_ALL") != "" {
		t.Fatalf("required test cannot run: %s", reason)
	}
	t.Skip(reason)
}

func gid(t *testing.T, name string) uint32 {
	t.Helper()
	out := run(t, "getent", "group", name)
	f := strings.Split(strings.TrimSpace(out), ":")
	n, err := strconv.ParseUint(f[2], 10, 32)
	if err != nil {
		t.Fatalf("group %s: %q", name, out)
	}
	return uint32(n)
}

// cred is the identity a process runs as.
func cred(t *testing.T, uid uint32) *syscall.Credential {
	t.Helper()
	switch uid {
	case svcShell: // the gate's account: its own group, the socket group, systemd-journal
		return &syscall.Credential{Uid: svcShell, Gid: svcShell, Groups: []uint32{socketGroup, gid(t, "systemd-journal")}}
	case svcOther: // in the socket group, not in systemd-journal
		return &syscall.Credential{Uid: svcOther, Gid: svcOther, Groups: []uint32{socketGroup}}
	}
	return &syscall.Credential{Uid: uid, Gid: uid}
}

// run runs a fixed command with its own bounded context, not the test's:
// t.Context() is already cancelled when t.Cleanup functions run, and the
// cleanups restore the production helper and the base policy.
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // G204: fixed test commands
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

type response struct {
	V     int             `json:"v"`
	ID    string          `json:"id"`
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Warnings []string `json:"warnings"`
}

func (r *response) code() string {
	if r.Error == nil {
		return "ok"
	}
	return r.Error.Code
}

// gate runs the real gate as uid with one request and returns its answer
// and the request id.
func gate(t *testing.T, uid uint32, op string, args any) (resp response, requestID string) {
	t.Helper()
	id := newID()
	a, _ := json.Marshal(args)
	req := fmt.Sprintf(`{"v":1,"id":%q,"op":%q,"args":%s,"timeout_ms":30000}`+"\n", id, op, a)
	cmd := exec.CommandContext(t.Context(), gateBin, "serve", "--policy", gatePolicy, "--principal", "e2e")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, uid)}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = "/"
	cmd.Stdin = strings.NewReader(req)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("gate %s: %v\nstdout %q\nstderr %q", op, err, out.String(), errb.String())
	}
	var r response
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("gate %s: %q: %v", op, out.String(), err)
	}
	return r, id
}

func mustGate(t *testing.T, op string, args, into any) (resp response, requestID string) {
	t.Helper()
	r, id := gate(t, svcShell, op, args)
	if !r.OK {
		t.Fatalf("%s %v: %+v", op, args, r.Error)
	}
	if into != nil {
		if err := json.Unmarshal(r.Data, into); err != nil {
			t.Fatalf("%s: %s: %v", op, r.Data, err)
		}
	}
	return r, id
}

func wantGate(t *testing.T, uid uint32, op string, args any, code string) {
	t.Helper()
	r, _ := gate(t, uid, op, args)
	if r.code() != code {
		t.Fatalf("%s %v as uid %d: %s %+v, want %s", op, args, uid, r.code(), r.Error, code)
	}
}

// direct connects to the core helper socket as uid with this binary in
// client mode, sends one request line and returns what the helper wrote.
func direct(t *testing.T, uid uint32, line string) string {
	t.Helper()
	return directTo(t, uid, socketPath, line)
}

// directTo is direct for a given helper socket.
func directTo(t *testing.T, uid uint32, socket, line string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), self) //nolint:gosec // G204: this test binary itself, in client mode
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, uid)}
	cmd.Env = []string{"E2E_CLIENT=send", "E2E_SOCKET=" + socket}
	cmd.Stdin = strings.NewReader(line)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("client: %v %q", err, out)
	}
	return string(out)
}

type journalEntry struct {
	Message  string `json:"MESSAGE"`
	Priority string `json:"PRIORITY"`
	PID      string `json:"_PID"`
	Unit     string `json:"_SYSTEMD_UNIT"`
	Ident    string `json:"SYSLOG_IDENTIFIER"`
}

// journal returns ident's entries since the given time.
func journal(t *testing.T, ident string, since time.Time) []journalEntry {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "journalctl", "--no-pager", "-o", "json", "-t", ident, //nolint:gosec // G204: fixed test command
		"--since", "@"+strconv.FormatInt(since.Unix()-1, 10)).Output()
	if err != nil {
		t.Fatalf("journalctl: %v", err)
	}
	var es []journalEntry
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e journalEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			es = append(es, e)
		}
	}
	return es
}

// findJournal waits until an entry of ident since start contains every
// string in want.
func findJournal(t *testing.T, ident string, since time.Time, want ...string) journalEntry {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
	entries:
		for _, e := range journal(t, ident, since) {
			for _, w := range want {
				if !strings.Contains(e.Message, w) {
					continue entries
				}
			}
			return e
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s journal entry since %v containing %q", ident, since, want)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// installPolicy copies a policy variant into place, regenerates the units
// and reloads systemd; the base policy is restored when the test ends.
func installPolicy(t *testing.T, variant string) {
	t.Helper()
	cp := func(v string) {
		run(t, "install", "-o", "root", "-g", "root", "-m", "0600", filepath.Join(bin(), v), privPolicy)
		run(t, privdBin, "units", "--policy", privPolicy, "--out", "/etc/systemd/system")
		run(t, "systemctl", "daemon-reload")
	}
	cp(variant)
	t.Cleanup(func() { cp("privileged.yaml") })
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: fixed test paths
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---- Units and socket --------------------------------------------------------

func TestUnitsVerify(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "systemd-analyze", "verify", "--man=no",
		"/etc/systemd/system/shell-mcp-privd.socket", "/etc/systemd/system/shell-mcp-privd@.service",
		"/etc/systemd/system/shell-mcp-privd-broad.socket", "/etc/systemd/system/shell-mcp-privd-broad@.service").CombinedOutput()
	t.Logf("systemd-analyze verify:\n%s", out)
	if err != nil {
		t.Fatalf("systemd-analyze verify: %v", err)
	}
}

var exposureRE = regexp.MustCompile(`Overall exposure level for [^:]+: (\d+\.\d)`)

func exposure(t *testing.T, unit string) float64 {
	t.Helper()
	out, _ := exec.CommandContext(t.Context(), "systemd-analyze", "security", "--no-pager", unit).CombinedOutput() //nolint:gosec // G204: fixed unit names
	t.Logf("systemd-analyze security %s:\n%s", unit, out)
	m := exposureRE.FindSubmatch(out)
	if m == nil {
		t.Fatalf("%s: no exposure level in the output", unit)
	}
	got, _ := strconv.ParseFloat(string(m[1]), 64)
	return got
}

// The core unit's exposure may only improve (E2E_SECURITY_MAX, the
// measured score with no slack). The broad unit's is recorded for
// information only: it is root-equivalent by design.
func TestSecurityExposure(t *testing.T) {
	got := exposure(t, "shell-mcp-privd@.service")
	fmt.Printf("E2E_EXPOSURE=%.1f\n", got)
	fmt.Printf("E2E_EXPOSURE_BROAD=%.1f\n", exposure(t, "shell-mcp-privd-broad@.service"))
	maxS := os.Getenv("E2E_SECURITY_MAX")
	need(t, maxS != "", "E2E_SECURITY_MAX is not set")
	limit, err := strconv.ParseFloat(maxS, 64)
	if err != nil {
		t.Fatalf("E2E_SECURITY_MAX %q", maxS)
	}
	if got > limit {
		t.Fatalf("exposure %.1f is worse than the threshold %.1f", got, limit)
	}
}

// Both sockets are root:<socket group> 0660 in a root-owned 0711 directory
// (PRIVILEGED §2, §3; DirectoryMode=).
func TestSocketPermissions(t *testing.T) {
	check := func(p string, uid, gid uint32, mode os.FileMode, socket bool) {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if st.Uid != uid || st.Gid != gid || fi.Mode().Perm() != mode || (fi.Mode()&os.ModeSocket != 0) != socket {
			t.Fatalf("%s: %d:%d %v", p, st.Uid, st.Gid, fi.Mode())
		}
	}
	check("/run/shell-mcp", 0, 0, 0o711, false)
	check(socketPath, 0, socketGroup, 0o660, true)
	check(broadSocket, 0, socketGroup, 0o660, true)
}

// ---- The helper through the gate ----------------------------------------------

// A write inside paths.write succeeds, is backed up first, keeps owner and
// mode, is read back; restore brings the old content back.
func TestHelperWriteBackupRestore(t *testing.T) {
	p := "/etc/example-app/app.conf"
	before := readFile(t, p)
	var w struct {
		Verified  bool     `json:"verified"`
		Mode      string   `json:"mode"`
		BackupIDs []string `json:"backup_ids"`
	}
	mustGate(t, "priv_write_file", map[string]any{"path": p, "content_b64": "ZTJlOiB2Mgo="}, &w) // "e2e: v2\n"
	if !w.Verified || w.Mode != "0640" || len(w.BackupIDs) != 1 || readFile(t, p) != "e2e: v2\n" {
		t.Fatalf("write %+v content %q", w, readFile(t, p))
	}
	fi, _ := os.Stat(p)
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != 0 || st.Gid != 0 || fi.Mode().Perm() != 0o640 {
		t.Fatalf("owner or mode changed: %d:%d %v", st.Uid, st.Gid, fi.Mode())
	}
	for _, suffix := range []string{".meta.json", ".data"} {
		bf, err := os.Stat(filepath.Join(backupDir, w.BackupIDs[0]+suffix))
		if err != nil || bf.Mode().Perm() != 0o600 || bf.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Fatalf("backup %s: %v", suffix, err)
		}
	}
	if readFile(t, filepath.Join(backupDir, w.BackupIDs[0]+".data")) != before {
		t.Fatal("backup does not hold the previous content")
	}
	var r struct {
		BackupIDs []string `json:"backup_ids"`
	}
	mustGate(t, "priv_restore_backup", map[string]any{"id": w.BackupIDs[0]}, &r)
	if readFile(t, p) != before || len(r.BackupIDs) != 1 {
		t.Fatalf("restore: content %q, backups %v", readFile(t, p), r.BackupIDs)
	}
}

// Root-only file operations the gate itself could never do.
func TestHelperOperations(t *testing.T) {
	dir := "/etc/example-app/e2e-ops"
	mustGate(t, "priv_mkdir", map[string]any{"path": dir, "mode": "0750"}, nil)
	f := dir + "/owned.conf"
	mustGate(t, "priv_write_file", map[string]any{"path": f, "content_b64": "eAo=", "owner": "example-app", "group": "example-app", "mode": "0640"}, nil)
	fi, _ := os.Stat(f)
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != exampleApp || st.Gid != exampleApp {
		t.Fatalf("owner %d:%d", st.Uid, st.Gid)
	}
	mustGate(t, "priv_chown", map[string]any{"path": f, "owner": "root", "group": "root"}, nil)
	mustGate(t, "priv_chmod", map[string]any{"path": f, "mode": "0600"}, nil)
	wantGate(t, svcShell, "priv_chown", map[string]any{"path": f, "owner": "svc-shell"}, "policy_denied")
	wantGate(t, svcShell, "priv_chmod", map[string]any{"path": f, "mode": "4755"}, "policy_denied")
	mustGate(t, "priv_copy", map[string]any{"source": f, "destination": dir + "/copy.conf"}, nil)
	mustGate(t, "priv_move", map[string]any{"source": dir + "/copy.conf", "destination": dir + "/moved.conf"}, nil)
	mustGate(t, "priv_stat", map[string]any{"path": dir + "/moved.conf"}, nil)
	mustGate(t, "priv_list_dir", map[string]any{"path": dir}, nil)
	mustGate(t, "priv_read_file", map[string]any{"path": f}, nil)
	// Outside the roots, and on the never list, the helper refuses.
	wantGate(t, svcShell, "priv_read_file", map[string]any{"path": "/etc/example-other/secret.txt"}, "path_denied")
	wantGate(t, svcShell, "priv_write_file", map[string]any{"path": "/etc/example-other/x", "content_b64": "eA=="}, "path_denied")
	wantGate(t, svcShell, "priv_read_file", map[string]any{"path": "/etc/shadow"}, "path_denied")
	var del struct {
		BackupIDs []string `json:"backup_ids"`
	}
	mustGate(t, "priv_delete", map[string]any{"path": dir, "recursive": true}, &del)
	if len(del.BackupIDs) != 1 {
		t.Fatalf("tree delete backups %v", del.BackupIDs)
	}
	mustGate(t, "priv_restore_backup", map[string]any{"id": del.BackupIDs[0]}, nil)
	if readFile(t, f) != "x\n" {
		t.Fatal("tree not restored")
	}
	mustGate(t, "priv_delete", map[string]any{"path": dir, "recursive": true}, nil)
	var ex struct {
		Stdout   string `json:"stdout"`
		ExitCode *int   `json:"exit_code"`
	}
	mustGate(t, "priv_exec", map[string]any{"command_id": "probe-echo", "args": []string{"echo", "root-ok"}}, &ex)
	if ex.Stdout != "root-ok\n" || ex.ExitCode == nil || *ex.ExitCode != 0 {
		t.Fatalf("exec %+v", ex)
	}
	var lb struct {
		Backups []json.RawMessage `json:"backups"`
	}
	mustGate(t, "priv_list_backups", map[string]any{}, &lb)
	if len(lb.Backups) == 0 {
		t.Fatal("no backups listed")
	}
}

// Only client_uid is served: the same request from another account in the
// socket group, or from root, gets the connection closed without a byte.
func TestHelperWrongPeerRefused(t *testing.T) {
	start := time.Now()
	mustGate(t, "priv_stat", map[string]any{"path": "/etc/example-app"}, nil) // control
	wantGate(t, svcOther, "priv_stat", map[string]any{"path": "/etc/example-app"}, "helper_refused")
	line := fmt.Sprintf(`{"v":1,"id":%q,"op":"priv_stat","args":{"path":"/etc/example-app"}}`+"\n", newID())
	if out := direct(t, svcOther, line); out != "" {
		t.Fatalf("wrong peer got %q", out)
	}
	if out := direct(t, 0, line); out != "" {
		t.Fatalf("root peer got %q", out)
	}
	if out := direct(t, svcShell, line); !strings.Contains(out, `"ok":true`) {
		t.Fatalf("client_uid got %q", out)
	}
	e := findJournal(t, "shell-mcp-privd", start, `"check":"peer_uid"`, `"peer_uid":4200003`)
	if e.Priority != "4" {
		t.Fatalf("peer refusal logged at priority %s", e.Priority)
	}
	findJournal(t, "shell-mcp-privd", start, `"check":"peer_uid"`, `"peer_uid":0`)
}

// One helper instance per connection: two open connections are two running
// instances with different PIDs, and none is left after they close.
func TestHelperOneInstancePerConnection(t *testing.T) {
	self, _ := os.Executable()
	var holds []*exec.Cmd
	for range 2 {
		c := exec.CommandContext(t.Context(), self) //nolint:gosec // G204: this test binary itself, in client mode
		c.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, svcShell)}
		c.Env = []string{"E2E_CLIENT=hold"}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		holds = append(holds, c)
	}
	active := func() []string {
		out := run(t, "systemctl", "list-units", "--no-legend", "--plain", "--state=active", "shell-mcp-privd@*.service")
		var units []string
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			if f := strings.Fields(l); len(f) > 0 {
				units = append(units, f[0])
			}
		}
		return units
	}
	var units []string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if units = active(); len(units) == 2 {
			break
		}
	}
	if len(units) != 2 {
		t.Fatalf("active instances %v, want 2", units)
	}
	pids := map[string]bool{}
	for _, u := range units {
		pid := strings.TrimSpace(run(t, "systemctl", "show", "-p", "MainPID", "--value", u))
		if pid == "" || pid == "0" {
			t.Fatalf("%s has no main pid", u)
		}
		pids[pid] = true
	}
	if len(pids) != 2 {
		t.Fatalf("instances share a pid: %v", pids)
	}
	for _, c := range holds {
		_ = c.Process.Kill()
		_ = c.Wait()
	}
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if len(active()) == 0 {
			return
		}
	}
	t.Fatalf("instances left after the connections closed: %v", active())
}

// A policy edited without regenerating the units is refused (PRIVILEGED
// §2), and the authenticated gate is told why: helper_policy_mismatch, not
// helper_refused. Another account still gets nothing.
func TestHelperPolicyHashMismatch(t *testing.T) {
	mustGate(t, "priv_stat", map[string]any{"path": "/etc/example-app"}, nil) // control
	orig := readFile(t, privPolicy)
	t.Cleanup(func() { _ = os.WriteFile(privPolicy, []byte(orig), 0o600) })
	start := time.Now()
	if err := os.WriteFile(privPolicy, []byte(orig+"# edited after the units were generated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantGate(t, svcShell, "priv_stat", map[string]any{"path": "/etc/example-app"}, "helper_policy_mismatch")
	e := findJournal(t, "shell-mcp-privd", start, `"check":"policy_hash"`, `"outcome":"helper_policy_mismatch"`, `"peer_uid":4200001`)
	if e.Priority != "4" {
		t.Fatalf("self-check failure logged at priority %s", e.Priority)
	}
	wantGate(t, svcOther, "priv_stat", map[string]any{"path": "/etc/example-app"}, "helper_refused")
	if err := os.WriteFile(privPolicy, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGate(t, "priv_stat", map[string]any{"path": "/etc/example-app"}, nil)
}

// A policy that no longer parses is reported to the authenticated gate as
// helper_policy_invalid, with a one-line reason and no policy content.
func TestHelperPolicyInvalidAnswered(t *testing.T) {
	mustGate(t, "priv_stat", map[string]any{"path": "/etc/example-app"}, nil) // control
	orig := readFile(t, privPolicy)
	t.Cleanup(func() { _ = os.WriteFile(privPolicy, []byte(orig), 0o600) })
	start := time.Now()
	if err := os.WriteFile(privPolicy, []byte(orig+"unknown_key_for_e2e: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, _ := gate(t, svcShell, "priv_stat", map[string]any{"path": "/etc/example-app"})
	if r.code() != "helper_policy_invalid" || strings.Contains(r.Error.Message, "unknown_key_for_e2e") {
		t.Fatalf("got %s %+v, want helper_policy_invalid without policy content", r.code(), r.Error)
	}
	findJournal(t, "shell-mcp-privd", start, `"check":"policy"`, `"outcome":"helper_policy_invalid"`)
	wantGate(t, svcOther, "priv_stat", map[string]any{"path": "/etc/example-app"}, "helper_refused")
}

// unitDropIn overrides the helper's service unit with a drop-in for the
// rest of the test.
func unitDropIn(t *testing.T, content string) {
	t.Helper()
	dir := "/etc/systemd/system/shell-mcp-privd@.service.d"
	run(t, "install", "-d", "-o", "root", "-g", "root", "-m", "0755", dir)
	if err := os.WriteFile(filepath.Join(dir, "e2e.conf"), []byte(content), 0o644); err != nil { //nolint:gosec // G306: unit drop-ins are root:root 0644
		t.Fatal(err)
	}
	run(t, "systemctl", "daemon-reload")
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
	})
}

// The peer check reads only the unit's SHELL_MCP_PRIVD_CLIENT_UID. A unit
// that names another account than the policy serves that account only far
// enough to tell it helper_client_uid_mismatch; a unit without the value
// serves nobody and says so in the journal.
func TestHelperUnitClientUID(t *testing.T) {
	line := func() string {
		return fmt.Sprintf(`{"v":1,"id":%q,"op":"priv_stat","args":{"path":"/etc/example-app"}}`+"\n", newID())
	}
	if out := direct(t, svcShell, line()); !strings.Contains(out, `"ok":true`) { // control
		t.Fatalf("client_uid got %q", out)
	}
	if !strings.Contains(readFile(t, "/etc/systemd/system/shell-mcp-privd@.service"), "Environment=SHELL_MCP_PRIVD_CLIENT_UID=4200001\n") {
		t.Fatal("the generated unit does not name client_uid")
	}

	unitDropIn(t, "[Service]\nEnvironment=SHELL_MCP_PRIVD_CLIENT_UID=4200003\n")
	start := time.Now()
	if out := direct(t, svcShell, line()); out != "" {
		t.Fatalf("the policy's client, no longer the unit's, got %q", out)
	}
	findJournal(t, "shell-mcp-privd", start, `"check":"peer_uid"`, `"peer_uid":4200001`, `"outcome":"refused"`)
	var r response
	out := direct(t, svcOther, line())
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.code() != "helper_client_uid_mismatch" || r.ID != "" {
		t.Fatalf("the unit's client got %q, want helper_client_uid_mismatch without an id", out)
	}
	findJournal(t, "shell-mcp-privd", start, `"check":"client_uid"`, `"outcome":"helper_client_uid_mismatch"`)

	// An empty Environment= clears every earlier assignment (systemd.exec(5)).
	unitDropIn(t, "[Service]\nEnvironment=\n")
	start = time.Now()
	if out := direct(t, svcShell, line()); out != "" {
		t.Fatalf("a unit without SHELL_MCP_PRIVD_CLIENT_UID answered %q", out)
	}
	wantGate(t, svcShell, "priv_stat", map[string]any{"path": "/etc/example-app"}, "helper_refused")
	e := findJournal(t, "shell-mcp-privd", start, `"check":"unit_client_uid"`, `"outcome":"refused"`)
	if e.Priority != "4" {
		t.Fatalf("refusal logged at priority %s", e.Priority)
	}
}

// With the helper's own checks and Landlock bypassed (the e2e test build),
// systemd alone keeps it from writing outside ReadWritePaths= (EROFS) and
// from reading the credential paths in InaccessiblePaths=.
func TestHelperSystemdConfinesWithoutOwnChecks(t *testing.T) {
	raw := func(op, p string) string {
		line := fmt.Sprintf(`{"v":1,"id":%q,"op":%q,"args":{"path":%q}}`+"\n", newID(), op, p)
		return direct(t, svcShell, line)
	}
	// The production binary has no such operation.
	if out := raw("bypass_raw_write", "/etc/example-app/bypass.txt"); !strings.Contains(out, `"unknown_op"`) {
		t.Fatalf("production helper: %q", out)
	}
	run(t, "install", "-o", "root", "-g", "root", "-m", "0755", filepath.Join(bin(), "shell-mcp-privd-bypass"), privdBin)
	t.Cleanup(func() {
		run(t, "install", "-o", "root", "-g", "root", "-m", "0755", filepath.Join(bin(), "shell-mcp-privd"), privdBin)
	})
	result := func(out string) string {
		var r struct {
			Data struct {
				Result string `json:"result"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("bypass helper: %q", out)
		}
		return r.Data.Result
	}
	// Control: inside ReadWritePaths= the raw write works.
	if got := result(raw("bypass_raw_write", "/etc/example-app/bypass.txt")); got != "OK" {
		t.Fatalf("raw write inside paths.write: %s", got)
	}
	_ = os.Remove("/etc/example-app/bypass.txt")
	for _, p := range []string{"/etc/example-other/bypass.txt", "/usr/local/bin/bypass", "/var/lib/bypass"} {
		if got := result(raw("bypass_raw_write", p)); got != "EROFS" {
			t.Fatalf("raw write %s: %s, want EROFS", p, got)
		}
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s was written", p)
		}
	}
	// Control: root outside the unit reads the real, non-empty /etc/shadow.
	// Inside the unit InaccessiblePaths= puts an empty mode-0000 node over
	// it; root with CAP_DAC_READ_SEARCH may open that node, but it must
	// never see the real file's content.
	shadow, err := os.ReadFile("/etc/shadow")
	if err != nil || len(shadow) == 0 {
		t.Fatalf("control read of /etc/shadow: %v (%d bytes)", err, len(shadow))
	}
	realSum := sha256.Sum256(shadow)
	var sr struct {
		Data struct {
			Result string `json:"result"`
			Bytes  int    `json:"bytes"`
			SHA256 string `json:"sha256"`
		} `json:"data"`
	}
	out := raw("bypass_raw_read", "/etc/shadow")
	if err := json.Unmarshal([]byte(out), &sr); err != nil {
		t.Fatalf("bypass helper: %q", out)
	}
	if sr.Data.Result == "OK" && (sr.Data.Bytes != 0 || sr.Data.SHA256 == hex.EncodeToString(realSum[:])) {
		t.Fatalf("the unit read the real /etc/shadow (%d bytes)", sr.Data.Bytes)
	}
	t.Logf("inside the unit /etc/shadow reads as: %s, %d bytes", sr.Data.Result, sr.Data.Bytes)
	if got := result(raw("bypass_raw_read", "/etc/example-app/app.conf")); got != "OK" {
		t.Fatalf("raw read inside the roots: %s", got)
	}
}

// A capability outside the unit's bounding set is unavailable to the helper
// and its commands; declaring it (CAP_KILL) makes it available.
func TestHelperCapabilityBoundingSet(t *testing.T) {
	sleeper := func() *exec.Cmd {
		c := exec.CommandContext(t.Context(), "/usr/bin/sleep", "120")
		c.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, svcOther)}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
		return c
	}
	signal := func(pid int) string {
		var ex struct {
			Stdout string `json:"stdout"`
		}
		mustGate(t, "priv_exec", map[string]any{"command_id": "probe-signal", "args": []string{"signal", strconv.Itoa(pid)}}, &ex)
		return strings.TrimSpace(ex.Stdout)
	}
	target := sleeper()
	if got := signal(target.Process.Pid); got != "EPERM" {
		t.Fatalf("without CAP_KILL: %s, want EPERM", got)
	}
	if err := target.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("target died without CAP_KILL")
	}
	installPolicy(t, "privileged-cap-kill.yaml")
	if !strings.Contains(readFile(t, "/etc/systemd/system/shell-mcp-privd@.service"), "CAP_KILL") {
		t.Fatal("regenerated unit lacks CAP_KILL")
	}
	target = sleeper()
	if got := signal(target.Process.Pid); got != "SIGNALLED" {
		t.Fatalf("with CAP_KILL: %s, want SIGNALLED", got)
	}
}

// The helper and its commands have no network (PrivateNetwork=yes,
// RestrictAddressFamilies=AF_UNIX, and no TCP rule in Landlock).
func TestHelperNoNetwork(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	if out := strings.TrimSpace(run(t, probeBin, "connect", port)); out != "CONNECTED" {
		t.Fatalf("control connect: %s", out)
	}
	var ex struct {
		Stdout string `json:"stdout"`
	}
	mustGate(t, "priv_exec", map[string]any{"command_id": "probe-connect", "args": []string{"connect", port}}, &ex)
	if got := strings.TrimSpace(ex.Stdout); got == "CONNECTED" || got == "" {
		t.Fatalf("the helper's command connected: %q", got)
	}
}

// Landlock inside the helper: a file readable by root and outside every
// root is denied to the helper's commands.
func TestHelperLandlock(t *testing.T) {
	if out := strings.TrimSpace(run(t, probeBin, "read-outside")); out != "READ:outside" {
		t.Fatalf("control read: %s", out)
	}
	var ex struct {
		Stdout string `json:"stdout"`
	}
	mustGate(t, "priv_exec", map[string]any{"command_id": "probe-read-outside", "args": []string{"read-outside"}}, &ex)
	if got := strings.TrimSpace(ex.Stdout); got != "EACCES" {
		t.Fatalf("helper command read outside its roots: %q, want EACCES", got)
	}
}

// One journal line per helper request, joined to the gate's line by the
// request id, never with content.
func TestAuditJournal(t *testing.T) {
	start := time.Now()
	canary := "E2E-AUDIT-CANARY"
	content := "RTJFLUFVRElULUNBTkFSWQo=" // base64 of the canary line
	_, id := mustGate(t, "priv_write_file", map[string]any{"path": "/etc/example-app/audit.conf", "content_b64": content, "mode": "0640"}, nil)
	t.Cleanup(func() { _ = os.Remove("/etc/example-app/audit.conf") })
	h := findJournal(t, "shell-mcp-privd", start, `"id":"`+id+`"`)
	g := findJournal(t, "shell-mcp-gate", start, `"id":"`+id+`"`)
	for _, want := range []string{`"peer_uid":4200001`, `"op":"priv_write_file"`, `"outcome":"ok"`, `"path":"/etc/example-app/audit.conf"`, `"mode":"0640"`} {
		if !strings.Contains(h.Message, want) {
			t.Errorf("helper line lacks %s: %q", want, h.Message)
		}
	}
	if h.Priority != "6" || !strings.HasPrefix(h.Unit, "shell-mcp-privd@") {
		t.Errorf("helper line priority %s unit %s", h.Priority, h.Unit)
	}
	if !strings.Contains(g.Message, `"principal":"e2e"`) || !strings.Contains(g.Message, `"outcome":"ok"`) {
		t.Errorf("gate line %q", g.Message)
	}
	for _, e := range journal(t, "shell-mcp-privd", start) {
		if strings.Contains(e.Message, canary) || strings.Contains(e.Message, content) {
			t.Fatalf("helper journal leaks content: %q", e.Message)
		}
	}
	for _, e := range journal(t, "shell-mcp-gate", start) {
		if strings.Contains(e.Message, canary) || strings.Contains(e.Message, content) {
			t.Fatalf("gate journal leaks content: %q", e.Message)
		}
	}
	// Two requests, two instances: different units and pids in the journal.
	_, id2 := mustGate(t, "priv_stat", map[string]any{"path": "/etc/example-app"}, nil)
	h2 := findJournal(t, "shell-mcp-privd", start, `"id":"`+id2+`"`)
	if h2.Unit == h.Unit || h2.PID == h.PID {
		t.Fatalf("one instance served two connections: %s/%s and %s/%s", h.Unit, h.PID, h2.Unit, h2.PID)
	}
}

// ---- Services, journal and polkit (S1b's list) ---------------------------------

func TestServiceStatus(t *testing.T) {
	var s map[string]any
	mustGate(t, "service_status", map[string]any{"unit": "example-app.service"}, &s)
	b, _ := json.Marshal(s)
	for _, want := range []string{`"active_state":"active"`, `"sub_state":"running"`, `"load_state":"loaded"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("status lacks %s: %s", want, b)
		}
	}
	mustGate(t, "service_status", map[string]any{"unit": "example-missing.service"}, &s)
	if b, _ := json.Marshal(s); !strings.Contains(string(b), `"load_state":"not-found"`) {
		t.Errorf("missing unit: %s", b)
	}
	wantGate(t, svcShell, "service_status", map[string]any{"unit": "dbus.service"}, "policy_denied")
}

func TestServiceList(t *testing.T) {
	out := run(t, "systemctl", "list-units", "--no-pager", "--output=json", "--type=service")
	if !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Fatalf("systemctl list-units --output=json is not JSON on this systemd: %q", out[:min(len(out), 200)])
	}
	var l struct {
		Units []struct {
			Unit string `json:"unit"`
		} `json:"units"`
	}
	mustGate(t, "service_list", map[string]any{}, &l)
	seen := map[string]bool{}
	for _, u := range l.Units {
		seen[u.Unit] = true
		if !strings.HasPrefix(u.Unit, "example-") {
			t.Errorf("listed a unit outside services.status: %s", u.Unit)
		}
	}
	if !seen["example-app.service"] || !seen["example-other.service"] {
		t.Fatalf("list %v", seen)
	}
}

func TestJournal(t *testing.T) {
	var j struct {
		Output string `json:"output"`
	}
	r, _ := mustGate(t, "journal", map[string]any{"unit": "example-app.service", "lines": 50, "since": "-1d", "priority": "info"}, &j)
	if !strings.Contains(j.Output, "example-app starting") {
		t.Fatalf("journal output %q warnings %v", j.Output, r.Warnings)
	}
	wantGate(t, svcShell, "journal", map[string]any{"unit": "example-other.service"}, "policy_denied")
	// Without systemd-journal: a warning about unseen messages, or
	// exec_failed naming the group — never the lines.
	r, _ = gate(t, svcOther, "journal", map[string]any{"unit": "example-app.service", "lines": 50})
	switch {
	case r.OK && strings.Contains(strings.Join(r.Warnings, " "), "systemd-journal"):
	case !r.OK && r.code() == "exec_failed" && strings.Contains(r.Error.Message, "systemd-journal"):
	default:
		t.Fatalf("without the group: %s %+v %v %s", r.code(), r.Error, r.Warnings, r.Data)
	}
	if strings.Contains(string(r.Data), "example-app starting") {
		t.Fatal("journal lines returned without systemd-journal")
	}
}

// service_control: allowed by the gate policy and by the polkit rule
// succeeds; allowed by the gate but outside the rule — another unit,
// another verb, or no rule at all — is not_authorized.
func TestServiceControlPolkit(t *testing.T) {
	var s map[string]any
	mustGate(t, "service_control", map[string]any{"unit": "example-app.service", "action": "restart"}, &s)
	if b, _ := json.Marshal(s["status"]); !strings.Contains(string(b), `"active_state":"active"`) {
		t.Fatalf("status after restart: %s", b)
	}
	wantGate(t, svcShell, "service_control", map[string]any{"unit": "example-app.service", "action": "stop"}, "not_authorized")
	wantGate(t, svcShell, "service_control", map[string]any{"unit": "example-other.service", "action": "restart"}, "not_authorized")
	if active := strings.TrimSpace(run(t, "systemctl", "is-active", "example-app.service")); active != "active" {
		t.Fatalf("a refused stop stopped the unit: %s", active)
	}
	rule := "/etc/polkit-1/rules.d/60-shell-mcp.rules"
	saved := readFile(t, rule)
	if err := os.Remove(rule); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(rule, []byte(saved), 0o644) }) //nolint:gosec // G306: polkit rules are root:root 0644
	time.Sleep(2 * time.Second)                                        // polkitd reloads rules on change
	wantGate(t, svcShell, "service_control", map[string]any{"unit": "example-app.service", "action": "restart"}, "not_authorized")
}

// The gate's own audit line reaches journald through /dev/log (identifier
// shell-mcp-gate) with the request id and the op's arguments.
func TestGateAuditJournal(t *testing.T) {
	start := time.Now()
	_, id := mustGate(t, "service_status", map[string]any{"unit": "example-app.service"}, nil)
	e := findJournal(t, "shell-mcp-gate", start, `"id":"`+id+`"`)
	if !strings.Contains(e.Message, `"op":"service_status"`) || !strings.Contains(e.Message, `"unit":"example-app.service"`) {
		t.Fatalf("gate audit %q", e.Message)
	}
}
