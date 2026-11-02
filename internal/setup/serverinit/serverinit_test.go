//go:build linux

package serverinit_test

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx/setuptest"
	"github.com/tyler-rich/shell-mcp/internal/setup/serverinit"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// --- The real filesystem, as the test process -----------------------------------

// ids is the owner init is asked for: the test's own uid and gid or, when
// the test runs as root, 65532 (root may give files to any uid).
func ids() (uid, gid uint32) {
	if os.Geteuid() == 0 {
		return 65532, 65532
	}
	return uint32(os.Geteuid()), uint32(os.Getegid()) //nolint:gosec // G115: this process's ids
}

func u(n uint32) string { return strconv.FormatUint(uint64(n), 10) }

func realEnv(terminal bool) *serverinit.Env {
	groups, _ := os.Getgroups()
	return &serverinit.Env{Euid: os.Geteuid(), Egid: os.Getegid(), Groups: groups, Rand: rand.Reader,
		IsTerminal: func(io.Writer) bool { return terminal }}
}

type result struct {
	code           int
	stdout, stderr string
}

func runReal(t *testing.T, env *serverinit.Env, args ...string) result {
	t.Helper()
	o, err := serverinit.ParseFlags(args)
	if err != nil {
		t.Fatalf("ParseFlags(%q): %v", args, err)
	}
	var out, errb bytes.Buffer
	code := serverinit.Run(o, serverinit.RealFiles(uint32(os.Geteuid())), env, &out, &errb) //nolint:gosec // G115: this process's uid
	return result{code, out.String(), errb.String()}
}

// newDir is a fresh parent directory (0755) and the --dir init creates in it.
func newDir(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "srv")
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(p, "secrets")
}

func idArgs(dir string, extra ...string) []string {
	uid, gid := ids()
	return append([]string{"--dir", dir, "--uid", u(uid), "--gid", u(gid)}, extra...)
}

type entry struct {
	data     string
	mode     fs.FileMode
	uid, gid uint32
	mtime    time.Time
	ino      uint64
}

// snapshot is every entry in dir's parent, without following links.
func snapshot(t *testing.T, dir string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	_ = filepath.WalkDir(filepath.Dir(dir), func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // what does not exist is not in the snapshot
		}
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		e := entry{mode: fi.Mode(), uid: st.Uid, gid: st.Gid, mtime: fi.ModTime(), ino: st.Ino}
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own directory
			if err != nil {
				t.Fatal(err)
			}
			e.data = string(b)
		}
		out[p] = e
		return nil
	})
	return out
}

func sameSnapshot(a, b map[string]entry) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

func noTemps(t *testing.T, dir string) {
	t.Helper()
	_ = filepath.WalkDir(filepath.Dir(dir), func(p string, d fs.DirEntry, err error) error {
		if err == nil && setupx.IsTemp(d.Name()) {
			t.Errorf("temp file left: %s", p)
		}
		return nil
	})
}

func stat(t *testing.T, p string) (fs.FileMode, uint32, uint32) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return fi.Mode(), st.Uid, st.Gid
}

func read(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFreshRun(t *testing.T) {
	dir := newDir(t)
	uid, gid := ids()
	r := runReal(t, realEnv(false), idArgs(dir)...)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if m, fu, fg := stat(t, dir); m != fs.ModeDir|0o700 || fu != uid || fg != gid {
		t.Errorf("directory %v %d:%d", m, fu, fg)
	}
	for name, mode := range map[string]fs.FileMode{serverinit.TokenFile: 0o600, serverinit.KeyFile: 0o600, serverinit.PubFile: 0o644} {
		if m, fu, fg := stat(t, filepath.Join(dir, name)); m != mode || fu != uid || fg != gid {
			t.Errorf("%s: %v %d:%d, want %v %d:%d", name, m, fu, fg, mode, uid, gid)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, serverinit.ApproversFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("approvers written without --approver: %v", err)
	}
	tok := read(t, filepath.Join(dir, serverinit.TokenFile))
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).Match(tok) {
		t.Errorf("token of %d bytes is not 43 base64url characters on one line", len(tok))
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(string(tok)); err != nil || len(raw) != 32 {
		t.Errorf("token does not decode to 32 bytes: %v", err)
	}
	key := read(t, filepath.Join(dir, serverinit.KeyFile))
	blk, _ := pem.Decode(key)
	if blk == nil || blk.Type != "OPENSSH PRIVATE KEY" || !bytes.Contains(blk.Bytes, []byte("shell-mcp")) {
		t.Fatal("not an OpenSSH private key with the comment shell-mcp")
	}
	priv, err := ssh.ParseRawPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ed, ok := priv.(*ed25519.PrivateKey)
	if !ok {
		t.Fatalf("key is %T", priv)
	}
	signer, err := ssh.NewSignerFromKey(*ed)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "\n") + " shell-mcp\n"
	if pub := read(t, filepath.Join(dir, serverinit.PubFile)); string(pub) != want {
		t.Errorf(".pub %q, want %q", pub, want)
	}
	if !strings.Contains(r.stdout, strings.TrimSuffix(want, "\n")) || !strings.Contains(r.stdout, ssh.FingerprintSHA256(signer.PublicKey())) {
		t.Errorf("stdout does not print ssh_key.pub and its fingerprint:\n%s", r.stdout)
	}
	noTemps(t, dir)
}

// TestServerLoadsTheSecrets: the token, the key and the approvers file load
// through the server's own configuration loader with no warning, sshx
// accepts the key, and it authenticates to an SSH server that authorises
// ssh_key.pub.
func TestServerLoadsTheSecrets(t *testing.T) {
	dir := newDir(t)
	if r := runReal(t, realEnv(true), idArgs(dir, "--approver", "alice")...); r.code != 0 {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	env := map[string]string{
		"SHELL_MCP_TOKEN_FILE":          filepath.Join(dir, serverinit.TokenFile),
		"SHELL_MCP_SSH_KEY_FILE":        filepath.Join(dir, serverinit.KeyFile),
		"SHELL_MCP_TARGET_NAME":         "app-host",
		"SHELL_MCP_TARGET_HOST":         "127.0.0.1",
		"SHELL_MCP_TARGET_USER":         "svc-shell",
		"SHELL_MCP_TARGET_HOST_KEYS":    "ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"SHELL_MCP_PROFILE":             "operator",
		"SHELL_MCP_APPROVAL_METHOD":     "web",
		"SHELL_MCP_APPROVAL_PUBLIC_URL": "https://approve.example.test",
		"SHELL_MCP_APPROVERS_FILE":      filepath.Join(dir, serverinit.ApproversFile),
	}
	cfg, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatalf("the server refuses init's files: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("warnings: %q", cfg.Warnings)
	}
	if len(cfg.Approvers) != 1 || cfg.Approvers[0].Name != "alice" {
		t.Errorf("approvers %v", cfg.Approvers)
	}
	if _, err := approvers.Load(env["SHELL_MCP_APPROVERS_FILE"], approvers.MaxApprovers); err != nil {
		t.Errorf("approvers.Load: %v", err)
	}
	pool, err := sshx.NewPool(cfg, sshx.Options{})
	if err != nil {
		t.Fatalf("sshx refuses the key: %v", err)
	}
	pool.Close()

	authorized, _, _, _, err := ssh.ParseAuthorizedKey(read(t, filepath.Join(dir, serverinit.PubFile)))
	if err != nil {
		t.Fatal(err)
	}
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	sc := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), authorized.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("not authorised")
	}}
	sc.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		a, err := ln.Accept()
		if err != nil {
			return
		}
		_ = a.SetDeadline(time.Now().Add(10 * time.Second))
		if conn, chans, reqs, err := ssh.NewServerConn(a, sc); err == nil {
			go ssh.DiscardRequests(reqs)
			go func() {
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "no channels")
				}
			}()
			_ = conn.Wait()
		}
		_ = a.Close()
	}()
	b, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = b.SetDeadline(time.Now().Add(10 * time.Second))
	signer, err := ssh.ParsePrivateKey(read(t, filepath.Join(dir, serverinit.KeyFile)))
	if err != nil {
		t.Fatal(err)
	}
	cc, _, _, err := ssh.NewClientConn(b, "pipe", &ssh.ClientConfig{User: "svc-shell", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("the key does not authenticate: %v", err)
	}
	_ = cc.Close()
}

func TestSecondRunChangesNothing(t *testing.T) {
	dir := newDir(t)
	args := idArgs(dir, "--approver", "alice")
	if r := runReal(t, realEnv(true), args...); r.code != 0 {
		t.Fatalf("first run: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	before := snapshot(t, dir)
	time.Sleep(20 * time.Millisecond)
	for _, terminal := range []bool{true, false} {
		r := runReal(t, realEnv(terminal), args...)
		if r.code != 0 {
			t.Fatalf("second run (terminal %v): exit %d\n%s%s", terminal, r.code, r.stdout, r.stderr)
		}
		if after := snapshot(t, dir); !sameSnapshot(before, after) {
			t.Fatal("a second run changed the directory")
		}
		for _, name := range []string{serverinit.TokenFile, serverinit.KeyFile, serverinit.PubFile, serverinit.ApproversFile} {
			if !regexp.MustCompile(`(?m)^ok   ` + regexp.QuoteMeta(filepath.Join(dir, name)) + `: kept`).MatchString(r.stdout) {
				t.Errorf("%s not reported kept:\n%s", name, r.stdout)
			}
		}
		if strings.Contains(r.stdout, "otpauth://") || strings.Contains(r.stdout, ": create") {
			t.Errorf("a second run created or showed something:\n%s", r.stdout)
		}
		if !strings.Contains(r.stdout, "nothing to do: every file kept") {
			t.Errorf("no unchanged result line:\n%s", r.stdout)
		}
	}
}

func TestMissingFileGenerated(t *testing.T) {
	dir := newDir(t)
	if r := runReal(t, realEnv(false), idArgs(dir)...); r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	key := read(t, filepath.Join(dir, serverinit.KeyFile))
	for _, f := range []string{serverinit.PubFile, serverinit.TokenFile} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	r := runReal(t, realEnv(false), idArgs(dir)...)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stdout)
	}
	if !bytes.Equal(read(t, filepath.Join(dir, serverinit.KeyFile)), key) {
		t.Error("the key was replaced")
	}
	read(t, filepath.Join(dir, serverinit.TokenFile))
	if !strings.Contains(r.stdout, filepath.Join(dir, serverinit.PubFile)+": create") || !strings.Contains(r.stdout, filepath.Join(dir, serverinit.KeyFile)+": kept") {
		t.Errorf(".pub not written again from the kept key:\n%s", r.stdout)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	dir := newDir(t)
	before := snapshot(t, dir)
	r := runReal(t, realEnv(false), idArgs(dir, "--approver", "alice", "--dry-run")...)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if after := snapshot(t, dir); !sameSnapshot(before, after) {
		t.Fatal("a dry run changed the filesystem")
	}
	for _, s := range []string{"<43 random characters>", "<new Ed25519 key>", "would enrol alice"} {
		if !strings.Contains(r.stdout, s) {
			t.Errorf("the dry run does not show %q:\n%s", s, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "otpauth://") || r.stderr != "" {
		t.Errorf("a dry run showed a seed or wrote an audit line:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := runReal(t, realEnv(false), idArgs(dir)...); r.code != 0 {
		t.Fatal(r.code)
	}
	before = snapshot(t, dir)
	if r := runReal(t, realEnv(false), idArgs(dir, "--approver", "alice", "--dry-run")...); r.code != 0 {
		t.Fatalf("a dry run over an existing directory: exit %d\n%s", r.code, r.stdout)
	}
	if after := snapshot(t, dir); !sameSnapshot(before, after) {
		t.Fatal("a dry run changed an existing directory")
	}
}

// TestNoSecretOnOutput scans stdout and stderr for the token, the private
// key's PEM lines and its seed in several encodings, and the approver's
// seed, which appears once on stdout (the enrolment) and nowhere else.
func TestNoSecretOnOutput(t *testing.T) {
	dir := newDir(t)
	first := runReal(t, realEnv(true), idArgs(dir, "--approver", "alice")...)
	if first.code != 0 {
		t.Fatalf("exit %d", first.code)
	}
	second := runReal(t, realEnv(true), idArgs(dir, "--approver", "alice")...)
	dry := runReal(t, realEnv(true), idArgs(dir, "--approver", "alice", "--dry-run")...)
	key := read(t, filepath.Join(dir, serverinit.KeyFile))
	priv, err := ssh.ParseRawPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.(*ed25519.PrivateKey).Seed()
	forbidden := []string{string(read(t, filepath.Join(dir, serverinit.TokenFile))), hex.EncodeToString(seed),
		base64.StdEncoding.EncodeToString(seed)[:40], base64.RawURLEncoding.EncodeToString(seed)[:40]}
	sc := bufio.NewScanner(bytes.NewReader(key))
	for first := true; sc.Scan(); {
		if l := sc.Text(); !strings.HasPrefix(l, "-----") {
			if !first { // the first line is the format's constant header
				forbidden = append(forbidden, l)
			}
			first = false
		}
	}
	list, err := approvers.Parse(read(t, filepath.Join(dir, serverinit.ApproversFile)), approvers.MaxApprovers)
	if err != nil {
		t.Fatal(err)
	}
	apprSeed := approvers.EncodeSeed(list[0].Seed())
	for i, r := range []result{first, second, dry} {
		for _, f := range forbidden {
			if strings.Contains(r.stdout, f) || strings.Contains(r.stderr, f) {
				t.Errorf("run %d prints secret material %.6q…", i, f)
			}
		}
		if strings.Contains(r.stderr, apprSeed) {
			t.Errorf("run %d: the approver's seed on stderr", i)
		}
		want := 0
		if i == 0 {
			want = 1
		}
		if n := strings.Count(r.stdout, apprSeed); n != want {
			t.Errorf("run %d shows the approver's seed %d times, want %d", i, n, want)
		}
	}
}

// TestAudit: one JSON line per file on stderr, with the name, owner and mode,
// the key's fingerprint and the approver's name, never a value.
func TestAudit(t *testing.T) {
	dir := newDir(t)
	uid, gid := ids()
	check := func(r result, msg string) {
		t.Helper()
		if r.code != 0 {
			t.Fatalf("exit %d", r.code)
		}
		seen := map[string]map[string]any{}
		for _, l := range strings.Split(strings.TrimSpace(r.stderr), "\n") {
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatalf("stderr line is not JSON: %q", l)
			}
			if m["msg"] == msg {
				f, _ := m["file"].(string)
				seen[filepath.Base(f)] = m
			}
		}
		for _, f := range []string{serverinit.TokenFile, serverinit.KeyFile, serverinit.PubFile, serverinit.ApproversFile} {
			m, ok := seen[f]
			if !ok {
				t.Errorf("no %q line for %s:\n%s", msg, f, r.stderr)
				continue
			}
			if m["owner"] != u(uid)+":"+u(gid) || m["mode"] == nil {
				t.Errorf("%s: %v", f, m)
			}
		}
		if fp, _ := seen[serverinit.KeyFile]["fingerprint"].(string); !strings.HasPrefix(fp, "SHA256:") {
			t.Errorf("the key's line has no fingerprint: %v", seen[serverinit.KeyFile])
		}
		if seen[serverinit.ApproversFile]["approver"] != "alice" {
			t.Errorf("approvers line: %v", seen[serverinit.ApproversFile])
		}
	}
	check(runReal(t, realEnv(true), idArgs(dir, "--approver", "alice")...), "secret created")
	check(runReal(t, realEnv(true), idArgs(dir, "--approver", "alice")...), "secret kept")
}

func TestLeftoverRemoved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the leftover would be root's in a directory of 65532's; TestLeftoverRemovedFake covers it")
	}
	dir := newDir(t)
	if r := runReal(t, realEnv(false), idArgs(dir)...); r.code != 0 {
		t.Fatal(r.code)
	}
	left := filepath.Join(dir, "."+serverinit.TokenFile+".shell-mcp-abcdefghijkl")
	if err := os.WriteFile(left, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runReal(t, realEnv(false), idArgs(dir)...)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stdout)
	}
	if _, err := os.Lstat(left); !errors.Is(err, fs.ErrNotExist) {
		t.Error("the leftover temp file was not removed")
	}
	if !regexp.MustCompile(`(?m)^WARN .*` + regexp.QuoteMeta(left)).MatchString(r.stdout) {
		t.Errorf("no WARN naming the leftover:\n%s", r.stdout)
	}
}

func edKey(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "shell-mcp")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := ssh.NewPublicKey(pub)
	return pem.EncodeToMemory(blk), p
}

func encryptedKey(t *testing.T) []byte {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "shell-mcp", []byte("passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(blk)
}

func ecdsaKey(t *testing.T) []byte {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "shell-mcp")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(blk)
}

// own gives p to the owner init is asked for (as root: 65532).
func own(t *testing.T, p string) {
	t.Helper()
	if os.Geteuid() == 0 {
		if err := os.Lchown(p, 65532, 65532); err != nil {
			t.Fatal(err)
		}
	}
}

func mustMkdir(t *testing.T, p string, mode fs.FileMode) {
	t.Helper()
	if err := os.Mkdir(p, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	own(t, p)
}

func mustWrite(t *testing.T, p, data string, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	own(t, p)
}

// TestRefusalsReal: every refusal a process can build on its own files, each
// exit 1 with a FAIL naming the cause, nothing written and no temp file.
func TestRefusalsReal(t *testing.T) {
	uid, gid := ids()
	key, _ := edKey(t)
	_, otherPub := edKey(t)
	token := strings.Repeat("a", 43)
	approver := "alice " + strings.Repeat("A", 32) + "\n"
	cases := []struct {
		name     string
		setup    func(t *testing.T, dir string) (dirArg string, extra []string)
		terminal bool
		want     string
	}{
		{"parent missing", func(t *testing.T, dir string) (string, []string) {
			return filepath.Join(dir, "a", "b"), nil
		}, true, "does not exist"},
		{"dir is a file", func(t *testing.T, dir string) (string, []string) {
			mustWrite(t, dir, "x", 0o600)
			return dir, nil
		}, true, "not a directory"},
		{"dir is a symlink", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir+"-real", 0o700)
			if err := os.Symlink(dir+"-real", dir); err != nil {
				t.Fatal(err)
			}
			return dir, nil
		}, true, "symbolic link"},
		{"dir group-accessible", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o750)
			return dir, nil
		}, true, "group or other"},
		{"parent world-writable", func(t *testing.T, dir string) (string, []string) {
			if err := os.Chmod(filepath.Dir(dir), 0o777); err != nil { //nolint:gosec // G302: the refusal under test
				t.Fatal(err)
			}
			return dir, nil
		}, true, "writable by group or other"},
		{"ancestor is a symlink", func(t *testing.T, dir string) (string, []string) {
			parent := filepath.Dir(dir)
			if err := os.Symlink(parent, parent+"-link"); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(parent+"-link", "secrets"), nil
		}, true, "symbolic link"},
		{"token mode", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.TokenFile), token, 0o640)
			return dir, nil
		}, true, "chmod 600"},
		{"token short", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.TokenFile), token[:42], 0o600)
			return dir, nil
		}, true, "43"},
		{"token with a line break inside", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.TokenFile), token+"\n"+token+"\n", 0o600)
			return dir, nil
		}, true, "line break"},
		{"token a symlink", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, "elsewhere"), token, 0o600)
			if err := os.Symlink(filepath.Join(dir, "elsewhere"), filepath.Join(dir, serverinit.TokenFile)); err != nil {
				t.Fatal(err)
			}
			return dir, nil
		}, true, "regular file"},
		{"key encrypted", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.KeyFile), string(encryptedKey(t)), 0o600)
			return dir, nil
		}, true, "passphrase"},
		{"key not Ed25519", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.KeyFile), string(ecdsaKey(t)), 0o600)
			return dir, nil
		}, true, "Ed25519"},
		{"key garbage", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.KeyFile), "not a key\n", 0o600)
			return dir, nil
		}, true, "cannot be parsed"},
		{"key mode", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.KeyFile), string(key), 0o644)
			return dir, nil
		}, true, "chmod 600"},
		{"pub does not match", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.KeyFile), string(key), 0o600)
			mustWrite(t, filepath.Join(dir, serverinit.PubFile), string(ssh.MarshalAuthorizedKey(otherPub)), 0o644)
			return dir, nil
		}, true, "does not match"},
		{"pub without key", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.PubFile), string(ssh.MarshalAuthorizedKey(otherPub)), 0o644)
			return dir, nil
		}, true, "without"},
		{"pub group-writable", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			k, p := edKey(t)
			mustWrite(t, filepath.Join(dir, serverinit.KeyFile), string(k), 0o600)
			mustWrite(t, filepath.Join(dir, serverinit.PubFile), string(ssh.MarshalAuthorizedKey(p)), 0o664)
			return dir, nil
		}, true, "chmod 644"},
		{"approvers mode", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.ApproversFile), approver, 0o640)
			return dir, nil
		}, true, "chmod 600"},
		{"approvers unparseable", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.ApproversFile), "Alice !!\n", 0o600)
			return dir, nil
		}, true, "approvers"},
		{"second approver", func(t *testing.T, dir string) (string, []string) {
			mustMkdir(t, dir, 0o700)
			mustWrite(t, filepath.Join(dir, serverinit.ApproversFile), approver, 0o600)
			return dir, []string{"--approver", "bob"}
		}, true, "approver add --allow-multiple"},
		{"approver without a terminal", func(t *testing.T, dir string) (string, []string) {
			return dir, []string{"--approver", "alice"}
		}, false, "terminal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newDir(t)
			dirArg, extra := c.setup(t, dir)
			before := snapshot(t, dir)
			r := runReal(t, realEnv(c.terminal), append([]string{"--dir", dirArg, "--uid", u(uid), "--gid", u(gid)}, extra...)...)
			if r.code != 1 {
				t.Fatalf("exit %d, want 1\n%s%s", r.code, r.stdout, r.stderr)
			}
			if !regexp.MustCompile(`(?m)^FAIL .*` + regexp.QuoteMeta(c.want)).MatchString(r.stdout) {
				t.Errorf("no FAIL naming %q:\n%s", c.want, r.stdout)
			}
			if after := snapshot(t, dir); !sameSnapshot(before, after) {
				t.Error("a refused run changed the filesystem")
			}
			noTemps(t, dir)
			if strings.Contains(r.stdout+r.stderr, token[:20]) {
				t.Error("a refusal printed a token")
			}
		})
	}
}

// --- The fake host: other uids, root, failures --------------------------------------

const fdir = "/srv/shell-mcp/secrets"

func fake() *setuptest.Fake {
	f := setuptest.New()
	f.Dir("/srv", 0o755, 0, 0)
	f.Dir("/srv/shell-mcp", 0o755, 0, 0)
	return f
}

func runFake(t *testing.T, f *setuptest.Fake, env serverinit.Env, args ...string) result {
	t.Helper()
	o, err := serverinit.ParseFlags(args)
	if err != nil {
		t.Fatalf("ParseFlags(%q): %v", args, err)
	}
	if env.Rand == nil {
		env.Rand = rand.Reader
	}
	if env.IsTerminal == nil {
		env.IsTerminal = func(io.Writer) bool { return true }
	}
	var out, errb bytes.Buffer
	code := serverinit.Run(o, f, &env, &out, &errb)
	return result{code, out.String(), errb.String()}
}

func TestRootOnTheHost(t *testing.T) {
	f := fake()
	r := runFake(t, f, serverinit.Env{Euid: 0}, "--dir", fdir, "--approver", "alice")
	if r.code != 0 {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	snap := f.Snapshot()
	for p, m := range map[string]fs.FileMode{fdir: fs.ModeDir | 0o700, fdir + "/mcp_token": 0o600, fdir + "/ssh_key": 0o600,
		fdir + "/ssh_key.pub": 0o644, fdir + "/approvers": 0o600} {
		e, ok := snap[p]
		if !ok || e.Mode != m || e.UID != 65532 || e.GID != 65532 {
			t.Errorf("%s: %+v, want %v 65532:65532", p, e, m)
		}
	}
	if _, err := approvers.Parse(snap[fdir+"/approvers"].Data, approvers.MaxApprovers); err != nil {
		t.Errorf("approvers file: %v", err)
	}
	if len(f.Temps()) != 0 {
		t.Errorf("temps %v", f.Temps())
	}
}

func TestRootOwnedDirOnTheHost(t *testing.T) {
	f := fake()
	f.Dir(fdir, 0o700, 0, 0)
	r := runFake(t, f, serverinit.Env{Euid: 0}, "--dir", fdir)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stdout)
	}
	if !regexp.MustCompile(`(?m)^NOTE .*--form bind`).MatchString(r.stdout) {
		t.Errorf("no NOTE that the bind form needs the directory owned by 65532:\n%s", r.stdout)
	}
	if f.Snapshot()[fdir].UID != 0 {
		t.Error("the directory's owner was changed")
	}
}

func TestLeftoverRemovedFake(t *testing.T) {
	f := fake()
	f.Dir(fdir, 0o700, 65532, 65532)
	left := fdir + "/.ssh_key.shell-mcp-abcdefghijkl"
	f.Put(left, "x", 0o600, 0, 0)
	r := runFake(t, f, serverinit.Env{Euid: 0}, "--dir", fdir)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stdout)
	}
	if _, ok := f.Snapshot()[left]; ok || !strings.Contains(r.stdout, left) {
		t.Errorf("leftover not removed and reported:\n%s", r.stdout)
	}
}

// TestRefusalsFake: refusals that need a uid other than the test's.
func TestRefusalsFake(t *testing.T) {
	root := serverinit.Env{Euid: 0}
	cases := []struct {
		name  string
		env   serverinit.Env
		setup func(f *setuptest.Fake)
		args  []string
		want  string
	}{
		{"uid neither root nor --uid", serverinit.Env{Euid: 1000, Egid: 1000}, nil, nil, "effective uid 1000"},
		{"in the image, a directory owned by root", serverinit.Env{Euid: 65532, Egid: 65532}, func(f *setuptest.Fake) { f.Dir(fdir, 0o700, 0, 0) }, nil, "owned by 0"},
		{"a directory owned by another uid", root, func(f *setuptest.Fake) { f.Dir(fdir, 0o700, 1000, 1000) }, nil, "owned by 1000"},
		{"gid not ours", serverinit.Env{Euid: 65532, Egid: 100, Groups: []int{100}}, func(f *setuptest.Fake) { f.Dir(fdir, 0o700, 65532, 65532) }, nil, "--gid 65532"},
		{"uid 0", root, nil, []string{"--uid", "0"}, "--uid 0"},
		{"gid 0", root, nil, []string{"--gid", "0"}, "--gid 0"},
		{"relative dir", root, nil, []string{"--dir", "secrets"}, "absolute"},
		{"unclean dir", root, nil, []string{"--dir", "/srv/shell-mcp/../shell-mcp/secrets"}, "absolute"},
		{"token owned by root", root, func(f *setuptest.Fake) {
			f.Dir(fdir, 0o700, 65532, 65532)
			f.Put(fdir+"/mcp_token", strings.Repeat("a", 43), 0o600, 0, 0)
		}, nil, "chown 65532:65532"},
		{"pub owned by root", root, func(f *setuptest.Fake) {
			f.Dir(fdir, 0o700, 65532, 65532)
			k, p := edKey(t)
			f.Put(fdir+"/ssh_key", string(k), 0o600, 65532, 65532)
			f.Put(fdir+"/ssh_key.pub", string(ssh.MarshalAuthorizedKey(p)), 0o644, 0, 0)
		}, nil, "chown 65532:65532"},
		{"approvers owned by root", root, func(f *setuptest.Fake) {
			f.Dir(fdir, 0o700, 65532, 65532)
			f.Put(fdir+"/approvers", "alice "+strings.Repeat("A", 32)+"\n", 0o600, 0, 0)
		}, nil, "chown 65532:65532"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := fake()
			if c.setup != nil {
				c.setup(f)
			}
			args := append([]string{"--dir", fdir}, c.args...)
			if len(c.args) > 0 && c.args[0] == "--dir" {
				args = c.args
			}
			before := f.Snapshot()
			r := runFake(t, f, c.env, args...)
			if r.code != 1 || !regexp.MustCompile(`(?m)^FAIL .*`+regexp.QuoteMeta(c.want)).MatchString(r.stdout) {
				t.Fatalf("exit %d, want 1 with a FAIL naming %q:\n%s", r.code, c.want, r.stdout)
			}
			if f.Writes != 0 || len(f.Snapshot()) != len(before) {
				t.Error("a refused run wrote something")
			}
		})
	}
}

// TestRollback: a write that fails part-way removes what the run created,
// the directory included when the run created it, and leaves no temp file.
func TestRollback(t *testing.T) {
	for _, c := range []struct {
		name      string
		fail      string
		committed bool
	}{
		{"the approvers write fails", fdir + "/approvers", false},
		{"the .pub read-back fails", fdir + "/ssh_key.pub", true},
		{"the key write fails", fdir + "/ssh_key", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := fake()
			before := f.Snapshot()
			if c.committed {
				f.FailCommitted[c.fail] = errors.New("injected")
			} else {
				f.FailWrite[c.fail] = errors.New("injected")
			}
			r := runFake(t, f, serverinit.Env{Euid: 0}, "--dir", fdir, "--approver", "alice")
			if r.code != 1 || !strings.Contains(r.stdout, "rolled back") {
				t.Fatalf("exit %d, want 1 with a rollback:\n%s", r.code, r.stdout)
			}
			var extra []string
			for p := range f.Snapshot() {
				if _, ok := before[p]; !ok {
					extra = append(extra, p)
				}
			}
			slices.Sort(extra)
			if len(extra) != 0 {
				t.Errorf("left after the rollback: %v", extra)
			}
			if len(f.Temps()) != 0 {
				t.Errorf("temps %v", f.Temps())
			}
			if strings.Contains(r.stdout, "otpauth://") {
				t.Error("the seed was shown for an enrolment that was rolled back")
			}
		})
	}
	f := fake()
	f.Dir(fdir, 0o700, 65532, 65532)
	f.Put(fdir+"/mcp_token", strings.Repeat("a", 43), 0o600, 65532, 65532)
	f.FailWrite[fdir+"/ssh_key.pub"] = errors.New("injected")
	if r := runFake(t, f, serverinit.Env{Euid: 0}, "--dir", fdir); r.code != 1 {
		t.Fatalf("exit %d", r.code)
	}
	snap := f.Snapshot()
	if _, ok := snap[fdir]; !ok {
		t.Error("an existing directory was removed")
	}
	if _, ok := snap[fdir+"/mcp_token"]; !ok {
		t.Error("a kept file was removed")
	}
	if _, ok := snap[fdir+"/ssh_key"]; ok {
		t.Error("the key the run created was left")
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"--dir"}, {"--dir", "/srv/x", "extra"}, {"--dir", "/srv/x", "--uid", "x"},
		{"--dir", "/srv/x", "--uid", "-1"}, {"--dir", "/srv/x", "--gid", "4294967296"}, {"--dir", "/srv/x", "--approver", "Alice"},
		{"--dir", "/srv/x", "--token", "t"}} {
		if _, err := serverinit.ParseFlags(args); err == nil {
			t.Errorf("ParseFlags(%q) accepted", args)
		}
	}
	o, err := serverinit.ParseFlags([]string{"--dir", "/srv/x"})
	if err != nil || o.UID != 65532 || o.GID != 65532 || o.Dir != "/srv/x" || o.Approver != "" || o.DryRun {
		t.Errorf("defaults: %+v, %v", o, err)
	}
}
