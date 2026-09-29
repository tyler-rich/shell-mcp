//go:build linux

package ops_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
	"github.com/tyler-rich/shell-mcp/internal/privd/ops"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/units"
)

// fixture is an invented host layout under a secure temp dir: a read root,
// a write root, a backup store and a helper binary. Nothing here describes
// a real host; users and groups are invented and resolved by fake lookups.
type fixture struct {
	t                                   *testing.T
	d, read, write, backups, etc, probe string
	policyPath                          string
	uid, gid                            uint32
	opts                                ops.Options
	audit                               *bytes.Buffer
	status                              string
	// sandboxCalls counts ApplySandbox; peekedAtSandbox is what was still
	// unread on the connection when it was applied.
	sandboxCalls    int
	peekedAtSandbox int
	clientFD        int
}

const reqID = "0b5c0000-0000-4000-8000-000000000002"

// Base64 of the base capability set's mask (CapBnd 000000000000000f).
func statusFor(uid, nnp, capBnd string) string {
	return "Name:\tshell-mcp-privd\nUid:\t" + uid + "\t" + uid + "\t" + uid + "\t" + uid +
		"\nGid:\t0\t0\t0\t0\nCapBnd:\t" + capBnd + "\nNoNewPrivs:\t" + nnp + "\nSeccomp:\t2\n"
}

type opt func(*fixture, *string)

func maxTier(t string) opt {
	return func(_ *fixture, s *string) { *s = strings.Replace(*s, "max_tier: destructive", "max_tier: "+t, 1) }
}

func keep(n int) opt {
	return func(_ *fixture, s *string) { *s = strings.Replace(*s, "keep: 3", fmt.Sprintf("keep: %d", n), 1) }
}

func clientUID(uid uint32) opt {
	return func(f *fixture, s *string) {
		*s = strings.Replace(*s, fmt.Sprintf("client_uid: %d", f.uid), fmt.Sprintf("client_uid: %d", uid), 1)
	}
}

func newFixture(t *testing.T, opts ...opt) *fixture {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("the helper's unit tests run as an unprivileged user (root is exercised by the e2e job)")
	}
	d := gatetest.SecureDir(t)
	f := &fixture{
		t: t, d: d,
		read:    filepath.Join(d, "srv", "app"),
		write:   filepath.Join(d, "etc", "example-app"),
		backups: filepath.Join(d, "var", "lib", "shell-mcp", "backups"),
		etc:     filepath.Join(d, "etc", "shell-mcp"),
		uid:     uint32(os.Getuid()), //nolint:gosec // G115: test ids fit
		gid:     uint32(os.Getgid()), //nolint:gosec // G115: test ids fit
		audit:   &bytes.Buffer{},
		status:  statusFor("0", "1", "000000000000000f"),
	}
	for _, p := range []string{f.read, f.write, f.etc} {
		gatetest.Mkdir(t, p, 0o755)
	}
	gatetest.Mkdir(t, f.backups, 0o700)
	gatetest.WriteFile(t, filepath.Join(f.read, "hello.txt"), "hello\nworld\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(f.read, "secrets", "token"), "TOPSECRET", 0o600)
	gatetest.WriteFile(t, filepath.Join(f.write, "app.conf"), "key: value\n", 0o640)
	exe := filepath.Join(d, "libexec", "shell-mcp-privd")
	gatetest.WriteFile(t, exe, "invented helper binary", 0o755)
	f.probe = filepath.Join(d, "bin", "example-probe")
	if _, err := os.Stat(f.probe); err != nil {
		gatetest.Mkdir(t, filepath.Dir(f.probe), 0o755)
		gatetest.BuildProbe(t, filepath.Dir(f.probe), "example-probe", filepath.Join(d, "outside.txt"))
	}
	y := fmt.Sprintf(`version: 1
client_uid: %d
socket_group: svc-shell-priv
max_tier: destructive
sandbox:
  landlock: best-effort
limits:
  max_read_bytes: 65536
  max_write_bytes: 65536
  max_output_bytes: 4096
  default_timeout_s: 5
  max_timeout_s: 10
  max_delete_entries: 20
paths:
  read: [%s]
  write: [%s]
  deny: ["%s/secrets/**"]
owners:
  users: [tester, root]
  groups: [tester, root]
modes:
  max: "0755"
backups:
  keep: 3
commands:
  - id: probe-echo
    path: %s
    tier: read
    templates: [["echo", "{regex:^[a-z]+$}"], ["write", "{path:write}", "{regex:^[a-z]+$}"]]
  - id: probe-op
    path: %s
    tier: operator
    templates: [["echo", "operator"]]
`, f.uid, f.read, f.write, f.read, f.probe, f.probe)
	for _, o := range opts {
		o(f, &y)
	}
	f.policyPath = filepath.Join(f.etc, "privileged.yaml")
	gatetest.WriteFile(t, f.policyPath, y, 0o600)
	f.opts = ops.Options{
		Version:    "test",
		PolicyPath: f.policyPath,
		Executable: exe,
		Trust:      gatetest.Trust(),
		Lookups: func(o *policy.LoadOptions) {
			users := map[string]uint32{"root": 0, "tester": f.uid, "example-app": 1001}
			groups := map[string]uint32{"root": 0, "tester": f.gid, "svc-shell-priv": 60124}
			o.LookupUser = func(n string) (uint32, error) {
				if id, ok := users[n]; ok {
					return id, nil
				}
				return 0, errors.New("unknown user")
			}
			o.LookupGroup = func(n string) (uint32, error) {
				if id, ok := groups[n]; ok {
					return id, nil
				}
				return 0, errors.New("unknown group")
			}
			o.UserName = func(uid uint32) string {
				for n, id := range users {
					if id == uid {
						return n
					}
				}
				return ""
			}
		},
		SystemBinDirs: []string{filepath.Join(d, "sysbin")},
		ReadStatus:    func() ([]byte, error) { return []byte(f.status), nil },
		BackupDir:     f.backups,
		Audit:         f.audit,
		Now:           func() time.Time { return time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC) },
	}
	f.opts.ApplySandbox = func(*policy.Policy, string) (sandbox.Report, error) {
		f.sandboxCalls++
		buf := make([]byte, 1<<16)
		n, _, _ := unix.Recvfrom(f.clientFD, buf, unix.MSG_PEEK|unix.MSG_DONTWAIT)
		f.peekedAtSandbox = n
		return sandbox.Report{Mode: "best-effort"}, nil
	}
	f.rehash()
	return f
}

// rehash sets the unit's expected hash to the policy file's current hash.
func (f *fixture) rehash() {
	f.t.Helper()
	p, err := policy.Load(f.policyPath, f.loadOptions())
	if err != nil {
		f.t.Fatalf("fixture policy: %v", err)
	}
	f.opts.ExpectedSHA256 = p.SHA256
}

func (f *fixture) loadOptions() *policy.LoadOptions {
	o := &policy.LoadOptions{Trust: f.opts.Trust, HelperExecutable: f.opts.Executable, SystemBinDirs: f.opts.SystemBinDirs}
	f.opts.Lookups(o)
	return o
}

// serveRaw runs Serve on one end of a socket pair after writing in to the
// other end, and returns everything the helper wrote before closing.
func (f *fixture) serveRaw(in string) (out string, code int) {
	f.t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = unix.Close(fds[1]) }()
	f.clientFD = fds[1]
	if _, err := unix.Write(fds[1], []byte(in)); err != nil {
		f.t.Fatal(err)
	}
	conn := os.NewFile(uintptr(fds[0]), "conn")
	o := f.opts
	o.Conn = conn
	code = ops.Serve(&o)
	_ = conn.Close()
	var b []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := unix.Read(fds[1], buf)
		if n <= 0 || err != nil {
			break
		}
		b = append(b, buf[:n]...)
	}
	return string(b), code
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
	Warnings []string        `json:"warnings"`
	Gate     json.RawMessage `json:"gate"`
}

type m = map[string]any

func request(op string, args any) string {
	a, _ := json.Marshal(args)
	return fmt.Sprintf(`{"v":1,"id":%q,"op":%q,"args":%s,"timeout_ms":5000}`+"\n", reqID, op, a)
}

func (f *fixture) serve(op string, args any) response {
	f.t.Helper()
	out, code := f.serveRaw(request(op, args))
	var r response
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		f.t.Fatalf("%s: response %q (exit %d) is not JSON: %v", op, out, code, err)
	}
	if code != 0 || r.V != 1 || r.ID != reqID || !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
		f.t.Fatalf("%s: exit %d envelope %q", op, code, out)
	}
	return r
}

func (f *fixture) ok(op string, args, into any) response {
	f.t.Helper()
	r := f.serve(op, args)
	if !r.OK || r.Error != nil {
		f.t.Fatalf("%s %v: %+v", op, args, r.Error)
	}
	if into != nil {
		if err := json.Unmarshal(r.Data, into); err != nil {
			f.t.Fatalf("%s data %s: %v", op, r.Data, err)
		}
	}
	return r
}

func (f *fixture) fail(op string, args any, code string) {
	f.t.Helper()
	r := f.serve(op, args)
	if r.OK || r.Error == nil || r.Error.Code != code {
		f.t.Fatalf("%s %v: got ok=%v error %+v, want %s", op, args, r.OK, r.Error, code)
	}
}

// auditLines returns the audit lines written so far.
func (f *fixture) auditLines() []string {
	s := strings.TrimRight(f.audit.String(), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func (f *fixture) lastAudit() string {
	f.t.Helper()
	l := f.auditLines()
	if len(l) == 0 {
		f.t.Fatal("no audit line")
	}
	return l[len(l)-1]
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: test fixture
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// backupsIn lists the backup store's file names.
func (f *fixture) backupFiles() []string {
	f.t.Helper()
	ents, err := os.ReadDir(f.backups)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

var _ = units.BackupDir
