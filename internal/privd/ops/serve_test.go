//go:build linux

package ops_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
	"github.com/tyler-rich/shell-mcp/internal/privd/ops"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// breakage is one post-authentication self-check failure (PRIVILEGED §7)
// and the check and code it is reported with.
type breakage struct {
	setup       func(f *fixture)
	check, code string
}

// breakages are paired with the passing control in
// TestServeAnswersAuthenticatedPeer.
func breakages(t *testing.T) map[string]breakage {
	rewritePolicy := func(f *fixture, from, to string) {
		y := readFile(t, f.policyPath)
		if !strings.Contains(y, from) {
			t.Fatalf("fixture policy lacks %q", from)
		}
		if err := os.WriteFile(f.policyPath, []byte(strings.Replace(y, from, to, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return map[string]breakage{
		"not root":           {func(f *fixture) { f.status = statusFor("60123", "1", "000000000000000f") }, "uid", "helper_install_insecure"},
		"no NoNewPrivs":      {func(f *fixture) { f.status = statusFor("0", "0", "000000000000000f") }, "no_new_privs", "helper_install_insecure"},
		"broad bounding set": {func(f *fixture) { f.status = statusFor("0", "1", "000001ffffffffff") }, "capabilities", "helper_capabilities_broad"},
		"unreadable status": {func(f *fixture) {
			f.opts.ReadStatus = func() ([]byte, error) { f.statusReads++; return nil, errors.New("no proc") }
		}, "uid", "helper_install_insecure"},
		"insecure binary": {func(f *fixture) {
			if err := os.Chmod(f.opts.Executable, 0o775); err != nil { //nolint:gosec // G302: a deliberately insecure or test fixture mode
				t.Fatal(err)
			}
		}, "binary", "helper_install_insecure"},
		"insecure policy": {func(f *fixture) {
			if err := os.Chmod(f.policyPath, 0o620); err != nil { //nolint:gosec // G302: a deliberately insecure or test fixture mode
				t.Fatal(err)
			}
		}, "policy_file", "helper_install_insecure"},
		"missing policy": {func(f *fixture) { f.opts.PolicyPath = filepath.Join(f.etc, "absent.yaml") }, "policy_file", "helper_install_insecure"},
		"policy YAML error": {func(f *fixture) {
			if err := os.WriteFile(f.policyPath, []byte("version: 1\nsudo: true\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "policy", "helper_policy_invalid"},
		"policy validation error": {func(f *fixture) {
			rewritePolicy(f, "write: ["+f.write+"]", "write: [/etc/ssh]")
		}, "policy", "helper_policy_invalid"},
		// A policy edited without regenerating the units (PRIVILEGED §2).
		"policy hash differs": {func(f *fixture) {
			rewritePolicy(f, "version: 1\n", "version: 1\n# edited after the units were generated\n")
		}, "policy_hash", "helper_policy_mismatch"},
		"no hash in the unit": {func(f *fixture) { f.opts.ExpectedSHA256 = "" }, "policy_hash", "helper_policy_mismatch"},
		// The unit names another client than the policy (a hand-edited
		// unit): the peer passed the unit's check, so it is told.
		"client_uid differs from the unit's": {func(f *fixture) {
			rewritePolicy(f, fmt.Sprintf("client_uid: %d", f.uid), fmt.Sprintf("client_uid: %d", f.uid+1))
			f.rehash()
		}, "client_uid", "helper_client_uid_mismatch"},
	}
}

// After the peer check passes, a failed self-check is answered — to the
// authenticated gate only — with its own code and a one-line reason that
// names no local path, before any byte of the request is read: the
// response has no id, the sandbox is never applied, and the journal gets
// one WARN line naming the check and the code.
func TestSelfCheckFailuresAnswered(t *testing.T) {
	for name, c := range breakages(t) {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c.setup(f)
			in := request("priv_stat", m{"path": f.read})
			out, code := f.serveRaw(in)
			var r response
			if err := json.Unmarshal([]byte(out), &r); err != nil || code == 0 {
				t.Fatalf("exit %d, response %q", code, out)
			}
			if r.V != 1 || r.ID != "" || r.OK || r.Error == nil || r.Error.Code != c.code || strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
				t.Fatalf("response %q, want one line with %s and no id", out, c.code)
			}
			if msg := r.Error.Message; msg == "" || strings.Contains(msg, f.d) || strings.ContainsAny(msg, "\r\n") {
				t.Fatalf("message %q is empty, multi-line or names a local path", msg)
			}
			if f.unread != len(in) || f.sandboxCalls != 0 {
				t.Fatalf("%d of %d request bytes left unread, sandbox applied %d times", f.unread, len(in), f.sandboxCalls)
			}
			l := f.lastAudit()
			for _, want := range []string{`"check":"` + c.check + `"`, `"outcome":"` + c.code + `"`, fmt.Sprintf(`"peer_uid":%d`, f.uid)} {
				if !strings.HasPrefix(l, "<4>") || !strings.Contains(l, want) {
					t.Fatalf("audit line %q lacks %s at WARN", l, want)
				}
			}
		})
	}
}

// Before the peer is authenticated nothing is written to it: a missing or
// malformed SHELL_MCP_PRIVD_CLIENT_UID in the unit, or a peer whose
// SO_PEERCRED uid is not that value, closes the connection without a byte
// and leaves one WARN line explaining why. Nothing is read from disk first.
func TestPreAuthRefusalsAreSilent(t *testing.T) {
	for name, c := range map[string]struct {
		env   func(uid uint32) string
		check string
	}{
		"wrong peer uid":          {func(uid uint32) string { return strconv.FormatUint(uint64(uid)+1, 10) }, "peer_uid"},
		"no client uid in unit":   {func(uint32) string { return "" }, "unit_client_uid"},
		"root as client uid":      {func(uint32) string { return "0" }, "unit_client_uid"},
		"malformed client uid":    {func(uid uint32) string { return " " + strconv.FormatUint(uint64(uid), 10) }, "unit_client_uid"},
		"client uid out of range": {func(uint32) string { return "4294967295" }, "unit_client_uid"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.opts.UnitClientUID = c.env(f.uid)
			in := request("priv_stat", m{"path": f.read})
			out, code := f.serveRaw(in)
			if out != "" || code == 0 {
				t.Fatalf("refusal wrote %q (exit %d)", out, code)
			}
			if f.unread != len(in) || f.sandboxCalls != 0 || f.statusReads != 0 || f.lookups != 0 {
				t.Fatalf("unread %d of %d, sandbox %d, status reads %d, policy loads %d", f.unread, len(in), f.sandboxCalls, f.statusReads, f.lookups)
			}
			l := f.lastAudit()
			if !strings.HasPrefix(l, "<4>") || !strings.Contains(l, `"check":"`+c.check+`"`) || !strings.Contains(l, `"outcome":"refused"`) {
				t.Fatalf("audit line %q", l)
			}
		})
	}
}

// The peer check comes first: a wrong peer is refused silently whatever
// else is broken, so an unauthenticated caller learns nothing about the
// helper's installation.
func TestPeerCheckComesFirst(t *testing.T) {
	for name, c := range breakages(t) {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c.setup(f)
			f.opts.UnitClientUID = strconv.FormatUint(uint64(f.uid)+1, 10)
			in := request("priv_stat", m{"path": f.read})
			out, code := f.serveRaw(in)
			if out != "" || code == 0 {
				t.Fatalf("wrong peer got %q (exit %d)", out, code)
			}
			if f.unread != len(in) || f.statusReads != 0 || f.lookups != 0 {
				t.Fatalf("unread %d of %d, status reads %d, policy loads %d", f.unread, len(in), f.statusReads, f.lookups)
			}
			if l := f.lastAudit(); !strings.Contains(l, `"check":"peer_uid"`) || !strings.Contains(l, `"outcome":"refused"`) {
				t.Fatalf("audit line %q", l)
			}
		})
	}
}

// The invariant behind the gate's helper_refused: the helper reads no byte
// of the request until the peer check and every self-check have passed and
// Landlock is applied. Every refusal — silent or answered — leaves the
// whole request queued on the socket, and on success all of it is still
// unread when the sandbox is applied.
func TestNoRequestByteReadBeforeChecksPass(t *testing.T) {
	cases := map[string]func(f *fixture){
		"wrong peer":  func(f *fixture) { f.opts.UnitClientUID = strconv.FormatUint(uint64(f.uid)+1, 10) },
		"no unit uid": func(f *fixture) { f.opts.UnitClientUID = "" },
		"sandbox refuses": func(f *fixture) {
			f.opts.ApplySandbox = func(*policy.Policy, string) (sandbox.Report, error) {
				f.sandboxCalls++
				return sandbox.Report{}, sandbox.ErrUnavailable
			}
		},
	}
	for name, c := range breakages(t) {
		cases[name] = c.setup
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			setup(f)
			in := request("priv_stat", m{"path": f.read})
			_, _ = f.serveRaw(in)
			if f.unread != len(in) {
				t.Fatalf("the helper read %d of %d request bytes before refusing", len(in)-f.unread, len(in))
			}
		})
	}
	f := newFixture(t)
	in := request("priv_stat", m{"path": f.read})
	if _, code := f.serveRaw(in); code != 0 || f.sandboxCalls != 1 || f.unreadAtSandbox != len(in) || f.unread != 0 {
		t.Fatalf("exit %d, sandbox calls %d, unread at sandbox %d of %d, unread at exit %d", code, f.sandboxCalls, f.unreadAtSandbox, len(in), f.unread)
	}
}

// Stdin that is not a stream socket is refused (a pipe cannot carry peer
// credentials either).
func TestRefusesNonSocketStdin(t *testing.T) {
	f := newFixture(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	_, _ = w.WriteString(request("priv_stat", m{"path": f.read}))
	o := f.opts
	o.Conn = r
	if code := ops.Serve(&o); code == 0 {
		t.Fatal("pipe stdin served")
	}
	if l := f.lastAudit(); !strings.Contains(l, `"check":"stdin"`) {
		t.Fatalf("audit %q", l)
	}
}

func TestServeAnswersAuthenticatedPeer(t *testing.T) {
	f := newFixture(t)
	var e struct {
		Path, Type string
	}
	r := f.ok("priv_stat", m{"path": filepath.Join(f.read, "hello.txt")}, &e)
	if e.Type != "file" {
		t.Fatalf("stat %+v", e)
	}
	var g struct {
		MaxTier string `json:"max_tier"`
		Hash    string `json:"policy_sha256"`
	}
	if err := json.Unmarshal(r.Gate, &g); err != nil || g.Hash != f.opts.ExpectedSHA256 || g.MaxTier != "destructive" {
		t.Fatalf("gate info %s", r.Gate)
	}
	// Landlock is applied after the checks and before a byte is read.
	if f.sandboxCalls != 1 || f.unreadAtSandbox != len(request("priv_stat", m{"path": filepath.Join(f.read, "hello.txt")})) {
		t.Fatalf("sandbox calls %d, unread bytes at sandbox time %d", f.sandboxCalls, f.unreadAtSandbox)
	}
	l := f.lastAudit()
	for _, want := range []string{`"id":"` + reqID + `"`, `"peer_uid":`, `"peer_pid":`, `"op":"priv_stat"`, `"outcome":"ok"`, `"duration_ms":`} {
		if !strings.Contains(l, want) {
			t.Errorf("audit line lacks %s: %q", want, l)
		}
	}
	if !strings.HasPrefix(l, "<6>") {
		t.Errorf("success is not logged at info: %q", l)
	}
}

// A Landlock refusal in the core unit is answered like the other
// self-check failures (PRIVILEGED §7 step 3): helper_sandbox_unavailable —
// never the gate's own sandbox_unavailable, so an operator can tell which
// component lacks the sandbox — without an id (the request is unread),
// with a one-line message naming no local path, a WARN journal line naming
// the check, and exit status 1.
func TestSandboxRefusal(t *testing.T) {
	f := newFixture(t)
	f.opts.ApplySandbox = func(*policy.Policy, string) (sandbox.Report, error) {
		return sandbox.Report{}, sandbox.ErrUnavailable
	}
	in := request("priv_stat", m{"path": f.read})
	out, code := f.serveRaw(in)
	var r response
	if err := json.Unmarshal([]byte(out), &r); err != nil || code != 1 || r.ID != "" || r.Error == nil || r.Error.Code != "helper_sandbox_unavailable" || f.unread != len(in) {
		t.Fatalf("exit %d response %q, unread %d of %d", code, out, f.unread, len(in))
	}
	if msg := r.Error.Message; msg == "" || strings.Contains(msg, f.d) || strings.ContainsAny(msg, "\r\n") {
		t.Fatalf("message %q is empty, multi-line or names a local path", msg)
	}
	l := f.lastAudit()
	for _, want := range []string{`"check":"landlock"`, `"outcome":"helper_sandbox_unavailable"`, fmt.Sprintf(`"peer_uid":%d`, f.uid)} {
		if !strings.HasPrefix(l, "<4>") || !strings.Contains(l, want) {
			t.Fatalf("audit line %q lacks %s at WARN", l, want)
		}
	}
}

func TestRequestErrors(t *testing.T) {
	f := newFixture(t)
	for in, code := range map[string]string{
		`{"v":1,"id":"` + reqID + `","op":"priv_stat","op":"priv_stat"}` + "\n": "bad_request",
		`{"v":2,"id":"` + reqID + `","op":"priv_stat"}` + "\n":                  "protocol_mismatch",
		`{"v":1,"id":"a","op":"priv_stat"}` + "\n":                              "bad_request",
		"not json\n": "bad_request",
	} {
		out, _ := f.serveRaw(in)
		var r response
		if err := json.Unmarshal([]byte(out), &r); err != nil || r.Error == nil || r.Error.Code != code {
			t.Errorf("%q: %q, want %s", in, out, code)
		}
	}
	for _, op := range []string{"priv_pkg_install", "priv_pkg_update_index", "priv_pkg_upgrade", "priv_pkg_remove", "read_file", "priv_made_up"} {
		f.fail(op, m{}, "unknown_op")
	}
	f.fail("priv_stat", m{"path": f.read, "extra": true}, "bad_request")
}

func TestTierDenied(t *testing.T) {
	f := newFixture(t, maxTier("read"))
	f.ok("priv_stat", m{"path": f.read}, nil)
	f.ok("priv_list_backups", m{}, nil)
	for op, args := range map[string]m{
		"priv_write_file":     {"path": filepath.Join(f.write, "x"), "content_b64": b64("x")},
		"priv_mkdir":          {"path": filepath.Join(f.write, "d")},
		"priv_chown":          {"path": filepath.Join(f.write, "app.conf"), "owner": "tester"},
		"priv_chmod":          {"path": filepath.Join(f.write, "app.conf"), "mode": "0600"},
		"priv_copy":           {"source": filepath.Join(f.read, "hello.txt"), "destination": filepath.Join(f.write, "c")},
		"priv_move":           {"source": filepath.Join(f.write, "app.conf"), "destination": filepath.Join(f.write, "m")},
		"priv_restore_backup": {"id": "20260929T120000Z-0123456789abcdef"},
		"priv_delete":         {"path": filepath.Join(f.write, "app.conf")},
	} {
		f.fail(op, args, "tier_denied")
	}
	f.fail("priv_exec", m{"command_id": "probe-op", "args": []string{"echo", "operator"}}, "tier_denied")
	if readFile(t, filepath.Join(f.write, "app.conf")) != "key: value\n" {
		t.Fatal("a tier-denied op changed something")
	}
	f2 := newFixture(t, maxTier("operator"))
	f2.fail("priv_delete", m{"path": filepath.Join(f2.write, "app.conf")}, "tier_denied")
}
