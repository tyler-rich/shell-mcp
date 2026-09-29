//go:build linux

package ops_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
	"github.com/tyler-rich/shell-mcp/internal/privd/ops"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// A refusal (PRIVILEGED §3, §7) closes the connection without writing a
// single byte and logs one WARN audit line naming the failed check. Every
// case is paired with the passing control in TestServeAnswersAuthenticatedPeer.
func TestRefusalsCloseWithoutResponse(t *testing.T) {
	for name, c := range map[string]struct {
		setup func(f *fixture)
		check string
	}{
		"not root":          {func(f *fixture) { f.status = statusFor("60123", "1", "000000000000000f") }, "uid"},
		"no NoNewPrivs":     {func(f *fixture) { f.status = statusFor("0", "0", "000000000000000f") }, "no_new_privs"},
		"broad bounding set": {func(f *fixture) { f.status = statusFor("0", "1", "000001ffffffffff") }, "capabilities"},
		"unreadable status": {func(f *fixture) {
			f.opts.ReadStatus = func() ([]byte, error) { return nil, errors.New("no proc") }
		}, "uid"},
		"insecure binary": {func(f *fixture) {
			if err := os.Chmod(f.opts.Executable, 0o775); err != nil {
				t.Fatal(err)
			}
		}, "binary"},
		"insecure policy": {func(f *fixture) {
			if err := os.Chmod(f.policyPath, 0o620); err != nil {
				t.Fatal(err)
			}
		}, "policy"},
		"invalid policy": {func(f *fixture) {
			if err := os.WriteFile(f.policyPath, []byte("version: 1\nsudo: true\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "policy"},
		// A policy edited without regenerating the units (PRIVILEGED §2).
		"policy hash differs": {func(f *fixture) {
			fh, err := os.OpenFile(f.policyPath, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = fh.WriteString("# edited after the units were generated\n")
			_ = fh.Close()
		}, "policy_hash"},
		"no hash in the unit": {func(f *fixture) { f.opts.ExpectedSHA256 = "" }, "policy_hash"},
		"wrong peer uid":      {func(f *fixture) {}, "peer_uid"},
	} {
		t.Run(name, func(t *testing.T) {
			var f *fixture
			if name == "wrong peer uid" {
				f = newFixture(t, func(f *fixture, s *string) { clientUID(f.uid+1)(f, s) })
			} else {
				f = newFixture(t)
			}
			c.setup(f)
			out, code := f.serveRaw(request("priv_stat", m{"path": f.read}))
			if out != "" || code == 0 {
				t.Fatalf("refusal wrote %q (exit %d)", out, code)
			}
			if f.sandboxCalls != 0 {
				t.Fatal("sandbox applied before the refusal")
			}
			l := f.lastAudit()
			if !strings.HasPrefix(l, "<4>") || !strings.Contains(l, `"check":"`+c.check+`"`) || !strings.Contains(l, `"outcome":"refused"`) {
				t.Fatalf("audit line %q", l)
			}
		})
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
	if f.sandboxCalls != 1 || f.peekedAtSandbox == 0 {
		t.Fatalf("sandbox calls %d, unread bytes at sandbox time %d", f.sandboxCalls, f.peekedAtSandbox)
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

func TestSandboxRefusal(t *testing.T) {
	f := newFixture(t)
	f.opts.ApplySandbox = func(*policy.Policy, string) (sandbox.Report, error) {
		return sandbox.Report{}, sandbox.ErrUnavailable
	}
	// The request is never read, so the response has no id.
	out, code := f.serveRaw(request("priv_stat", m{"path": f.read}))
	var r response
	if err := json.Unmarshal([]byte(out), &r); err != nil || code != 0 || r.ID != "" || r.Error == nil || r.Error.Code != "sandbox_unavailable" {
		t.Fatalf("exit %d response %q", code, out)
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
