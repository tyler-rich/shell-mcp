//go:build linux

package ops_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// twoHelpers stands in for the core and the broad helper sockets. Each
// answers ok with data naming itself, so a test can tell where the gate
// sent a request.
type twoHelpers struct {
	mu  sync.Mutex
	got map[string][]string // socket → request lines
}

const (
	coreSock  = "/run/shell-mcp/privd.sock"
	broadSock = "/run/shell-mcp/privd-broad.sock"
)

func startTwoHelpers(t *testing.T, f *fixture, privileged string) *twoHelpers {
	t.Helper()
	h := &twoHelpers{got: map[string][]string{}}
	dir := sockDir(t)
	local := map[string]string{}
	for name, sock := range map[string]string{"core": coreSock, "broad": broadSock} {
		p := filepath.Join(dir, name+".sock")
		local[sock] = p
		l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				line, _ := bufio.NewReader(c).ReadString('\n')
				h.mu.Lock()
				h.got[sock] = append(h.got[sock], line)
				h.mu.Unlock()
				var r struct {
					ID string `json:"id"`
				}
				_ = json.Unmarshal([]byte(line), &r)
				_, _ = c.Write([]byte(`{"v":1,"id":"` + r.ID + `","ok":true,"data":{"from":"` + name + `"},"warnings":[]}` + "\n"))
				_ = c.Close()
			}
		}()
	}
	f.opts.DialHelper = func(ctx context.Context, socket string) (net.Conn, error) {
		p, ok := local[socket]
		if !ok {
			return nil, errors.New("gate dialed an unexpected socket " + socket)
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", p)
	}
	f.opts.HelperGrace = 200 * time.Millisecond
	f.writePolicy("destructive", privileged)
	return h
}

const bothSockets = "privileged:\n  enabled: true\n  socket: " + coreSock + "\n  broad_socket: " + broadSock + "\n  max_tier: destructive\n"

func (h *twoHelpers) count(sock string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.got[sock])
}

// The gate sends the package operations (and their previews) and priv_power
// to privileged.broad_socket, priv_exec to the socket its `unit` argument
// names (the server supplies it; the gate cannot read the privileged
// policy), and everything else to privileged.socket. The helper instance is
// authoritative; this only picks the door.
func TestRouting(t *testing.T) {
	t.Parallel()
	for op, c := range map[string]struct {
		args string
		want string
	}{
		"priv_stat":                     {`{"path":"/etc/example-app"}`, "core"},
		"priv_backup_check":             {`{"path":"/etc/example-app/x"}`, "core"},
		"priv_chown_preview":            {`{"path":"/etc/example-app/x","owner":"root"}`, "core"},
		"priv_chmod_preview":            {`{"path":"/etc/example-app/x","mode":"0640","recursive":true}`, "core"},
		"priv_write_file":               {`{"path":"/etc/example-app/x","content_b64":"eA=="}`, "core"},
		"priv_delete":                   {`{"path":"/etc/example-app/x"}`, "core"},
		"priv_delete_preview":           {`{"path":"/etc/example-app/x","recursive":true}`, "core"},
		"priv_restore_preview":          {`{"id":"20261019T120000Z-0123456789abcdef"}`, "core"},
		"priv_exec_preview":             {`{"command_id":"renew","args":[]}`, "core"},
		"priv_exec":                     {`{"command_id":"probe","args":[]}`, "core"},
		"priv_exec/core":                {`{"command_id":"probe","args":[],"unit":"core"}`, "core"},
		"priv_exec/broad":               {`{"command_id":"renew","args":[],"unit":"broad"}`, "broad"},
		"priv_pkg_update_index":         {`{}`, "broad"},
		"priv_pkg_update_index_preview": {`{}`, "broad"},
		"priv_pkg_install":              {`{"packages":["htop"]}`, "broad"},
		"priv_pkg_install_preview":      {`{"packages":["htop"]}`, "broad"},
		"priv_pkg_upgrade":              {`{}`, "broad"},
		"priv_pkg_upgrade_preview":      {`{}`, "broad"},
		"priv_pkg_remove":               {`{"packages":["htop"]}`, "broad"},
		"priv_pkg_remove_preview":       {`{"packages":["htop"]}`, "broad"},
		"priv_power":                    {`{"action":"reboot"}`, "broad"},
		"priv_power_preview":            {`{"action":"reboot"}`, "broad"},
		"priv_power_cancel":             {`{}`, "broad"},
		"priv_policy":                   {`{}`, "core"},
	} {
		t.Run(op, func(t *testing.T) {
			f := newFixture(t, "destructive")
			startTwoHelpers(t, f, bothSockets)
			name := op
			if i := len("priv_exec/"); len(op) > i && op[:i] == "priv_exec/" {
				name = "priv_exec"
			}
			r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"` + name + `","args":` + c.args + `,"timeout_ms":2000}` + "\n")
			if !r.OK || string(r.Data) != `{"from":"`+c.want+`"}` {
				t.Fatalf("%s went to %s (error %+v), want %s", op, r.Data, r.Error, c.want)
			}
		})
	}
}

// A broad route without privileged.broad_socket is refused before anything
// is sent; a malformed unit argument is bad_request; the args are still
// forwarded byte for byte.
func TestRoutingRefusals(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "destructive")
	h := startTwoHelpers(t, f, "privileged:\n  enabled: true\n  socket: "+coreSock+"\n  max_tier: destructive\n")
	f.ok("priv_stat", m{"path": "/etc/example-app"}, nil) // control
	f.fail("priv_pkg_update_index", m{}, "privileged_disabled")
	f.fail("priv_power", m{"action": "reboot"}, "privileged_disabled")
	f.fail("priv_exec", m{"command_id": "renew", "args": []string{}, "unit": "broad"}, "privileged_disabled")
	if h.count(broadSock) != 0 || h.count(coreSock) != 1 {
		t.Fatalf("sent core %d broad %d", h.count(coreSock), h.count(broadSock))
	}
	f2 := newFixture(t, "destructive")
	h2 := startTwoHelpers(t, f2, bothSockets)
	for _, args := range []string{
		`{"command_id":"probe","args":[],"unit":"sideways"}`,
		`{"command_id":"probe","args":[],"unit":"Broad"}`,
		`{"command_id":"probe","args":[],"unit":7}`,
		`{"command_id":"probe","args":[],"unit":"core","unit":"broad"}`,
	} {
		r, _ := f2.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"priv_exec","args":` + args + `,"timeout_ms":2000}` + "\n")
		if r.OK || r.Error == nil || r.Error.Code != "bad_request" {
			t.Errorf("%s: %+v", args, r.Error)
		}
	}
	if h2.count(broadSock)+h2.count(coreSock) != 0 {
		t.Fatal("a malformed unit argument was forwarded")
	}
	args := `{"command_id":"renew","args":["--all"],"unit":"broad"}`
	f2.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"priv_exec","args":` + args + `,"timeout_ms":2000}` + "\n")
	h2.mu.Lock()
	defer h2.mu.Unlock()
	var got struct {
		Args json.RawMessage `json:"args"`
	}
	if len(h2.got[broadSock]) != 1 || json.Unmarshal([]byte(h2.got[broadSock][0]), &got) != nil || string(got.Args) != args {
		t.Fatalf("forwarded %q", h2.got[broadSock])
	}
}

// The gate's tiers for the new operations: the previews are read, the
// mutating package operations operator (remove destructive), priv_power
// destructive, and priv_power_cancel read (S4c-8: never approval-gated).
func TestRoutingTiers(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "destructive")
	h := startTwoHelpers(t, f, "privileged:\n  enabled: true\n  socket: "+coreSock+"\n  broad_socket: "+broadSock+"\n  max_tier: read\n")
	for _, op := range []string{"priv_pkg_update_index_preview", "priv_pkg_install_preview", "priv_pkg_upgrade_preview", "priv_pkg_remove_preview", "priv_power_preview", "priv_power_cancel"} {
		f.ok(op, m{}, nil)
	}
	for _, op := range []string{"priv_pkg_update_index", "priv_pkg_install", "priv_pkg_upgrade", "priv_pkg_remove", "priv_power"} {
		f.fail(op, m{}, "tier_denied")
	}
	f.writePolicy("destructive", "privileged:\n  enabled: true\n  socket: "+coreSock+"\n  broad_socket: "+broadSock+"\n  max_tier: operator\n")
	f.ok("priv_pkg_install", m{}, nil)
	f.fail("priv_pkg_remove", m{}, "tier_denied")
	f.fail("priv_power", m{}, "tier_denied")
	if h.count(broadSock) != 7 {
		t.Fatalf("broad got %d requests, want 7", h.count(broadSock))
	}
}

// TestBackupCheckIsReadTier: priv_backup_check (handoff P-11) is a read op
// the gate forwards at ceiling read, to the core socket.
func TestBackupCheckIsReadTier(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "read")
	h := startTwoHelpers(t, f, "privileged:\n  enabled: true\n  socket: "+coreSock+"\n  broad_socket: "+broadSock+"\n  max_tier: read\n")
	f.writePolicy("read", "privileged:\n  enabled: true\n  socket: "+coreSock+"\n  broad_socket: "+broadSock+"\n  max_tier: read\n")
	r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"priv_backup_check","args":{"path":"/etc/example-app/x"},"timeout_ms":2000}` + "\n")
	if !r.OK || string(r.Data) != `{"from":"core"}` || h.count(coreSock) != 1 {
		t.Fatalf("priv_backup_check at ceiling read: %s %+v", r.Data, r.Error)
	}
}

// TestPolicySummaryIsReadTier: priv_policy (handoff P-8) is a read op the
// gate forwards at ceiling read under privileged.max_tier read, to the core
// socket.
func TestPolicySummaryIsReadTier(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "read")
	pol := "privileged:\n  enabled: true\n  socket: " + coreSock + "\n  broad_socket: " + broadSock + "\n  max_tier: read\n"
	h := startTwoHelpers(t, f, pol)
	f.writePolicy("read", pol)
	r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"priv_policy","args":{},"timeout_ms":2000}` + "\n")
	if !r.OK || string(r.Data) != `{"from":"core"}` || h.count(coreSock) != 1 || h.count(broadSock) != 0 {
		t.Fatalf("priv_policy at ceiling read: %s %+v", r.Data, r.Error)
	}
}

// The chown and chmod previews (handoff P-2b) are read-tier core ops: sent
// to the core socket under privileged.max_tier read at ceiling read, while
// the operations themselves are refused there.
func TestMetaPreviewsAreReadTier(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "read")
	pol := "privileged:\n  enabled: true\n  socket: " + coreSock + "\n  broad_socket: " + broadSock + "\n  max_tier: read\n"
	h := startTwoHelpers(t, f, pol)
	f.writePolicy("read", pol)
	for _, op := range []string{`"priv_chown_preview","args":{"path":"/etc/example-app/x","group":"root"}`, `"priv_chmod_preview","args":{"path":"/etc/example-app/x","mode":"0640"}`} {
		r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":` + op + `,"timeout_ms":2000}` + "\n")
		if !r.OK || string(r.Data) != `{"from":"core"}` {
			t.Fatalf("%s at ceiling read: %s %+v", op, r.Data, r.Error)
		}
	}
	for _, op := range []string{`"priv_chown","args":{"path":"/etc/example-app/x","group":"root"}`, `"priv_chmod","args":{"path":"/etc/example-app/x","mode":"0640"}`} {
		r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":` + op + `,"timeout_ms":2000}` + "\n")
		if r.OK || r.Error == nil || r.Error.Code != "tier_denied" {
			t.Fatalf("%s at ceiling read: %+v", op, r.Error)
		}
	}
	if h.count(coreSock) != 2 || h.count(broadSock) != 0 {
		t.Fatalf("core %d broad %d", h.count(coreSock), h.count(broadSock))
	}
}

// The restore preview (handoff P-2c) is a read-tier core op: sent to the
// core socket at ceiling read under privileged.max_tier read, while the
// restore itself (operator) is refused there.
func TestRestorePreviewIsReadTier(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "read")
	pol := "privileged:\n  enabled: true\n  socket: " + coreSock + "\n  broad_socket: " + broadSock + "\n  max_tier: read\n"
	h := startTwoHelpers(t, f, pol)
	f.writePolicy("read", pol)
	r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"priv_restore_preview","args":{"id":"20261019T120000Z-0123456789abcdef"},"timeout_ms":2000}` + "\n")
	if !r.OK || string(r.Data) != `{"from":"core"}` {
		t.Fatalf("priv_restore_preview at ceiling read: %s %+v", r.Data, r.Error)
	}
	r, _ = f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"priv_restore_backup","args":{"id":"20261019T120000Z-0123456789abcdef"},"timeout_ms":2000}` + "\n")
	if r.OK || r.Error == nil || r.Error.Code != "tier_denied" {
		t.Fatalf("priv_restore_backup at ceiling read: %+v", r.Error)
	}
	if h.count(coreSock) != 1 || h.count(broadSock) != 0 {
		t.Fatalf("core %d broad %d", h.count(coreSock), h.count(broadSock))
	}
}

// The delete preview (handoff P-2a) is a read-tier core op: sent to the
// core socket at ceiling read under privileged.max_tier read, while the
// delete itself is refused there.
func TestDeletePreviewIsReadTier(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "read")
	pol := "privileged:\n  enabled: true\n  socket: " + coreSock + "\n  broad_socket: " + broadSock + "\n  max_tier: read\n"
	h := startTwoHelpers(t, f, pol)
	f.writePolicy("read", pol)
	r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"priv_delete_preview","args":{"path":"/etc/example-app/x","recursive":true},"timeout_ms":2000}` + "\n")
	if !r.OK || string(r.Data) != `{"from":"core"}` {
		t.Fatalf("priv_delete_preview at ceiling read: %s %+v", r.Data, r.Error)
	}
	r, _ = f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"priv_delete","args":{"path":"/etc/example-app/x"},"timeout_ms":2000}` + "\n")
	if r.OK || r.Error == nil || r.Error.Code != "tier_denied" {
		t.Fatalf("priv_delete at ceiling read: %+v", r.Error)
	}
	if h.count(coreSock) != 1 || h.count(broadSock) != 0 {
		t.Fatalf("core %d broad %d", h.count(coreSock), h.count(broadSock))
	}
}
