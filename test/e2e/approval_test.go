//go:build e2e && linux

package e2e

import (
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
	"github.com/tyler-rich/shell-mcp/internal/approval/totp"
)

// Approval end to end with a simulated human (docs/handoff/S4B-APPROVAL.md
// §9.2, on an operator tool): the real shell-mcp (stdio, operator profile,
// SHELL_MCP_APPROVAL_METHOD=web, operator tools gated), its approval
// listener on loopback, the test sshd and the installed gate with the
// operator policy. The test acts as the approver: it opens the page through
// the bookmark route, reads the CSRF token, computes the TOTP code from a
// seed generated for this run, and POSTs the decision. Every value is
// invented.

// approver is one enrolled approver's authenticator: its seed, and the
// last step it used, since each step's code is accepted once per approver
// and none from before the server's start.
type approver struct {
	name string
	seed []byte
	last int64
}

// human is the simulated person at the approval page, holding the
// authenticators of one or more enrolled approvers (invented names).
//
// One approver (singleApprover) is the page as most deployments see it: a
// form without an approver choice, and every approval after the first
// waits for the next 30 s step. TestApprovalWebFlow uses it.
//
// Several (manyApprovers, the server's maximum) let a test that only needs
// its requests approved approve up to that many within one step, each by
// another approver, instead of waiting a step for each: every approval
// still needs a current code of an enrolled approver, entered on the page.
// Code replay, one use per step per approver and lockouts are proven by the
// totp and page unit tests; a consumed approval (a second re-call) never
// reaches the page, so the approver model does not touch those checks.
type human struct {
	approvers []*approver
}

const (
	singleApprover = 1
	manyApprovers  = approvers.MaxApprovers
)

var approverNames = [manyApprovers]string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"}

// newHuman enrols n approvers with fresh seeds.
func newHuman(t *testing.T, n int) *human {
	t.Helper()
	h := &human{}
	for _, name := range approverNames[:n] {
		a := &approver{name: name, seed: make([]byte, 20)}
		if _, err := rand.Read(a.seed); err != nil {
			t.Fatal(err)
		}
		h.approvers = append(h.approvers, a)
	}
	return h
}

// file writes the approvers file for h's approvers and returns its path.
func (h *human) file(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, a := range h.approvers {
		b.WriteString(a.name + " " + approvers.EncodeSeed(a.seed) + "\n")
	}
	file := filepath.Join(t.TempDir(), "approvers")
	if err := os.WriteFile(file, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// env is the server configuration that enrols more than one approver.
func (h *human) env() []string {
	if len(h.approvers) == 1 {
		return nil
	}
	return []string{"SHELL_MCP_APPROVAL_MAX_APPROVERS=" + strconv.Itoa(len(h.approvers))}
}

func step(t time.Time) int64 { return t.Unix() / int64(totp.Period/time.Second) }

// started records a server start: no code for the current step or an
// earlier one will be accepted, from any approver.
func (h *human) started() {
	now := step(time.Now())
	for _, a := range h.approvers {
		a.last = max(a.last, now)
	}
}

// code returns the approver whose next unused step comes first, and its
// code for that step, waiting until the step is within the verifier's ±1
// window.
func (h *human) code(t *testing.T) (a *approver, code string) {
	t.Helper()
	a = h.approvers[0]
	for _, b := range h.approvers[1:] {
		if b.last < a.last {
			a = b
		}
	}
	want := a.last + 1
	for step(time.Now())+totp.Skew < want {
		time.Sleep(500 * time.Millisecond)
	}
	a.last = want
	return a, totp.Generate(a.seed, time.Unix(want*int64(totp.Period/time.Second), 0))
}

type approvalServer struct {
	cs   *mcp.ClientSession
	log  *syncedBuffer
	port int
}

func (s *approvalServer) origin() string { return "http://127.0.0.1:" + strconv.Itoa(s.port) }

func startApprovalServer(t *testing.T, h *human, file string, port int, extra ...string) *approvalServer {
	t.Helper()
	log := &syncedBuffer{}
	var cs *mcp.ClientSession
	var err error
	deadline := time.Now().Add(15 * time.Second)
	for {
		env := append([]string{
			"SHELL_MCP_APPROVAL_METHOD=web",
			"SHELL_MCP_APPROVAL_TIERS=operator,destructive",
			"SHELL_MCP_APPROVAL_PORT=" + strconv.Itoa(port),
			"SHELL_MCP_APPROVAL_PUBLIC_URL=http://127.0.0.1:" + strconv.Itoa(port),
			"SHELL_MCP_APPROVERS_FILE=" + file,
		}, append(h.env(), extra...)...)
		cs, err = startServer(t, log, env...)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connect: %v; server log: %s", err, log.String())
		}
		time.Sleep(500 * time.Millisecond)
	}
	s := &approvalServer{cs: cs, log: log, port: port}
	// Wait until the approval listener answers.
	for {
		res, gerr := http.Get(s.origin() + "/") //nolint:noctx // test
		if gerr == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("approval listener not up: %v; server log: %s", gerr, log.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	h.started()
	return s
}

func (s *approvalServer) call(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	return s.callTool(t, "shell_write_file", args)
}

func (s *approvalServer) callTool(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	return callOn(t, s.cs, s.log, name, args)
}

var csrfRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// decide acts as an approver: bookmark route with the id, the page, the
// CSRF token, the approver (when several are enrolled) and its code, the
// POST.
func (s *approvalServer) decide(t *testing.T, h *human, id, verb string) {
	t.Helper()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 10 * time.Second}
	res, err := noRedirect.Get(s.origin() + "/?id=" + id) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	loc := res.Header.Get("Location")
	if res.StatusCode != http.StatusSeeOther || loc != "/approvals/"+id {
		t.Fatalf("bookmark route: %d %q", res.StatusCode, loc)
	}
	res, err = noRedirect.Get(s.origin() + loc) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if !strings.Contains(string(page), "Approval page for shell-mcp at "+s.origin()) {
		t.Fatalf("no origin banner: %s", page)
	}
	m := csrfRE.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no CSRF token: %s", page)
	}
	a, code := h.code(t)
	form := url.Values{"code": {code}, "csrf_token": {string(m[1])}}
	if len(h.approvers) > 1 {
		if !strings.Contains(string(page), `<select name="approver">`) {
			t.Fatalf("several approvers, but no approver choice: %s", page)
		}
		form.Set("approver", a.name)
	}
	res, err = noRedirect.PostForm(s.origin()+loc+"/"+verb, form) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	want := map[string]string{"approve": "Approved by ", "decline": "Declined by "}[verb] + a.name
	if res.StatusCode != http.StatusOK || !strings.Contains(string(b), want) {
		t.Fatalf("%s: %d %s", verb, res.StatusCode, b)
	}
}

func pendingID(t *testing.T, env map[string]any) string {
	t.Helper()
	refusal(t, env, "approval_pending", "Show the user this URL exactly as written")
	ap, _ := env["approval"].(map[string]any)
	id, _ := ap["id"].(string)
	if len(id) != 26 {
		t.Fatalf("approval object %v", env["approval"])
	}
	return id
}

func withApproval(args map[string]any, id string) map[string]any {
	out := map[string]any{"approval_id": id}
	for k, v := range args {
		out[k] = v
	}
	return out
}

func fileIs(t *testing.T, p, want string) {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own fixture
	if err != nil || string(b) != want {
		t.Fatalf("%s: %q, %v; want %q", p, b, err, want)
	}
}

// writeLines counts the write_file audit lines of c's server for p.
func writeLines(t *testing.T, c *serverConn, p string) int {
	t.Helper()
	return len(c.gate(t, `"principal":"`+opsWho+`"`, `"op":"write_file"`, `"`+p+`"`))
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func TestApprovalWebFlow(t *testing.T) {
	opsServer(t) // fixtures, and the ungated server that sets up the file
	// One approver: the page without an approver choice, each approval
	// after the first waiting for the next step.
	h := newHuman(t, singleApprover)
	file := h.file(t)
	port := freeLoopbackPort(t)
	srv := startApprovalServer(t, h, file, port)
	t.Cleanup(func() { _ = srv.cs.Close() })
	// The approval server's own lines; the setup and the out-of-band writes
	// go through the operator server.
	conn := connOf(t, srv.cs)

	p := opsWork + "/approved.txt"
	opOK(t, "shell_write_file", map[string]any{"path": p, "content": "v1\n"})
	args := map[string]any{"path": p, "content": "v2\n"}

	t.Run("pending leaves the file unchanged", func(t *testing.T) {
		id := pendingID(t, srv.call(t, args))
		fileIs(t, p, "v1\n")
		// Only the preview's reads reached the gate.
		conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"hash_file"`, `"`+p+`"`)
		if n := writeLines(t, conn, p); n != 0 {
			t.Fatalf("%d write_file lines before approval", n)
		}

		srv.decide(t, h, id, "approve")
		okDataAs(t, srv.call(t, withApproval(args, id)), opsWho)
		fileIs(t, p, "v2\n")
		conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"write_file"`, `"ceiling":"operator"`, `"`+p+`"`)
		if n := writeLines(t, conn, p); n != 1 {
			t.Fatalf("%d write_file lines after the approved re-call, want 1", n)
		}

		// A second re-call is invalid and writes nothing.
		refusal(t, srv.call(t, withApproval(args, id)), "approval_invalid", "")
		time.Sleep(time.Second)
		if n := writeLines(t, conn, p); n != 1 {
			t.Fatalf("%d write_file lines after the second re-call, want 1", n)
		}
	})

	t.Run("a change after approval invalidates it", func(t *testing.T) {
		a := map[string]any{"path": p, "content": "v3\n"}
		id := pendingID(t, srv.call(t, a))
		srv.decide(t, h, id, "approve")
		opOK(t, "shell_write_file", map[string]any{"path": p, "content": "changed\n"})
		refusal(t, srv.call(t, withApproval(a, id)), "approval_invalid", "changed since approval")
		fileIs(t, p, "changed\n")
	})

	t.Run("decline", func(t *testing.T) {
		a := map[string]any{"path": p, "content": "v4\n"}
		id := pendingID(t, srv.call(t, a))
		srv.decide(t, h, id, "decline")
		refusal(t, srv.call(t, withApproval(a, id)), "approval_declined", "")
		fileIs(t, p, "changed\n")
		log := srv.log.String()
		if !regexp.MustCompile(`"msg":"approval decided"[^\n]*"decision":"declined"`).MatchString(log) ||
			!regexp.MustCompile(`"msg":"approval decided"[^\n]*"approver":"alice"`).MatchString(log) {
			t.Fatalf("no decline line naming the approver: %s", log)
		}
	})

	// An approval for a create never becomes a replace. A file created out
	// of band after approval is caught by the re-call's fresh preview first
	// (approval_invalid: its hash covers current.state, which is no longer
	// absent), before any write is sent; the gate's own refusal (exists) is
	// for a file that appears between that preview and the write, which
	// the unit tests cover at the commit itself.
	t.Run("an approved create never replaces a file created after approval", func(t *testing.T) {
		q := opsWork + "/approved-create.txt"
		a := map[string]any{"path": q, "content": "approved\n"}
		id := pendingID(t, srv.call(t, a))
		srv.decide(t, h, id, "approve")
		// Out of band: through the operator server, not one of conn's lines.
		opOK(t, "shell_write_file", map[string]any{"path": q, "content": "out of band\n"})
		refusal(t, srv.call(t, withApproval(a, id)), "approval_invalid", "changed since approval")
		fileIs(t, q, "out of band\n")
		time.Sleep(time.Second)
		for _, j := range conn.gate(t, `"principal":"`+opsWho+`"`, `"op":"write_file"`, `"`+q+`"`) {
			t.Fatalf("a write was sent after the preview changed: %s", j.Message)
		}
	})

	t.Run("an approved create is sent with expect_absent", func(t *testing.T) {
		q := opsWork + "/approved-create-2.txt"
		a := map[string]any{"path": q, "content": "approved\n"}
		id := pendingID(t, srv.call(t, a))
		srv.decide(t, h, id, "approve")
		okDataAs(t, srv.call(t, withApproval(a, id)), opsWho)
		fileIs(t, q, "approved\n")
		// The real gate, under its Landlock sandbox, committed it as a
		// create-only write.
		conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"write_file"`, `"expect_absent":true`, `"`+q+`"`, `"outcome":"ok"`)
	})

	// What an approval binds of the destination (expected_sha256 for a
	// write; expected_destination_sha256, P-9, for a copy or move with
	// overwrite) changed out of band after approval: the re-call's fresh
	// preview refuses it (approval_invalid) before any operation is sent,
	// and the change survives. A change between that preview and the
	// commit is the gate's own exists (verified replace), which the unit
	// tests cover at the commit itself (fsx TestVerifiedReplaceCommitWindow,
	// ops TestGateVerifiedReplaceCommitWindow).
	boundCases := []struct {
		tool, op string
		args     func(src, dst string) map[string]any
	}{
		{"shell_write_file", "write_file", func(_, dst string) map[string]any { return map[string]any{"path": dst, "content": "new\n"} }},
		{"shell_copy_path", "copy", func(src, dst string) map[string]any {
			return map[string]any{"source": src, "destination": dst, "overwrite": true}
		}},
		{"shell_move_path", "move", func(src, dst string) map[string]any {
			return map[string]any{"source": src, "destination": dst, "overwrite": true}
		}},
	}
	t.Run("changed destination refused", func(t *testing.T) {
		for _, c := range boundCases {
			t.Run(c.op, func(t *testing.T) {
				src, dst := opsWork+"/bound-"+c.op+".src", opsWork+"/bound-"+c.op+".txt"
				opOK(t, "shell_write_file", map[string]any{"path": src, "content": "new\n"})
				opOK(t, "shell_write_file", map[string]any{"path": dst, "content": "approved old\n"})
				a := c.args(src, dst)
				id := pendingID(t, srv.callTool(t, c.tool, a))
				srv.decide(t, h, id, "approve")
				// Out of band, and itself a write_file: through the operator
				// server, not one of conn's lines.
				opOK(t, "shell_write_file", map[string]any{"path": dst, "content": "changed out of band\n"})
				refusal(t, srv.callTool(t, c.tool, withApproval(a, id)), "approval_invalid", "changed since approval")
				fileIs(t, dst, "changed out of band\n")
				fileIs(t, src, "new\n")
				time.Sleep(time.Second)
				for _, j := range conn.gate(t, `"principal":"`+opsWho+`"`, `"op":"`+c.op+`"`, `"`+dst+`"`) {
					t.Fatalf("a %s was sent after the destination changed: %s", c.op, j.Message)
				}
			})
		}
	})

	// An approved copy or move over a file is sent bound to the destination
	// the approver saw, and the real gate, under its Landlock sandbox,
	// commits it as a verified replace (RENAME_EXCHANGE, then the check).
	t.Run("an approved overwrite commits bound to the destination", func(t *testing.T) {
		for _, c := range boundCases[1:] {
			t.Run(c.op, func(t *testing.T) {
				src, dst := opsWork+"/bound-ok-"+c.op+".src", opsWork+"/bound-ok-"+c.op+".txt"
				opOK(t, "shell_write_file", map[string]any{"path": src, "content": "new\n"})
				opOK(t, "shell_write_file", map[string]any{"path": dst, "content": "approved old\n"})
				a := c.args(src, dst)
				id := pendingID(t, srv.callTool(t, c.tool, a))
				srv.decide(t, h, id, "approve")
				okDataAs(t, srv.callTool(t, c.tool, withApproval(a, id)), opsWho)
				fileIs(t, dst, "new\n")
				conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"`+c.op+`"`, `"overwrite":true`, `"`+dst+`"`, `"outcome":"ok"`)
			})
		}
	})
	// Before the restart below closes the server conn names.
	conn.same(t)

	t.Run("a restart between approval and re-call invalidates it", func(t *testing.T) {
		a := map[string]any{"path": p, "content": "v5\n"}
		id := pendingID(t, srv.call(t, a))
		srv.decide(t, h, id, "approve")
		_ = srv.cs.Close()
		srv = startApprovalServer(t, h, file, port)
		refusal(t, srv.call(t, withApproval(a, id)), "approval_invalid", "unknown approval")
		fileIs(t, p, "changed\n")
	})

	// Never logged: codes, seeds, CSRF tokens, content.
	log := srv.log.String()
	for _, s := range []string{approvers.EncodeSeed(h.approvers[0].seed), "v2\\n", "changed\\n"} {
		if strings.Contains(log, s) {
			t.Fatalf("server log contains %q", s)
		}
	}
}
