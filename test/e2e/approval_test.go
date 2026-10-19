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

// human is the simulated approver: one seed, and the last step it used,
// since each step's code is accepted once and none from before the
// server's start.
type human struct {
	seed []byte
	last int64
}

func step(t time.Time) int64 { return t.Unix() / int64(totp.Period/time.Second) }

// started records a server start: no code for the current step or an
// earlier one will be accepted.
func (h *human) started() { h.last = max(h.last, step(time.Now())) }

// code returns a code for the next unused step, waiting until that step
// is within the verifier's ±1 window.
func (h *human) code(t *testing.T) string {
	t.Helper()
	want := h.last + 1
	for step(time.Now())+totp.Skew < want {
		time.Sleep(500 * time.Millisecond)
	}
	h.last = want
	return totp.Generate(h.seed, time.Unix(want*int64(totp.Period/time.Second), 0))
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
		}, extra...)
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

// decide acts as the approver: bookmark route with the id, the page, the
// CSRF token, the code, the POST.
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
	res, err = noRedirect.PostForm(s.origin()+loc+"/"+verb, url.Values{"code": {h.code(t)}, "csrf_token": {string(m[1])}}) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	want := map[string]string{"approve": "Approved by alice", "decline": "Declined by alice"}[verb]
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

// writeLines counts the gate's write_file audit lines for p since start.
func writeLines(t *testing.T, since time.Time, p string) int {
	t.Helper()
	n := 0
	for _, j := range journal(t, "shell-mcp-gate", since) {
		if strings.Contains(j.Message, `"principal":"`+opsWho+`"`) && strings.Contains(j.Message, `"op":"write_file"`) && strings.Contains(j.Message, p) {
			n++
		}
	}
	return n
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
	h := &human{seed: make([]byte, 20)}
	if _, err := rand.Read(h.seed); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "approvers")
	if err := os.WriteFile(file, []byte("alice "+approvers.EncodeSeed(h.seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	port := freeLoopbackPort(t)
	srv := startApprovalServer(t, h, file, port)
	t.Cleanup(func() { _ = srv.cs.Close() })

	p := opsWork + "/approved.txt"
	opOK(t, "shell_write_file", map[string]any{"path": p, "content": "v1\n"})
	args := map[string]any{"path": p, "content": "v2\n"}

	// The journal reads whole seconds: keep the setup write out of the
	// window.
	time.Sleep(2100 * time.Millisecond)
	start := time.Now()

	t.Run("pending leaves the file unchanged", func(t *testing.T) {
		id := pendingID(t, srv.call(t, args))
		fileIs(t, p, "v1\n")
		// Only the preview's reads reached the gate.
		findJournal(t, "shell-mcp-gate", start, `"principal":"`+opsWho+`"`, `"op":"read_file"`)
		if n := writeLines(t, start, p); n != 0 {
			t.Fatalf("%d write_file lines before approval", n)
		}

		srv.decide(t, h, id, "approve")
		okDataAs(t, srv.call(t, withApproval(args, id)), opsWho)
		fileIs(t, p, "v2\n")
		findJournal(t, "shell-mcp-gate", start, `"principal":"`+opsWho+`"`, `"op":"write_file"`, `"ceiling":"operator"`)
		if n := writeLines(t, start, p); n != 1 {
			t.Fatalf("%d write_file lines after the approved re-call, want 1", n)
		}

		// A second re-call is invalid and writes nothing.
		refusal(t, srv.call(t, withApproval(args, id)), "approval_invalid", "")
		time.Sleep(time.Second)
		if n := writeLines(t, start, p); n != 1 {
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
		since := time.Now()
		opOK(t, "shell_write_file", map[string]any{"path": q, "content": "out of band\n"})
		refusal(t, srv.call(t, withApproval(a, id)), "approval_invalid", "changed since approval")
		fileIs(t, q, "out of band\n")
		time.Sleep(time.Second)
		for _, j := range journal(t, "shell-mcp-gate", since) {
			if strings.Contains(j.Message, `"principal":"`+opsWho+`"`) && strings.Contains(j.Message, `"op":"write_file"`) &&
				strings.Contains(j.Message, `"expect_absent":true`) {
				t.Fatalf("a write was sent after the preview changed: %s", j.Message)
			}
		}
	})

	t.Run("an approved create is sent with expect_absent", func(t *testing.T) {
		q := opsWork + "/approved-create-2.txt"
		a := map[string]any{"path": q, "content": "approved\n"}
		id := pendingID(t, srv.call(t, a))
		srv.decide(t, h, id, "approve")
		since := time.Now()
		okDataAs(t, srv.call(t, withApproval(a, id)), opsWho)
		fileIs(t, q, "approved\n")
		// The real gate, under its Landlock sandbox, committed it as a
		// create-only write.
		findJournal(t, "shell-mcp-gate", since, `"principal":"`+opsWho+`"`, `"op":"write_file"`, `"expect_absent":true`, q, `"outcome":"ok"`)
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
				opOK(t, "shell_write_file", map[string]any{"path": dst, "content": "changed out of band\n"})
				// The journal reads whole seconds (and journal() starts a
				// second early): keep the out-of-band write, itself a
				// write_file, out of the window.
				time.Sleep(2100 * time.Millisecond)
				since := time.Now()
				refusal(t, srv.callTool(t, c.tool, withApproval(a, id)), "approval_invalid", "changed since approval")
				fileIs(t, dst, "changed out of band\n")
				fileIs(t, src, "new\n")
				time.Sleep(time.Second)
				for _, j := range journal(t, "shell-mcp-gate", since) {
					if strings.Contains(j.Message, `"principal":"`+opsWho+`"`) && strings.Contains(j.Message, `"op":"`+c.op+`"`) {
						t.Fatalf("a %s was sent after the destination changed: %s", c.op, j.Message)
					}
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
				since := time.Now()
				okDataAs(t, srv.callTool(t, c.tool, withApproval(a, id)), opsWho)
				fileIs(t, dst, "new\n")
				findJournal(t, "shell-mcp-gate", since, `"principal":"`+opsWho+`"`, `"op":"`+c.op+`"`, `"overwrite":true`, dst, `"outcome":"ok"`)
			})
		}
	})

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
	for _, s := range []string{approvers.EncodeSeed(h.seed), "v2\\n", "changed\\n"} {
		if strings.Contains(log, s) {
			t.Fatalf("server log contains %q", s)
		}
	}
}
