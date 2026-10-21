//go:build e2e && linux

package e2e

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Which journal lines belong to a test. journald delivers a line some time
// after it was written, and journal() reads from a whole second before its
// start, so a time window can hand one test another test's lines (PR #40's
// first run counted the chain race test's priv_exec lines in
// TestPrivRunCommandToolApproval). A test counts or waits for a line only
// by a marker of its own: a request id it sent, a path or backup id no
// other test names, or the SSH client address of a server only it uses.
// Every query reads all of this run's lines (runStart); the marker, never
// the time, decides which of them are the test's.

// runStart is when this run of the suite started.
var runStart = time.Now()

// runLines returns ident's entries of this run that contain every string
// in want.
func runLines(t *testing.T, ident string, want ...string) []journalEntry {
	t.Helper()
	var out []journalEntry
entries:
	for _, e := range journal(t, ident, runStart) {
		for _, w := range want {
			if !strings.Contains(e.Message, w) {
				continue entries
			}
		}
		out = append(out, e)
	}
	return out
}

// waitLine waits until an entry of ident from this run contains every
// string in want, and returns it.
func waitLine(t *testing.T, ident string, want ...string) journalEntry {
	t.Helper()
	return findJournal(t, ident, runStart, want...)
}

// lineID is the request id of a gate or helper audit line ("" for one
// without, such as a refusal before the request was read).
func lineID(e *journalEntry) string {
	var l struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(e.Message), &l)
	return l.ID
}

// serverConn marks the requests of one server: the gate writes the SSH
// client address of each request into its audit line ("client"), and a
// server keeps one SSH connection to the target (sshx reuses it until it
// fails), so that address is on every request of that server and on no
// other's. It is learned from a stat of a path no other request names.
// A server that reconnected would send later requests from another
// address, which these counts would not see: same checks that it did not.
type serverConn struct {
	cs     *mcp.ClientSession
	client string // `"client":"<ip>:<port>"`, as the gate's line has it
}

func connOf(t *testing.T, cs *mcp.ClientSession) *serverConn {
	t.Helper()
	return &serverConn{cs: cs, client: learnClient(t, cs)}
}

// learnClient sends a stat of a fresh path through the server and returns
// the client address of the gate's line for it.
func learnClient(t *testing.T, cs *mcp.ClientSession) string {
	t.Helper()
	marker := "/srv/e2e-client-" + randomHex(8)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "shell_stat_path", Arguments: map[string]any{"path": marker}}); err != nil {
		t.Fatalf("marker stat: %v", err)
	}
	e := waitLine(t, "shell-mcp-gate", `"op":"stat"`, `"path":"`+marker+`"`)
	var l struct {
		Client string `json:"client"`
	}
	if err := json.Unmarshal([]byte(e.Message), &l); err != nil || !strings.HasPrefix(l.Client, sshdHost+":") {
		t.Fatalf("the marker's gate line names no SSH client: %q", e.Message)
	}
	return `"client":"` + l.Client + `"`
}

// same fails the test unless the server is still on the connection c
// names, so that no line of its was missed by a count since c was made.
func (c *serverConn) same(t *testing.T) {
	t.Helper()
	if now := learnClient(t, c.cs); now != c.client {
		t.Fatalf("the server reconnected (%s, now %s): counts by its address missed its later lines", c.client, now)
	}
}

// gate returns this run's gate lines of c's server that contain every
// string in want.
func (c *serverConn) gate(t *testing.T, want ...string) []journalEntry {
	t.Helper()
	return runLines(t, "shell-mcp-gate", append([]string{c.client}, want...)...)
}

// waitGate waits for a gate line of c's server that contains every string
// in want.
func (c *serverConn) waitGate(t *testing.T, want ...string) {
	t.Helper()
	waitLine(t, "shell-mcp-gate", append([]string{c.client}, want...)...)
}

// helper returns this run's helper lines for requests of c's server (the
// gate's line with the same request id names c's address) that contain
// every string in want. A helper line is found once the gate's line for
// the same request is in the journal too.
func (c *serverConn) helper(t *testing.T, want ...string) []journalEntry {
	t.Helper()
	ids := map[string]bool{}
	for _, g := range c.gate(t) {
		if id := lineID(&g); id != "" {
			ids[id] = true
		}
	}
	var out []journalEntry
	for _, h := range runLines(t, "shell-mcp-privd", want...) {
		if ids[lineID(&h)] {
			out = append(out, h)
		}
	}
	return out
}

// waitHelper waits until helper finds a line, and returns the first.
func (c *serverConn) waitHelper(t *testing.T, want ...string) journalEntry {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if l := c.helper(t, want...); len(l) > 0 {
			return l[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no helper journal entry for a request from %s containing %q", c.client, want)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
