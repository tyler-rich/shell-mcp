//go:build linux

package ops_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// {path:read:fd} (POLICY §4, handoff N-22): the gate passes the descriptor
// it resolved and checked as /dev/fd/(4+k), so a command that reopens it
// reads that file whatever happens to the name afterwards; exec_preview
// shows and hashes it (device and inode). Every layout is invented.

// fdCommands are this file's commands, appended to the base policy.
const fdCommands = `  - id: probe-fd
    path: {BIN}/probe
    tier: read
    templates: [["cat", "{path:read:fd}"], ["procattrs", "{path:read:fd}", "{path:read:fd}"]]
  - id: probe-str
    path: {BIN}/probe
    tier: read
    templates: [["cat", "{path:read}"]]
  - id: probe-fd-op
    path: {BIN}/probe
    tier: operator
    templates: [["cat", "{path:read:fd}"]]
`

type execFD struct {
	FD   int    `json:"fd"`
	Path string `json:"path"`
}

// fdPreview and fdExec are exec_preview's and exec's data with fds.
type fdPreview struct {
	execPreview
	Fds []execFD `json:"fds"`
}

type fdExec struct {
	Argv   []string `json:"argv"`
	Stdout string   `json:"stdout"`
	Fds    []execFD `json:"fds"`
}

func fdFixture(t *testing.T) (f *fixture, dir string) {
	t.Helper()
	f = newFixture(t, "destructive")
	f.rawPolicy(strings.NewReplacer("{TIER}", "destructive", "{PRIV}", "").Replace(basePolicy + fdCommands))
	dir = filepath.Join(f.read, "fd")
	gatetest.Mkdir(t, dir, 0o755)
	return f, dir
}

// TestExecPathReadFD: preview and exec show /dev/fd/4 in argv and the file
// in fds; the command reads the file through it; two placeholders are 4
// and 5, and the command holds exactly those descriptors.
func TestExecPathReadFD(t *testing.T) {
	f, dir := fdFixture(t)
	a := filepath.Join(dir, "compose.yaml")
	gatetest.WriteFile(t, a, "services: {}\n", 0o644)
	b := filepath.Join(dir, "b.yaml")
	gatetest.WriteFile(t, b, "b\n", 0o644)
	req := m{"command_id": "probe-fd", "args": []string{"cat", a}}
	var pv fdPreview
	f.ok("exec_preview", req, &pv)
	if !slices.Equal(pv.Argv, []string{f.probe, "cat", "/dev/fd/4"}) || !slices.Equal(pv.Template, []string{"cat", "{path:read:fd}"}) ||
		!slices.Equal(pv.Fds, []execFD{{4, a}}) {
		t.Fatalf("preview %+v", pv)
	}
	var d fdExec
	f.ok("exec", req, &d)
	if d.Stdout != "READ:services: {}\n\n" || !slices.Equal(d.Argv, pv.Argv) || !slices.Equal(d.Fds, pv.Fds) {
		t.Fatalf("exec %+v", d)
	}
	// A command without a descriptor reports an empty list.
	var s fdExec
	f.ok("exec", m{"command_id": "probe-str", "args": []string{"cat", a}}, &s)
	if s.Fds == nil || len(s.Fds) != 0 {
		t.Fatalf("fds of a command without one: %#v", s.Fds)
	}
	f.ok("exec", m{"command_id": "probe-fd", "args": []string{"procattrs", a, b}}, &d)
	var fds string
	for _, l := range strings.Split(d.Stdout, "\n") {
		if v, ok := strings.CutPrefix(l, "fds="); ok {
			fds = v
		}
	}
	var held []string
	for _, x := range strings.Split(fds, ",") {
		if x != "" && !strings.HasPrefix(x, "3:100000:/sys/fs/cgroup/") {
			held = append(held, x)
		}
	}
	if want := []string{"4:100000:" + a, "5:100000:" + b}; !slices.Equal(held, want) {
		t.Fatalf("the command holds %v, want %v", held, want)
	}
	if !slices.Equal(d.Fds, []execFD{{4, a}, {5, b}}) {
		t.Fatalf("fds %+v", d.Fds)
	}
}

// TestExecPathReadFDRefusals: a directory is is_a_directory, a FIFO and a
// deny-listed file path_denied, at the preview and at exec alike, with the
// same message; nothing runs.
func TestExecPathReadFDRefusals(t *testing.T) {
	f, dir := fdFixture(t)
	sub := filepath.Join(dir, "sub")
	gatetest.Mkdir(t, sub, 0o755)
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	for p, code := range map[string]string{sub: "is_a_directory", fifo: "path_denied", filepath.Join(f.secrets, "token"): "path_denied"} {
		req := m{"command_id": "probe-fd", "args": []string{"cat", p}}
		pr, er := f.call("exec_preview", req), f.call("exec", req)
		if pr.OK || er.OK || pr.Error.Code != code || er.Error.Code != code || pr.Error.Message != er.Error.Message {
			t.Fatalf("%s: preview %+v, exec %+v, want %s", p, pr.Error, er.Error, code)
		}
	}
}

// TestExecPathReadFDSwapAfterResolution: the name is swapped for a symlink
// to a deny-listed file after the gate resolved it and before the command
// runs (a deterministic hook standing in for the owning account). The
// string form then reads the denied file (the control: the swap reaches
// the command); the descriptor form reads the file the gate checked.
func TestExecPathReadFDSwapAfterResolution(t *testing.T) {
	f, dir := fdFixture(t)
	p := filepath.Join(dir, "t")
	reset := func() {
		_ = os.Remove(p)
		_ = os.Remove(p + ".away")
		gatetest.WriteFile(t, p, "ORIGINAL\n", 0o644)
	}
	swaps := 0
	f.opts.InjectBeforeExec = func() {
		swaps++
		if err := os.Rename(p, p+".away"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(filepath.Join(f.secrets, "token"), p); err != nil {
			t.Error(err)
		}
	}
	reset()
	var d fdExec
	f.ok("exec", m{"command_id": "probe-str", "args": []string{"cat", p}}, &d)
	if d.Stdout != "READ:TOPSECRET\n" {
		t.Fatalf("control: the string form read %q after the swap", d.Stdout)
	}
	reset()
	f.ok("exec", m{"command_id": "probe-fd", "args": []string{"cat", p}}, &d)
	if d.Stdout != "READ:ORIGINAL\n\n" {
		t.Fatalf("the descriptor form read %q after the swap", d.Stdout)
	}
	if swaps != 2 {
		t.Fatalf("the hook ran %d times", swaps)
	}
}

// TestExecPreviewFDBindsTheFile: exec recomputes the preview's hash from
// the descriptors it passes. The same file rewritten in place (the same
// inode) still runs; another file put under the name, with the same
// content, is exists and nothing runs.
func TestExecPreviewFDBindsTheFile(t *testing.T) {
	f, dir := fdFixture(t)
	p := filepath.Join(dir, "app.conf")
	gatetest.WriteFile(t, p, "a\n", 0o644)
	req := m{"command_id": "probe-fd-op", "args": []string{"cat", p}}
	var pv fdPreview
	f.ok("exec_preview", req, &pv)
	withHash := m{"expected_preview_sha256": pv.PreviewSHA256}
	for k, v := range req {
		withHash[k] = v
	}
	var d fdExec
	f.ok("exec", withHash, &d)
	if err := os.WriteFile(p, []byte("b\n"), 0o644); err != nil { //nolint:gosec // G306: a fixture
		t.Fatal(err)
	}
	f.ok("exec", withHash, &d)
	if d.Stdout != "READ:b\n\n" {
		t.Fatalf("rewritten in place: %q", d.Stdout)
	}
	gatetest.WriteFile(t, p+".new", "b\n", 0o644)
	if err := os.Rename(p+".new", p); err != nil {
		t.Fatal(err)
	}
	r := f.call("exec", withHash)
	if r.OK || r.Error.Code != "exists" || !strings.Contains(r.Error.Message, "resolves differently than its preview") {
		t.Fatalf("another file under the name: %+v %s", r.Error, r.Data)
	}
	// Its own preview runs again.
	var again fdPreview
	f.ok("exec_preview", req, &again)
	if again.PreviewSHA256 == pv.PreviewSHA256 {
		t.Fatal("the preview hash did not change with the file")
	}
	// The string form of the same file hashes differently from the
	// descriptor form (the argv and fds differ).
	var str fdPreview
	f.ok("exec_preview", m{"command_id": "probe-str", "args": []string{"cat", p}}, &str)
	if str.PreviewSHA256 == again.PreviewSHA256 || str.Fds == nil || len(str.Fds) != 0 {
		t.Fatalf("string form %+v", str)
	}
}
