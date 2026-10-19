package tools

import (
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// The gate's copy and move bound to the destination the approver saw (P-9,
// as for the privileged tools; docs/TOOLS.md, "Approval previews"): with
// overwrite, the preview hashes an existing destination file and the
// re-call sends that hash as expected_destination_sha256; a preview that
// saw no destination re-calls with overwrite false. Without an approval the
// call is sent as given (TestOperatorToolsCallTheirOp). Every path and hash
// below is an invented fixture.

const (
	bindSrc = "/srv/app/config/app.yaml.new"
	bindDst = "/srv/app/config/app.yaml"
)

var bindOp = map[string]string{"shell_copy_path": "copy", "shell_move_path": "move"}

func bindArgs(overwrite bool) map[string]any {
	return map[string]any{"source": bindSrc, "destination": bindDst, "overwrite": overwrite}
}

func withOverwrite(args map[string]any) map[string]any {
	out := map[string]any{"overwrite": true}
	for k, v := range args {
		out[k] = v
	}
	return out
}

func gateAbsent(g *recordingGate, p string) {
	g.setPath("stat", p, gateReply{code: "not_found", msg: "no such file"})
}

// TestCopyMovePreconditions: an approved copy or move with overwrite over a
// file sends expected_destination_sha256 of the content the fresh preview
// saw; one whose preview saw no destination is sent with overwrite false,
// so it never replaces a file that appeared.
func TestCopyMovePreconditions(t *testing.T) {
	for name, op := range bindOp {
		t.Run(name, func(t *testing.T) {
			run := func(absent bool) map[string]any {
				t.Helper()
				a := newApprovalHarness(t, approval.MethodWeb)
				if absent {
					gateAbsent(a.g, bindDst)
				}
				id := a.pending(name, bindArgs(true))
				a.approve(id)
				if env, _ := a.call(name, withID(bindArgs(true), id)); env["ok"] != true {
					t.Fatalf("re-call: %v", env)
				}
				return a.g.args(t, op)
			}
			if w := run(false); w["overwrite"] != true || w["expected_destination_sha256"] != shaOld {
				t.Fatalf("over a file: %v", w)
			}
			if w := run(true); w["overwrite"] != false || w["expected_destination_sha256"] != nil {
				t.Fatalf("with no destination: %v", w)
			}
		})
	}
}

// TestCopyMovePreviewBindsDestination: the approver sees the destination's
// state and SHA-256; with no destination, its absence.
func TestCopyMovePreviewBindsDestination(t *testing.T) {
	for name := range bindOp {
		t.Run(name, func(t *testing.T) {
			a := newApprovalHarness(t, approval.MethodWeb)
			id := a.pending(name, bindArgs(true))
			if ops := strings.Join(a.g.ops(), ","); ops != "stat,stat,read_file" {
				t.Fatalf("preview ops %s", ops)
			}
			p := previewMap(t, a, id)
			for k, v := range map[string]string{
				"source.state": "present", "source.type": "file", "destination.state": "file", "destination.type": "file",
				"destination.mode": "0640", "destination.size": "11", "destination.sha256": shaOld, "overwrite": "true",
			} {
				if p[k] != v {
					t.Fatalf("preview %s = %q, want %q (all %v)", k, p[k], v, p)
				}
			}
			b := newApprovalHarness(t, approval.MethodWeb)
			gateAbsent(b.g, bindDst)
			id = b.pending(name, bindArgs(true))
			if ops := strings.Join(b.g.ops(), ","); ops != "stat,stat" {
				t.Fatalf("absent preview ops %s", ops)
			}
			if p = previewMap(t, b, id); p["destination.state"] != "absent" {
				t.Fatalf("absent preview %v", p)
			}
		})
	}
}

// TestCopyMoveChangedAfterApproval: a destination whose content changes,
// or one that appears, after approval is approval_invalid at the re-call's
// fresh preview, and no copy or move is sent; one that changes between the
// fresh preview and the commit is the gate's exists, passed through.
func TestCopyMoveChangedAfterApproval(t *testing.T) {
	for name, op := range bindOp {
		t.Run(name, func(t *testing.T) {
			a := newApprovalHarness(t, approval.MethodWeb)
			id := a.pending(name, bindArgs(true))
			a.approve(id)
			a.g.set("read_file", gateReply{data: fakeReadSHA("key: other\n", shaNew)})
			env, _ := a.call(name, withID(bindArgs(true), id))
			if errCode(env) != "approval_invalid" || len(a.mutatingOps()) != 0 {
				t.Fatalf("content changed after approval: %v, ops %v", env, a.g.ops())
			}

			b := newApprovalHarness(t, approval.MethodWeb)
			gateAbsent(b.g, bindDst)
			id = b.pending(name, bindArgs(true))
			b.approve(id)
			b.g.setPath("stat", bindDst, gateReply{data: fakeFileStat})
			env, _ = b.call(name, withID(bindArgs(true), id))
			if errCode(env) != "approval_invalid" || len(b.mutatingOps()) != 0 {
				t.Fatalf("destination appeared after approval: %v, ops %v", env, b.g.ops())
			}

			c := newApprovalHarness(t, approval.MethodWeb)
			c.g.set(op, gateReply{code: "exists", msg: "the destination changed after it was checked; it was not replaced, and nothing was changed"})
			id = c.pending(name, bindArgs(true))
			c.approve(id)
			env, _ = c.call(name, withID(bindArgs(true), id))
			if errCode(env) != "exists" || c.g.args(t, op)["expected_destination_sha256"] != shaOld {
				t.Fatalf("changed before the commit: %v", env)
			}
		})
	}
}

// TestCopyMovePreviewRefusals: an operation the gate would refuse requests
// no approval and sends nothing that changes the host: a destination that
// exists without overwrite, a directory or symlink destination, a file the
// gate gives no hash for.
func TestCopyMovePreviewRefusals(t *testing.T) {
	link := `{"path":"` + bindDst + `","name":"app.yaml","type":"symlink","size":5,"mode":"0777","uid":0,"gid":0,"mtime":"2026-10-01T00:00:00Z","link_target":"other"}`
	for _, c := range []struct {
		name, tool string
		overwrite  bool
		set        func(g *recordingGate)
		code       string
	}{
		{"copy over a file without overwrite", "shell_copy_path", false, func(*recordingGate) {}, "exists"},
		{"move over a file without overwrite", "shell_move_path", false, func(*recordingGate) {}, "exists"},
		{"copy onto a directory", "shell_copy_path", true, func(g *recordingGate) { g.setPath("stat", bindDst, gateReply{data: fakeDirStat}) }, "is_a_directory"},
		{"move onto a directory", "shell_move_path", true, func(g *recordingGate) { g.setPath("stat", bindDst, gateReply{data: fakeDirStat}) }, "exists"},
		{"copy onto a symlink", "shell_copy_path", true, func(g *recordingGate) { g.setPath("stat", bindDst, gateReply{data: link}) }, "path_denied"},
		{"move onto a symlink", "shell_move_path", true, func(g *recordingGate) { g.setPath("stat", bindDst, gateReply{data: link}) }, "path_denied"},
		{"copy over a file with no hash", "shell_copy_path", true, func(g *recordingGate) {
			g.set("read_file", gateReply{data: `{"path":"` + bindDst + `","size":300000000,"binary":true,"offset":0,"truncated":false}`})
		}, "too_large"},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newApprovalHarness(t, approval.MethodWeb)
			c.set(a.g)
			env, _ := a.call(c.tool, bindArgs(c.overwrite))
			if errCode(env) != c.code || env["approval"] != nil || len(a.mutatingOps()) != 0 {
				t.Fatalf("%v, want %s; ops %v", env, c.code, a.g.ops())
			}
		})
	}
}
