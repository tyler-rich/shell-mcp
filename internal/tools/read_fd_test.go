package tools

import (
	"fmt"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// {path:read:fd} (POLICY §4, handoff N-22): the gate's exec_preview and
// exec carry fds, the descriptors a command gets ({fd, path}); the approval
// preview shows each as one line next to the argv's /dev/fd/N, and the run
// tools return them. Commands, paths and hashes are invented.

func fakeExecPreviewFD(sha string) string {
	return fmt.Sprintf(`{"command_id":"app-check","tier":"destructive","description":"Check the configuration","root_equivalent":false,`+
		`"template":["check","--config","{path:read:fd}"],"argv":["/usr/local/bin/example-app","check","--config","/dev/fd/4"],`+
		`"cwd":"/","fds":[{"fd":4,"path":"/srv/app/app.conf"}],"policy_sha256":"ab12","preview_sha256":%q}`, sha)
}

const fakeExecFD = `{"command_id":"app-check","argv":["/usr/local/bin/example-app","check","--config","/dev/fd/4"],"fds":[{"fd":4,"path":"/srv/app/app.conf"}],` +
	`"exit_code":0,"signal":null,"timed_out":false,"stdout":"ok\n","stderr":"","stdout_truncated":false,"stderr_truncated":false,"duration_ms":7}`

func TestRunCommandPreviewShowsDescriptors(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	a.g.set("exec_preview", gateReply{data: fakeExecPreviewFD(shaExec)})
	a.g.set("exec", gateReply{data: fakeExecFD})
	args := map[string]any{"command_id": "app-check", "args": []string{"check", "--config", "/srv/app/app.conf"}}
	id := a.pending("shell_run_command", args)
	pm := previewMap(t, a, id)
	for k, v := range map[string]string{"argv[3]": "/dev/fd/4", "template[2]": "{path:read:fd}",
		"fds[0]": "fd 4: /srv/app/app.conf, opened read-only by the gate"} {
		if pm[k] != v {
			t.Fatalf("preview %s = %q, want %q (all %v)", k, pm[k], v, pm)
		}
	}
	a.approve(id)
	env, _ := a.call("shell_run_command", withID(args, id))
	d := data(t, env)
	fds, ok := d["fds"].([]any)
	if !ok || len(fds) != 1 || fmt.Sprint(fds[0]) != "map[fd:4 path:/srv/app/app.conf]" || d["stdout"] != "ok\n" {
		t.Fatalf("data %v", d)
	}
}

func TestReadCommandReturnsDescriptors(t *testing.T) {
	g := newRecordingGate(map[string]gateReply{"exec": {data: fakeExecFD}})
	h := readHarness(t, g)
	env, _ := h.call("shell_run_read_command", map[string]any{"command_id": "app-check", "args": []string{"check", "--config", "/srv/app/app.conf"}})
	d := data(t, env)
	if fds, ok := d["fds"].([]any); !ok || len(fds) != 1 || fmt.Sprint(fds[0]) != "map[fd:4 path:/srv/app/app.conf]" {
		t.Fatalf("data %v", d)
	}
	// Without descriptors the list is empty, never absent.
	g.set("exec", gateReply{data: fakeExec("x\n", 0)})
	env, _ = h.call("shell_run_read_command", map[string]any{"command_id": "app-status", "args": []string{"status", "--json"}})
	if fds, ok := data(t, env)["fds"].([]any); !ok || len(fds) != 0 {
		t.Fatalf("data %v", data(t, env))
	}
}
