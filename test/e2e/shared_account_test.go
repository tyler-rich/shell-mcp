//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The shared-account layout (docs/SECURITY.md §2, TARGET-SETUP §4): 0.2.0's
// TARGET-SETUP put every key on one service account, and the helper's
// install added that account to the socket group. A key whose policy has no
// privileged forwarding then ran its commands as an account that can connect
// to the helper: below Landlock ABI 9 only the socket's permissions and the
// helper's peer-UID check govern that connect, and both pass, while human
// approval is the server's, not the helper's. The probe here asks the helper
// for priv_policy (a read op that changes nothing) from a read command of
// such a policy, inside the gate's own Landlock and no_new_privs.
//
// /etc/shell-mcp/gate-shared.yaml (setup.sh): max_tier read, no privileged
// section, the probe's priv-ask command for each helper socket.
const sharedPolicy = "/etc/shell-mcp/gate-shared.yaml"

// TestSharedAccountNoForwardingRefused: served by svc-shell, which is in the
// socket group, the policy is refused with install_insecure before any
// request, hello included, and check-policy as svc-shell fails on it. When
// the gate still serves it (before the fix), the test reports what the probe
// got from the helper through the gate's exec.
func TestSharedAccountNoForwardingRefused(t *testing.T) {
	for _, sock := range []string{socketPath, broadSocket} {
		hello, _ := gatePolicyAt(t, sharedPolicy, svcShell, "read", "hello", map[string]any{})
		probe := map[string]any{"command_id": "probe-priv-ask", "args": []string{"priv-ask", sock}}
		if hello.code() != "install_insecure" {
			e, _ := gatePolicyAt(t, sharedPolicy, svcShell, "read", "exec", probe)
			var res struct {
				Stdout string `json:"stdout"`
			}
			_ = json.Unmarshal(e.Data, &res)
			t.Fatalf("the gate served a policy without privileged forwarding to an account in the socket group (hello: %s, sandbox %s); "+
				"the probe through exec asked %s for priv_policy: %s %q", hello.code(), sandboxOf(&hello), sock, e.code(), strings.TrimSpace(res.Stdout))
		}
		if !strings.Contains(hello.Error.Message, "socket group") || !strings.Contains(hello.Error.Message, "second service account") {
			t.Fatalf("the refusal must name the cause and the fix: %q", hello.Error.Message)
		}
		if r, _ := gatePolicyAt(t, sharedPolicy, svcShell, "read", "exec", probe); r.code() != "install_insecure" {
			t.Fatalf("exec of the probe as svc-shell: %s %s", r.code(), r.Data)
		}
	}
	cmd := exec.CommandContext(t.Context(), gateBin, "check-policy", "--policy", sharedPolicy)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, svcShell)}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = "/"
	out, err := cmd.Output()
	if err == nil || !strings.Contains(string(out), "FAIL install: gate process belongs to group \"svc-shell-priv\"") ||
		!strings.Contains(string(out), "serve would refuse with install_insecure") {
		t.Fatalf("check-policy as svc-shell: %v\n%s", err, out)
	}
}

// TestSharedAccountSecondAccountCannotReachHelper: the same policy served by
// the second account, svc-shell-std (not in the socket group), is served,
// and the probe's connect to either helper socket is refused (the socket's
// 0660 root:svc-shell-priv; from Landlock ABI 9 also the sandbox, which grants
// no helper socket to a policy without forwarding).
func TestSharedAccountSecondAccountCannotReachHelper(t *testing.T) {
	hello, _ := gatePolicyAt(t, sharedPolicy, svcStd, "read", "hello", map[string]any{})
	if hello.code() != "ok" {
		t.Fatalf("hello as svc-shell-std: %s %+v", hello.code(), hello.Error)
	}
	t.Logf("sandbox as svc-shell-std: %s", sandboxOf(&hello))
	for _, sock := range []string{socketPath, broadSocket} {
		r, _ := gatePolicyAt(t, sharedPolicy, svcStd, "read", "exec", map[string]any{"command_id": "probe-priv-ask", "args": []string{"priv-ask", sock}})
		var res struct {
			Stdout string `json:"stdout"`
		}
		if r.code() != "ok" || json.Unmarshal(r.Data, &res) != nil || strings.TrimSpace(res.Stdout) != "EACCES" {
			t.Fatalf("probe as svc-shell-std on %s: %s %s", sock, r.code(), r.Data)
		}
	}
}

// sandboxOf is a hello answer's kernel Landlock ABI and what it enforces on
// Unix sockets, for the test's messages.
func sandboxOf(r *response) string {
	var h struct {
		Sandbox struct {
			KernelABI         int    `json:"kernel_abi"`
			UnixSocketControl string `json:"unix_socket_control"`
		} `json:"sandbox"`
	}
	if r.code() != "ok" || json.Unmarshal(r.Data, &h) != nil {
		return "unknown"
	}
	return "kernel Landlock ABI " + strconv.Itoa(h.Sandbox.KernelABI) + ", unix sockets: " + h.Sandbox.UnixSocketControl
}
