//go:build e2e && linux

package e2e

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The chown and chmod preview hash across helper instances (handoff D4, as
// amended). Every helper instance runs in a mount namespace of its own,
// whose mounts get new ids from the kernel: the lowest free ones
// (mnt_alloc_id, ida_alloc), freed again only when a namespace is torn
// down. So an unchanged tree's mount ids can differ between two instances.
//
// Why the reproduction does not depend on timing. Let P be the ids the
// preview's instance held, the lowest free ones when it ran. The test
// waits until that instance has exited (no helper instance unit is left;
// e2e tests run one at a time) and the kernel's deferred release of its
// mounts has had time to run, so P is free again. Only then does it open
// an extra namespace (holdMountNamespace), which copies every host mount
// and so takes the lowest free ids: P's lowest ones, or lower ones. It
// holds that namespace during the re-call (and, for the preview/operation
// case, during the operation). The next instance is then given the next
// free ids above those held, never P again: its ids for the tree's mount
// differ from the preview's, every time, however long anything took. (Had
// the extra namespace been opened while P was still held, it would have
// taken other ids, and the next instance could get P back once released:
// that is the one case the wait rules out. Holding a namespace across the
// preview and releasing it before the re-call, as a first version of this
// test did, depended on that release completing in time.) Every path is
// invented.

// holdMountNamespace starts a process in a new, private mount namespace
// (a copy of every mount, each with a newly allocated id) and returns once
// the namespace exists. The namespace is held until the test ends.
func holdMountNamespace(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "/usr/bin/unshare", "--mount", "--propagation", "private", "/usr/bin/sleep", "300")
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	self, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		// unshare(1) execs sleep in the new namespace; until then the
		// process is still in ours.
		if got, err := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/ns/mnt"); err == nil && got != self {
			if c, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/comm"); err == nil && strings.TrimSpace(string(c)) == "sleep" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the extra mount namespace was not set up")
		}
	}
}

// waitHelperInstancesGone waits until no helper instance unit of either
// unit is loaded (CollectMode=inactive-or-failed unloads an ended one), so
// the previous request's instance has exited and its namespace is gone,
// then waits a settle time for the kernel's deferred release of its mounts
// (task work and RCU callbacks after the last process left).
func waitHelperInstancesGone(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		out := run(t, "systemctl", "list-units", "--all", "--no-legend", "--plain", "shell-mcp-privd@*.service", "shell-mcp-privd-broad@*.service")
		if strings.TrimSpace(out) == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper instances still loaded:\n%s", out)
		}
	}
	time.Sleep(time.Second)
}

// TestPrivMetaHashAcrossNamespaces: an unchanged tree is approved and
// changed although the mount ids differ between the instances involved;
// and a mount placed into the tree after the preview is still refused, by
// the operation's own walk in its own instance.
func TestPrivMetaHashAcrossNamespaces(t *testing.T) {
	srv, h := privWriteServer(t)
	if err := os.MkdirAll(privMetaDir, 0o755); err != nil { //nolint:gosec // G301: a fixture directory on a root-only path
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(privMetaDir) })

	t.Run("approval preview and re-call in instances with other mount ids", func(t *testing.T) {
		tree := privMetaDir + "/ns-approval"
		paths := metaTreeAt(t, tree)
		args := map[string]any{"path": tree, "mode": "0750", "recursive": true}
		id := pendingID(t, srv.callTool(t, "shell_priv_set_permissions", args))
		waitHelperInstancesGone(t)
		holdMountNamespace(t) // held during the re-call's preview and operation
		srv.decide(t, h, id, "approve")
		d := okDataAs(t, srv.callTool(t, "shell_priv_set_permissions", withApproval(args, id)), "e2e-ssh")
		if d["entries"] != 4.0 || d["changed"] != 4.0 {
			t.Fatalf("data %v", d)
		}
		for _, p := range paths {
			if m, _, _, _ := statOwner(t, p); m.Perm() != 0o750 {
				t.Fatalf("%s is %v", p, m)
			}
		}
	})

	t.Run("preview and operation in instances with other mount ids", func(t *testing.T) {
		tree := privMetaDir + "/ns-op"
		paths := metaTreeAt(t, tree)
		args := map[string]any{"path": tree, "owner": "example-app", "recursive": true}
		var pv struct {
			PreviewSHA256 string `json:"preview_sha256"`
		}
		mustGate(t, "priv_chown_preview", args, &pv)
		waitHelperInstancesGone(t)
		holdMountNamespace(t) // held during the operation
		a := map[string]any{"expected_preview_sha256": pv.PreviewSHA256}
		for k, v := range args {
			a[k] = v
		}
		mustGate(t, "priv_chown", a, nil)
		for _, p := range paths {
			if _, uid, _, _ := statOwner(t, p); uid != exampleApp {
				t.Fatalf("%s is owned by %d", p, uid)
			}
		}
	})

	t.Run("a mount placed into the tree after the preview is refused", func(t *testing.T) {
		tree := privMetaDir + "/ns-mounted"
		metaTreeAt(t, tree)
		args := map[string]any{"path": tree, "mode": "0700", "recursive": true}
		var pv struct {
			PreviewSHA256 string `json:"preview_sha256"`
		}
		mustGate(t, "priv_chmod_preview", args, &pv)
		// A bind mount of sub over itself: the same device, inode, birth
		// time, owner and mode, so the preview hash cannot tell it apart;
		// only the mount crossing does, inside the operation's instance.
		run(t, "mount", "--bind", tree+"/sub", tree+"/sub")
		t.Cleanup(func() { _ = exec.CommandContext(context.Background(), "umount", tree+"/sub").Run() })
		a := map[string]any{"expected_preview_sha256": pv.PreviewSHA256}
		for k, v := range args {
			a[k] = v
		}
		wantGate(t, svcShell, "priv_chmod", a, "path_denied")
		for p, want := range map[string]os.FileMode{tree: 0o755, tree + "/a.conf": 0o640, tree + "/sub": 0o755, tree + "/sub/b.conf": 0o600} {
			if m, _, _, _ := statOwner(t, p); m.Perm() != want {
				t.Fatalf("%s changed to %v", p, m)
			}
		}
		// Previewed with the mount in place, it is refused at the preview.
		wantGate(t, svcShell, "priv_chmod_preview", args, "path_denied")
	})
}
