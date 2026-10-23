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
// amended): every helper instance runs in a mount namespace of its own,
// whose mounts get new ids (the lowest free ones), so the mount id of an
// unchanged tree differs between two instances whenever another mount
// namespace came or went between them. Here an extra mount namespace held
// before a preview and released after it makes the next instance's ids
// differ every time: the approval preview against the re-call's, and the
// preview against the operation's own recompute. Every path is invented.

// mountNamespace is an extra mount namespace held by a sleeping process.
type mountNamespace struct {
	cmd *exec.Cmd
}

// holdMountNamespace starts a process in a new, private mount namespace
// (a copy of every mount, each with a newly allocated id) and returns once
// the namespace exists.
func holdMountNamespace(t *testing.T) *mountNamespace {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "/usr/bin/unshare", "--mount", "--propagation", "private", "/usr/bin/sleep", "300")
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	ns := &mountNamespace{cmd: cmd}
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
				return ns
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the extra mount namespace was not set up")
		}
	}
}

// release ends the namespace's process and waits for its mounts (and their
// ids) to be freed: the kernel releases them as the last process leaves,
// partly from deferred work, so it also waits a settle time.
func (ns *mountNamespace) release(t *testing.T) {
	t.Helper()
	_ = ns.cmd.Process.Kill()
	_ = ns.cmd.Wait()
	time.Sleep(2 * time.Second)
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
		ns := holdMountNamespace(t)
		id := pendingID(t, srv.callTool(t, "shell_priv_set_permissions", args))
		ns.release(t)
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
		ns := holdMountNamespace(t)
		mustGate(t, "priv_chown_preview", args, &pv)
		ns.release(t)
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
