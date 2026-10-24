//go:build e2e && linux

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// shell_priv_copy_path's owner and group end to end (handoff
// docs/handoff/S4C-PRIVILEGED.md N-19, P-15; PRIVILEGED §6): the real
// server, gate and helper (core unit). A copy may name its owner and group
// as a write does, from the privileged policy's owners lists; under rule R
// the copy's owner is the one given, else the destination's, else root's,
// and an explicit owner must itself pass; both ids are set on the new
// inode. example-app is the other account. Every path and value is
// invented.

func TestPrivCopyOwner(t *testing.T) {
	srv, h := privWriteServer(t)
	approveRun := func(t *testing.T, args map[string]any) map[string]any {
		t.Helper()
		id := pendingID(t, srv.callTool(t, "shell_priv_copy_path", args))
		pg := srv.page(t, id)
		for _, k := range []string{"owner", "group"} {
			if v, ok := args[k]; ok && !strings.Contains(pg, `<th>set.`+k+`</th><td class="v">`+fmt.Sprint(v)+`</td>`) {
				t.Fatalf("the approval page does not show set.%s %v", k, v)
			}
		}
		srv.decide(t, h, id, "approve")
		return srv.callTool(t, "shell_priv_copy_path", withApproval(args, id))
	}
	appDir := "/etc/example-app/e2e-copy-owner-app"
	freshDir(t, appDir, exampleApp, 0o755)
	src := privWriteDir + "/app.bin"
	rootFile(t, src, "binary\x00payload\n", 0o755)
	app := map[string]any{"owner": "example-app", "group": "example-app"}

	t.Run("into the account's directory: refused as root's, accepted as the account's", func(t *testing.T) {
		p := appDir + "/app.bin"
		for _, extra := range []map[string]any{nil, {"owner": "root", "group": "root"}} {
			args := map[string]any{"source": src, "destination": p}
			for k, v := range extra {
				args[k] = v
			}
			env := srv.callTool(t, "shell_priv_copy_path", args)
			refusal(t, env, "path_denied", "example-app")
			noApproval(t, env)
		}
		r, _ := gate(t, svcShell, "priv_copy", map[string]any{"source": src, "destination": p, "owner": "root", "group": "root"})
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, "the directory "+appDir+" is ") || !strings.Contains(r.Error.Message, "uid "+strconv.Itoa(exampleApp)) {
			t.Fatalf("the helper's refusal of owner root: %s %+v", r.code(), r.Error)
		}
		if _, err := os.Lstat(p); err == nil {
			t.Fatal("a refused copy created the file")
		}
		d := okDataAs(t, approveRun(t, map[string]any{"source": src, "destination": p, "owner": "example-app", "group": "example-app"}), "e2e-ssh")
		mode, uid, gid, _ := statOwner(t, p)
		if uid != exampleApp || gid != exampleApp || d["uid"] != float64(exampleApp) || d["gid"] != float64(exampleApp) ||
			d["owner"] != "example-app" || d["group"] != "example-app" || readFile(t, p) != "binary\x00payload\n" {
			t.Fatalf("copied as example-app: %d:%d %v", uid, gid, d)
		}
		if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || mode.Perm() != 0o755 {
			t.Fatalf("the copy's mode %v", mode)
		}
	})

	t.Run("over root's file in the account's directory: both needed, then the account's", func(t *testing.T) {
		p := appDir + "/root.bin"
		rootFile(t, p, "root's\n", 0o640)
		env := srv.callTool(t, "shell_priv_copy_path", map[string]any{"source": src, "destination": p, "overwrite": true, "owner": "example-app"})
		refusal(t, env, "path_denied", "group")
		noApproval(t, env)
		d := okDataAs(t, approveRun(t, map[string]any{"source": src, "destination": p, "overwrite": true, "owner": "example-app", "group": "example-app"}), "e2e-ssh")
		if _, uid, gid, _ := statOwner(t, p); uid != exampleApp || gid != exampleApp || readFile(t, p) != "binary\x00payload\n" {
			t.Fatalf("over root's file: %d:%d %v", uid, gid, d)
		}
		if ids, _ := d["backup_ids"].([]any); len(ids) != 1 {
			t.Fatalf("backup ids %v", d["backup_ids"])
		}
	})

	t.Run("owners and groups off the lists are refused", func(t *testing.T) {
		p := privWriteDir + "/never.bin"
		for _, extra := range []map[string]any{{"owner": "nobody"}, {"group": "nogroup"}, {"owner": "example-app", "group": "nogroup"}} {
			args := map[string]any{"source": src, "destination": p}
			for k, v := range extra {
				args[k] = v
			}
			wantGate(t, svcShell, "priv_copy", args, "policy_denied")
		}
		if _, err := os.Lstat(p); err == nil {
			t.Fatal("a refused owner created the file")
		}
	})

	t.Run("a group-writable directory: no owner passes", func(t *testing.T) {
		shared := "/etc/example-app/e2e-copy-owner-shared"
		freshDir(t, shared, exampleApp, 0o775)
		p := shared + "/app.bin"
		env := srv.callTool(t, "shell_priv_copy_path", withArgsE2E(map[string]any{"source": src, "destination": p}, app))
		refusal(t, env, "path_denied", shared)
		noApproval(t, env)
		wantGate(t, svcShell, "priv_copy", withArgsE2E(map[string]any{"source": src, "destination": p}, app), "path_denied")
		if _, err := os.Lstat(p); err == nil {
			t.Fatal("a refused copy created the file")
		}
	})

	t.Run("a setgid directory: the group given is the one set", func(t *testing.T) {
		sg := "/etc/example-app/e2e-copy-owner-setgid"
		freshDir(t, sg, 0, 0o755)
		if err := os.Chown(sg, 0, exampleApp); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(sg, 0o755|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
		d := okDataAs(t, approveRun(t, map[string]any{"source": src, "destination": sg + "/app.bin", "group": "example-app"}), "e2e-ssh")
		mode, uid, gid, _ := statOwner(t, sg+"/app.bin")
		if uid != 0 || gid != exampleApp || d["group"] != "example-app" || mode&os.ModeSetgid != 0 {
			t.Fatalf("a copy given group example-app: %d:%d %v %v", uid, gid, mode, d)
		}
		mustGate(t, "priv_copy", map[string]any{"source": src, "destination": sg + "/root.bin"}, nil)
		if _, uid, gid, _ := statOwner(t, sg+"/root.bin"); uid != 0 || gid != 0 {
			t.Fatalf("a copy without a group: %d:%d, want root:root", uid, gid)
		}
	})
}

func withArgsE2E(base, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// TestPrivCopyOwnerRace (core unit): example-app, which owns a directory
// under the write root, exchanges a directory in it with a symlink to a
// root-only directory elsewhere in the root, again and again, while the
// helper copies a file beneath it: without an owner, as root, and as
// example-app. Root's copies are always refused; example-app's land in
// example-app's own directory as example-app's (verify_failed when the
// racer moved it before the read-back), or are refused; nothing ever lands
// in the root-only directory.
func TestPrivCopyOwnerRace(t *testing.T) {
	race := "/etc/example-app/e2e-copy-owner-race"
	vault := "/etc/example-app/e2e-copy-owner-vault"
	freshDir(t, race, exampleApp, 0o755)
	freshDir(t, vault, 0, 0o700)
	d := race + "/d"
	if err := os.Mkdir(d, 0o755); err != nil { //nolint:gosec // G301: example-app's directory, given to it below
		t.Fatal(err)
	}
	if err := os.Chown(d, exampleApp, exampleApp); err != nil {
		t.Fatal(err)
	}
	srcDir := "/etc/example-app/e2e-copy-owner-src"
	freshDir(t, srcDir, 0, 0o755)
	src := srcDir + "/race.bin"
	rootFile(t, src, "x\n", 0o644)
	stop := startRacer(t, "SWAPS", "E2E_CLIENT=swap", "E2E_SWAP_NAME="+d, "E2E_SWAP_ALT="+d+".alt", "E2E_SWAP_TO="+vault)
	landed, refused := 0, 0
	for i := range 40 {
		for _, c := range []struct {
			name  string
			extra map[string]any
			own   bool
		}{
			{"root", nil, false},
			{"owner root", map[string]any{"owner": "root", "group": "root"}, false},
			{"example-app", map[string]any{"owner": "example-app", "group": "example-app"}, true},
		} {
			args := withArgsE2E(map[string]any{"source": src, "destination": fmt.Sprintf("%s/c%d-%d", d, i, len(c.name))}, c.extra)
			r, _ := gate(t, svcShell, "priv_copy", args)
			switch {
			case r.OK && c.own, c.own && r.code() == "verify_failed":
				landed++
			case r.OK:
				stop()
				t.Fatalf("run %d: %s's copy was left under example-app's directory", i, c.name)
			case r.code() == "path_denied" || r.code() == "not_a_directory":
				refused++
			default:
				stop()
				t.Fatalf("run %d: %s: %s %+v", i, c.name, r.code(), r.Error)
			}
		}
	}
	if n := stop(); n == 0 {
		t.Fatal("the racer never swapped")
	}
	if names, _ := os.ReadDir(vault); len(names) != 0 {
		t.Fatalf("the root-only directory holds %d entries", len(names))
	}
	for _, dir := range []string{d, d + ".alt"} {
		names, _ := os.ReadDir(dir)
		for _, n := range names {
			if _, uid, gid, _ := statOwner(t, filepath.Join(dir, n.Name())); uid != exampleApp || gid != exampleApp {
				t.Fatalf("%s/%s is %d:%d", dir, n.Name(), uid, gid)
			}
		}
	}
	t.Logf("%d copies landed as example-app, %d refused", landed, refused)
}
