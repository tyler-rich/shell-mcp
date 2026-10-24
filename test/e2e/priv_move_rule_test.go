//go:build e2e && linux

package e2e

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/test/e2e/runner"
)

// The move rule end to end (handoff docs/handoff/S4C-PRIVILEGED.md N-17;
// PRIVILEGED §6, "Moves"): the real server, gate and helper (core unit).
// Root moves a non-directory only when its owner is owner-matched at the
// source (another account could not have put it there) and passes rule R
// at the destination (another account could not move it on); every
// directory of a moved tree has a mode priv_mkdir could create; the source
// is staged in the destination's directory and checked before the commit,
// so a replaced destination never passes through the source's directory.
// example-app is the other account. Every path and value is invented.

const movePrefix = ".shell-mcp-move-"

// appFile makes p as example-app's file: written under a name beside it,
// given to example-app, then renamed into place, so a racer watching p
// never sees it root's.
func appFile(t *testing.T, p, content string) {
	t.Helper()
	prep := filepath.Join(filepath.Dir(p), ".prep-"+filepath.Base(p))
	rootFile(t, prep, content, 0o640)
	if err := os.Chown(prep, exampleApp, exampleApp); err != nil {
		t.Fatal(err)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, prep, unix.AT_FDCWD, p, unix.RENAME_NOREPLACE); err != nil {
		t.Fatal(err)
	}
}

// appTree makes p as example-app's directory holding example-app's
// own.conf, renamed into place as appFile does.
func appTree(t *testing.T, p string) {
	t.Helper()
	prep := filepath.Join(filepath.Dir(p), ".prep-"+filepath.Base(p))
	_ = os.RemoveAll(prep)
	if err := os.Mkdir(prep, 0o755); err != nil { //nolint:gosec // G301: example-app's directory, given to it below
		t.Fatal(err)
	}
	if err := os.Chown(prep, exampleApp, exampleApp); err != nil {
		t.Fatal(err)
	}
	rootFile(t, filepath.Join(prep, "own.conf"), "own\n", 0o640)
	if err := os.Chown(filepath.Join(prep, "own.conf"), exampleApp, exampleApp); err != nil {
		t.Fatal(err)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, prep, unix.AT_FDCWD, p, unix.RENAME_NOREPLACE); err != nil {
		t.Fatal(err)
	}
}

// rootDir makes p, root's, with mode, and checks the mode on disk: os.Chmod
// takes the special bits only as os.ModeSetuid, os.ModeSetgid and
// os.ModeSticky and drops raw octal ones.
func rootDir(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	const bits = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	if got, _, _, _ := statOwner(t, p); got&bits != mode&bits {
		t.Fatalf("%s has mode %v, want %v", p, got&bits, mode)
	}
}

// startRacer runs this binary as example-app in client mode with env until
// the returned function closes its stdin; that function returns the
// count the racer printed after word.
func startRacer(t *testing.T, word string, env ...string) func() int {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), self) //nolint:gosec // G204: this test binary itself, in client mode
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, exampleApp)}
	cmd.Env = append(runner.Env(), env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return func() int {
		_ = stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Fatalf("racer: %v %q", err, out.String())
		}
		f := strings.Fields(out.String())
		if len(f) != 2 || f[0] != word {
			t.Fatalf("racer: %q", out.String())
		}
		n, _ := strconv.Atoi(f[1])
		return n
	}
}

// exchangeClient is a racer: run as another account, it exchanges E2E_X and
// E2E_Y (RENAME_EXCHANGE) until its stdin closes, then prints how many
// exchanges succeeded.
func exchangeClient() int {
	x, y := os.Getenv("E2E_X"), os.Getenv("E2E_Y")
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(done)
	}()
	n := 0
	for {
		select {
		case <-done:
			fmt.Println("EXCHANGES", n)
			return 0
		default:
		}
		if unix.Renameat2(unix.AT_FDCWD, x, unix.AT_FDCWD, y, unix.RENAME_EXCHANGE) == nil {
			n++
		}
	}
}

// grabClient is a racer: run as another account, it takes any root-owned
// entry that appears under E2E_GRAB, renaming it to E2E_GRAB.grab.<n> in
// the same directory, until its stdin closes, then prints how many it took.
func grabClient() int {
	name := os.Getenv("E2E_GRAB")
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(done)
	}()
	n := 0
	for {
		select {
		case <-done:
			fmt.Println("GRABS", n)
			return 0
		default:
		}
		var st unix.Stat_t
		if unix.Lstat(name, &st) != nil || st.Uid != 0 {
			continue
		}
		if unix.Rename(name, fmt.Sprintf("%s.grab.%d", name, n)) == nil {
			n++
		}
	}
}

// noStaged fails when dir holds a staging entry.
func noStaged(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), movePrefix) {
				t.Fatalf("%s holds the staging entry %s", d, e.Name())
			}
		}
	}
}

func TestPrivMoveRule(t *testing.T) {
	srv, h := privWriteServer(t)
	approveRun := func(t *testing.T, args map[string]any) map[string]any {
		t.Helper()
		id := pendingID(t, srv.callTool(t, "shell_priv_move_path", args))
		srv.decide(t, h, id, "approve")
		return srv.callTool(t, "shell_priv_move_path", withApproval(args, id))
	}
	appDir := "/etc/example-app/e2e-move-app"
	freshDir(t, appDir, exampleApp, 0o755)
	closed := privWriteDir // root's, 0700, under the closed write root
	app := strconv.Itoa(exampleApp)

	t.Run("(a) root's file into the account's directory", func(t *testing.T) {
		src, dst := closed+"/a.conf", appDir+"/a.conf"
		rootFile(t, src, "root's\n", 0o600)
		env := srv.callTool(t, "shell_priv_move_path", map[string]any{"source": src, "destination": dst})
		refusal(t, env, "path_denied", "example-app")
		noApproval(t, env)
		r, _ := gate(t, svcShell, "priv_move", map[string]any{"source": src, "destination": dst})
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, "the directory "+appDir+" is ") || !strings.Contains(r.Error.Message, "uid "+app) {
			t.Fatalf("the helper's refusal: %s %+v", r.code(), r.Error)
		}
		if readFile(t, src) != "root's\n" {
			t.Fatal("the source changed")
		}
		if _, err := os.Lstat(dst); err == nil {
			t.Fatal("a refused move placed the file")
		}
	})

	t.Run("(b) root's file in the account's directory, world-readable, into a closed one", func(t *testing.T) {
		src, dst := appDir+"/planted.conf", closed+"/planted.conf"
		rootFile(t, src, "planted\n", 0o644)
		env := srv.callTool(t, "shell_priv_move_path", map[string]any{"source": src, "destination": dst})
		refusal(t, env, "path_denied", "could have put it there")
		noApproval(t, env)
		r, _ := gate(t, svcShell, "priv_move", map[string]any{"source": src, "destination": dst})
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, "the directory "+appDir+" is ") {
			t.Fatalf("the helper's refusal: %s %+v", r.code(), r.Error)
		}
		if _, err := os.Lstat(dst); err == nil {
			t.Fatal("a refused move placed the file")
		}
	})

	t.Run("(b) swapped for root's file after approval", func(t *testing.T) {
		own, rf := appDir+"/own.conf", appDir+"/root-swap.conf"
		appFile(t, own, "own\n")
		rootFile(t, rf, "ROOT\n", 0o600)
		args := map[string]any{"source": own, "destination": closed + "/own.conf"}
		id := pendingID(t, srv.callTool(t, "shell_priv_move_path", args))
		srv.decide(t, h, id, "approve")
		// example-app's swap, made here as root: the same rename.
		if err := unix.Renameat2(unix.AT_FDCWD, own, unix.AT_FDCWD, rf, unix.RENAME_EXCHANGE); err != nil {
			t.Fatal(err)
		}
		refusal(t, srv.callTool(t, "shell_priv_move_path", withApproval(args, id)), "path_denied", "could have put it there")
		if _, err := os.Lstat(closed + "/own.conf"); err == nil || readFile(t, own) != "ROOT\n" {
			t.Fatal("root's file was moved, or the swap undone")
		}
	})

	t.Run("owner-matched: the account's own file and tree move within its directory", func(t *testing.T) {
		sub := appDir + "/sub"
		freshDir(t, sub, exampleApp, 0o755)
		src := appDir + "/mine.conf"
		appFile(t, src, "mine\n")
		okDataAs(t, approveRun(t, map[string]any{"source": src, "destination": sub + "/mine.conf"}), "e2e-ssh")
		if _, uid, _, _ := statOwner(t, sub+"/mine.conf"); uid != exampleApp || readFile(t, sub+"/mine.conf") != "mine\n" {
			t.Fatalf("moved: uid %d", uid)
		}
		appTree(t, appDir+"/t")
		mustGate(t, "priv_move", map[string]any{"source": appDir + "/t", "destination": sub + "/t"}, nil)
		if readFile(t, sub+"/t/own.conf") != "own\n" {
			t.Fatal("the tree was not moved")
		}
	})

	t.Run("a planted tree: the preview says it is checked when it runs; the helper refuses it", func(t *testing.T) {
		pt := appDir + "/pt"
		appTree(t, pt)
		rootFile(t, pt+"/root.conf", "ROOT\n", 0o600)
		args := map[string]any{"source": pt, "destination": closed + "/pt"}
		id := pendingID(t, srv.callTool(t, "shell_priv_move_path", args))
		if pg := srv.page(t, id); !strings.Contains(pg, "checked") {
			t.Fatal("the approval page does not say a directory's contents are checked when it runs")
		}
		srv.decide(t, h, id, "approve")
		refusal(t, srv.callTool(t, "shell_priv_move_path", withApproval(args, id)), "path_denied", "the directory "+appDir+" is ")
		if _, err := os.Lstat(closed + "/pt"); err == nil || readFile(t, pt+"/root.conf") != "ROOT\n" {
			t.Fatal("a refused tree was moved")
		}
	})

	t.Run("directory modes priv_mkdir could not create", func(t *testing.T) {
		for _, c := range []struct {
			name string
			mode os.FileMode
			want string
		}{
			{"wide", 0o777, "0777"},
			{"group", 0o775, "0775"},
			{"setgid", 0o755 | os.ModeSetgid, "2755"},
			{"sticky", 0o755 | os.ModeSticky, "1755"},
		} {
			d := closed + "/" + c.name
			rootDir(t, d, c.mode)
			r, _ := gate(t, svcShell, "priv_move", map[string]any{"source": d, "destination": d + "2"})
			if r.code() != "path_denied" || !strings.Contains(r.Error.Message, d) || !strings.Contains(r.Error.Message, c.want) {
				t.Fatalf("%s: %s %+v", c.name, r.code(), r.Error)
			}
			if _, err := os.Lstat(d + "2"); err == nil {
				t.Fatalf("%s was moved", c.name)
			}
		}
	})

	t.Run("an entry a stopped move left is reported and never touched", func(t *testing.T) {
		left := closed + "/" + movePrefix + "0123456789abcdef0123456789abcdef"
		rootFile(t, left, "staged\n", 0o600) // what a helper killed between its stage and its commit leaves
		rootFile(t, closed+"/x.conf", "x\n", 0o600)
		r, _ := gate(t, svcShell, "priv_move", map[string]any{"source": closed + "/x.conf", "destination": closed + "/y.conf"})
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, left) {
			t.Fatalf("a move beside the staged entry: %s %+v", r.code(), r.Error)
		}
		for _, op := range []string{"priv_read_file", "priv_stat", "priv_delete_preview"} {
			r, _ := gate(t, svcShell, op, map[string]any{"path": left})
			if r.code() != "path_denied" || !strings.Contains(r.Error.Message, movePrefix) {
				t.Fatalf("%s of the staged entry: %s %+v", op, r.code(), r.Error)
			}
		}
		if readFile(t, left) != "staged\n" {
			t.Fatal("the staged entry changed")
		}
		if err := os.Remove(left); err != nil {
			t.Fatal(err)
		}
		mustGate(t, "priv_move", map[string]any{"source": closed + "/x.conf", "destination": closed + "/y.conf"}, nil)
	})
}

// TestPrivMoveRace (core unit): example-app races root's moves from and into
// its own directory: it swaps the source for a root-owned file, swaps a
// moved tree for a root-owned one holding a root-owned file, swaps the
// destination's directory for a closed one, and takes any root-owned entry
// that appears under a source's name during an overwrite. Root never places
// a root-owned file where example-app put it, never hands example-app one,
// and never leaves a staging entry.
func TestPrivMoveRace(t *testing.T) {
	appDir := "/etc/example-app/e2e-move-race"
	vault := "/etc/example-app/e2e-move-vault"
	freshDir(t, appDir, exampleApp, 0o755)
	freshDir(t, vault, 0, 0o700)

	t.Run("the source swapped for root's file", func(t *testing.T) {
		x, rf := appDir+"/x", appDir+"/rootf"
		appFile(t, x, "own\n")
		rootFile(t, rf, "ROOT\n", 0o600)
		stop := startRacer(t, "EXCHANGES", "E2E_CLIENT=exchange", "E2E_X="+x, "E2E_Y="+rf)
		got := map[string]int{}
		for i := range 60 {
			r, _ := gate(t, svcShell, "priv_move", map[string]any{"source": x, "destination": fmt.Sprintf("%s/m%d", vault, i)})
			switch r.code() {
			case "ok", "path_denied", "exists", "not_found":
				got[r.code()]++
			default:
				stop()
				t.Fatalf("run %d: %s %+v", i, r.code(), r.Error)
			}
			if _, err := os.Lstat(x); err != nil {
				appFile(t, x, "own\n")
			}
		}
		n := stop()
		for _, e := range mustReadDir(t, vault) {
			p := vault + "/" + e.Name()
			if _, uid, _, _ := statOwner(t, p); uid != exampleApp || readFile(t, p) == "ROOT\n" {
				t.Fatalf("%s is uid %d: root moved a file example-app swapped in", p, uid)
			}
		}
		if readFile(t, x) != "ROOT\n" && readFile(t, rf) != "ROOT\n" {
			t.Fatal("root's file left example-app's directory")
		}
		noStaged(t, appDir, vault)
		t.Logf("moves %v while the racer made %d exchanges", got, n)
		clearDir(t, vault)
		clearDir(t, appDir)
	})

	t.Run("a tree swapped for root's tree holding root's file", func(t *testing.T) {
		tree, rt := appDir+"/tree", appDir+"/roottree"
		appTree(t, tree)
		rootDir(t, rt, 0o755)
		rootFile(t, rt+"/root.conf", "ROOT\n", 0o600)
		stop := startRacer(t, "EXCHANGES", "E2E_CLIENT=exchange", "E2E_X="+tree, "E2E_Y="+rt)
		got := map[string]int{}
		for i := range 60 {
			r, _ := gate(t, svcShell, "priv_move", map[string]any{"source": tree, "destination": fmt.Sprintf("%s/t%d", vault, i)})
			switch r.code() {
			case "ok", "path_denied", "exists", "not_found":
				got[r.code()]++
			default:
				stop()
				t.Fatalf("run %d: %s %+v", i, r.code(), r.Error)
			}
			if _, err := os.Lstat(tree); err != nil {
				appTree(t, tree)
			}
		}
		n := stop()
		for _, e := range mustReadDir(t, vault) {
			if _, err := os.Lstat(vault + "/" + e.Name() + "/root.conf"); err == nil {
				t.Fatalf("%s/%s is root's tree: root moved a tree example-app swapped in", vault, e.Name())
			}
		}
		noStaged(t, appDir, vault)
		t.Logf("moves %v while the racer made %d exchanges", got, n)
		clearDir(t, vault)
		clearDir(t, appDir)
	})

	t.Run("into the account's directory while it swaps that directory", func(t *testing.T) {
		sub, alt := appDir+"/sub", appDir+"/closed"
		if err := os.Mkdir(sub, 0o755); err != nil { //nolint:gosec // G301: example-app's directory, given to it below
			t.Fatal(err)
		}
		if err := os.Chown(sub, exampleApp, exampleApp); err != nil {
			t.Fatal(err)
		}
		rootDir(t, alt, 0o755)
		stop := startRacer(t, "EXCHANGES", "E2E_CLIENT=exchange", "E2E_X="+sub, "E2E_Y="+alt)
		for i := range 40 {
			src := fmt.Sprintf("%s/r%d", vault, i)
			rootFile(t, src, "root's\n", 0o600)
			r, _ := gate(t, svcShell, "priv_move", map[string]any{"source": src, "destination": fmt.Sprintf("%s/r%d", sub, i)})
			if r.code() != "path_denied" {
				stop()
				t.Fatalf("run %d: %s %+v, want path_denied", i, r.code(), r.Error)
			}
		}
		n := stop()
		for _, d := range []string{sub, alt} {
			if ents := mustReadDir(t, d); len(ents) != 0 {
				t.Fatalf("%s holds %d entries", d, len(ents))
			}
		}
		t.Logf("40 moves refused while the racer made %d exchanges", n)
		clearDir(t, vault)
		clearDir(t, appDir)
	})

	t.Run("the replaced destination is never in the source's directory", func(t *testing.T) {
		y := appDir + "/y"
		stop := startRacer(t, "GRABS", "E2E_CLIENT=grab", "E2E_GRAB="+y)
		got := map[string]int{}
		for i := range 200 {
			old := fmt.Sprintf("%s/o%d", vault, i)
			rootFile(t, old, "OLD\n", 0o600)
			if _, err := os.Lstat(y); err != nil {
				appFile(t, y, "new\n")
			}
			r, _ := gate(t, svcShell, "priv_move", map[string]any{"source": y, "destination": old, "overwrite": true})
			switch r.code() {
			case "ok", "not_found", "exists":
				got[r.code()]++
			default:
				stop()
				t.Fatalf("run %d: %s %+v", i, r.code(), r.Error)
			}
		}
		n := stop()
		if n != 0 {
			t.Fatalf("example-app took %d root-owned entries from its directory", n)
		}
		for _, e := range mustReadDir(t, appDir) {
			if strings.Contains(e.Name(), ".grab.") {
				t.Fatalf("example-app holds %s", e.Name())
			}
		}
		noStaged(t, appDir, vault)
		t.Logf("overwrites %v; the racer took nothing", got)
	})
}

func mustReadDir(t *testing.T, d string) []os.DirEntry {
	t.Helper()
	ents, err := os.ReadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	return ents
}

// clearDir removes everything in d, keeping d.
func clearDir(t *testing.T, d string) {
	t.Helper()
	for _, e := range mustReadDir(t, d) {
		if err := os.RemoveAll(filepath.Join(d, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
}
