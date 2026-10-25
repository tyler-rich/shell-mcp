//go:build e2e && linux

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The gate's own versions of two gaps closed on the privileged side
// (handoff docs/handoff/S4C-PRIVILEGED.md N-11, N-18), end to end: the
// real gate as the service account (svc-shell), with Landlock, and a real
// other account (example-app). setup.sh declares the policy
// /etc/shell-mcp/gate-hardening.yaml: the read root /srv/e2e-gate (root's)
// with the write root /srv/e2e-gate/work (the service account's), and the
// commands probe-cat (read: cat a {path:read}, echo one, pwd, cat t
// relative to the cwd) and probe-put (operator: write a {path:write}, echo
// one). Every path and name is an invented fixture.

const (
	hardPolicy = "/etc/shell-mcp/gate-hardening.yaml"
	hardRoot   = "/srv/e2e-gate"
	hardWork   = hardRoot + "/work"
)

// hard sends one request to the gate under the hardening policy, as the
// service account, at ceiling destructive.
func hard(t *testing.T, op string, args any) response {
	t.Helper()
	r, _ := gatePolicyAt(t, hardPolicy, svcShell, "destructive", op, args)
	return r
}

// hardExec previews a command and runs it with the preview's hash (an
// invalid one when the preview is refused); it returns both answers.
func hardExec(t *testing.T, command string, args []string, cwd string) (preview, run response) {
	t.Helper()
	req := map[string]any{"command_id": command, "args": args}
	if cwd != "" {
		req["cwd"] = cwd
	}
	preview = hard(t, "exec_preview", req)
	hash := strings.Repeat("0", 64)
	if preview.OK {
		var p struct {
			PreviewSHA256 string `json:"preview_sha256"`
		}
		if err := json.Unmarshal(preview.Data, &p); err != nil {
			t.Fatalf("%s previewed %s: %v", command, preview.Data, err)
		}
		hash = p.PreviewSHA256
	}
	req["expected_preview_sha256"] = hash
	return preview, hard(t, "exec", req)
}

// ownDir makes p (removed first) owned by uid:gid with mode, and removes it
// when the test ends.
func ownDir(t *testing.T, p string, uid, gid int, mode os.FileMode) {
	t.Helper()
	_ = os.RemoveAll(p)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	setDir(t, p, uid, gid, mode)
	t.Cleanup(func() { _ = os.RemoveAll(p) })
}

// setDir gives p an owner and an exact mode.
func setDir(t *testing.T, p string, uid, gid int, mode os.FileMode) {
	t.Helper()
	if err := os.Chown(p, uid, gid); err != nil {
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

// ownFile writes p as uid's file with mode.
func ownFile(t *testing.T, p, content string, uid int, mode os.FileMode) {
	t.Helper()
	rootFile(t, p, content, mode)
	if err := os.Chown(p, uid, uid); err != nil {
		t.Fatal(err)
	}
}

// TestGateExecPathChain (N-11): with every directory from / to the parent
// root's or the service account's and closed, the gate's {path:read},
// {path:write} and cwd resolve and run. With any one of them (the read
// root, the write root, an intermediate directory, the parent)
// group-writable, world-writable or sticky, exec_preview and exec refuse
// with path_denied naming it, and nothing runs; owned by example-app (one
// other account, and closed otherwise), a {path:read} still runs (the
// owner-matched exception) while {path:write} and the cwd are refused. A
// directory given as the cwd, {path:read} or {path:write} is refused the
// same way when it is open itself (sticky counting as open), except a
// {path:read} directory owned by example-app, and runs when it is closed.
func TestGateExecPathChain(t *testing.T) {
	a := hardWork + "/chain"
	b := a + "/b"
	sub := b + "/c"
	ownDir(t, a, svcShell, svcShell, 0o755)
	for _, d := range []string{b, sub} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		setDir(t, d, svcShell, svcShell, 0o755)
	}
	file := b + "/t"
	ownFile(t, file, "original\n", svcShell, 0o644)
	newFile := b + "/new"

	t.Run("closed", func(t *testing.T) {
		_, r := hardExec(t, "probe-cat", []string{"cat", file}, "")
		if out := stdoutOf(t, &r); out != "READ:original\n\n" {
			t.Fatalf("read %q", out)
		}
		_, r = hardExec(t, "probe-cat", []string{"pwd"}, sub)
		if out := stdoutOf(t, &r); out != sub+"\n" {
			t.Fatalf("cwd %q", out)
		}
		_, r = hardExec(t, "probe-put", []string{"write", newFile}, "")
		if out := stdoutOf(t, &r); out != "WROTE\n" {
			t.Fatalf("write %q", out)
		}
		fileIs(t, newFile, "probe")
		_ = os.Remove(newFile)
		for _, command := range []string{"probe-cat", "probe-put"} {
			_, r = hardExec(t, command, []string{"echo", sub}, "")
			if out := stdoutOf(t, &r); out != sub+"\n" {
				t.Fatalf("%s a closed directory: %q", command, out)
			}
		}
	})

	for _, lvl := range []struct {
		name string
		dir  string
		uid  int
	}{{"read root", hardRoot, 0}, {"write root", hardWork, svcShell}, {"intermediate", a, svcShell}, {"parent", b, svcShell}} {
		for _, o := range []struct {
			name string
			app  bool
			mode os.FileMode
		}{
			{"owned by example-app", true, 0o755},
			{"group-writable", false, 0o775},
			{"world-writable", false, 0o777},
			{"sticky", false, os.ModeSticky | 0o777},
		} {
			t.Run(lvl.name+" "+o.name, func(t *testing.T) {
				uid := lvl.uid
				if o.app {
					uid = exampleApp
				}
				setDir(t, lvl.dir, uid, uid, o.mode)
				defer setDir(t, lvl.dir, lvl.uid, lvl.uid, 0o755)
				pr, er := hardExec(t, "probe-cat", []string{"cat", file}, "")
				if o.app {
					// An owner-matched read: example-app's directory, closed otherwise.
					if out := stdoutOf(t, &er); !pr.OK || out != "READ:original\n\n" {
						t.Fatalf("an owner-matched read: preview %+v, read %q", pr.Error, out)
					}
				} else if pr.code() != "path_denied" || !strings.Contains(pr.Error.Message, lvl.dir) || er.code() != "path_denied" || er.Error.Message != pr.Error.Message {
					t.Fatalf("cat: preview %s %+v, exec %s %+v, want path_denied naming %s", pr.code(), pr.Error, er.code(), er.Error, lvl.dir)
				}
				for _, c := range []struct {
					command string
					args    []string
					cwd     string
				}{
					{"probe-cat", []string{"pwd"}, sub},
					{"probe-put", []string{"write", newFile}, ""},
					{"probe-put", []string{"write", file}, ""},
				} {
					pr, er := hardExec(t, c.command, c.args, c.cwd)
					if pr.code() != "path_denied" || !strings.Contains(pr.Error.Message, lvl.dir) || strings.Contains(pr.Error.Message, "as root") {
						t.Fatalf("%s %v cwd %q: preview %s %+v, want path_denied naming %s", c.command, c.args, c.cwd, pr.code(), pr.Error, lvl.dir)
					}
					if er.code() != "path_denied" || er.Error.Message != pr.Error.Message {
						t.Fatalf("%s %v: exec %s %+v, want the preview's refusal", c.command, c.args, er.code(), er.Error)
					}
				}
				if _, err := os.Lstat(newFile); err == nil {
					t.Fatalf("%s was created", newFile)
				}
				fileIs(t, file, "original\n")
			})
		}
	}

	for _, o := range []struct {
		name string
		app  bool
		mode os.FileMode
	}{
		{"owned by example-app", true, 0o755},
		{"group-writable", false, 0o775},
		{"world-writable", false, 0o777},
		{"sticky", false, os.ModeSticky | 0o777},
		{"sticky, not writable", false, os.ModeSticky | 0o755},
	} {
		t.Run("directory target "+o.name, func(t *testing.T) {
			uid := svcShell
			if o.app {
				uid = exampleApp
			}
			setDir(t, sub, uid, uid, o.mode)
			defer setDir(t, sub, svcShell, svcShell, 0o755)
			reqs := []struct {
				command string
				args    []string
				cwd     string
			}{
				{"probe-cat", []string{"pwd"}, sub},
				{"probe-cat", []string{"echo", sub}, ""},
				{"probe-put", []string{"echo", sub}, ""},
			}
			if o.app {
				// An owner-matched {path:read} directory runs; the cwd and
				// {path:write} stay strict.
				_, r := hardExec(t, "probe-cat", []string{"echo", sub}, "")
				if out := stdoutOf(t, &r); out != sub+"\n" {
					t.Fatalf("an owner-matched read directory: %q", out)
				}
				reqs = append(reqs[:1], reqs[2])
			}
			for _, c := range reqs {
				pr, er := hardExec(t, c.command, c.args, c.cwd)
				if pr.code() != "path_denied" || !strings.Contains(pr.Error.Message, sub) {
					t.Fatalf("%s %v cwd %q: preview %s %+v, want path_denied naming %s", c.command, c.args, c.cwd, pr.code(), pr.Error, sub)
				}
				if er.code() != "path_denied" || er.Error.Message != pr.Error.Message {
					t.Fatalf("%s %v: exec %s %+v, want the preview's refusal", c.command, c.args, er.code(), er.Error)
				}
			}
		})
	}
}

// TestGateExecPathChainRace (N-11): example-app, which owns a directory
// under the gate's write root, exchanges a command's {path:write} target
// (in that directory), a directory above it, or the name a command reads
// relative to a cwd it owns, with a symlink to a file only the service
// account can read, again and again, while the gate previews and runs the
// command with each fresh preview's hash. Every request is refused at the
// resolution, and the file is never read or written. (A {path:read} there
// is the owner-matched exception, whose residual
// TestGateExecOwnerMatchedReadRace shows.)
func TestGateExecPathChainRace(t *testing.T) {
	vault := hardWork + "/vault"
	race := hardWork + "/race"
	ownDir(t, vault, svcShell, svcShell, 0o700)
	victim := vault + "/t"
	ownFile(t, victim, "VICTIM\n", svcShell, 0o600)
	for _, c := range []struct{ name, target, swap, to, cwd string }{
		{"the target in its parent", "t", "t", victim, ""},
		{"a directory above the target", "sub/t", "sub", vault, ""},
		{"a symlink planted in the cwd", "t", "t", victim, race},
	} {
		t.Run(c.name, func(t *testing.T) {
			ownDir(t, race, exampleApp, exampleApp, 0o755)
			if err := os.Mkdir(race+"/sub", 0o700); err != nil {
				t.Fatal(err)
			}
			setDir(t, race+"/sub", exampleApp, exampleApp, 0o755)
			ownFile(t, race+"/t", "decoy\n", exampleApp, 0o644)
			ownFile(t, race+"/sub/t", "decoy\n", exampleApp, 0o644)
			stop := startRacer(t, "SWAPS", "E2E_CLIENT=swap", "E2E_SWAP_NAME="+filepath.Join(race, c.swap),
				"E2E_SWAP_ALT="+filepath.Join(race, c.swap+".alt"), "E2E_SWAP_TO="+c.to)
			target := filepath.Join(race, c.target)
			type req struct {
				command string
				args    []string
			}
			reqs := []req{{"probe-put", []string{"write", target}}}
			if c.cwd != "" {
				reqs = []req{{"probe-cat", []string{"cat", c.target}}}
			}
			requests := 0
			for i := range 20 {
				for _, rc := range reqs {
					pr, er := hardExec(t, rc.command, rc.args, c.cwd)
					for _, r := range []response{pr, er} {
						if strings.Contains(string(r.Data), "VICTIM") {
							stop()
							t.Fatalf("run %d: %s read the service account's file: %s", i, rc.command, r.Data)
						}
						if r.code() != "path_denied" {
							stop()
							t.Fatalf("run %d: %s %v: %s %+v %s, want path_denied", i, rc.command, rc.args, r.code(), r.Error, r.Data)
						}
					}
					requests++
				}
			}
			if n := stop(); n == 0 {
				t.Fatal("the racer did not swap")
			}
			fileIs(t, victim, "VICTIM\n")
			t.Logf("%d requests refused at the preview and at exec", requests)
		})
	}
}

// TestGateMoveReplacedRace (N-18): example-app can write the source's
// directory (shared with the service account through its group) and takes
// any file of the service account's that appears under the source's name,
// while the gate moves example-app's file there over a file of the service
// account's in a directory only the service account can write. With
// expected_destination_sha256 (a verified replace) and without, the
// replaced file never appears under the source's name: example-app takes
// nothing, and no staging entry is left.
func TestGateMoveReplacedRace(t *testing.T) {
	shared := hardWork + "/shared"
	vault := hardWork + "/vault-move"
	ownDir(t, shared, svcShell, exampleApp, 0o770)
	ownDir(t, vault, svcShell, svcShell, 0o700)
	sum := sha256.Sum256([]byte("OLD\n"))
	oldSHA := hex.EncodeToString(sum[:])
	for _, verified := range []bool{true, false} {
		t.Run(fmt.Sprintf("verified=%v", verified), func(t *testing.T) {
			// Each case starts from empty directories: what an earlier case
			// left (a taken file) is not this one's.
			clearDir(t, shared)
			clearDir(t, vault)
			y := shared + "/y"
			stop := startRacer(t, "GRABS", "E2E_CLIENT=grab", "E2E_GRAB="+y, "E2E_GRAB_UID="+strconv.Itoa(svcShell))
			got := map[string]int{}
			for i := range 200 {
				old := fmt.Sprintf("%s/o%d", vault, i)
				ownFile(t, old, "OLD\n", svcShell, 0o600)
				if _, err := os.Lstat(y); err != nil {
					appFile(t, y, "new\n")
				}
				args := map[string]any{"source": y, "destination": old, "overwrite": true}
				if verified {
					args["expected_destination_sha256"] = oldSHA
				}
				r := hard(t, "move", args)
				switch r.code() {
				case "ok", "not_found", "exists":
					got[r.code()]++
				default:
					n := stop()
					t.Fatalf("run %d: %s %+v (example-app took %d)", i, r.code(), r.Error, n)
				}
			}
			if n := stop(); n != 0 {
				t.Fatalf("example-app took %d of the service account's replaced files from the source's directory", n)
			}
			for _, e := range mustReadDir(t, shared) {
				if strings.Contains(e.Name(), ".grab.") {
					t.Fatalf("example-app holds %s", e.Name())
				}
			}
			noStaged(t, shared, vault)
			if got["ok"] == 0 {
				t.Fatalf("no move succeeded: %v", got)
			}
			t.Logf("moves %v; the racer took nothing", got)
		})
	}
}

// TestGateMoveStagingEntry (N-18): an entry a stopped gate move left in a
// directory (.shell-mcp-move-<32 hex>) is never read, moved or deleted
// through the gate and never given to a command, and nothing moves into or
// out of the directory that holds it; each refusal names it, and it is
// left as it was.
func TestGateMoveStagingEntry(t *testing.T) {
	dir := hardWork + "/strand"
	ownDir(t, dir, svcShell, svcShell, 0o755)
	staged := dir + "/" + movePrefix + strings.Repeat("0f", 16)
	ownFile(t, staged, "left by a stopped move\n", svcShell, 0o640)
	x := dir + "/x.conf"
	ownFile(t, x, "x\n", svcShell, 0o640)
	out := hardWork + "/strand-out.conf"
	ownFile(t, out, "out\n", svcShell, 0o640)
	t.Cleanup(func() { _ = os.Remove(out); _ = os.Remove(hardWork + "/strand-x.conf") })
	for _, c := range []struct {
		op   string
		args map[string]any
	}{
		{"read_file", map[string]any{"path": staged}},
		{"move", map[string]any{"source": staged, "destination": hardWork + "/strand-back.conf"}},
		{"delete_preview", map[string]any{"path": dir, "recursive": true}},
		{"move", map[string]any{"source": x, "destination": hardWork + "/strand-x.conf"}},
		{"move", map[string]any{"source": out, "destination": dir + "/out.conf"}},
		{"exec_preview", map[string]any{"command_id": "probe-cat", "args": []string{"cat", staged}}},
	} {
		r := hard(t, c.op, c.args)
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, movePrefix) {
			t.Fatalf("%s %v: %s %+v, want path_denied naming the staging entry", c.op, c.args, r.code(), r.Error)
		}
	}
	fileIs(t, staged, "left by a stopped move\n")
	fileIs(t, x, "x\n")
	fileIs(t, out, "out\n")
	var st unix.Stat_t
	if err := unix.Lstat(dir+"/out.conf", &st); err == nil {
		t.Fatal("a file was moved into the directory holding the staging entry")
	}
}

// TestGateExecOwnerMatchedRead (N-11, the owner-matched exception for
// {path:read}): a file in a directory one other account owns (example-app's
// application directory, as in POLICY §4's compose example) and that
// directory itself are given to a read command; the cwd there, and a
// {path:write} in such a directory under the write root, are refused. A group-writable application directory, and a path
// holding directories of two other accounts (svc-other's holding
// example-app's), refuse a read, naming why.
func TestGateExecOwnerMatchedRead(t *testing.T) {
	app := hardRoot + "/app"
	ownDir(t, app, exampleApp, exampleApp, 0o755)
	compose := app + "/compose.yaml"
	ownFile(t, compose, "services: {}\n", exampleApp, 0o644)

	t.Run("POLICY's compose example", func(t *testing.T) {
		pr, r := hardExec(t, "probe-compose", []string{"echo", "compose", "-f", compose, "ps", "--format", "json"}, "")
		if out := stdoutOf(t, &r); !pr.OK || out != "compose\n-f\n"+compose+"\nps\n--format\njson\n" {
			t.Fatalf("preview %+v, ran %q", pr.Error, out)
		}
		_, r = hardExec(t, "probe-cat", []string{"cat", compose}, "")
		if out := stdoutOf(t, &r); out != "READ:services: {}\n\n" {
			t.Fatalf("read %q", out)
		}
		_, r = hardExec(t, "probe-cat", []string{"echo", app}, "")
		if out := stdoutOf(t, &r); out != app+"\n" {
			t.Fatalf("the application directory as a {path:read}: %q", out)
		}
	})

	t.Run("write and cwd stay strict", func(t *testing.T) {
		// The same layout under the write root, for {path:write}.
		appW := hardWork + "/app"
		ownDir(t, appW, exampleApp, exampleApp, 0o755)
		ownFile(t, appW+"/compose.yaml", "services: {}\n", exampleApp, 0o644)
		for _, c := range []struct {
			command string
			args    []string
			cwd     string
		}{
			{"probe-cat", []string{"pwd"}, app},
			{"probe-put", []string{"echo", appW}, ""},
			{"probe-put", []string{"write", appW + "/compose.yaml"}, ""},
			{"probe-put", []string{"write", appW + "/new.yaml"}, ""},
		} {
			pr, er := hardExec(t, c.command, c.args, c.cwd)
			if pr.code() != "path_denied" || !strings.Contains(pr.Error.Message, "uid "+strconv.Itoa(exampleApp)) || er.code() != "path_denied" {
				t.Fatalf("%s %v cwd %q: preview %s %+v, exec %s", c.command, c.args, c.cwd, pr.code(), pr.Error, er.code())
			}
		}
		fileIs(t, appW+"/compose.yaml", "services: {}\n")
		if _, err := os.Lstat(appW + "/new.yaml"); err == nil {
			t.Fatal("a refused write created its file")
		}
	})

	t.Run("group-writable", func(t *testing.T) {
		setDir(t, app, exampleApp, exampleApp, 0o775)
		defer setDir(t, app, exampleApp, exampleApp, 0o755)
		for _, args := range [][]string{{"cat", compose}, {"echo", app}} {
			pr, er := hardExec(t, "probe-cat", args, "")
			if pr.code() != "path_denied" || !strings.Contains(pr.Error.Message, app) || !strings.Contains(pr.Error.Message, "group- or world-writable") ||
				er.code() != "path_denied" || er.Error.Message != pr.Error.Message {
				t.Fatalf("%v: preview %s %+v, exec %s %+v", args, pr.code(), pr.Error, er.code(), er.Error)
			}
		}
	})

	t.Run("two other accounts", func(t *testing.T) {
		outer := hardRoot + "/two"
		ownDir(t, outer, svcOther, svcOther, 0o755)
		inner := outer + "/app"
		if err := os.Mkdir(inner, 0o700); err != nil {
			t.Fatal(err)
		}
		setDir(t, inner, exampleApp, exampleApp, 0o755)
		f := inner + "/compose.yaml"
		ownFile(t, f, "services: {}\n", exampleApp, 0o644)
		for _, args := range [][]string{{"cat", f}, {"echo", inner}} {
			pr, er := hardExec(t, "probe-cat", args, "")
			if pr.code() != "path_denied" || !strings.Contains(pr.Error.Message, inner) || !strings.Contains(pr.Error.Message, "while the directory "+outer+" is owned by uid "+strconv.Itoa(svcOther)) ||
				er.code() != "path_denied" || er.Error.Message != pr.Error.Message {
				t.Fatalf("%v: preview %s %+v, exec %s %+v", args, pr.code(), pr.Error, er.code(), er.Error)
			}
		}
	})
}

// TestGateExecOwnerMatchedReadRace (the accepted residual of the
// owner-matched exception): example-app, which owns the directory of a
// read command's target, exchanges the target (or a directory above it,
// within its own directory) with a symlink, again and again, while the
// gate previews and runs the read with the fresh hash. The swap redirects
// the read, so the command reads what the link names, as the service
// account: a file only the service account can read, or one the gate's
// deny list covers, can be read and returned to the client (the residual
// POLICY §4 documents); a file the service account cannot read (root's,
// 0600) never is.
func TestGateExecOwnerMatchedReadRace(t *testing.T) {
	vault := hardWork + "/vault-read"
	ownDir(t, vault, svcShell, svcShell, 0o700)
	ownFile(t, vault+"/t", "SERVICE-ONLY\n", svcShell, 0o600)
	denied := hardWork + "/denied"
	ownDir(t, denied, svcShell, svcShell, 0o755)
	ownFile(t, denied+"/t", "DENIED\n", svcShell, 0o644)
	rootVault := hardWork + "/root-only"
	ownDir(t, rootVault, 0, 0, 0o700)
	rootFile(t, rootVault+"/t", "ROOT-ONLY\n", 0o600)
	race := hardRoot + "/race"
	for _, c := range []struct {
		name, target, swap, to string
		readable               bool
	}{
		{"the target, to the service account's file", "t", "t", vault + "/t", true},
		{"the target, to a denied file", "t", "t", denied + "/t", true},
		{"a directory above the target, to the service account's directory", "sub/t", "sub", vault, true},
		{"the target, to root's file", "t", "t", rootVault + "/t", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ownDir(t, race, exampleApp, exampleApp, 0o755)
			if err := os.Mkdir(race+"/sub", 0o700); err != nil {
				t.Fatal(err)
			}
			setDir(t, race+"/sub", exampleApp, exampleApp, 0o755)
			ownFile(t, race+"/t", "decoy\n", exampleApp, 0o644)
			ownFile(t, race+"/sub/t", "decoy\n", exampleApp, 0o644)
			stop := startRacer(t, "SWAPS", "E2E_CLIENT=swap", "E2E_SWAP_NAME="+filepath.Join(race, c.swap),
				"E2E_SWAP_ALT="+filepath.Join(race, c.swap+".alt"), "E2E_SWAP_TO="+c.to)
			target := filepath.Join(race, c.target)
			got := map[string]int{}
			for i := range 60 {
				pr, er := hardExec(t, "probe-cat", []string{"cat", target}, "")
				out := ""
				if er.OK {
					var d struct {
						Stdout string `json:"stdout"`
					}
					_ = json.Unmarshal(er.Data, &d)
					out = d.Stdout
				}
				switch {
				case strings.Contains(string(pr.Data)+string(er.Data), "ROOT-ONLY"):
					stop()
					t.Fatalf("run %d: the read reached root's file: %s", i, er.Data)
				case out == "READ:decoy\n\n":
					got["decoy"]++
				case strings.HasPrefix(out, "READ:") && c.readable:
					got["redirected"]++
				case er.OK:
					got["not read"]++
				default:
					got[er.code()]++
				}
			}
			n := stop()
			if n == 0 {
				t.Fatal("the racer did not swap")
			}
			t.Logf("reads %v; the racer made %d exchanges", got, n)
		})
	}
}
