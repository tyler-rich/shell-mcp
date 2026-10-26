//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The child memory limit, end to end (handoff N-30, N-25's memory half):
// the real gate as the service account under the hardening policy, and the
// real helper in its generated core unit, both at the default
// limits.max_memory_mb (1024 MiB; the e2e policies leave it out). The
// fixtures are benign and sparse (1 GiB that takes no disk space): a loose
// ref in a gitlink's .git that example-app owns, and a JSON file. Without
// the limit, git reads the whole ref into memory and answers ok, and jq
// reads the whole file and reports a parse error at its end; with it, both
// fail at the limit within seconds. Every path and name is invented.

// defaultData is the probe's "rlimits" line at the default limit.
var defaultData = fmt.Sprintf("data=%d/%d", 1024<<20, 1024<<20)

type memExecData struct {
	ExitCode *int    `json:"exit_code"`
	Signal   *string `json:"signal"`
	Stdout   string  `json:"stdout"`
	Stderr   string  `json:"stderr"`
}

// execDataOf decodes an exec or priv_exec answer that ran.
func execDataOf(t *testing.T, r *response) memExecData {
	t.Helper()
	var d memExecData
	if !r.OK || json.Unmarshal(r.Data, &d) != nil {
		t.Fatalf("not run: %+v %s", r.Error, r.Data)
	}
	return d
}

// sparseFile makes p an empty file of size bytes owned by uid (no disk
// space used) and removes it when the test ends.
func sparseFile(t *testing.T, p string, uid int, size int64) {
	t.Helper()
	ownFile(t, p, "", uid, 0o644)
	if err := os.Truncate(p, size); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(p) })
}

// TestGateChildMemoryLimit: a declared command runs with RLIMIT_DATA at
// the default, soft and hard; its child gets the same; it cannot raise it;
// an allocation past it fails at once and is reported as its own exit.
func TestGateChildMemoryLimit(t *testing.T) {
	for _, args := range [][]string{{"rlimits"}, {"child-rlimits"}} {
		_, r := hardExec(t, "probe-mem", args, "")
		if out := stdoutOf(t, &r); !strings.Contains(out, defaultData) {
			t.Fatalf("%v: %q, want %s", args, out, defaultData)
		}
	}
	_, r := hardExec(t, "probe-mem", []string{"raise-data"}, "")
	if out := strings.TrimSpace(stdoutOf(t, &r)); out != "raise=EPERM unlimited=EPERM" {
		t.Fatalf("raise-data as the service account: %q", out)
	}
	start := time.Now()
	_, r = hardExec(t, "probe-mem", []string{"alloc", "2048"}, "")
	d := execDataOf(t, &r)
	if d.ExitCode == nil || *d.ExitCode == 0 || !strings.Contains(d.Stderr, "out of memory") {
		t.Fatalf("2048 MiB under the default: %+v", d)
	}
	if el := time.Since(start); el > 20*time.Second {
		t.Fatalf("took %v", el)
	}
}

// TestGateGitGitlinkSparseRef (N-25's memory half): example-app's gitlink
// HEAD names a 1 GiB sparse loose ref; git_status answers exec_failed,
// naming the limit, within seconds.
func TestGateGitGitlinkSparseRef(t *testing.T) {
	gitlinkRepo(t)
	gitdir := subLib + "/.git"
	ownFile(t, gitdir+"/HEAD", "ref: refs/heads/x\n", exampleApp, 0o644)
	sparseFile(t, gitdir+"/refs/heads/x", exampleApp, 1<<30)
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes(subLib, old, old); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r := hard(t, "git_status", map[string]any{"repo": hardRepo})
	if r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "limits.max_memory_mb (1024 MiB)") {
		t.Fatalf("git_status with a 1 GiB sparse ref in example-app's gitlink: %s %+v %s", r.code(), r.Error, r.Data)
	}
	if el := time.Since(start); el > 20*time.Second {
		t.Fatalf("took %v", el)
	}
}

// TestGateJqSparseRead (N-30): jq given an owner-matched {path:read} that
// example-app made a 1 GiB sparse file fails at the limit ("cannot allocate
// memory") instead of reading it all.
func TestGateJqSparseRead(t *testing.T) {
	app := hardRoot + "/memapp"
	ownDir(t, app, exampleApp, exampleApp, 0o755)
	sparseFile(t, app+"/compose.json", exampleApp, 1<<30)
	start := time.Now()
	pr, r := hardExec(t, "jq-keys", []string{"-c", "keys", app + "/compose.json"}, "")
	if !pr.OK {
		t.Fatalf("preview: %+v", pr.Error)
	}
	d := execDataOf(t, &r)
	if !strings.Contains(d.Stderr, "cannot allocate memory") || strings.Contains(d.Stderr, "parse error") {
		t.Fatalf("jq on a 1 GiB sparse file: %+v", d)
	}
	if el := time.Since(start); el > 30*time.Second {
		t.Fatalf("took %v", el)
	}
}

// privExecData runs a read-tier root command in the core unit.
func privExecData(t *testing.T, command string, args ...string) memExecData {
	t.Helper()
	r, _ := gate(t, svcShell, "priv_exec", map[string]any{"command_id": command, "args": args})
	return execDataOf(t, &r)
}

// TestPrivCoreMemoryLimit: in the core unit a root command runs with the
// default limit, passes it on and cannot raise it (the unit's bounding set
// has no CAP_SYS_RESOURCE), and jq on a large root-owned file fails at the
// limit instead of reaching the unit's MemoryMax=.
func TestPrivCoreMemoryLimit(t *testing.T) {
	for _, a := range []string{"rlimits", "child-rlimits"} {
		if d := privExecData(t, "probe-mem", a); !strings.Contains(d.Stdout, defaultData) {
			t.Fatalf("%s as root in the core unit: %q, want %s", a, d.Stdout, defaultData)
		}
	}
	if d := privExecData(t, "probe-mem", "raise-data"); strings.TrimSpace(d.Stdout) != "raise=EPERM unlimited=EPERM" {
		t.Fatalf("raise-data as root in the core unit: %q", d.Stdout)
	}
	big := "/var/log/example-app/e2e-memory.json"
	sparseFile(t, big, 0, 1<<30)
	d := privExecData(t, "jq-keys", "-c", "keys", big)
	if !strings.Contains(d.Stderr, "cannot allocate memory") || strings.Contains(d.Stderr, "parse error") {
		t.Fatalf("jq as root on a 1 GiB sparse file: %+v", d)
	}
}

// TestPrivCoreOOMPolicyContinue: a command whose child tree reaches the core
// unit's MemoryMax= (two children of 300 MiB, then the command itself past
// them; each under its own 1024 MiB limit) has the command killed by the
// cgroup's OOM killer; under OOMPolicy=continue the instance keeps running,
// so the helper ends what is left and answers with the signal.
func TestPrivCoreOOMPolicyContinue(t *testing.T) {
	start := time.Now()
	d := privExecData(t, "probe-mem", "alloc-tree", "2", "300", "1000")
	if d.Signal == nil || *d.Signal != "SIGKILL" || strings.Contains(d.Stdout, "not stopped") {
		t.Fatalf("a tree past MemoryMax=: %+v", d)
	}
	if el := time.Since(start); el > 25*time.Second {
		t.Fatalf("took %v", el)
	}
	// The helper and its socket still serve.
	if out := privExec(t, "probe-echo", "", "echo", "after-oom"); out != "after-oom" {
		t.Fatalf("after the OOM kill: %q", out)
	}
}
