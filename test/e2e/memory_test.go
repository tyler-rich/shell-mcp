//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
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
	if d.ExitCode == nil || *d.ExitCode == 0 || !goOOM(d.Stderr) {
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
	// /etc/example-app: a closed root-owned read root (the runner's /var/log
	// is group-writable, which the helper's chain rule refuses).
	big := "/etc/example-app/e2e-memory.json"
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
	sliceBefore := sliceMemoryEvents()
	stop, snaps := make(chan struct{}), make(chan map[string]cgroupSnap, 1)
	go pollInstanceCgroups(stop, snaps)
	r, id := gate(t, svcShell, "priv_exec", map[string]any{"command_id": "probe-mem", "args": []string{"alloc-tree", "2", "300", "1000"}})
	close(stop) // one last read right after the answer, then the poller returns
	last := <-snaps
	var d memExecData
	if !r.OK || json.Unmarshal(r.Data, &d) != nil {
		t.Fatalf("a tree past MemoryMax=: %s %+v\n%s", r.code(), r.Error, oomDiagnostic(t, id, start, sliceBefore, last))
	}
	if d.Signal == nil || *d.Signal != "SIGKILL" || strings.Contains(d.Stdout, "not stopped") {
		t.Fatalf("a tree past MemoryMax=: exit %v signal %v stdout %q stderr %q; this host's swap: %s\n%s",
			deref(d.ExitCode), deref(d.Signal), d.Stdout, firstLine(d.Stderr), swapTotal(t), oomDiagnostic(t, id, start, sliceBefore, last))
	}
	if el := time.Since(start); el > 25*time.Second {
		t.Fatalf("took %v", el)
	}
	// The helper and its socket still serve.
	if out := privExec(t, "probe-echo", "", "echo", "after-oom"); out != "after-oom" {
		t.Fatalf("after the OOM kill: %q", out)
	}
}

// TestPrivOOMDetachedSurvivorEnded: a command that first starts a
// grandchild in a session of its own (setsid, ignoring SIGTERM, outside
// the command's process group, so the group kill does not reach it) and
// then grows a child tree past the unit's MemoryMax= is OOM-killed; the
// grandchild, reparented to the helper (its child subreaper), is killed
// and reaped before the answer, which is the command's signal. In the core
// unit the memory pressure can reclaim the dentry of the helper's own
// /proc/<pid>, after which /proc/self reaches a new procfs inode that the
// Landlock rule does not cover and every read through the path is EACCES:
// the helper lists its children through the descriptor it opened before
// the sandbox (PRIVILEGED §6, S7-5). The broad unit has no Landlock; the
// same case there guards the reap.
func TestPrivOOMDetachedSurvivorEnded(t *testing.T) {
	for _, c := range []struct{ unit, command, linger string }{
		{"core", "probe-mem", "66s"},
		{"broad", "probe-broad-mem", "67s"},
	} {
		t.Run(c.unit, func(t *testing.T) {
			// The grandchild, seen while the request runs (a goroutine may
			// not fail the test).
			stop, seen := make(chan struct{}), make(chan gatetest.Proc, 1)
			go func() {
				for {
					if p, ok, err := gatetest.LookupChild(0, "linger", c.linger); err == nil && ok {
						seen <- p
						return
					}
					select {
					case <-stop:
						return
					case <-time.After(5 * time.Millisecond):
					}
				}
			}()
			a := map[string]any{"command_id": c.command, "args": []string{"alloc-tree-detach", c.linger, "2", "300", "1000"}}
			if c.unit == "broad" {
				a["unit"] = "broad"
			}
			start := time.Now()
			r, id := gate(t, svcShell, "priv_exec", a)
			close(stop)
			var g gatetest.Proc
			select {
			case g = <-seen:
				t.Cleanup(g.Kill)
			default:
				t.Fatalf("the grandchild was never seen; answer %s %+v", r.code(), r.Error)
			}
			line := helperLineOf(id)
			if !r.OK {
				t.Fatalf("a setsid grandchild after the OOM kill: %s %+v (grandchild reaped: %v)\nhelper: %s",
					r.code(), r.Error, g.Reaped(), line)
			}
			var d memExecData
			if json.Unmarshal(r.Data, &d) != nil || d.Signal == nil || *d.Signal != "SIGKILL" {
				t.Fatalf("not the OOM kill: %s; this host's swap: %s\nhelper: %s", r.Data, swapTotal(t), line)
			}
			if !g.Reaped() {
				t.Fatalf("the helper answered while its grandchild %d was still there\nhelper: %s", g.Pid, line)
			}
			if strings.Contains(line, "reap_error") {
				t.Fatalf("the journal line carries reap_error: %s", line)
			}
			if el := time.Since(start); el > 25*time.Second {
				t.Fatalf("took %v", el)
			}
		})
	}
}

// helperLineOf is the helper's journal line for request id, waiting up to
// 10 s for it ("" when there is none).
func helperLineOf(id string) string {
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if l, ok := findLine(id); ok {
			return l
		}
	}
	return ""
}

// deref is *p for messages, or "<nil>".
func deref[T any](p *T) any {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// swapTotal is /proc/meminfo's SwapTotal line: with swap, a cgroup past
// MemoryMax= is pushed into swap rather than OOM-killed.
func swapTotal(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return err.Error()
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "SwapTotal:") {
			return strings.Join(strings.Fields(l), " ")
		}
	}
	return "no SwapTotal line"
}

// The OOM diagnostic (test only): what TestPrivCoreOOMPolicyContinue
// prints when it fails, to find why the helper's reap of the command's
// leftover processes failed after the OOM kill.

// cgroupRoot holds the helper instances' cgroups: systemd places every
// instance of a template unit under system-<escaped prefix>.slice.
const cgroupRoot = "/sys/fs/cgroup/system.slice"

// cgroupMemoryFiles are the memory controller files read from an instance
// and from the instances' slice.
var cgroupMemoryFiles = []string{"memory.events", "memory.current", "memory.peak", "memory.swap.events", "memory.max", "memory.swap.max"}

// cgroupSnap is one read of a cgroup's memory files, and when.
type cgroupSnap struct {
	at    time.Time
	files map[string]string
}

// helperSlices are the cgroup directories of the helper instances' slices.
func helperSlices() []string {
	ents, err := os.ReadDir(cgroupRoot)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "system-shell") && strings.HasSuffix(e.Name(), ".slice") {
			out = append(out, cgroupRoot+"/"+e.Name())
		}
	}
	return out
}

// readCgroup reads dir's memory files ("" for one it cannot read).
func readCgroup(dir string) map[string]string {
	m := map[string]string{}
	for _, f := range cgroupMemoryFiles {
		b, err := os.ReadFile(dir + "/" + f) //nolint:gosec // G304: the runner's own cgroup files
		if err != nil {
			m[f] = "(" + err.Error() + ")"
			continue
		}
		m[f] = strings.Join(strings.Fields(string(b)), " ")
	}
	return m
}

// sliceMemoryEvents reads every helper slice's memory files (memory.events
// in a parent is hierarchical: it counts its instances' events).
func sliceMemoryEvents() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, s := range helperSlices() {
		out[s] = readCgroup(s)
	}
	return out
}

// pollInstanceCgroups reads every helper instance cgroup's memory files
// every 10 ms, keeping the last read of each (an instance's cgroup goes
// away when it is collected, soon after it answers); once stop is closed
// it reads once more and sends what it kept.
func pollInstanceCgroups(stop <-chan struct{}, out chan<- map[string]cgroupSnap) {
	kept := map[string]cgroupSnap{}
	read := func() {
		for _, s := range helperSlices() {
			ents, err := os.ReadDir(s)
			if err != nil {
				continue
			}
			for _, e := range ents {
				if e.IsDir() && strings.HasSuffix(e.Name(), ".service") {
					kept[s+"/"+e.Name()] = cgroupSnap{at: time.Now(), files: readCgroup(s + "/" + e.Name())}
				}
			}
		}
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			read()
			out <- kept
			return
		case <-tick.C:
			read()
		}
	}
}

// oomKillRE matches the kernel's OOM kill lines, for the victim's pid and
// name: "Killed process <pid> (<name>)" and "oom-kill:…,task=<name>,pid=<pid>".
var oomKillRE = []*regexp.Regexp{
	regexp.MustCompile(`Killed process (\d+) \(([^)]*)\)`),
	regexp.MustCompile(`oom-kill:.*task=([^,]*),pid=(\d+)`),
}

// oomDiagnostic describes the request id's OOM case: the helper's journal
// line for it and its other lines, the kernel log since start, the OOM
// victim, the instance cgroup's last memory files, the slices' memory files
// before and after, and whether the helper itself met an allocation failure.
func oomDiagnostic(t *testing.T, id string, start time.Time, sliceBefore map[string]map[string]string, last map[string]cgroupSnap) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("---- OOM diagnostic (request " + id + ")\n")
	// The helper's line for the request, and every line of its process.
	var line journalEntry
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && line.Message == ""; time.Sleep(200 * time.Millisecond) {
		for _, e := range journal(t, "shell-mcp-privd", start) {
			if strings.Contains(e.Message, id) {
				line = e
			}
		}
	}
	helperPID := line.PID
	fmt.Fprintf(&b, "helper journal line (pid %s, unit %s, priority %s):\n  %s\n", line.PID, line.Unit, line.Priority, line.Message)
	if helperPID != "" {
		for _, e := range journal(t, "shell-mcp-privd", start) {
			if e.PID == helperPID && e.Message != line.Message {
				fmt.Fprintf(&b, "  other helper line: %s\n", e.Message)
			}
		}
	}
	// The kernel log for the window.
	kout, err := exec.CommandContext(t.Context(), "journalctl", "-k", "--no-pager", "-o", "short-monotonic", //nolint:gosec // G204: fixed test command
		"--since", "@"+strconv.FormatInt(start.Unix()-1, 10)).CombinedOutput()
	if err != nil {
		fmt.Fprintf(&b, "journalctl -k: %v\n", err)
	}
	var victims, helperAlloc []string
	b.WriteString("kernel log (memory and OOM lines):\n")
	for _, l := range strings.Split(string(kout), "\n") {
		low := strings.ToLower(l)
		if !strings.Contains(low, "oom") && !strings.Contains(low, "memory") && !strings.Contains(low, "killed process") &&
			!strings.Contains(low, "allocation failure") && !strings.Contains(low, "shell-mcp") {
			continue
		}
		b.WriteString("  " + l + "\n")
		for _, re := range oomKillRE {
			if m := re.FindStringSubmatch(l); m != nil {
				victims = append(victims, strings.Join(m[1:], " "))
			}
		}
		if (strings.Contains(low, "allocation failure") || strings.Contains(low, "invoked oom-killer")) &&
			(strings.Contains(l, "shell-mcp-privd") || (helperPID != "" && strings.Contains(l, "pid="+helperPID))) {
			helperAlloc = append(helperAlloc, l)
		}
	}
	fmt.Fprintf(&b, "OOM victims (pid name / name pid): %q\n", victims)
	fmt.Fprintf(&b, "helper allocation failures in the kernel log: %q; in its journal line: %v\n", helperAlloc,
		strings.Contains(line.Message, "cannot allocate") || strings.Contains(line.Message, "ENOMEM") || strings.Contains(line.Message, "out of memory"))
	// The instance's cgroup as last read, and the slices before and after.
	for dir, s := range last {
		fmt.Fprintf(&b, "instance cgroup %s (read %v after the request started):\n", dir, s.at.Sub(start).Round(time.Millisecond))
		for _, f := range cgroupMemoryFiles {
			fmt.Fprintf(&b, "  %s: %s\n", f, s.files[f])
		}
	}
	if len(last) == 0 {
		b.WriteString("no instance cgroup was seen under " + cgroupRoot + "\n")
	}
	for s, after := range sliceMemoryEvents() {
		fmt.Fprintf(&b, "slice %s:\n  memory.events before: %s\n  memory.events after:  %s\n  memory.swap.events after: %s\n",
			s, sliceBefore[s]["memory.events"], after["memory.events"], after["memory.swap.events"])
	}
	return b.String()
}

// goOOM reports a Go program's fatal error at its memory limit: "out of
// memory" when the heap cannot grow, "cannot allocate memory" when the
// runtime's own metadata cannot (where the limit is met decides which).
func goOOM(stderr string) bool {
	return strings.Contains(stderr, "fatal error: runtime: out of memory") || strings.Contains(stderr, "fatal error: out of memory") ||
		strings.Contains(stderr, "fatal error: runtime: cannot allocate memory")
}
