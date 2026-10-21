//go:build linux

// Command applier is a sandbox test program, built CGO_ENABLED=0 by the
// sandbox tests (Landlock cannot be undone, so it never runs in the test
// process). It loads a policy without commands, optionally pins goroutines
// to their own OS threads, applies the sandbox, optionally pins more
// goroutines to OS threads started after it, and then checks each probe
// from every pinned thread. It prints one JSON object. Never shipped.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
)

type threadResult struct {
	TID        int    `json:"tid"`
	NoNewPrivs string `json:"no_new_privs"`
	Seccomp    string `json:"seccomp"`
	Filters    string `json:"seccomp_filters"`
	Read       string `json:"read"`
}

type output struct {
	FiltersBefore string `json:"seccomp_filters_before"`
	CGO           string `json:"cgo"`
	// ThreadPath is the all-thread path this binary's sandbox takes.
	ThreadPath string         `json:"thread_path"`
	Report     sandbox.Report `json:"report"`
	Error      string         `json:"error,omitempty"`
	Threads    []threadResult `json:"threads"`
	// TIDsBefore lists the process's threads just before Apply;
	// ThreadsAfter are the threads pinned after it.
	TIDsBefore   []int             `json:"tids_before"`
	ThreadsAfter []threadResult    `json:"threads_after"`
	Probes       map[string]string `json:"probes"`
}

func main() {
	pol := flag.String("policy", "", "policy file")
	threads := flag.Int("threads", 0, "goroutines pinned to their own OS threads before Apply")
	threadsAfter := flag.Int("threads-after", 0, "goroutines pinned to their own OS threads after Apply")
	readPath := flag.String("read", "", "path each thread tries to read after Apply")
	allowed := flag.String("allowed", "", "path that must stay readable after Apply")
	connect := flag.Int("connect", 0, "TCP port to connect to on 127.0.0.1")
	bind := flag.Bool("bind", false, "try a TCP bind")
	signalPID := flag.Int("signal", 0, "pid to send SIGTERM")
	mptcp := flag.Bool("mptcp", false, "try a raw socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)")
	flag.Parse()

	out := output{Probes: map[string]string{}, CGO: "unknown", ThreadPath: sandbox.ThreadPath()}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "CGO_ENABLED" {
				out.CGO = s.Value
			}
		}
	}
	data, err := os.ReadFile(*pol)
	if err != nil {
		fail(&out, err)
	}
	self, _ := os.Executable()
	p, err := policy.Parse(data, *pol, &policy.LoadOptions{Trust: policy.RootTrust(), GateExecutable: self, ServiceHome: "/nonexistent-home"})
	if err != nil {
		fail(&out, err)
	}

	// Pin goroutines to distinct OS threads before the sandbox exists.
	before := pin(*threads, *readPath)

	out.FiltersBefore = statusField("Seccomp_filters")
	out.TIDsBefore = taskIDs()
	out.Report, err = sandbox.Apply(p)
	if err != nil {
		out.Error = err.Error()
		emit(out)
		os.Exit(0)
	}
	// And more after it: the runtime starts new OS threads for them once
	// its idle ones are taken.
	after := pin(*threadsAfter, *readPath)
	out.Threads = probe(before)
	out.ThreadsAfter = probe(after)
	if *readPath != "" {
		_, err := os.ReadFile(*readPath)
		out.Probes["read"] = result(err, "READ")
	}
	if *allowed != "" {
		_, err := os.ReadFile(*allowed)
		out.Probes["allowed"] = result(err, "READ")
	}
	if *connect != 0 {
		c, err := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(*connect), 2*time.Second)
		if err == nil {
			_ = c.Close()
		}
		out.Probes["connect"] = result(err, "CONNECTED")
	}
	if *bind {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err == nil {
			_ = l.Close()
		}
		out.Probes["bind"] = result(err, "BOUND")
	}
	if *mptcp {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP)
		if err == nil {
			_ = unix.Close(fd)
		}
		out.Probes["mptcp"] = result(err, "OPENED")
	}
	if *signalPID != 0 {
		out.Probes["signal"] = result(syscall.Kill(*signalPID, syscall.SIGTERM), "SIGNALLED")
	}
	emit(out)
}

type req struct{ reply chan threadResult }

// pin starts n goroutines, each locked to its own OS thread for the rest of
// the run, and returns their request channels.
func pin(n int, readPath string) []chan req {
	var workers []chan req
	for i := 0; i < n; i++ {
		ch := make(chan req)
		ready := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			close(ready)
			r := <-ch
			res := threadResult{TID: unix.Gettid(), NoNewPrivs: statusField("NoNewPrivs"), Seccomp: statusField("Seccomp"), Filters: statusField("Seccomp_filters")}
			if readPath != "" {
				_, err := os.ReadFile(readPath)
				res.Read = result(err, "READ")
			}
			r.reply <- res
			select {} // keep the thread locked and alive
		}()
		<-ready
		workers = append(workers, ch)
	}
	return workers
}

// probe asks every pinned goroutine for its thread's result.
func probe(workers []chan req) []threadResult {
	var res []threadResult
	for _, ch := range workers {
		r := req{reply: make(chan threadResult)}
		ch <- r
		res = append(res, <-r.reply)
	}
	return res
}

// taskIDs lists the process's threads.
func taskIDs() []int {
	ents, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil
	}
	var ids []int
	for _, e := range ents {
		if id, err := strconv.Atoi(e.Name()); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

func fail(o *output, err error) {
	o.Error = err.Error()
	emit(*o)
	os.Exit(1)
}

func emit(o output) {
	b, _ := json.Marshal(o)
	fmt.Println(string(b))
}

func result(err error, ok string) string {
	if err == nil {
		return ok
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return unix.ErrnoName(errno)
	}
	return "ERR: " + err.Error()
}

func statusField(name string) string {
	b, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return "ERR"
	}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && k == name {
			return strings.TrimSpace(v)
		}
	}
	return "MISSING"
}
