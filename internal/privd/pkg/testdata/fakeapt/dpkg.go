//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The "dpkg" mode stands in for dpkg --configure --pending (handoff N-14,
// S7-4), as measured with dpkg 1.22.22: it takes the frontend lock (or
// refuses as dpkg does when another process holds it), folds the journal
// (updates/NNNN, applied in order) into the status file, configures every
// unpacked, half-configured or trigger-waiting package, leaves half-installed
// and reinstreq ones as they are, and exits 1 when a package could not be
// configured. SIGINT is ignored while it "runs a maintainer script" (the
// slow part), as dpkg ignores it in maintscript_exec. Invented packages.

type dpkgDef struct {
	DpkgDir string `json:"dpkg_dir"`
	// Fail are packages left half-configured (exit 1).
	Fail []string `json:"fail,omitempty"`
	// Noop changes nothing and exits 0.
	Noop bool `json:"noop,omitempty"`
	// Bump upgrades this package to Version 9.9 (a change no recovery makes).
	Bump string `json:"bump,omitempty"`
	// SlowMS sleeps this long first, as a maintainer script; HalfFirst marks
	// the first configurable package half-configured before (in the
	// journal); IgnoreTerm ignores SIGTERM too.
	SlowMS     int  `json:"slow_ms,omitempty"`
	HalfFirst  bool `json:"half_first,omitempty"`
	IgnoreTerm bool `json:"ignore_term,omitempty"`
	// Signals records every SIGINT and SIGTERM this process gets in this
	// file.
	Signals string `json:"signals,omitempty"`
	// Child starts a process in its process group that records its signals.
	Child string `json:"child,omitempty"`
	// LockRuns refuses the first N runs with dpkg's lock message.
	LockRuns int `json:"lock_runs,omitempty"`
}

var configurable = []string{"unpacked", "half-configured", "triggers-awaited", "triggers-pending"}

func dpkgRun(args []string) int {
	if !slices.Equal(args, []string{"--force-confold", "--configure", "--pending"}) {
		fmt.Fprintf(os.Stderr, "fake dpkg: unexpected arguments %q\n", args)
		return 2
	}
	b, err := os.ReadFile(logPath + ".model.json") //nolint:gosec // G304: test control file
	var m dpkgDef
	if err != nil || json.Unmarshal(b, &m) != nil {
		fmt.Fprintln(os.Stderr, "fake dpkg: no model")
		return 2
	}
	c, _ := os.ReadFile(logPath + ".count") //nolint:gosec // G304: test control file
	k, _ := strconv.Atoi(strings.TrimSpace(string(c)))
	_ = os.WriteFile(logPath+".count", []byte(strconv.Itoa(k+1)), 0o600)
	lock := filepath.Join(m.DpkgDir, "lock-frontend")
	f, err := os.OpenFile(lock, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: test fixture
	if err != nil {
		return 2
	}
	defer func() { _ = f.Close() }()
	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0}
	if k < m.LockRuns || unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lk) != nil {
		fmt.Fprintln(os.Stderr, "dpkg: error: dpkg frontend lock was locked by /usr/bin/dpkg process with pid 4343")
		fmt.Fprintln(os.Stderr, "Note: removing the lock file is always wrong, can damage the locked area")
		return 2
	}
	if m.Noop {
		return 0
	}
	if m.Signals != "" {
		ch := make(chan os.Signal, 8)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			for s := range ch {
				record(m.Signals, s.String())
				if s == syscall.SIGTERM && !m.IgnoreTerm {
					os.Exit(143)
				}
			}
		}()
	} else {
		signal.Ignore(syscall.SIGINT)
		if m.IgnoreTerm {
			signal.Ignore(syscall.SIGTERM)
		}
	}
	if m.Child != "" {
		self, _ := os.Executable()
		cmd := exec.Command(self) //nolint:gosec // G204: this test binary itself, as the recording child
		cmd.Env = []string{"FAKEAPT_CHILD=" + m.Child}
		_ = cmd.Start()
	}
	st := foldJournal(m.DpkgDir, readStatus(m.DpkgDir))
	if m.HalfFirst {
		for _, p := range st {
			if slices.Contains(configurable, stateWord(p.status)) && !strings.Contains(p.status, "reinstreq") {
				p.status = "install ok half-configured"
				writeJournal(m.DpkgDir, "0000", p)
				break
			}
		}
	}
	if m.SlowMS > 0 {
		time.Sleep(time.Duration(m.SlowMS) * time.Millisecond)
	}
	failed := false
	for i, p := range st {
		switch {
		case !slices.Contains(configurable, stateWord(p.status)) || strings.Contains(p.status, "reinstreq"):
		case slices.Contains(m.Fail, p.name):
			st[i].status = "install ok half-configured"
			fmt.Fprintf(os.Stderr, "dpkg: error processing package %s (--configure):\n installed %s package post-installation script subprocess returned error exit status 1\n", p.name, p.name)
			failed = true
		default:
			st[i].status = "install ok installed"
			fmt.Printf("Setting up %s (%s) ...\n", p.name, p.version)
		}
		if p.name == m.Bump {
			st[i].version = "9.9"
		}
	}
	writeStatus(m.DpkgDir, st)
	ents, _ := os.ReadDir(filepath.Join(m.DpkgDir, "updates"))
	for _, e := range ents {
		_ = os.Remove(filepath.Join(m.DpkgDir, "updates", e.Name()))
	}
	if failed {
		return 1
	}
	return 0
}

func stateWord(status string) string { return status[strings.LastIndex(status, " ")+1:] }

func record(path, what string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: test fixture
	if err == nil {
		_, _ = fmt.Fprintln(f, what)
		_ = f.Close()
	}
}

// foldJournal applies the journal's records (all-digit names, in order)
// over the status, as dpkg does when it opens its database for writing.
func foldJournal(dir string, st []installed) []installed {
	ents, _ := os.ReadDir(filepath.Join(dir, "updates"))
	for _, e := range ents {
		if strings.Trim(e.Name(), "0123456789") != "" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "updates", e.Name())) //nolint:gosec // G304: test fixture
		if err != nil {
			continue
		}
		for _, p := range parseStanzas(string(b)) {
			if i := slices.IndexFunc(st, func(q installed) bool { return q.name == p.name }); i >= 0 {
				st[i] = p
			} else {
				st = append(st, p)
			}
		}
	}
	return st
}

func writeJournal(dir, name string, p installed) {
	rec := fmt.Sprintf("Package: %s\nStatus: %s\nArchitecture: %s\nVersion: %s\n", p.name, p.status, p.arch, p.version)
	if p.depends != "" {
		rec += "Depends: " + p.depends + "\n"
	}
	_ = os.WriteFile(filepath.Join(dir, "updates", name), []byte(rec), 0o644) //nolint:gosec // G306: dpkg's journal is world-readable
}
