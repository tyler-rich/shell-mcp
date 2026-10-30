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

// The model: an invented repository (the last entry of a name is its
// candidate) and a dpkg status file under the helper's dpkg directory. A
// simulation prints apt's change lines for the transaction it resolves; a
// real run takes the dpkg frontend lock (or refuses as apt does when
// another process holds it) and writes the transaction into the status
// file, as the run section of the model says.

type pkgDef struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Depends []string `json:"depends,omitempty"`
	// Conflicts are removed when this package is installed.
	Conflicts []string `json:"conflicts,omitempty"`
}

type runDef struct {
	// Extra are packages the real run installs beyond its transaction.
	Extra []pkgDef `json:"extra,omitempty"`
	// Partial applies only the first N changes (0: all).
	Partial int `json:"partial,omitempty"`
	// Unfinished leaves this package half-configured.
	Unfinished string `json:"unfinished,omitempty"`
	// SlowMS sleeps this long before applying the transaction; OnInt says
	// what SIGINT does meanwhile: "partial" applies the first change and
	// exits 0 with apt's warning (apt's own stop), "ignore" ignores it.
	SlowMS int    `json:"slow_ms,omitempty"`
	OnInt  string `json:"on_int,omitempty"`
	// IgnoreTerm ignores SIGTERM while sleeping (only SIGKILL ends it).
	IgnoreTerm bool `json:"ignore_term,omitempty"`
	// UnfinishedFirst marks the first package half-configured before the
	// sleep, as dpkg does once it started configuring it.
	UnfinishedFirst bool `json:"unfinished_first,omitempty"`
	// Child starts a process in the run's process group that records the
	// signals it gets in this file (dpkg and maintainer scripts).
	Child string `json:"child,omitempty"`
	// Fail exits 100 with apt's download error and changes nothing.
	Fail bool `json:"fail,omitempty"`
	// Exit is the exit code after a run that changed the status (default 0).
	Exit int `json:"exit,omitempty"`
	// Stdout is printed first; Flood prints 1 MiB of it.
	Stdout string `json:"stdout,omitempty"`
	Flood  bool   `json:"flood,omitempty"`
}

type modelDef struct {
	DpkgDir string   `json:"dpkg_dir"`
	Repo    []pkgDef `json:"repo"`
	// SwapAfter replaces Repo with SwapRepo once that many runs have ended.
	SwapAfter int      `json:"swap_after,omitempty"`
	SwapRepo  []pkgDef `json:"swap_repo,omitempty"`
	Run       runDef   `json:"run"`
}

type installed struct {
	name, arch, version, status string
	// depends is kept as it is (the fake dpkg's dependency fixtures).
	depends string
}

type change struct {
	kind, name, from, to string // kind: inst, upg, remv
}

func modelPath() string { return logPath + ".model.json" }

func loadModel() modelDef {
	var m modelDef
	b, err := os.ReadFile(modelPath())
	if err != nil || json.Unmarshal(b, &m) != nil {
		fmt.Fprintln(os.Stderr, "fakeapt: no model")
		os.Exit(2)
	}
	return m
}

func model(args []string) int {
	m := loadModel()
	defer countRun(m)
	var op string
	var names []string
	simulate, onlyUpgrade, noRemove, reinstall := false, false, false, false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			names = args[i+1:]
			i = len(args)
		case a == "-o":
			i++
		case a == "-s":
			simulate = true
		case a == "--only-upgrade":
			onlyUpgrade = true
		case a == "--no-remove":
			noRemove = true
		case a == "--reinstall":
			reinstall = true
		case strings.HasPrefix(a, "-"):
		case op == "":
			op = a
		}
	}
	if op == "update" {
		fmt.Println("Reading package lists...")
		return 0
	}
	st := readStatus(m.DpkgDir)
	// apt refuses everything, simulations too, while a package that needs
	// a reinstall has no archive of its version (apt 3.0.3 and 3.2.0,
	// measured in S7-7).
	for _, p := range st {
		if strings.HasPrefix(p.status, "install reinstreq ") && !slices.ContainsFunc(m.Repo, func(r pkgDef) bool { return r.Name == p.name && r.Version == p.version }) {
			fmt.Fprintf(os.Stderr, "E: The package %s needs to be reinstalled, but I can't find an archive for it.\n", p.name)
			return 100
		}
	}
	changes, code := resolve(m, st, op, names, onlyUpgrade, reinstall)
	if code != 0 {
		return code
	}
	if noRemove && slices.ContainsFunc(changes, func(c change) bool { return c.kind == "remv" }) {
		fmt.Fprintln(os.Stderr, "E: Packages need to be removed but remove is disabled.")
		return 100
	}
	if simulate {
		fmt.Println("Reading package lists...")
		for _, c := range changes {
			switch c.kind {
			case "inst":
				fmt.Printf("Inst %s (%s Invented:1.0/stable [all])\n", c.name, c.to)
			case "upg", "reinst":
				fmt.Printf("Inst %s [%s] (%s Invented:1.0/stable [all])\n", c.name, c.from, c.to)
			case "remv":
				fmt.Printf("Remv %s [%s]\n", c.name, c.from)
			}
		}
		for _, c := range changes {
			if c.kind != "remv" {
				fmt.Printf("Conf %s (%s Invented:1.0/stable [all])\n", c.name, c.to)
			}
		}
		return 0
	}
	return realRun(m, st, changes)
}

// resolve computes the transaction apt would run: requested names (or
// name=version) with their missing dependencies, a reinstall of a package
// on the system at the pinned version (--reinstall), an upgrade of
// everything whose candidate differs, or a removal of packages on the
// system in any state but not-installed and config-files.
func resolve(m modelDef, st []installed, op string, names []string, onlyUpgrade, reinstall bool) ([]change, int) {
	cur := map[string]string{}
	onSystem := map[string]string{}
	for _, p := range st {
		if p.status == "install ok installed" {
			cur[p.name] = p.version
		}
		if s := stateWord(p.status); s != "not-installed" && s != "config-files" {
			onSystem[p.name] = p.version
		}
	}
	cand := map[string]pkgDef{}
	for _, p := range m.Repo {
		cand[p.Name] = p
	}
	var out []change
	seen := map[string]bool{}
	var add func(p pkgDef)
	add = func(p pkgDef) {
		if seen[p.Name] {
			return
		}
		seen[p.Name] = true
		for _, d := range p.Depends {
			if _, ok := cur[d]; ok {
				continue
			}
			if dp, ok := cand[d]; ok {
				add(dp)
			}
		}
		for _, c := range p.Conflicts {
			if v, ok := cur[c]; ok && !seen[c] {
				seen[c] = true
				out = append(out, change{kind: "remv", name: c, from: v})
			}
		}
		switch v, ok := cur[p.Name]; {
		case !ok:
			out = append(out, change{kind: "inst", name: p.Name, to: p.Version})
		case v != p.Version:
			out = append(out, change{kind: "upg", name: p.Name, from: v, to: p.Version})
		}
	}
	switch op {
	case "install":
		for _, n := range names {
			name, ver, pinned := strings.Cut(n, "=")
			p, ok := cand[name]
			if pinned {
				ok = false
				for _, r := range m.Repo {
					if r.Name == name && r.Version == ver {
						p, ok = r, true
					}
				}
				if !ok {
					fmt.Fprintf(os.Stderr, "E: Version '%s' for '%s' was not found\n", ver, name)
					return nil, 100
				}
			}
			if !ok {
				fmt.Fprintf(os.Stderr, "E: Unable to locate package %s\n", name)
				return nil, 100
			}
			if _, inst := cur[name]; onlyUpgrade && !inst {
				fmt.Printf("Skipping %s, it is not installed and only upgrades are requested.\n", name)
				continue
			}
			if v, ok := onSystem[name]; reinstall && ok && v == p.Version {
				seen[name] = true
				out = append(out, change{kind: "reinst", name: name, from: v, to: v})
				continue
			}
			add(p)
		}
	case "upgrade":
		for _, p := range m.Repo {
			if v, ok := cur[p.Name]; ok && v != cand[p.Name].Version && p.Version == cand[p.Name].Version {
				add(p)
			}
		}
	case "remove":
		for _, n := range names {
			if v, ok := onSystem[n]; ok {
				out = append(out, change{kind: "remv", name: n, from: v})
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "E: Invalid operation %s\n", op)
		return nil, 100
	}
	return out, 0
}

func realRun(m modelDef, st []installed, changes []change) int {
	lock := filepath.Join(m.DpkgDir, "lock-frontend")
	f, err := os.OpenFile(lock, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: test fixture
	if err != nil {
		fmt.Fprintln(os.Stderr, "E: Could not open lock file", lock)
		return 100
	}
	defer func() { _ = f.Close() }()
	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0}
	if err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lk); err != nil {
		probe := unix.Flock_t{Type: unix.F_WRLCK}
		_ = unix.FcntlFlock(f.Fd(), unix.F_GETLK, &probe)
		lockMessage(int(probe.Pid), "apt-get")
	}
	// A real run refuses while dpkg's journal has entries (a simulation
	// does not look: measured, S4c-7 and S7-7).
	if ents, _ := os.ReadDir(filepath.Join(m.DpkgDir, "updates")); slices.ContainsFunc(ents, func(e os.DirEntry) bool { return strings.Trim(e.Name(), "0123456789") == "" }) {
		fmt.Fprintln(os.Stderr, "E: dpkg was interrupted, you must manually run 'dpkg --configure -a' to correct the problem. ")
		return 100
	}
	// dpkg refuses to remove a package that needs a reinstall (measured).
	for _, c := range changes {
		if i := slices.IndexFunc(st, func(p installed) bool { return p.name == c.name }); c.kind == "remv" && i >= 0 && strings.Contains(st[i].status, " reinstreq ") {
			fmt.Fprintf(os.Stderr, "dpkg: error processing package %s (--remove):\n package is in a very bad inconsistent state; you should\n reinstall it before attempting a removal\n", c.name)
			fmt.Fprintln(os.Stderr, "E: Sub-process /usr/bin/dpkg returned an error code (1)")
			return 100
		}
	}
	r := m.Run
	if r.Stdout != "" {
		fmt.Println(r.Stdout)
	}
	if r.Flood {
		fmt.Print(strings.Repeat("y", 1<<20))
	}
	if r.Fail {
		fmt.Fprintln(os.Stderr, "E: Failed to fetch file:/srv/invented/example-hello_1.1_all.deb  File not found")
		return 100
	}
	if r.Child != "" {
		self, _ := os.Executable()
		c := exec.Command(self) //nolint:gosec // G204: this test binary itself, as the recording child
		c.Env = []string{"FAKEAPT_CHILD=" + r.Child}
		_ = c.Start()
	}
	if r.UnfinishedFirst && len(changes) > 0 {
		writeStatus(m.DpkgDir, apply(st, changes[:1], "", changes[0].name))
	}
	if r.SlowMS > 0 {
		ints := make(chan os.Signal, 1)
		switch r.OnInt {
		case "partial":
			signal.Notify(ints, syscall.SIGINT)
		case "ignore":
			signal.Ignore(syscall.SIGINT)
		}
		if r.IgnoreTerm {
			signal.Ignore(syscall.SIGTERM)
		}
		select {
		case <-ints:
			// apt's own stop: the dpkg run in progress finishes, nothing
			// after it is unpacked or removed, and apt exits 0.
			writeStatus(m.DpkgDir, apply(st, changes[:min(1, len(changes))], "", ""))
			fmt.Fprintln(os.Stderr, "W: Operation was interrupted before it could finish")
			return 0
		case <-time.After(time.Duration(r.SlowMS) * time.Millisecond):
		}
	}
	todo := changes
	if r.Partial > 0 && r.Partial < len(todo) {
		todo = todo[:r.Partial]
	}
	for _, e := range r.Extra {
		todo = append(todo, change{kind: "inst", name: e.Name, to: e.Version})
	}
	writeStatus(m.DpkgDir, apply(st, todo, r.Unfinished, ""))
	for _, c := range todo {
		fmt.Printf("Setting up %s (%s) ...\n", c.name, c.to)
	}
	return r.Exit
}

// apply returns the status after changes; unfinished (or half) is left
// half-configured.
func apply(st []installed, changes []change, unfinished, half string) []installed {
	out := slices.Clone(st)
	for _, c := range changes {
		i := slices.IndexFunc(out, func(p installed) bool { return p.name == c.name })
		switch c.kind {
		case "inst", "upg", "reinst":
			p := installed{name: c.name, arch: "all", version: c.to, status: "install ok installed"}
			if i >= 0 {
				out[i] = p
			} else {
				out = append(out, p)
			}
		case "remv":
			if i >= 0 {
				out[i].status = "deinstall ok config-files"
			}
		}
	}
	for i := range out {
		if out[i].name == unfinished || out[i].name == half {
			out[i].status = "install ok half-configured"
		}
	}
	return out
}

func readStatus(dir string) []installed {
	b, err := os.ReadFile(filepath.Join(dir, "status")) //nolint:gosec // G304: test fixture
	if err != nil {
		fmt.Fprintln(os.Stderr, "fakeapt: no status file")
		os.Exit(2)
	}
	return parseStanzas(string(b))
}

func parseStanzas(s string) []installed {
	var out []installed
	for _, stanza := range strings.Split(strings.TrimSpace(s), "\n\n") {
		var p installed
		for _, l := range strings.Split(stanza, "\n") {
			k, v, _ := strings.Cut(l, ": ")
			switch k {
			case "Package":
				p.name = v
			case "Architecture":
				p.arch = v
			case "Version":
				p.version = v
			case "Status":
				p.status = v
			case "Depends":
				p.depends = v
			}
		}
		if p.name != "" {
			out = append(out, p)
		}
	}
	return out
}

func writeStatus(dir string, st []installed) {
	var b strings.Builder
	for _, p := range st {
		fmt.Fprintf(&b, "Package: %s\nStatus: %s\nPriority: optional\nArchitecture: %s\nVersion: %s\n", p.name, p.status, p.arch, p.version)
		if p.depends != "" {
			fmt.Fprintf(&b, "Depends: %s\n", p.depends)
		}
		b.WriteString("Description: invented\n continuation line\n\n")
	}
	tmp := filepath.Join(dir, "status-new")
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil { //nolint:gosec // G306: dpkg's status is world-readable
		os.Exit(2)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "status")); err != nil {
		os.Exit(2)
	}
}

// countRun counts the runs and swaps the repository after SwapAfter.
func countRun(m modelDef) {
	c, _ := os.ReadFile(logPath + ".count") //nolint:gosec // G304: test control file
	k, _ := strconv.Atoi(strings.TrimSpace(string(c)))
	k++
	_ = os.WriteFile(logPath+".count", []byte(strconv.Itoa(k)), 0o600)
	if m.SwapAfter > 0 && k == m.SwapAfter {
		m.Repo, m.SwapAfter = m.SwapRepo, 0
		b, _ := json.Marshal(m)
		_ = os.WriteFile(modelPath(), b, 0o600)
	}
}

// holdLock takes the dpkg frontend lock on path, says so on stdout, and
// keeps it until stdin closes (a process holding the lock for a test).
func holdLock(path string) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: test fixture
	if err != nil {
		os.Exit(2)
	}
	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0}
	if err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lk); err != nil {
		os.Exit(3)
	}
	fmt.Println("locked")
	b := make([]byte, 1)
	_, _ = os.Stdin.Read(b)
}

// child records every SIGINT and SIGTERM it gets in path, and otherwise
// sleeps (a dpkg or maintainer script in apt-get's process group).
func child(path string) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	for s := range ch {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: test fixture
		if err == nil {
			_, _ = fmt.Fprintln(f, s.String())
			_ = f.Close()
		}
	}
}

func sleepForever() {
	for {
		time.Sleep(time.Hour)
	}
}
