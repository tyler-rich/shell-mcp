//go:build linux

package pkg_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
)

// dpkg's status file (S4c-7, handoff D5): the bounded reader, the
// unfinished-state check, the diff that decides a package operation's
// result, the transaction's canonical form and hash, and the pinned argv.
// Every package, version and architecture is invented; the stanza layout
// is dpkg's (Package, Status, Architecture, Version, continuation lines),
// checked against dpkg 1.22.22 and 1.23.7.

const statusFile = `Package: dpkg
Essential: yes
Status: install ok installed
Priority: required
Architecture: amd64
Version: 1.22.22
Description: Debian package management system
 This package provides the low-level infrastructure for handling the
 installation and removal of Debian software packages.
 .
 A continuation line that looks like a field: Package: example-evil

Package: example-lib
Status: install ok installed
Architecture: amd64
Multi-Arch: same
Version: 2.1-1

Package: example-lib
Status: install ok installed
Architecture: i386
Multi-Arch: same
Version: 2.1-1

Package: example-data
Status: install ok installed
Architecture: all
Version: 1:3.0~rc1+dfsg-2
Conffiles:
 /etc/example-data/conf 0123456789abcdef0123456789abcdef

Package: example-old
Status: deinstall ok config-files
Architecture: all
Version: 0.9-1

Package: example-gone
Status: purge ok not-installed
Architecture: all
`

func mustParse(t *testing.T, s string) pkg.Status {
	t.Helper()
	st, err := pkg.ParseStatus([]byte(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return st
}

func TestParseStatus(t *testing.T) {
	t.Parallel()
	st := mustParse(t, statusFile)
	if st.Native != "amd64" {
		t.Fatalf("native %q", st.Native)
	}
	// apt's names: qualified with :arch only when it is neither all nor
	// native (pkgCache::PkgIterator::FullName(true)).
	want := map[string]string{"dpkg": "1.22.22", "example-lib": "2.1-1", "example-lib:i386": "2.1-1", "example-data": "1:3.0~rc1+dfsg-2", "example-old": "0.9-1", "example-gone": ""}
	if len(st.Packages) != len(want) {
		t.Fatalf("packages %+v", st.Packages)
	}
	for k, v := range want {
		p, ok := st.Packages[k]
		if !ok || p.Version != v {
			t.Fatalf("%s: %+v (all %+v)", k, p, st.Packages)
		}
	}
	if p := st.Packages["example-old"]; p.Want != "deinstall" || p.Flag != "ok" || p.State != "config-files" {
		t.Fatalf("example-old %+v", p)
	}
	if _, ok := st.Packages["example-evil"]; ok {
		t.Fatal("a continuation line was read as a field")
	}
	for name, bad := range map[string]string{
		"no package":           "Status: install ok installed\nVersion: 1\n",
		"bad name":             "Package: Example\nStatus: install ok installed\nArchitecture: all\nVersion: 1\n",
		"bad version":          "Package: example-a\nStatus: install ok installed\nArchitecture: all\nVersion: 1 2\n",
		"bad status":           "Package: example-a\nStatus: install ok\nArchitecture: all\nVersion: 1\n",
		"unknown state":        "Package: example-a\nStatus: install ok sideways\nArchitecture: all\nVersion: 1\n",
		"bad arch":             "Package: example-a\nStatus: install ok installed\nArchitecture: AMD/64\nVersion: 1\n",
		"duplicate":            "Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\nPackage: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2\n",
		"no dpkg":              "Package: example-a\nStatus: install ok installed\nArchitecture: all\nVersion: 1\n",
		"duplicate field":      "Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\nVersion: 2\n",
		"installed no version": "Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\n",
		"nul":                  "Package: dpkg\x00\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n",
	} {
		if _, err := pkg.ParseStatus([]byte(bad)); err == nil {
			t.Errorf("%s: parsed %q", name, bad)
		}
	}
	// Bounds: entries and bytes.
	var b strings.Builder
	b.WriteString("Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n")
	for i := range pkg.MaxStatusPackages {
		b.WriteString("Package: example-p" + strconv.Itoa(i) + "\nStatus: install ok installed\nArchitecture: all\nVersion: 1\n\n")
	}
	if _, err := pkg.ParseStatus([]byte(b.String())); err == nil {
		t.Fatal("more than MaxStatusPackages entries parsed")
	}
	if _, err := pkg.ParseStatus(make([]byte, pkg.MaxStatusBytes+1)); err == nil {
		t.Fatal("more than MaxStatusBytes parsed")
	}
}

func TestReadStatus(t *testing.T) {
	t.Parallel()
	d := gatetest.SecureDir(t)
	if _, err := pkg.ReadStatus(d); err == nil {
		t.Fatal("a missing status file read as empty")
	}
	gatetest.WriteFile(t, filepath.Join(d, "status"), statusFile, 0o644)
	st, err := pkg.ReadStatus(d)
	if err != nil || st.Packages["example-data"].Version != "1:3.0~rc1+dfsg-2" {
		t.Fatalf("%+v %v", st, err)
	}
	// Never through a symlink.
	l := gatetest.SecureDir(t)
	if err := os.Symlink(filepath.Join(d, "status"), filepath.Join(l, "status")); err != nil {
		t.Fatal(err)
	}
	if _, err := pkg.ReadStatus(l); err == nil {
		t.Fatal("read the status file through a symlink")
	}
}

// TestUnfinished: every state dpkg leaves mid-way, and a package needing
// reinstallation, is unfinished; installed, config-files and not-installed
// are final.
func TestUnfinished(t *testing.T) {
	t.Parallel()
	st := mustParse(t, statusFile)
	if u := st.Unfinished(); len(u) != 0 {
		t.Fatalf("a final status reported unfinished: %v", u)
	}
	var b strings.Builder
	b.WriteString(statusFile + "\n")
	for name, s := range map[string]string{
		"example-u1": "install ok half-installed", "example-u2": "install ok unpacked", "example-u3": "install ok half-configured",
		"example-u4": "install ok triggers-awaited", "example-u5": "install ok triggers-pending", "example-u6": "install reinstreq installed",
		"example-u7": "hold ok half-configured",
	} {
		b.WriteString("Package: " + name + "\nStatus: " + s + "\nArchitecture: all\nVersion: 1.0\n\n")
	}
	u := mustParse(t, b.String()).Unfinished()
	want := []string{"example-u1", "example-u2", "example-u3", "example-u4", "example-u5", "example-u6", "example-u7"}
	if !slices.Equal(u, want) {
		t.Fatalf("unfinished %v, want %v", u, want)
	}
}

func TestPendingUpdates(t *testing.T) {
	t.Parallel()
	d := gatetest.SecureDir(t)
	if u, err := pkg.PendingUpdates(d); err != nil || len(u) != 0 {
		t.Fatalf("no updates directory: %v %v", u, err)
	}
	gatetest.Mkdir(t, filepath.Join(d, "updates"), 0o755)
	if u, err := pkg.PendingUpdates(d); err != nil || len(u) != 0 {
		t.Fatalf("empty: %v %v", u, err)
	}
	gatetest.WriteFile(t, filepath.Join(d, "updates", "0000"), "Package: example-a\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(d, "updates", "tmp.i"), "", 0o644)
	if u, err := pkg.PendingUpdates(d); err != nil || !slices.Equal(u, []string{"0000", "tmp.i"}) {
		t.Fatalf("pending: %v %v", u, err)
	}
}

func TestDiff(t *testing.T) {
	t.Parallel()
	before := mustParse(t, statusFile)
	after := mustParse(t, strings.NewReplacer(
		"Package: example-lib\nStatus: install ok installed\nArchitecture: amd64\nMulti-Arch: same\nVersion: 2.1-1",
		"Package: example-lib\nStatus: install ok installed\nArchitecture: amd64\nMulti-Arch: same\nVersion: 2.2-1",
		"Package: example-data\nStatus: install ok installed", "Package: example-data\nStatus: deinstall ok config-files",
		"Package: example-old\nStatus: deinstall ok config-files", "Package: example-old\nStatus: install ok installed",
	).Replace(statusFile)+"\nPackage: example-new\nStatus: install ok half-configured\nArchitecture: i386\nVersion: 5\n")
	got := pkg.Diff(before, after)
	want := pkg.Transaction{
		Install: []pkg.Version{{Name: "example-new:i386", Version: "5"}, {Name: "example-old", Version: "0.9-1"}},
		Upgrade: []pkg.Upgrade{{Name: "example-lib", From: "2.1-1", To: "2.2-1"}},
		Remove:  []pkg.Removal{{Name: "example-data", Version: "1:3.0~rc1+dfsg-2"}},
	}
	if !got.Equal(want) || !slices.Equal(got.Install, want.Install) {
		t.Fatalf("diff %+v\nwant %+v", got, want)
	}
	if d := pkg.Diff(before, before); !d.Empty() {
		t.Fatalf("no change diffs as %+v", d)
	}
}

func TestTransactionEqual(t *testing.T) {
	t.Parallel()
	a := pkg.ParseSimulation([]byte("Inst example-b (1 R [all])\nInst example-a (2 R [all])\nInst example-c [1] (2 R [all])\nRemv example-d [3]\n")).Transaction()
	b := pkg.ParseSimulation([]byte("Remv example-d [3]\nInst example-c [1] (2 R [all])\nInst example-a (2 R [all])\nInst example-b (1 R [all])\n")).Transaction()
	if !a.Equal(b) || a.Install[0].Name != "example-a" {
		t.Fatalf("order: %+v %+v", a, b)
	}
	for name, other := range map[string]string{
		"version":  "Inst example-b (1 R [all])\nInst example-a (3 R [all])\nInst example-c [1] (2 R [all])\nRemv example-d [3]\n",
		"extra":    "Inst example-b (1 R [all])\nInst example-a (2 R [all])\nInst example-e (2 R [all])\nInst example-c [1] (2 R [all])\nRemv example-d [3]\n",
		"missing":  "Inst example-a (2 R [all])\nInst example-c [1] (2 R [all])\nRemv example-d [3]\n",
		"from":     "Inst example-b (1 R [all])\nInst example-a (2 R [all])\nInst example-c [0] (2 R [all])\nRemv example-d [3]\n",
		"removal":  "Inst example-b (1 R [all])\nInst example-a (2 R [all])\nInst example-c [1] (2 R [all])\n",
		"upgraded": "Inst example-b (1 R [all])\nInst example-a (2 R [all])\nInst example-c (2 R [all])\nRemv example-d [3]\n",
	} {
		if a.Equal(pkg.ParseSimulation([]byte(other)).Transaction()) {
			t.Errorf("%s: equal", name)
		}
	}
	if !(pkg.Transaction{}).Empty() || a.Empty() {
		t.Fatal("Empty")
	}
}

// TestPreviewHashCovers: the hash changes with every input it covers (the
// policy, the op, each requested name, each list entry and version, the
// purge flag, the argv) and not with the lists' order.
func TestPreviewHashCovers(t *testing.T) {
	t.Parallel()
	pol := strings.Repeat("a", 64)
	tx := func() pkg.Transaction {
		return pkg.Transaction{
			Install: []pkg.Version{{Name: "example-a", Version: "1"}, {Name: "example-b", Version: "2"}},
			Upgrade: []pkg.Upgrade{{Name: "example-c", From: "1", To: "2"}},
			Remove:  []pkg.Removal{{Name: "example-d", Version: "3"}},
		}
	}
	argv := []string{"-s", "install", "--", "example-a"}
	base := pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-a"}, tx(), argv)
	if len(base) != 64 || strings.Trim(base, "0123456789abcdef") != "" {
		t.Fatalf("hash %q", base)
	}
	swapped := tx()
	swapped.Install[0], swapped.Install[1] = swapped.Install[1], swapped.Install[0]
	if pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-a"}, swapped, argv) != base {
		t.Fatal("the lists' order changes the hash")
	}
	for name, h := range map[string]string{
		"policy":       pkg.PreviewHash(strings.Repeat("b", 64), pkg.OpInstall, []string{"example-a"}, tx(), argv),
		"op":           pkg.PreviewHash(pol, pkg.OpRemove, []string{"example-a"}, tx(), argv),
		"name":         pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-b"}, tx(), argv),
		"names":        pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-a", "example-b"}, tx(), argv),
		"argv":         pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-a"}, tx(), []string{"-s", "install", "--", "example-b"}),
		"install ver":  pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-a"}, mod(tx(), func(t *pkg.Transaction) { t.Install[1].Version = "3" }), argv),
		"install more": pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-a"}, mod(tx(), func(t *pkg.Transaction) { t.Install = append(t.Install, pkg.Version{Name: "example-e", Version: "1"}) }), argv),
		"upgrade from": pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-a"}, mod(tx(), func(t *pkg.Transaction) { t.Upgrade[0].From = "0" }), argv),
		"upgrade to":   pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-a"}, mod(tx(), func(t *pkg.Transaction) { t.Upgrade[0].To = "3" }), argv),
		"remove ver":   pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-a"}, mod(tx(), func(t *pkg.Transaction) { t.Remove[0].Version = "4" }), argv),
		"purge":        pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-a"}, mod(tx(), func(t *pkg.Transaction) { t.Remove[0].Purge = true }), argv),
		"moved": pkg.PreviewHash(pol, pkg.OpInstall, []string{"example-a"}, mod(tx(), func(t *pkg.Transaction) {
			t.Install, t.Remove = t.Install[:1], append(t.Remove, pkg.Removal{Name: "example-b", Version: "2"})
		}), argv),
	} {
		if h == base || len(h) != 64 {
			t.Errorf("%s: hash %q unchanged or malformed", name, h)
		}
	}
	u := pkg.UpdatePreviewHash(pol, []string{"-q", "update"})
	if len(u) != 64 || u == base || u == pkg.UpdatePreviewHash(strings.Repeat("b", 64), []string{"-q", "update"}) {
		t.Fatalf("update hash %q", u)
	}
}

func mod(t pkg.Transaction, f func(*pkg.Transaction)) pkg.Transaction {
	f(&t)
	return t
}

// TestPinnedArgs: the argv a package operation runs. An install pins each
// requested name to its approved version (dependencies are not pinned, so
// apt keeps them marked automatic) and never removes; an upgrade is
// install --only-upgrade over exactly the approved list, every package
// pinned; a removal is not pinned. Nothing to run is nil.
func TestPinnedArgs(t *testing.T) {
	t.Parallel()
	common := []string{"-q", "-y", "-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Use-Pty=0", "-o", "APT::Get::AutomaticRemove=false"}
	tx := pkg.Transaction{
		Install: []pkg.Version{{Name: "example-lib", Version: "2.1-1"}, {Name: "example-new", Version: "1.0"}},
		Upgrade: []pkg.Upgrade{{Name: "example-hello", From: "1.0", To: "1.1"}, {Name: "example-arch:i386", From: "3.0-1", To: "3.0-2"}},
	}
	got, err := pkg.PinnedArgs(pkg.OpInstall, false, []string{"example-hello", "example-new"}, tx)
	want := slices.Concat(common, []string{"--no-install-recommends", "--no-remove", "install", "--", "example-hello=1.1", "example-new=1.0"})
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("install %q %v\nwant %q", got, err, want)
	}
	got, _ = pkg.PinnedArgs(pkg.OpInstall, true, []string{"example-hello", "example-new"}, tx)
	if !slices.Equal(got, slices.Concat(common, []string{"--no-install-recommends", "--no-remove", "-s", "install", "--", "example-hello=1.1", "example-new=1.0"})) {
		t.Fatalf("simulated install %q", got)
	}
	got, _ = pkg.PinnedArgs(pkg.OpUpgrade, false, nil, pkg.Transaction{Upgrade: tx.Upgrade})
	want = slices.Concat(common, []string{"--no-install-recommends", "--no-remove", "--only-upgrade", "install", "--", "example-arch:i386=3.0-2", "example-hello=1.1"})
	if !slices.Equal(got, want) {
		t.Fatalf("upgrade %q\nwant %q", got, want)
	}
	got, _ = pkg.PinnedArgs(pkg.OpRemove, false, []string{"example-hello"}, pkg.Transaction{Remove: []pkg.Removal{{Name: "example-hello", Version: "1.0"}}})
	if !slices.Equal(got, slices.Concat(common, []string{"-o", "APT::Get::Purge=false", "remove", "--", "example-hello"})) {
		t.Fatalf("remove %q", got)
	}
	// A requested name already at its version is not in the transaction:
	// nothing to pin, and an operation with nothing left runs nothing.
	if got, err := pkg.PinnedArgs(pkg.OpInstall, false, []string{"example-other"}, tx); err != nil || got != nil {
		t.Fatalf("nothing to run: %q %v", got, err)
	}
	if got, err := pkg.PinnedArgs(pkg.OpUpgrade, false, nil, pkg.Transaction{}); err != nil || got != nil {
		t.Fatalf("empty upgrade: %q %v", got, err)
	}
	// Versions from host data are validated again: nothing that could be
	// read as an option or another operation reaches apt.
	for _, v := range []string{"", "1 2", "-o", "1.0-", "1/2", "1=2"} {
		bad := pkg.Transaction{Upgrade: []pkg.Upgrade{{Name: "example-hello", From: "1.0", To: v}}}
		if got, err := pkg.PinnedArgs(pkg.OpUpgrade, false, nil, bad); err == nil {
			t.Errorf("version %q pinned: %q", v, got)
		}
	}
	if _, err := pkg.PinnedArgs(pkg.OpUpdate, false, nil, tx); err == nil {
		t.Fatal("update pinned")
	}
}

// TestLockHolder: the dpkg frontend lock's holder, from fcntl(F_GETLK),
// with its command name; a lock nobody holds, and a missing lock file,
// report none.
func TestLockHolder(t *testing.T) {
	t.Parallel()
	d := gatetest.SecureDir(t)
	lock := filepath.Join(d, "lock-frontend")
	if _, held, err := pkg.LockHolder(lock); err != nil || held {
		t.Fatalf("missing file: held %v %v", held, err)
	}
	gatetest.WriteFile(t, lock, "", 0o640)
	if _, held, err := pkg.LockHolder(lock); err != nil || held {
		t.Fatalf("free: held %v %v", held, err)
	}
	// A process holding it: this test binary as a helper process.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := exec.CommandContext(t.Context(), self, "-test.run=TestHoldLockHelper") //nolint:gosec // G204: this test binary
	c.Env = append(os.Environ(), "PKG_TEST_HOLD_LOCK="+lock)
	in, _ := c.StdinPipe()
	out, _ := c.StdoutPipe()
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = c.Wait() })
	buf := make([]byte, 7)
	if _, err := out.Read(buf); err != nil || string(buf[:6]) != "locked" {
		t.Fatalf("helper process: %q %v", buf, err)
	}
	h, held, err := pkg.LockHolder(lock)
	if err != nil || !held || h.PID != c.Process.Pid || h.Comm == "" {
		t.Fatalf("held by %+v %v %v, want pid %d", h, held, err, c.Process.Pid)
	}
}

func TestHoldLockHelper(t *testing.T) {
	p := os.Getenv("PKG_TEST_HOLD_LOCK")
	if p == "" {
		t.Skip("a helper process for TestLockHolder")
	}
	holdLock(t, p)
}

// holdLock takes an fcntl write lock on path (as apt and dpkg do), says so
// on stdout, and keeps it until stdin closes.
func holdLock(t *testing.T, path string) {
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: test fixture
	if err != nil {
		t.Fatal(err)
	}
	lk := unix.Flock_t{Type: unix.F_WRLCK}
	if err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lk); err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdout.WriteString("locked\n")
	_, _ = os.Stdin.Read(make([]byte, 1))
}
