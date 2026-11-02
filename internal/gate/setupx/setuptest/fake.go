//go:build linux

// Package setuptest is the installers' fake host for unit tests: an
// in-memory filesystem with owners and modes, the user and group databases
// as files in it, scripted programs (groupadd, useradd and usermod edit
// those files as the real ones would), and failure injection for every
// change. Only tests import it.
package setuptest

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// File is one entry of the fake filesystem. Mode holds the type bits
// (fs.ModeDir, fs.ModeSymlink) and the permission bits.
type File struct {
	Data     []byte
	Mode     fs.FileMode
	UID, GID uint32
}

// Fake implements setupx.Host in memory.
type Fake struct {
	mu sync.Mutex
	// EUID is the effective uid (default 0); Env the environment.
	EUID int
	Env  map[string]string
	// Exe is the running binary.
	Exe string
	// Files is the filesystem, by absolute clean path.
	Files map[string]*File
	// Systemd says whether systemd runs as PID 1.
	Systemd bool
	// Programs answers Run; nil runs Simulate.
	Programs func(f *Fake, prog string, args []string) (setupx.Output, error)
	// Calls records every Run, argv[0] first.
	Calls [][]string
	// FailWrite fails WriteFile of a path before anything is changed;
	// FailCommitted replaces it and then fails (a failed read-back).
	FailWrite, FailCommitted, FailMkdir, FailRemove map[string]error
	// ChainErr makes CheckChain of a path fail.
	ChainErr map[string]error
	// Writes counts WriteFile calls that changed the filesystem.
	Writes int
}

// New is a minimal root-owned host: /, /etc with root's account and group
// and a few system groups, /usr/sbin and /usr/bin holding the installers'
// programs, /usr/local/bin/shell-mcp-gate as the running binary, and
// systemd running.
func New() *Fake {
	f := &Fake{Env: map[string]string{}, Exe: "/usr/local/bin/shell-mcp-gate", Files: map[string]*File{}, Systemd: true,
		FailWrite: map[string]error{}, FailCommitted: map[string]error{}, FailMkdir: map[string]error{}, FailRemove: map[string]error{},
		ChainErr: map[string]error{}}
	for _, d := range []string{"/", "/etc", "/usr", "/usr/sbin", "/usr/bin", "/usr/local", "/usr/local/bin", "/usr/local/libexec", "/var", "/var/lib", "/run", "/bin"} {
		f.Dir(d, 0o755, 0, 0)
	}
	f.Put("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n", 0o644, 0, 0)
	f.Put("/etc/group", "root:x:0:\nadm:x:4:\ndisk:x:6:\nsudo:x:27:\nsystemd-journal:x:999:\ndocker:x:998:\nnogroup:x:65534:\n", 0o644, 0, 0)
	for _, p := range append(setupx.Programs(), f.Exe, "/bin/sh") {
		f.Put(p, "\x7fELF", 0o755, 0, 0)
	}
	return f
}

// Dir creates a directory entry (and nothing above it).
func (f *Fake) Dir(p string, mode fs.FileMode, uid, gid uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Files[p] = &File{Mode: fs.ModeDir | mode, UID: uid, GID: gid}
}

// Put creates or replaces a regular file.
func (f *Fake) Put(p, data string, mode fs.FileMode, uid, gid uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Files[p] = &File{Data: []byte(data), Mode: mode, UID: uid, GID: gid}
}

// Get is a regular file's content, and whether it exists.
func (f *Fake) Get(p string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.Files[p]
	if !ok {
		return "", false
	}
	return string(e.Data), true
}

// Snapshot is a deep copy of the filesystem, for before/after comparisons.
func (f *Fake) Snapshot() map[string]File {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]File, len(f.Files))
	for k, v := range f.Files {
		c := *v
		c.Data = slices.Clone(v.Data)
		out[k] = c
	}
	return out
}

// Temps lists every path whose base name is an install temp name.
func (f *Fake) Temps() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for p := range f.Files {
		if setupx.IsTemp(path.Base(p)) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// Ran reports whether some call's argv starts with prefix.
func (f *Fake) Ran(prefix ...string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.Calls {
		if len(c) >= len(prefix) && slices.Equal(c[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

// Euid implements setupx.Host.
func (f *Fake) Euid() int { return f.EUID }

// LookupEnv implements setupx.Host.
func (f *Fake) LookupEnv(name string) (string, bool) { v, ok := f.Env[name]; return v, ok }

// Executable implements setupx.Host.
func (f *Fake) Executable() (string, error) { return f.Exe, nil }

// CheckChain implements setupx.Host: path and every directory above it
// exist, are root-owned and are not group- or world-writable.
func (f *Fake) CheckChain(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.ChainErr[p]; ok {
		return err
	}
	for q := p; ; q = path.Dir(q) {
		e, ok := f.Files[q]
		switch {
		case !ok:
			return fmt.Errorf("%s: %w", q, fs.ErrNotExist)
		case e.UID != 0:
			return fmt.Errorf("%s is owned by uid %d, not root", q, e.UID)
		case e.Mode.Perm()&0o022 != 0:
			return fmt.Errorf("%s is group- or world-writable", q)
		}
		if q == "/" {
			return nil
		}
	}
}

// State implements setupx.Host.
func (f *Fake) State(p string, limit int64) (setupx.FileState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.Files[p]
	if !ok {
		return setupx.FileState{}, nil
	}
	s := setupx.FileState{Exists: true, Mode: e.Mode, Owner: setupx.Owner{UID: e.UID, GID: e.GID}}
	if e.Mode.IsRegular() {
		if int64(len(e.Data)) > limit {
			return setupx.FileState{}, setupx.ErrTooLarge
		}
		s.Data = slices.Clone(e.Data)
	}
	return s, nil
}

// ReadDir implements setupx.Host.
func (f *Fake) ReadDir(p string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.Files[p]; !ok || !e.Mode.IsDir() {
		return nil, fs.ErrNotExist
	}
	var out []string
	for k := range f.Files {
		if k != "/" && path.Dir(k) == p {
			out = append(out, path.Base(k))
		}
	}
	slices.Sort(out)
	return out, nil
}

func (f *Fake) parentDir(p string) error {
	if e, ok := f.Files[path.Dir(p)]; !ok || !e.Mode.IsDir() {
		return fmt.Errorf("%s: %w", path.Dir(p), fs.ErrNotExist)
	}
	return nil
}

// WriteFile implements setupx.Host. A failure leaves no temp file, as the
// real helper does (its own tests prove that on a real filesystem).
func (f *Fake) WriteFile(p string, data []byte, mode fs.FileMode, owner setupx.Owner) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.parentDir(p); err != nil {
		return &setupx.WriteError{Path: p, Step: "create", Err: err}
	}
	if err, ok := f.FailWrite[p]; ok {
		return &setupx.WriteError{Path: p, Step: "write", Err: err}
	}
	f.Files[p] = &File{Data: slices.Clone(data), Mode: mode, UID: owner.UID, GID: owner.GID}
	f.Writes++
	if err, ok := f.FailCommitted[p]; ok {
		delete(f.FailCommitted, p)
		return &setupx.WriteError{Path: p, Step: "read-back", Committed: true, Err: err}
	}
	return nil
}

// Mkdir implements setupx.Host.
func (f *Fake) Mkdir(p string, mode fs.FileMode, owner setupx.Owner) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.parentDir(p); err != nil {
		return err
	}
	if _, ok := f.Files[p]; ok {
		return fs.ErrExist
	}
	if err, ok := f.FailMkdir[p]; ok {
		return err
	}
	f.Files[p] = &File{Mode: fs.ModeDir | mode, UID: owner.UID, GID: owner.GID}
	return nil
}

// Remove implements setupx.Host.
func (f *Fake) Remove(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.FailRemove[p]; ok {
		return err
	}
	e, ok := f.Files[p]
	if !ok {
		return fs.ErrNotExist
	}
	if e.Mode.IsDir() {
		for k := range f.Files {
			if k != p && path.Dir(k) == p {
				return errors.New("directory not empty")
			}
		}
	}
	delete(f.Files, p)
	return nil
}

// RemoveLeftovers implements setupx.Host.
func (f *Fake) RemoveLeftovers(target string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, k := range slices.Sorted(maps.Keys(f.Files)) {
		if path.Dir(k) == path.Dir(target) && setupx.IsTempFor(path.Base(k), path.Base(target)) {
			delete(f.Files, k)
			out = append(out, k)
		}
	}
	return out, nil
}

// Accounts implements setupx.Host, from the fake /etc/passwd and /etc/group.
func (f *Fake) Accounts() (*setupx.Accounts, error) {
	pw, _ := f.Get("/etc/passwd")
	gr, _ := f.Get("/etc/group")
	users, err := setupx.ParsePasswd([]byte(pw))
	if err != nil {
		return nil, err
	}
	groups, err := setupx.ParseGroup([]byte(gr))
	if err != nil {
		return nil, err
	}
	return &setupx.Accounts{Users: users, Groups: groups}, nil
}

// SystemdRunning implements setupx.Host.
func (f *Fake) SystemdRunning() bool { return f.Systemd }

// Run implements setupx.Host: records the call and answers through
// Programs, or Simulate.
func (f *Fake) Run(prog string, args ...string) (setupx.Output, error) {
	if !setupx.IsProgram(prog) {
		return setupx.Output{}, fmt.Errorf("%w: %s", setupx.ErrProgram, prog)
	}
	f.mu.Lock()
	f.Calls = append(f.Calls, append([]string{prog}, args...))
	pf := f.Programs
	f.mu.Unlock()
	if pf != nil {
		return pf(f, prog, args)
	}
	return f.Simulate(prog, args)
}

// OK is a successful program output with stdout out.
func OK(out string) setupx.Output { return setupx.Output{Stdout: []byte(out)} }

// Failed is a program that exited with code 1 and stderr msg.
func Failed(msg string) setupx.Output { return setupx.Output{Stderr: []byte(msg), Exit: 1} }

// flag returns the value after name in args, or "".
func flag(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func (f *Fake) appendLine(p, line string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.Files[p]
	e.Data = append(e.Data, []byte(line+"\n")...)
}

// Simulate answers the account programs as shadow-utils would, editing the
// fake /etc/passwd and /etc/group (groupadd --gid N name; useradd --uid U
// --gid G --home-dir H --create-home --shell S name; usermod -L name;
// usermod -aG group name), and every other program with exit 0 and no
// output.
func (f *Fake) Simulate(prog string, args []string) (setupx.Output, error) {
	name := ""
	if len(args) > 0 {
		name = args[len(args)-1]
	}
	switch prog {
	case setupx.Groupadd:
		f.appendLine("/etc/group", name+":x:"+flag(args, "--gid")+":")
	case setupx.Useradd:
		uid, gid := flag(args, "--uid"), flag(args, "--gid")
		home := flag(args, "--home-dir")
		f.appendLine("/etc/passwd", name+":x:"+uid+":"+gid+"::"+home+":"+flag(args, "--shell"))
		u, _ := strconv.ParseUint(uid, 10, 32)
		g, _ := strconv.ParseUint(gid, 10, 32)
		f.Dir(home, 0o750, uint32(u), uint32(g))
	case setupx.Usermod:
		if g := flag(args, "-aG"); g != "" {
			gr, _ := f.Get("/etc/group")
			var out []string
			for _, l := range strings.Split(strings.TrimSuffix(gr, "\n"), "\n") {
				if fl := strings.Split(l, ":"); len(fl) == 4 && fl[0] == g {
					if fl[3] == "" {
						fl[3] = name
					} else {
						fl[3] += "," + name
					}
					l = strings.Join(fl, ":")
				}
				out = append(out, l)
			}
			f.Put("/etc/group", strings.Join(out, "\n")+"\n", 0o644, 0, 0)
		}
	}
	return setupx.Output{}, nil
}
