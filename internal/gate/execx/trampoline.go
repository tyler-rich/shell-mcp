//go:build linux

package execx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The trampoline puts the child's limits in force before the command's
// first instruction. os/exec has no hook between fork and execve, and
// prlimit(2) after the start lands only once the command is already
// running, so Run starts the running binary itself (Spec.Trampoline) with
// exactly the argument TrampolineArg, an empty environment and one extra
// descriptor: one end of a socketpair(2) as fd 3. The trampoline checks how
// it was started, reads the command from fd 3, changes to its directory,
// lowers its own limits with setrlimit(2) and execve(2)s the command in its
// place: same pid, process group, parent-death signal, no_new_privs,
// Landlock domain and seccomp filters. It runs from this package's init,
// before the binary's main, while the Go runtime keeps the main goroutine
// on the main thread, so the execve happens on the thread whose
// parent-death signal os/exec set.
//
// Nothing outside Run can use it: the SSH forced command and the helper's
// unit fix the argv of the gate and the helper, and the trampoline refuses
// to run with any other argument, with a terminal on fd 0–2, with an
// environment, off the main thread, or unless fd 3 is a Unix stream socket
// whose peer is its parent process under its own uid. A command started
// through it inherits none of this: fd 3 is close-on-exec and the command
// gets the environment of its Spec.

// TrampolineArg is the trampoline's only argument.
const TrampolineArg = "shell-mcp-execx-trampoline-v1"

// TrampolineRefused is the trampoline's exit status when it refuses to run.
const TrampolineRefused = 125

// trampolineFD is the inherited control descriptor (ExtraFiles[0]).
const trampolineFD = 3

// Bounds on the encoded command.
const (
	maxConfigBytes  = 8 << 20
	maxConfigItems  = 1 << 16
	maxConfigLimits = 16
	// rlimNLimits is RLIM_NLIMITS: resources are numbered below it.
	rlimNLimits = 16
)

// statusAccepted is the trampoline's first byte on fd 3: the checks passed
// and the command was read. An errno (4 bytes, little endian) follows only
// when it could not start the command; on success fd 3 is closed by the
// execve and the parent reads EOF.
const statusAccepted = 0xA5

var configMagic = [4]byte{'S', 'M', 'X', '1'}

// childLimit is one resource limit the trampoline lowers itself to: both
// the soft and the hard limit become min(current, Max).
type childLimit struct {
	Resource uint32
	Max      uint64
}

// trampolineConfig is what Run sends on fd 3.
type trampolineConfig struct {
	Path   string
	Argv   []string
	Env    []string
	Dir    string
	Limits []childLimit
}

var errConfig = errors.New("malformed trampoline command")

// encodeConfig writes c in the trampoline's binary form: the magic, then
// the path, argv, env and dir as length-prefixed strings, then the limits.
// Strings are bytes, so argv and paths need not be UTF-8. A string with a
// NUL cannot reach execve(2) (EINVAL, as os/exec reports it); a command
// over the bounds is E2BIG.
func encodeConfig(c *trampolineConfig) ([]byte, error) {
	if len(c.Argv) > maxConfigItems || len(c.Env) > maxConfigItems || len(c.Limits) > maxConfigLimits {
		return nil, unix.E2BIG
	}
	for _, s := range append(append([]string{c.Path, c.Dir}, c.Argv...), c.Env...) {
		if strings.ContainsRune(s, 0) {
			return nil, unix.EINVAL
		}
	}
	b := append([]byte(nil), configMagic[:]...)
	str := func(s string) { b = binary.LittleEndian.AppendUint32(b, uint32(len(s))); b = append(b, s...) } //nolint:gosec // G115: bounded by maxConfigBytes below
	list := func(l []string) {
		b = binary.LittleEndian.AppendUint32(b, uint32(len(l))) //nolint:gosec // G115: bounded by maxConfigItems
		for _, s := range l {
			str(s)
		}
	}
	str(c.Path)
	list(c.Argv)
	list(c.Env)
	str(c.Dir)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(c.Limits))) //nolint:gosec // G115: bounded by maxConfigLimits
	for _, l := range c.Limits {
		b = binary.LittleEndian.AppendUint32(b, l.Resource)
		b = binary.LittleEndian.AppendUint64(b, l.Max)
	}
	if len(b) > maxConfigBytes {
		return nil, unix.E2BIG
	}
	return b, nil
}

// decodeConfig is the strict inverse of encodeConfig: every count and
// length is bounded, the input must be consumed exactly, strings may not
// contain NUL, path and dir must be absolute, argv[0] must be the path, and
// each environment entry must be NAME=value.
func decodeConfig(b []byte) (*trampolineConfig, error) {
	if len(b) > maxConfigBytes || len(b) < len(configMagic) || [4]byte(b[:4]) != configMagic {
		return nil, errConfig
	}
	b = b[4:]
	u32 := func() (uint32, bool) {
		if len(b) < 4 {
			return 0, false
		}
		v := binary.LittleEndian.Uint32(b)
		b = b[4:]
		return v, true
	}
	str := func() (string, bool) {
		n, ok := u32()
		if !ok || uint64(n) > uint64(len(b)) {
			return "", false
		}
		s := string(b[:n])
		b = b[n:]
		return s, !strings.ContainsRune(s, 0)
	}
	list := func() ([]string, bool) {
		n, ok := u32()
		if !ok || n > maxConfigItems || uint64(n)*4 > uint64(len(b)) {
			return nil, false
		}
		l := make([]string, 0, n)
		for range n {
			s, ok := str()
			if !ok {
				return nil, false
			}
			l = append(l, s)
		}
		return l, true
	}
	c := &trampolineConfig{}
	var ok bool
	if c.Path, ok = str(); !ok {
		return nil, errConfig
	}
	if c.Argv, ok = list(); !ok {
		return nil, errConfig
	}
	if c.Env, ok = list(); !ok {
		return nil, errConfig
	}
	if c.Dir, ok = str(); !ok {
		return nil, errConfig
	}
	n, ok := u32()
	if !ok || n > maxConfigLimits || uint64(n)*12 != uint64(len(b)) {
		return nil, errConfig
	}
	for range n {
		r, _ := u32()
		if r >= rlimNLimits {
			return nil, errConfig
		}
		c.Limits = append(c.Limits, childLimit{Resource: r, Max: binary.LittleEndian.Uint64(b)})
		b = b[8:]
	}
	if !strings.HasPrefix(c.Path, "/") || !strings.HasPrefix(c.Dir, "/") || len(c.Argv) == 0 || c.Argv[0] != c.Path {
		return nil, errConfig
	}
	for _, e := range c.Env {
		if k, _, found := strings.Cut(e, "="); !found || k == "" {
			return nil, errConfig
		}
	}
	return c, nil
}

// trampolineEnv is what the trampoline knows about how it was started.
type trampolineEnv struct {
	args     []string
	environ  []string
	pid, tid int
	ppid     int
	uid      int
	// isTerminal reports whether fd is a terminal.
	isTerminal func(fd int) bool
	// control describes fd 3: whether it is an AF_UNIX stream socket, and
	// its peer's credentials.
	control func() (unixStream bool, peer *unix.Ucred, err error)
}

// trampolineRefusal returns why the trampoline must not run, or "".
func trampolineRefusal(e *trampolineEnv) string {
	switch {
	case len(e.args) != 2 || e.args[1] != TrampolineArg:
		return "it takes exactly one argument"
	case len(e.environ) != 0:
		return "it must be started with an empty environment"
	case e.tid != e.pid:
		return "it must run on the main thread"
	}
	for fd := range 3 {
		if e.isTerminal(fd) {
			return fmt.Sprintf("fd %d is a terminal", fd)
		}
	}
	stream, peer, err := e.control()
	switch {
	case err != nil:
		return "fd 3 is not an open socket"
	case !stream:
		return "fd 3 is not a Unix stream socket"
	case peer == nil || int(peer.Pid) != e.ppid || e.ppid <= 1:
		return "fd 3's peer is not the parent process"
	case int(peer.Uid) != e.uid:
		return "fd 3's peer runs as another user"
	}
	return ""
}

// liveTrampolineEnv describes this process.
func liveTrampolineEnv() *trampolineEnv {
	return &trampolineEnv{
		args: os.Args, environ: os.Environ(),
		pid: unix.Getpid(), tid: unix.Gettid(), ppid: unix.Getppid(), uid: unix.Getuid(),
		isTerminal: func(fd int) bool {
			_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
			return err == nil
		},
		control: func() (bool, *unix.Ucred, error) {
			var st unix.Stat_t
			if err := unix.Fstat(trampolineFD, &st); err != nil {
				return false, nil, err
			}
			if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
				return false, nil, nil
			}
			dom, err1 := unix.GetsockoptInt(trampolineFD, unix.SOL_SOCKET, unix.SO_DOMAIN)
			typ, err2 := unix.GetsockoptInt(trampolineFD, unix.SOL_SOCKET, unix.SO_TYPE)
			if err1 != nil || err2 != nil || dom != unix.AF_UNIX || typ != unix.SOCK_STREAM {
				return false, nil, nil
			}
			cred, err := unix.GetsockoptUcred(trampolineFD, unix.SOL_SOCKET, unix.SO_PEERCRED)
			if err != nil {
				return true, nil, nil
			}
			return true, cred, nil
		},
	}
}

func init() {
	if len(os.Args) > 1 && os.Args[1] == TrampolineArg {
		os.Exit(trampoline())
	}
}

// trampoline runs the command Run sent on fd 3. It returns only when it
// refuses or the command cannot be started.
func trampoline() int {
	if why := trampolineRefusal(liveTrampolineEnv()); why != "" {
		_, _ = fmt.Fprintf(os.Stderr, "%s: refusing to run the internal exec trampoline: %s\n", os.Args[0], why)
		return TrampolineRefused
	}
	ctl := os.NewFile(trampolineFD, "execx-control")
	b, err := io.ReadAll(io.LimitReader(ctl, maxConfigBytes+1))
	if err != nil {
		return TrampolineRefused
	}
	c, err := decodeConfig(b)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s: refusing to run the internal exec trampoline: %v\n", os.Args[0], err)
		return TrampolineRefused
	}
	if _, err := ctl.Write([]byte{statusAccepted}); err != nil {
		return TrampolineRefused
	}
	fail := func(err error) int {
		errno := syscall.EINVAL
		_ = errors.As(err, &errno)
		_, _ = ctl.Write(binary.LittleEndian.AppendUint32(nil, uint32(errno)))
		return TrampolineRefused
	}
	if err := unix.Chdir(c.Dir); err != nil {
		return fail(err)
	}
	for _, l := range c.Limits {
		var cur syscall.Rlimit
		if err := syscall.Getrlimit(int(l.Resource), &cur); err != nil {
			return fail(err)
		}
		nl := syscall.Rlimit{Cur: min(cur.Cur, l.Max), Max: min(cur.Max, l.Max)}
		// syscall.Setrlimit, not x/sys/unix: for RLIMIT_NOFILE it also
		// stops syscall.Exec restoring the soft limit Go saved at startup.
		if err := syscall.Setrlimit(int(l.Resource), &nl); err != nil {
			return fail(err)
		}
	}
	// Every descriptor above stderr is close-on-exec: the control socket,
	// and anything the gate or helper itself inherited without the flag
	// (os/exec passes such descriptors on). The command gets exactly fd
	// 0–2. CLOSE_RANGE_CLOEXEC needs Linux 5.11; without it nothing runs.
	if err := unix.CloseRange(trampolineFD, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fail(err)
	}
	return fail(syscall.Exec(c.Path, c.Argv, c.Env)) //nolint:gosec // G204: the command Run sent over the checked control socket: a path resolved and ownership-checked at policy load, an argv matched to a policy template; no shell
}
