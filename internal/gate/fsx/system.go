//go:build linux

package fsx

import (
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// System files. The native system operations (sysinfo, disk, processes)
// read a fixed set of host files outside the policy's roots: /proc may not
// be a root (POLICY §3), so these ops read what they need themselves. These
// functions are the only way they do, and they accept nothing but the fixed
// names below — never a path from a request. The sandbox grants /proc and
// /etc read-only (POLICY §4a); /usr/lib/os-release is under /usr.

// systemFiles are the fixed host files the system ops may read.
var systemFiles = []string{
	"/etc/os-release", "/usr/lib/os-release",
	"/proc/uptime", "/proc/loadavg", "/proc/meminfo", "/proc/stat", "/proc/self/mountinfo",
}

// pidFiles are the per-process files the processes op may read.
var pidFiles = []string{"stat", "status", "cmdline"}

// maxPIDDigits bounds a pid in a /proc path (pid_max is at most 2^22).
const maxPIDDigits = 10

// validPID reports whether s is a decimal pid without a leading zero.
func validPID(s string) bool {
	if s == "" || len(s) > maxPIDDigits || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// allowedSystemFile reports whether p is one of the fixed system files or
// /proc/<pid>/{stat,status,cmdline}.
func allowedSystemFile(p string) bool {
	if slices.Contains(systemFiles, p) {
		return true
	}
	rest, ok := strings.CutPrefix(p, "/proc/")
	if !ok {
		return false
	}
	pid, file, ok := strings.Cut(rest, "/")
	return ok && validPID(pid) && slices.Contains(pidFiles, file)
}

// ReadSystemFile reads at most limit bytes of one of the fixed system files
// and reports whether the file was longer. Files in /proc report size 0, so
// the read itself is bounded.
func ReadSystemFile(p string, limit int) (data []byte, truncated bool, err error) {
	if !allowedSystemFile(p) || limit < 1 {
		return nil, false, errf(protocol.CodeInternal, "not a system file the gate reads")
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) //nolint:gosec // G304: p is one of the fixed names checked above
	if err != nil {
		return nil, false, mapErr(err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, false, mapErr(err)
	}
	if !fi.Mode().IsRegular() {
		return nil, false, errf(protocol.CodeInternal, "system file is not a regular file")
	}
	data, err = io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, false, mapErr(err)
	}
	if len(data) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

// ListPIDs returns up to limit pids from /proc in ascending order, and
// whether more exist.
func ListPIDs(limit int) (pids []int, truncated bool, err error) {
	d, err := os.Open("/proc")
	if err != nil {
		return nil, false, mapErr(err)
	}
	defer func() { _ = d.Close() }()
	scanned := 0
	for {
		names, rerr := d.Readdirnames(readDirChunk)
		for _, n := range names {
			if !validPID(n) {
				continue
			}
			pid, _ := strconv.Atoi(n)
			pids = append(pids, pid)
		}
		scanned += len(names)
		if errors.Is(rerr, io.EOF) || len(names) == 0 {
			break
		}
		if rerr != nil {
			return nil, false, mapErr(rerr)
		}
		if scanned > maxScan {
			truncated = true
			break
		}
	}
	slices.Sort(pids)
	if len(pids) > limit {
		return pids[:limit], true, nil
	}
	return pids, truncated, nil
}

// ErrStatfsTimeout is returned by Statfs when the filesystem does not
// answer in time (for example a hung network mount).
var ErrStatfsTimeout = errors.New("statfs timed out")

// Statfs runs statfs(2) on a mount point taken from mountinfo, bounded by
// timeout. A call that times out keeps running in the background until the
// gate exits (it serves one request).
func Statfs(mountPoint string, timeout time.Duration) (unix.Statfs_t, error) {
	if !strings.HasPrefix(mountPoint, "/") || strings.ContainsRune(mountPoint, 0) {
		return unix.Statfs_t{}, errf(protocol.CodeInternal, "mount point is not absolute")
	}
	type result struct {
		st  unix.Statfs_t
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var st unix.Statfs_t
		err := unix.Statfs(mountPoint, &st)
		ch <- result{st, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.st, r.err
	case <-timer.C:
		return unix.Statfs_t{}, ErrStatfsTimeout
	}
}
