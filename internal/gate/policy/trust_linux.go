//go:build linux

package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
)

// CheckChain verifies that p (after resolving symlinks) and every parent
// directory up to "/" are owned by a trusted uid and not group/other-
// writable; symlink components of the path as written must also be owned by
// a trusted uid. It returns the resolved path.
//
// A sticky world-writable directory (such as /tmp) is still refused: the
// check is "not group/other-writable", with no exception.
func CheckChain(t Trust, p string) (string, error) {
	if err := pathx.CheckClean(p); err != nil {
		return "", &OwnershipError{p, err.Error()}
	}
	// Symlinks in the path as written: whoever owns a link decides where it
	// points, so each one must be trusted too.
	cur := ""
	for _, c := range strings.Split(p[1:], "/") {
		if c == "" {
			break
		}
		cur += "/" + c
		fi, err := os.Lstat(cur)
		if err != nil {
			return "", &OwnershipError{cur, "cannot be inspected: " + errReason(err)}
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			if err := checkOwner(t, cur, fi); err != nil {
				return "", err
			}
		}
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", &OwnershipError{p, "cannot be resolved: " + errReason(err)}
	}
	for q := real; ; q = filepath.Dir(q) {
		fi, err := os.Lstat(q)
		if err != nil {
			return "", &OwnershipError{q, "cannot be inspected: " + errReason(err)}
		}
		if err := checkOwner(t, q, fi); err != nil {
			return "", err
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return "", &OwnershipError{q, fmt.Sprintf("is group- or other-writable (mode %04o)", fi.Mode().Perm())}
		}
		if q == "/" {
			break
		}
	}
	return real, nil
}

func checkOwner(t Trust, p string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return &OwnershipError{p, "has no owner information"}
	}
	if !t.Owns(st.Uid) {
		return &OwnershipError{p, fmt.Sprintf("is owned by uid %d, not a trusted owner", st.Uid)}
	}
	return nil
}

// checkFile checks an already-opened or stat'ed file: regular, trusted
// owner, not group/other-writable.
func checkFile(t Trust, p string, fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return &OwnershipError{p, "is not a regular file"}
	}
	if err := checkOwner(t, p, fi); err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return &OwnershipError{p, fmt.Sprintf("is group- or other-writable (mode %04o)", fi.Mode().Perm())}
	}
	return nil
}

// errReason drops the path from a PathError (the caller already names it).
func errReason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
