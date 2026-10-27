//go:build linux

package units

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// ProtectHome= values of the core unit.
const (
	// protectHomeHidden hides /home, /root and /run/user completely.
	protectHomeHidden = "yes"
	// protectHomeReadOnly leaves them visible and read-only.
	protectHomeReadOnly = "read-only"
)

// homeDirs are the directories ProtectHome=yes makes inaccessible.
var homeDirs = []string{"/home", "/root", "/run/user"}

// ProtectHome returns the core unit's ProtectHome= for the policy (handoff
// N-28) and, when it is read-only, the path that keeps it so.
//
// "yes" hides /home, /root and /run/user entirely, so it is chosen only
// when nothing the instance has to see lies in or under any of them: no
// read, write or persistence root (a write root there also needs its
// ReadWritePaths= entry, which "yes" would leave empty), no command binary
// or interpreter, and not the policy file its ExecStart= reads. Otherwise
// the directive stays "read-only". Every such path is judged as written and
// as it resolves (a link into /home is under /home); a path that cannot be
// resolved, such as a link loop or a dangling link, counts as under them,
// and the part of a path that does not exist yet is judged below its
// deepest existing ancestor.
func ProtectHome(p *policy.Policy) (value, because string) {
	var paths []string
	paths = append(paths, p.Paths.Read...)
	paths = append(paths, p.Paths.WriteRoots()...)
	paths = append(paths, p.File)
	for i := range p.Commands {
		paths = append(paths, p.Commands[i].Resolved, p.Commands[i].Interpreter)
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if underHomeDirs(path) {
			return protectHomeReadOnly, path
		}
		if r, err := resolveLoose(path); err != nil || underHomeDirs(r) {
			return protectHomeReadOnly, path
		}
	}
	return protectHomeHidden, ""
}

// underHomeDirs reports whether p is, is inside, or contains one of homeDirs.
func underHomeDirs(p string) bool {
	for _, d := range homeDirs {
		if pathx.Within(d, p) || pathx.Within(p, d) {
			return true
		}
	}
	return false
}

// resolveLoose resolves symbolic links in p like filepath.EvalSymlinks, but
// a part that does not exist yet is kept as written below the resolved
// deepest existing ancestor. A dangling link is an error, as is anything
// but "does not exist".
func resolveLoose(p string) (string, error) {
	rest := ""
	for cur := filepath.Clean(p); ; cur = filepath.Dir(cur) {
		r, err := filepath.EvalSymlinks(cur)
		switch {
		case err == nil:
			return filepath.Join(r, rest), nil
		case !errors.Is(err, fs.ErrNotExist):
			return "", err
		}
		if _, lerr := os.Lstat(cur); lerr == nil {
			return "", err // a link whose target is missing
		}
		if cur == "/" {
			return "", err
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}
