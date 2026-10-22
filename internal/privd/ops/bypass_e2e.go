//go:build linux && shellmcp_e2e_bypass

package ops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// This file is compiled only into the end-to-end test build of the helper
// (-tags shellmcp_e2e_bypass). It must never be part of a release: it adds
// operations that bypass every check of this helper — fsx confinement, the
// deny and never lists — and it skips Landlock, so that the e2e job can
// show that the generated unit's systemd sandbox (ProtectSystem=strict,
// ReadWritePaths=, InaccessiblePaths=) confines a helper whose own checks
// are gone.

func init() {
	BypassBuild = true
	extraOps["bypass_raw_write"] = opSpec{policy.TierRead, (*server).rawWrite}
	extraOps["bypass_raw_read"] = opSpec{policy.TierRead, (*server).rawRead}
	pkgHook = e2ePkgHook
}

// The e2e tests' package hook (written by them, root's): e2ePkgHookFile
// names the stage of the next package operation at which e2ePkgHook
// replaces the local repository e2eRepo with the one staged in
// e2eRepoNext and updates the package index. The repository is staged
// rather than written in place because apt's file: method links a flat
// repository's index into its lists, so a repository written in place
// changes what apt resolves at once, before the stage.
const (
	e2ePkgHookFile = "/run/shell-mcp-e2e-pkg-hook"
	e2eRepo        = "/srv/e2e-apt"
	e2eRepoNext    = "/srv/e2e-apt-next"
)

// e2ePkgHook swaps in the staged repository and updates the package index
// (apt-get -q update, through the helper's exec engine) at the stage the
// hook file names, once, so that the e2e tests can change what apt
// resolves between the operation's own steps (TestPackageChangedBeforeRun,
// TestPackageUpgradeExactList).
func e2ePkgHook(s *server, stage string) {
	b, err := os.ReadFile(e2ePkgHookFile)
	if err != nil || strings.TrimSpace(string(b)) != stage {
		return
	}
	_ = os.Remove(e2ePkgHookFile)
	if next, err := os.ReadDir(e2eRepoNext); err == nil {
		if old, err := os.ReadDir(e2eRepo); err == nil {
			for _, e := range old {
				_ = os.Remove(filepath.Join(e2eRepo, e.Name()))
			}
		}
		for _, e := range next {
			_ = os.Rename(filepath.Join(e2eRepoNext, e.Name()), filepath.Join(e2eRepo, e.Name()))
		}
		_ = os.Remove(e2eRepoNext)
	}
	argv, _ := pkg.Args(pkg.OpUpdate, false, nil)
	_, _ = execx.Run(context.Background(), &execx.Spec{Trampoline: s.o.Executable, Path: s.o.AptGet, Args: argv, Env: s.aptEnv(), Dir: "/",
		Timeout: time.Minute, MaxOutput: 64 << 10})
}

type rawArgs struct {
	Path string `json:"path"`
}

type rawResult struct {
	Result string `json:"result"` // "OK" or the errno name
	// Bytes and SHA256 describe what a read returned: InaccessiblePaths=
	// mounts an empty mode-0000 node that root (CAP_DAC_READ_SEARCH) can
	// open, so "OK" alone does not tell a hidden file from the real one.
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256,omitempty"`
}

func errnoName(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return unix.ErrnoName(errno)
	}
	return "ERR"
}

func (s *server) rawWrite(raw jsontext.Value) (data any, warns []string, failure error) {
	var a rawArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(a.Path, []byte("e2e bypass write\n"), 0o600); err != nil {
		return rawResult{Result: errnoName(err)}, nil, nil
	}
	return rawResult{Result: "OK"}, nil, nil
}

func (s *server) rawRead(raw jsontext.Value) (data any, warns []string, failure error) {
	var a rawArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(a.Path)
	if err != nil {
		return rawResult{Result: errnoName(err)}, nil, nil
	}
	sum := sha256.Sum256(b)
	return rawResult{Result: "OK", Bytes: len(b), SHA256: hex.EncodeToString(sum[:])}, nil, nil
}
