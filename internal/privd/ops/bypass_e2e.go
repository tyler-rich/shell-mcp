//go:build linux && shellmcp_e2e_bypass

package ops

import (
	"encoding/json/jsontext"
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

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
}

type rawArgs struct {
	Path string `json:"path"`
}

type rawResult struct {
	Result string `json:"result"` // "OK" or the errno name
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
		return rawResult{errnoName(err)}, nil, nil
	}
	return rawResult{"OK"}, nil, nil
}

func (s *server) rawRead(raw jsontext.Value) (data any, warns []string, failure error) {
	var a rawArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if _, err := os.ReadFile(a.Path); err != nil {
		return rawResult{errnoName(err)}, nil, nil
	}
	return rawResult{"OK"}, nil, nil
}
