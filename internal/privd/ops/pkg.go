//go:build linux

package ops

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The package operations (PRIVILEGED §6), run by the broad unit's
// instance only: priv_pkg_update_index, priv_pkg_install, priv_pkg_upgrade,
// priv_pkg_remove, and the read-tier previews of the last three, which run
// the same transaction with apt-get -s.

// maxLockWait bounds the wait for a held dpkg or lists lock; it is also at
// most half of the request's timeout.
const maxLockWait = 60 * time.Second

type pkgArgs struct {
	Packages []string `json:"packages"`
}

type noArgs struct{}

type pkgData struct {
	Op              string   `json:"op"`
	Packages        []string `json:"packages"`
	ExitCode        *int     `json:"exit_code"`
	Signal          *string  `json:"signal"`
	TimedOut        bool     `json:"timed_out"`
	Stdout          string   `json:"stdout"`
	Stderr          string   `json:"stderr"`
	StdoutTruncated bool     `json:"stdout_truncated"`
	StderrTruncated bool     `json:"stderr_truncated"`
	Attempts        int      `json:"attempts"`
	LockWaitMS      int64    `json:"lock_wait_ms"`
	DurationMS      int64    `json:"duration_ms"`
}

type pkgVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type pkgUpgrade struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

type pkgRemoval struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Purge   bool   `json:"purge"`
}

type previewData struct {
	Op       string       `json:"op"`
	Packages []string     `json:"packages"`
	Install  []pkgVersion `json:"install"`
	Upgrade  []pkgUpgrade `json:"upgrade"`
	Remove   []pkgRemoval `json:"remove"`
	// Complete is false when the simulation failed, its output was cut, or
	// a change line did not parse: the lists may then be partial.
	Complete        bool    `json:"complete"`
	ExitCode        *int    `json:"exit_code"`
	Signal          *string `json:"signal"`
	Stderr          string  `json:"stderr"`
	StderrTruncated bool    `json:"stderr_truncated"`
	DurationMS      int64   `json:"duration_ms"`
}

func (s *server) pkgUpdateIndex(raw jsontext.Value) (any, []string, error) {
	return s.pkgOp(raw, pkg.OpUpdate, false)
}

func (s *server) pkgInstall(raw jsontext.Value) (any, []string, error) {
	return s.pkgOp(raw, pkg.OpInstall, false)
}

func (s *server) pkgInstallPreview(raw jsontext.Value) (any, []string, error) {
	return s.pkgOp(raw, pkg.OpInstall, true)
}

func (s *server) pkgUpgrade(raw jsontext.Value) (any, []string, error) {
	return s.pkgOp(raw, pkg.OpUpgrade, false)
}

func (s *server) pkgUpgradePreview(raw jsontext.Value) (any, []string, error) {
	return s.pkgOp(raw, pkg.OpUpgrade, true)
}

func (s *server) pkgRemove(raw jsontext.Value) (any, []string, error) {
	return s.pkgOp(raw, pkg.OpRemove, false)
}

func (s *server) pkgRemovePreview(raw jsontext.Value) (any, []string, error) {
	return s.pkgOp(raw, pkg.OpRemove, true)
}

// pkgOp checks the request against the packages section and runs apt-get
// with the fixed argv for op.
func (s *server) pkgOp(raw jsontext.Value, op pkg.Op, simulate bool) (any, []string, error) {
	var names []string
	if op == pkg.OpInstall || op == pkg.OpRemove {
		var a pkgArgs
		if err := decode(raw, &a); err != nil {
			return nil, nil, err
		}
		if a.Packages == nil {
			return nil, nil, errf(protocol.CodeBadRequest, "packages is required")
		}
		names = a.Packages
	} else if err := decode(raw, &noArgs{}); err != nil {
		return nil, nil, err
	}
	pp := &s.p.Packages
	if !pp.Enabled {
		return nil, nil, errf(protocol.CodePolicyDenied, "package operations are not enabled in the privileged policy")
	}
	args, err := pkg.Args(op, simulate, names)
	if err != nil {
		return nil, nil, errf(protocol.CodeBadRequest, "packages: %s", err.Error())
	}
	switch op {
	case pkg.OpUpdate:
		if !pp.AllowUpdateIndex {
			return nil, nil, errf(protocol.CodePolicyDenied, "packages.allow_update_index is not set")
		}
	case pkg.OpUpgrade:
		if !pp.AllowUpgrade {
			return nil, nil, errf(protocol.CodePolicyDenied, "packages.allow_upgrade is not set")
		}
	case pkg.OpInstall, pkg.OpRemove:
		allowed, list := pp.Install, "packages.install"
		if op == pkg.OpRemove {
			allowed, list = pp.Remove, "packages.remove"
		}
		for _, n := range names {
			if !slices.Contains(allowed, n) {
				return nil, nil, errf(protocol.CodePolicyDenied, "package %s is not in %s", n, list)
			}
		}
	}
	timeout := s.timeout()
	r := pkg.Runner{
		AptGet:    pp.AptGet,
		Env:       pkg.Env(execHome),
		MaxOutput: s.p.Limits.MaxOutputBytes,
		LockWait:  min(maxLockWait, timeout/2),
		Retry:     s.o.PkgLockRetry,
	}
	res, err := r.Run(context.Background(), timeout, args)
	if errors.Is(err, pkg.ErrLockHeld) {
		return nil, nil, errf(protocol.CodeExecFailed, "the package database is locked by another process (waited %d s for the dpkg or package-list lock); try again later", res.LockWait.Milliseconds()/1000)
	}
	if err != nil {
		return nil, nil, err
	}
	maxOut := s.p.Limits.MaxOutputBytes
	stdout, cutOut := s.red.Truncate(res.Stdout, maxOut)
	stderr, cutErr := s.red.Truncate(res.Stderr, maxOut)
	var signal *string
	if res.Signal != "" {
		sig := res.Signal
		signal = &sig
	}
	if names == nil {
		names = []string{}
	}
	if simulate {
		// The simulation is parsed from the full captured output (before
		// the cut to max_output_bytes, never returned as text).
		sim := pkg.ParseSimulation(res.Stdout)
		d := previewData{
			Op: string(op), Packages: names,
			Install: []pkgVersion{}, Upgrade: []pkgUpgrade{}, Remove: []pkgRemoval{},
			ExitCode: res.ExitCode, Signal: signal, Stderr: string(stderr), StderrTruncated: res.StderrTruncated || cutErr,
			DurationMS: res.Duration.Milliseconds(),
		}
		for _, v := range sim.Install {
			d.Install = append(d.Install, pkgVersion{Name: v.Name, Version: v.Version})
		}
		for _, u := range sim.Upgrade {
			d.Upgrade = append(d.Upgrade, pkgUpgrade{Name: u.Name, From: u.From, To: u.To})
		}
		for _, rm := range sim.Remove {
			d.Remove = append(d.Remove, pkgRemoval{Name: rm.Name, Version: rm.Version, Purge: rm.Purge})
		}
		d.Complete = res.ExitCode != nil && *res.ExitCode == 0 && !res.StdoutTruncated && sim.Unparsed == 0 && !res.TimedOut
		return d, nil, nil
	}
	var warnings []string
	if res.OutputCeilingHit {
		warnings = append(warnings, "output exceeded the hard ceiling; the process group was killed")
	}
	return pkgData{
		Op: string(op), Packages: names,
		ExitCode: res.ExitCode, Signal: signal, TimedOut: res.TimedOut,
		Stdout: string(stdout), Stderr: string(stderr),
		StdoutTruncated: res.StdoutTruncated || cutOut, StderrTruncated: res.StderrTruncated || cutErr,
		Attempts: res.Attempts, LockWaitMS: res.LockWait.Milliseconds(), DurationMS: res.Duration.Milliseconds(),
	}, warnings, nil
}
