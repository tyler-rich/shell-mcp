//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/install"
	"github.com/tyler-rich/shell-mcp/internal/gate/ops"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
)

// The subprocess integration tests run this package's own test binary,
// rebuilt with CGO_ENABLED=0, as the gate. When SHELL_MCP_GATE_HARNESS=1 the
// binary runs the real serve path (runWith) with options that differ from
// production only in trust (root and the test uid, so tests can own their
// fixtures) and a fake identity read from HARNESS_* variables. This code is
// in a _test.go file: no shipped binary can contain it.
const harnessEnv = "SHELL_MCP_GATE_HARNESS"

func TestMain(m *testing.M) {
	if os.Getenv(harnessEnv) == "1" {
		os.Exit(runWith(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, harnessOptions))
	}
	os.Exit(m.Run())
}

func harnessOptions(version, policyPath, principal string) (ops.Options, error) {
	exe, err := os.Executable()
	if err != nil {
		return ops.Options{}, err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return ops.Options{}, err
	}
	uid, _ := strconv.ParseUint(os.Getenv("HARNESS_UID"), 10, 32)
	names := map[uint32]string{}
	for _, kv := range strings.Split(os.Getenv("HARNESS_GROUPS"), ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			g, _ := strconv.ParseUint(k, 10, 32)
			names[uint32(g)] = v
		}
	}
	var gids []uint32
	for _, s := range strings.Split(os.Getenv("HARNESS_GIDS"), ",") {
		if g, err := strconv.ParseUint(s, 10, 32); err == nil {
			gids = append(gids, uint32(g))
		}
	}
	o := ops.Options{
		Version: version, PolicyPath: policyPath, Principal: principal,
		Identity: install.Identity{UID: uint32(uid), GIDs: gids, GroupName: func(gid uint32) (string, error) {
			if n, ok := names[gid]; ok {
				return n, nil
			}
			return "", os.ErrNotExist
		}},
		Trust:        policy.TrustForTesting(install.ID(os.Getuid())),
		Executable:   exe,
		ServiceHome:  os.Getenv("HARNESS_HOME"),
		ApplySandbox: sandbox.Apply,
	}
	if v, ok := os.LookupEnv("SSH_ORIGINAL_COMMAND"); ok {
		o.SSHOriginalCommand = &v
	}
	if os.Getenv("HARNESS_FAULT") == "readback" {
		o.InjectReadBackFault = func(b []byte) []byte { return append(bytes.Clone(b), '!') }
	}
	return o, nil
}
