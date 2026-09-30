//go:build linux

package units_test

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/units"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const hash = "3f2c9b8a7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a"

// Invented policies; nothing here describes a real host.
func minimalPolicy() *policy.Policy {
	return &policy.Policy{
		ClientUID: 60123, SocketGroup: "svc-shell-priv", SocketGID: 60124,
		MaxTier: policy.TierRead, Landlock: policy.LandlockRequired,
		Limits:       policy.Limits{MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxOutputBytes: 1 << 20, DefaultTimeoutS: 60, MaxTimeoutS: 900, MaxDeleteEntries: 1000},
		ModesMax:     0o755,
		BackupsKeep:  10,
		Capabilities: append([]string(nil), policy.BaseCapabilities...),
		SHA256:       hash,
		File:         "/etc/shell-mcp/privileged.yaml",
	}
}

func examplePolicy() *policy.Policy {
	p := minimalPolicy()
	p.MaxTier = policy.TierDestructive
	p.Limits.MaxTimeoutS = 120
	p.Paths.Read = []string{"/etc/example-app", "/var/log/example-app"}
	p.Paths.Write = []string{"/etc/example-app/conf.d", "/srv/app/config"}
	p.Paths.Persistence = []policy.Persistence{{Path: "/etc/systemd/system/example-app.service.d", Acknowledge: "drop-ins for example-app only"}}
	p.Commands = []policy.Command{
		{ID: "reboot-host", Unit: policy.UnitCore, Capabilities: []string{"CAP_SYS_BOOT"}, ListB: 11, Acknowledge: "planned maintenance only"},
		{ID: "stop-worker", Unit: policy.UnitCore, Capabilities: []string{"CAP_KILL"}},
	}
	p.Capabilities = []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_KILL", "CAP_SYS_BOOT"}
	return p
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil { //nolint:gosec // G306: golden test data
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p) //nolint:gosec // G304: this package's own test data
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from the golden file (run with -update after review):\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func generate(t *testing.T, p *policy.Policy) units.Files {
	t.Helper()
	f, err := units.Core(p)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestGolden(t *testing.T) {
	for name, p := range map[string]*policy.Policy{"minimal": minimalPolicy(), "example": examplePolicy()} {
		f := generate(t, p)
		golden(t, name+".socket.golden", f.Socket)
		golden(t, name+".service.golden", f.Service)
	}
}

// directives parses a unit file into section.key → values (in order).
func directives(t *testing.T, unit string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	section := ""
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("malformed line %q", line)
			}
			out[section+k] = append(out[section+k], v)
		}
	}
	return out
}

func want(t *testing.T, d map[string][]string, key string, values ...string) {
	t.Helper()
	if !slices.Equal(d[key], values) {
		t.Errorf("%s = %q, want %q", key, d[key], values)
	}
}

// TestSocketDirectives: PRIVILEGED §2 and §3 — one instance per
// connection, root:<socket group> 0660, and the socket directory created
// root-owned and traversable but not listable (DirectoryMode applies to
// the directories systemd creates, which stay root:root; SocketUser= and
// SocketGroup= apply to the socket node only).
func TestSocketDirectives(t *testing.T) {
	d := directives(t, generate(t, minimalPolicy()).Socket)
	want(t, d, "[Socket]ListenStream", "/run/shell-mcp/privd.sock")
	want(t, d, "[Socket]Accept", "yes")
	want(t, d, "[Socket]SocketUser", "root")
	want(t, d, "[Socket]SocketGroup", "svc-shell-priv")
	want(t, d, "[Socket]SocketMode", "0660")
	want(t, d, "[Socket]DirectoryMode", "0711")
	want(t, d, "[Socket]MaxConnections", "16")
	want(t, d, "[Install]WantedBy", "sockets.target")
}

// TestServiceDirectives: every PRIVILEGED §5.1 directive, exactly.
func TestServiceDirectives(t *testing.T) {
	d := directives(t, generate(t, examplePolicy()).Service)
	s := "[Service]"
	want(t, d, s+"ExecStart", "/usr/local/libexec/shell-mcp-privd serve --policy /etc/shell-mcp/privileged.yaml")
	want(t, d, s+"StandardInput", "socket")
	want(t, d, s+"StandardOutput", "socket")
	want(t, d, s+"StandardError", "journal")
	want(t, d, s+"SyslogIdentifier", "shell-mcp-privd")
	// The unit pins the policy hash and names the peer the helper serves:
	// the peer check needs no disk read (PRIVILEGED §7).
	want(t, d, s+"Environment", "SHELL_MCP_PRIVD_POLICY_SHA256="+hash, "SHELL_MCP_PRIVD_CLIENT_UID=60123")
	want(t, d, s+"User", "root")
	want(t, d, s+"NoNewPrivileges", "yes")
	want(t, d, s+"CapabilityBoundingSet", "CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_KILL CAP_SYS_BOOT")
	want(t, d, s+"ProtectSystem", "strict")
	want(t, d, s+"ReadWritePaths", "/etc/example-app/conf.d /srv/app/config /etc/systemd/system/example-app.service.d /var/lib/shell-mcp/backups")
	want(t, d, s+"InaccessiblePaths", "-/etc/shadow -/etc/shadow- -/etc/gshadow -/etc/gshadow- -/etc/sudoers -/etc/sudoers.d -/etc/security/opasswd -/etc/ssh -/root/.ssh")
	want(t, d, s+"ProtectHome", "read-only")
	for _, k := range []string{"PrivateTmp", "PrivateDevices", "PrivateNetwork", "ProtectKernelTunables", "ProtectKernelModules",
		"ProtectKernelLogs", "ProtectControlGroups", "ProtectClock", "ProtectHostname", "RestrictNamespaces", "RestrictRealtime",
		"RestrictSUIDSGID", "LockPersonality", "MemoryDenyWriteExecute"} {
		want(t, d, s+k, "yes")
	}
	want(t, d, s+"RestrictAddressFamilies", "AF_UNIX")
	want(t, d, s+"IPAddressDeny", "any")
	want(t, d, s+"SystemCallArchitectures", "native")
	// CAP_SYS_BOOT is declared, so @reboot is not removed; nothing else
	// changes for capabilities.
	want(t, d, s+"SystemCallFilter", "@system-service", "~@mount @module @swap @raw-io @debug @obsolete")
	want(t, d, s+"UMask", "0077")
	want(t, d, s+"RuntimeMaxSec", "150")
	want(t, d, s+"TasksMax", "64")
	want(t, d, s+"MemoryMax", "256M")
	want(t, d, "[Unit]CollectMode", "inactive-or-failed")
	// Nothing else: a directive the generator adds must be added here.
	if n := len(d); n != 38 {
		keys := make([]string, 0, n)
		for k := range d {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		t.Errorf("%d directives, want 38: %q", n, keys)
	}
}

func TestSyscallFilterWithoutCapabilities(t *testing.T) {
	d := directives(t, generate(t, minimalPolicy()).Service)
	want(t, d, "[Service]SystemCallFilter", "@system-service", "~@mount @module @reboot @swap @raw-io @debug @obsolete")
	want(t, d, "[Service]CapabilityBoundingSet", "CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER")
	want(t, d, "[Service]ReadWritePaths", "/var/lib/shell-mcp/backups")
	want(t, d, "[Service]RuntimeMaxSec", "930")
}

// The generator never widens the unit beyond the policy: capabilities
// outside the policy's computed set, broad commands and packages are
// refused rather than rendered.
func TestRefusesWhatTheCoreUnitCannotHold(t *testing.T) {
	// Control: the unmodified policy generates.
	if _, err := units.Core(examplePolicy()); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, mut := range map[string]func(p *policy.Policy){
		"unknown capability":  func(p *policy.Policy) { p.Capabilities = append(p.Capabilities, "CAP_SYS_MODULE") },
		"core-ineffective":    func(p *policy.Policy) { p.Capabilities = append(p.Capabilities, "CAP_SYS_TIME") },
		"missing base":        func(p *policy.Policy) { p.Capabilities = p.Capabilities[1:] },
		"broad command":       func(p *policy.Policy) { p.Commands = []policy.Command{{ID: "x", Unit: policy.UnitBroad}} },
		"packages":            func(p *policy.Policy) { p.Packages.Enabled = true },
		"no hash":             func(p *policy.Policy) { p.SHA256 = "" },
		"bad hash":            func(p *policy.Policy) { p.SHA256 = strings.ToUpper(hash) },
		"relative policy":     func(p *policy.Policy) { p.File = "privileged.yaml" },
		"timeout over limit":  func(p *policy.Policy) { p.Limits.MaxTimeoutS = policy.MaxTimeoutCeiling + 1 },
		"space in path":       func(p *policy.Policy) { p.Paths.Write = []string{"/srv/my app"} },
		"percent in path":     func(p *policy.Policy) { p.Paths.Write = []string{"/srv/app%h"} },
		"dollar in path":      func(p *policy.Policy) { p.Paths.Write = []string{"/srv/$app"} },
		"quote in path":       func(p *policy.Policy) { p.Paths.Write = []string{`/srv/"app`} },
		"backslash in path":   func(p *policy.Policy) { p.Paths.Write = []string{`/srv/a\x20b`} },
		"newline in path":     func(p *policy.Policy) { p.Paths.Write = []string{"/srv/a\nExecStartPre=/x"} },
		"dash-leading policy": func(p *policy.Policy) { p.File = "/etc/shell-mcp/-x.yaml" },
		"percent in policy":   func(p *policy.Policy) { p.File = "/etc/shell-mcp/%n.yaml" },
		"odd socket group":    func(p *policy.Policy) { p.SocketGroup = "svc shell" },
		"root as client":      func(p *policy.Policy) { p.ClientUID = 0 },
		"(uid_t)-1 as client": func(p *policy.Policy) { p.ClientUID = 4294967295 },
		"persistence space": func(p *policy.Policy) {
			p.Paths.Persistence = []policy.Persistence{{Path: "/etc/cron.d/a b", Acknowledge: "x"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := examplePolicy()
			mut(p)
			if f, err := units.Core(p); err == nil {
				t.Fatalf("generated:\n%s", f.Service)
			}
		})
	}
}
