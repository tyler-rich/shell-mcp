//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

func runCmd(args []string, stdin string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestPolkitStub(t *testing.T) {
	code, out, errb := runCmd([]string{"polkit"}, "")
	if code != 2 || out != "" || !strings.Contains(errb, "polkit arrives in Session 1b") {
		t.Fatalf("polkit: %d %q %q", code, out, errb)
	}
}

// A malformed forced command still answers with one JSON response (so the
// server gets install_insecure, not a broken session), and exits 0.
func TestServeMalformedForcedCommand(t *testing.T) {
	for _, args := range [][]string{{"serve"}, {"serve", "--policy"}, {"serve", "--policy", "/x", "--bogus"}, {"serve", "--policy", "/x", "extra"}} {
		code, out, errb := runCmd(args, `{"v":1,"id":"a","op":"hello"}`+"\n")
		var r struct {
			OK    bool `json:"ok"`
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if code != 0 || errb != "" || json.Unmarshal([]byte(out), &r) != nil || r.OK || r.Error.Code != "install_insecure" {
			t.Fatalf("%v: %d %q %q", args, code, out, errb)
		}
	}
}

func TestCheckPolicy(t *testing.T) {
	if code, _, errb := runCmd([]string{"check-policy"}, ""); code != 2 || !strings.Contains(errb, "--policy") {
		t.Fatalf("usage: %d %q", code, errb)
	}
	// Under production trust a policy owned by the test uid fails the
	// ownership check; check-policy reports it and exits 1.
	d := gatetest.SecureDir(t)
	p := filepath.Join(d, "policy.yaml")
	gatetest.WriteFile(t, p, "version: 1\nmax_tier: read\n", 0o644)
	code, out, _ := runCmd([]string{"check-policy", "--policy", p}, "")
	if code != 1 || !strings.Contains(out, "FAIL") || !strings.Contains(out, "owned by uid") {
		t.Fatalf("check-policy: %d\n%s", code, out)
	}
	if !strings.Contains(out, "sandbox:") && !strings.Contains(out, "Landlock") {
		t.Fatalf("check-policy must report the sandbox probe:\n%s", out)
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := runCmd([]string{"version"}, "")
	if code != 0 || !strings.HasPrefix(out, "shell-mcp-gate dev") {
		t.Fatalf("version: exit %d, %q", code, out)
	}
}

func TestUnknownCommand(t *testing.T) {
	if code, _, _ := runCmd([]string{"exec"}, ""); code != 2 {
		t.Fatalf("unknown command exit %d", code)
	}
}
