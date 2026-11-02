package compose_test

import (
	"bytes"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/tyler-rich/shell-mcp/internal/setup/compose"
)

// FuzzParseImage: whatever is accepted is exactly repository[:tag]@sha256:digest
// in YAML-plain characters, with a 64-character lower-case hex digest.
func FuzzParseImage(f *testing.F) {
	for _, s := range []string{image3, "ghcr.io/tyler-rich/shell-mcp@sha256:" + digest, "a:b@sha256:" + digest, "x", "a@sha256:" + strings.Repeat("g", 64)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		img, err := compose.ParseImage(s)
		if err != nil {
			return
		}
		re := img.Repository
		if img.Tag != "" {
			re += ":" + img.Tag
		}
		if re+"@sha256:"+img.Digest != s || len(img.Digest) != 64 || strings.Trim(img.Digest, "0123456789abcdef") != "" {
			t.Fatalf("accepted %q as %+v", s, img)
		}
		if strings.ContainsAny(s, " \t\r\n#'\"{}[],&*!|>%`\\") {
			t.Fatalf("accepted %q with a YAML-special character", s)
		}
	})
}

// FuzzRender: any value set Check accepts renders to a compose file that
// parses, keeps the hardening keys, and carries each value verbatim, with no
// key added by a value.
func FuzzRender(f *testing.F) {
	f.Add(image3, pin1, "app-host", "target-a.example.test", "svc-shell", "mcp.example.test", "192.0.2.0/24", "192.0.2.10", "192.0.2.5", "operator", "approve.example.test", "bind", "/srv/shell-mcp/secrets")
	f.Add(image3, pin2, "a", "192.0.2.20", "u", "m", "172.16.0.0/16", "172.16.2.3", "172.16.2.4", "read-only", "", "secrets", "")
	f.Fuzz(func(t *testing.T, img, pin, name, host, user, mcp, subnet, server, proxy, profile, approve, form, dir string) {
		args := []string{"--image", img, "--host-key", pin, "--target-name", name, "--target-host", host, "--target-user", user,
			"--mcp-host", mcp, "--subnet", subnet, "--server-addr", server, "--proxy-addr", proxy, "--profile", profile, "--form", form}
		if approve != "" {
			args = append(args, "--approve-host", approve)
		}
		if dir != "" {
			args = append(args, "--dir", dir)
		}
		v, err := compose.ParseFlags(args)
		if err != nil {
			return
		}
		if _, cerr := v.Check(); cerr != nil {
			return
		}
		out, err := compose.Render(v)
		if err != nil {
			t.Fatalf("Render of checked values: %v", err)
		}
		var d doc
		dec := yaml.NewDecoder(bytes.NewReader(out))
		dec.KnownFields(true)
		if err := dec.Decode(&d); err != nil {
			t.Fatalf("not YAML: %v\n%s", err, out)
		}
		svc := d.Services["shell-mcp"]
		if len(d.Services) != 1 || svc["image"] != img || svc["user"] != "65532:65532" || svc["read_only"] != true {
			t.Fatalf("service changed: %#v", svc)
		}
		e, ok := svc["environment"].(map[string]any)
		if !ok {
			t.Fatalf("environment %#v", svc["environment"])
		}
		want := map[string]string{"SHELL_MCP_TARGET_NAME": name, "SHELL_MCP_TARGET_HOST": host, "SHELL_MCP_TARGET_USER": user,
			"SHELL_MCP_TARGET_HOST_KEYS": pin, "SHELL_MCP_PROFILE": profile, "SHELL_MCP_TRUSTED_PROXIES": proxy,
			"SHELL_MCP_ALLOWED_HOSTS": "localhost,127.0.0.1," + mcp}
		for k, w := range want {
			if e[k] != w {
				t.Fatalf("%s = %#v, want %q", k, e[k], w)
			}
		}
		n := 10
		if approve != "" {
			n += 4
		}
		if len(e) != n {
			t.Fatalf("%d variables, want %d: %v", len(e), n, e)
		}
	})
}
