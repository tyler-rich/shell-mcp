package transport

import (
	"net"
	"strings"
	"testing"
)

// FuzzHostAllowed: a Host is allowed only if its name equals an entry's
// name exactly (case-insensitively) and its port, if the entry names one,
// equals the entry's port.
func FuzzHostAllowed(f *testing.F) {
	for _, s := range []string{"localhost", "localhost:8080", "[::1]:8080", "mcp.example.test.", "evil.example.test", ":80", "[::1", "a:b:c", ""} {
		f.Add(s)
	}
	allowed := parseHostList([]string{"localhost", "127.0.0.1", "mcp.example.test", "[::1]:8080"})
	f.Fuzz(func(t *testing.T, host string) {
		if !hostAllowed(host, allowed) {
			return
		}
		h := strings.ToLower(host)
		name, port, err := net.SplitHostPort(h)
		if err != nil {
			name, port = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"), ""
		}
		switch name {
		case "localhost", "127.0.0.1", "mcp.example.test":
		case "::1":
			if port != "8080" {
				t.Fatalf("%q allowed with port %q", host, port)
			}
		default:
			t.Fatalf("%q allowed (name %q)", host, name)
		}
	})
}
