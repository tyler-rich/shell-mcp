package transport

import (
	"net"
	"slices"
	"strings"
)

// hostEntry is one SHELL_MCP_ALLOWED_HOSTS entry: a name or IP address,
// and a port when the entry names one (then only that port matches).
type hostEntry struct {
	name, port string
}

func parseHostList(list []string) []hostEntry {
	out := make([]hostEntry, 0, len(list))
	for _, e := range list {
		if name, port, ok := splitHost(strings.ToLower(e)); ok {
			out = append(out, hostEntry{name, port})
		}
	}
	return out
}

// splitHost splits "name", "name:port", "[v6]" or "[v6]:port" (a bare
// IPv6 address is accepted too, for allow-list entries). The port, when
// present, is 1–5 digits.
func splitHost(s string) (name, port string, ok bool) {
	switch {
	case s == "":
		return "", "", false
	case strings.HasPrefix(s, "["):
		if strings.HasSuffix(s, "]") {
			return s[1 : len(s)-1], "", true
		}
		h, p, err := net.SplitHostPort(s)
		if err != nil || !validPort(p) {
			return "", "", false
		}
		return h, p, true
	case strings.Count(s, ":") == 1:
		h, p, err := net.SplitHostPort(s)
		if err != nil || h == "" || !validPort(p) {
			return "", "", false
		}
		return h, p, true
	}
	return s, "", true
}

func validPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	for i := range len(p) {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
	}
	return true
}

// hostAllowed matches the request's Host exactly (case-insensitively)
// against the allow-list: no suffix or wildcard matching, no trailing dot.
func hostAllowed(host string, allowed []hostEntry) bool {
	name, port, ok := splitHost(strings.ToLower(host))
	if !ok || name == "" {
		return false
	}
	return slices.ContainsFunc(allowed, func(e hostEntry) bool {
		return e.name == name && (e.port == "" || e.port == port)
	})
}

// originAllowed matches the Origin header exactly (case-insensitively)
// against the allow-list (entries are lowercased by config). An empty list
// allows no Origin at all, "null" included.
func originAllowed(origin string, allowed []string) bool {
	return slices.Contains(allowed, strings.ToLower(origin))
}
