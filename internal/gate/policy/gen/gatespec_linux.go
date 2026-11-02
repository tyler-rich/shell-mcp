//go:build linux

package gen

import (
	"io"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// gateFields maps the gate loader's fields to the answers keys they come
// from (POLICY §9.1).
var gateFields = [][2]string{
	{"paths.read", "read"}, {"paths.write", "write"}, {"paths.deny", "deny"}, {"sandbox.landlock", "landlock"},
	{"services", "services"}, {"journal.units", "journal.units"}, {"git", "git"}, {"commands", "commands"},
}

// GateField rewrites one line of the gate loader's error to name its
// answers key, and the rule a protected-path refusal applies.
// GateField is a stub.
func GateField(line, preset string) string { return line }

func gateFieldImpl(line, preset string) string {
	l := LoaderField(line, "policy", gateFields, preset)
	if strings.Contains(l, "protected path") && !strings.Contains(l, "POLICY §3") {
		l += " (the gate's built-in protected set, POLICY §3)"
	}
	return l
}

// GateSpec is shell-mcp-gate policy new: the gate policy, loaded with the
// gate's own loader as serve loads it (exe is the running gate binary,
// resolved), and checkPolicy the gate's check-policy.
func GateSpec(h setupx.Host, exe string, checkPolicy func(path string, w io.Writer) int) *Spec {
	return &Spec{
		Command:    "shell-mcp-gate policy new",
		Kind:       "gate policy",
		Mode:       0o644,
		DefaultOut: func(a *Answers) string { return Dir + "/" + a.Preset + ".yaml" },
		Render:     RenderGate,
		Load: func(data []byte, p string, a *Answers) ([]string, error) {
			pol, err := policy.Parse(data, p, &policy.LoadOptions{Trust: policy.RootTrust(), GateExecutable: exe, ServiceHome: ServiceHome(h, a)})
			if err != nil {
				return nil, err
			}
			return pol.Warnings, nil
		},
		Field:       GateField,
		CheckPolicy: checkPolicy,
		Notes:       []string{"check-policy ran as root, so its identity checks describe root; shell-mcp-gate install runs it again as the service account and refuses on a FAIL"},
	}
}

// ServiceHome is the service account's home for the protected set: the
// user database's, else /var/lib/<user> (install's default).
func ServiceHome(h setupx.Host, a *Answers) string {
	if db, err := h.Accounts(); err == nil {
		if u, ok := db.User(a.Account.User); ok && u.Home != "" {
			return u.Home
		}
	}
	return "/var/lib/" + a.Account.User
}
