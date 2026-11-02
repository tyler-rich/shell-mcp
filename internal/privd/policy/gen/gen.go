// Package gen is shell-mcp-privd policy new's half (docs/POLICY.md §9):
// the privileged policy rendered from the answers file's root: section and
// the privileged example, with internal/gate/policy/gen's decoder,
// template and run. It lives here, not in the gate's package, so that the
// gate binary never links the privileged policy or its loader.
package gen

import (
	_ "embed"
	"fmt"

	ggen "github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
)

// The admin preset's privileged half (POLICY §9.2): a byte copy of
// examples/privileged/privileged.yaml, which a test holds equal to it.
//
//go:embed privileged.yaml
var preset []byte

// Preset is the privileged example the policy renders from.
func Preset() []byte { return append([]byte(nil), preset...) }

// Render renders the privileged policy for a's root: section (POLICY §9.3)
// and checks that it holds exactly the answers' values and the preset's.
// Render is a stub.
func Render(a *ggen.Answers) ([]byte, error) { return nil, nil }

func renderImpl(a *ggen.Answers) ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if a.Root == nil {
		return nil, &ggen.Error{Key: "root", Msg: "is absent: these answers enable no root actions, so there is no privileged policy to write"}
	}
	t, err := ggen.ParseTemplate(preset)
	if err != nil {
		return nil, err
	}
	o := &ggen.Out{}
	o.Header(t, a.Root.Comment)
	for _, n := range t.Nodes {
		renderNode(o, n, a)
	}
	b, err := o.Bytes()
	if err != nil {
		return nil, err
	}
	if err := ggen.CheckValues(b, values(t, a)); err != nil {
		return nil, err
	}
	return b, nil
}

func unknown(o *ggen.Out, key string) {
	o.Fail(fmt.Errorf("template: %s is not known to policy new", key))
}

func list(o *ggen.Out, k *ggen.Node, l []string, q func(string) string) {
	if len(l) > 0 {
		o.Value(k, o.Flow(l, q))
	}
}

func spaces(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}

func renderNode(o *ggen.Out, n *ggen.Node, a *ggen.Answers) {
	r := a.Root
	switch n.Key {
	case "version", "max_tier", "limits", "modes", "backups":
		o.Verbatim(n)
	case "client_uid":
		o.Value(n, ggen.Int(a.Account.UID))
	case "socket_group":
		o.Value(n, o.Plain(r.SocketGroup.Name))
	case "sandbox":
		o.Section(n, func(o *ggen.Out) {
			for _, k := range n.Kids {
				if k.Key == "landlock" && a.Landlock != "" {
					o.Value(k, a.Landlock)
				} else {
					o.Verbatim(k)
				}
			}
		})
	case "paths":
		o.Section(n, func(o *ggen.Out) {
			for _, k := range n.Kids {
				switch k.Key {
				case "read":
					list(o, k, r.Read, o.Plain)
				case "write":
					list(o, k, r.Write, o.Plain)
				case "deny":
					list(o, k, a.Deny, o.Quoted)
				case "persistence":
					if len(r.Persistence) == 0 {
						continue
					}
					o.Lines(k.Lead)
					o.Line(ggen.WithValue(k, ""))
					pad := spaces(k.Indent + 2)
					for _, p := range r.Persistence {
						o.Line(pad + "- path: " + o.Plain(p.Path))
						o.Line(pad + "  acknowledge: " + o.Quoted(p.Acknowledge))
					}
				default:
					unknown(o, "paths."+k.Key)
				}
			}
		})
	case "owners":
		if r.Owners == nil {
			return
		}
		o.Section(n, func(o *ggen.Out) {
			for _, k := range n.Kids {
				switch k.Key {
				case "users":
					list(o, k, r.Owners.Users, o.Plain)
				case "groups":
					list(o, k, r.Owners.Groups, o.Plain)
				default:
					unknown(o, "owners."+k.Key)
				}
			}
		})
	case "commands":
		if len(r.Commands) == 0 {
			return
		}
		o.Lines(n.Lead)
		o.Line(ggen.WithValue(n, ""))
		pad := spaces(n.Indent + 2)
		for i := range r.Commands {
			c := &r.Commands[i]
			o.Comment(n.Indent+2, c.Comment)
			o.Line(pad + "- id: " + o.Plain(c.ID))
			o.Line(pad + "  path: " + o.Plain(c.Path))
			o.Line(pad + "  tier: " + o.Plain(c.Tier))
			if c.Unit != "" {
				o.Line(pad + "  unit: " + o.Plain(c.Unit))
			}
			if c.Description != "" {
				o.Line(pad + "  description: " + o.Quoted(c.Description))
			}
			if c.RootEquivalent {
				o.Line(pad + "  root_equivalent: true")
			}
			if c.ReadsPrivateKeys {
				o.Line(pad + "  reads_private_keys: true")
			}
			if len(c.Capabilities) > 0 {
				o.Line(pad + "  capabilities: " + o.Flow(c.Capabilities, o.Plain))
			}
			if c.Acknowledge != "" {
				o.Line(pad + "  acknowledge: " + o.Quoted(c.Acknowledge))
			}
			tpls := make([]string, len(c.Templates))
			for i, t := range c.Templates {
				tpls[i] = o.Flow(t, o.Quoted)
			}
			o.Line(pad + "  templates: [" + join(tpls) + "]")
		}
	case "power":
		if r.Power == nil {
			return
		}
		o.Section(n, func(o *ggen.Out) {
			for _, k := range n.Kids {
				switch k.Key {
				case "allowed":
					list(o, k, r.Power.Allowed, o.Plain)
				case "acknowledge":
					o.Value(k, o.Quoted(r.Power.Acknowledge))
				default:
					unknown(o, "power."+k.Key)
				}
			}
		})
	case "packages":
		p := r.Packages
		if p == nil {
			return
		}
		o.Section(n, func(o *ggen.Out) {
			for _, k := range n.Kids {
				switch k.Key {
				case "enabled", "manager":
					o.Verbatim(k)
				case "install":
					list(o, k, p.Install, o.Plain)
				case "remove":
					list(o, k, p.Remove, o.Plain)
				case "allow_update_index":
					o.Value(k, boolText(p.AllowUpdateIndex))
				case "allow_upgrade":
					o.Value(k, boolText(p.AllowUpgrade))
				case "allow_recover":
					o.Value(k, boolText(p.AllowRecover))
				default:
					unknown(o, "packages."+k.Key)
				}
			}
		})
	default:
		unknown(o, n.Key)
	}
}

func join(l []string) string {
	s := ""
	for i, e := range l {
		if i > 0 {
			s += ", "
		}
		s += e
	}
	return s
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// values is what the privileged policy must hold: the preset's values, with
// every key the answers decide replaced by the answers' values.
func values(t *ggen.Template, a *ggen.Answers) map[string]any {
	r := a.Root
	w := t.Clone()
	w["client_uid"] = int(a.Account.UID)
	w["socket_group"] = r.SocketGroup.Name
	if a.Landlock != "" {
		if s := ggen.Sub(w, "sandbox"); s != nil {
			s["landlock"] = a.Landlock
		}
	}
	paths := map[string]any{}
	ggen.SetOrDelete(paths, "read", ggen.Strings(r.Read))
	ggen.SetOrDelete(paths, "write", ggen.Strings(r.Write))
	pers := make([]any, len(r.Persistence))
	for i, p := range r.Persistence {
		pers[i] = map[string]any{"path": p.Path, "acknowledge": p.Acknowledge}
	}
	ggen.SetOrDelete(paths, "persistence", pers)
	ggen.SetOrDelete(paths, "deny", ggen.Strings(a.Deny))
	ggen.SetOrDelete(w, "paths", paths)

	var owners map[string]any
	if r.Owners != nil {
		owners = map[string]any{}
		ggen.SetOrDelete(owners, "users", ggen.Strings(r.Owners.Users))
		ggen.SetOrDelete(owners, "groups", ggen.Strings(r.Owners.Groups))
	}
	ggen.SetOrDelete(w, "owners", owners)

	cmds := make([]any, len(r.Commands))
	for i := range r.Commands {
		c := &r.Commands[i]
		m := map[string]any{"id": c.ID, "path": c.Path, "tier": c.Tier, "templates": ggen.Templates(c.Templates)}
		for k, v := range map[string]string{"unit": c.Unit, "description": c.Description, "acknowledge": c.Acknowledge} {
			if v != "" {
				m[k] = v
			}
		}
		if c.RootEquivalent {
			m["root_equivalent"] = true
		}
		if c.ReadsPrivateKeys {
			m["reads_private_keys"] = true
		}
		if len(c.Capabilities) > 0 {
			m["capabilities"] = ggen.Strings(c.Capabilities)
		}
		cmds[i] = m
	}
	ggen.SetOrDelete(w, "commands", cmds)

	var power map[string]any
	if r.Power != nil {
		power = map[string]any{"acknowledge": r.Power.Acknowledge}
		ggen.SetOrDelete(power, "allowed", ggen.Strings(r.Power.Allowed))
	}
	ggen.SetOrDelete(w, "power", power)

	var pkgs map[string]any
	if p := r.Packages; p != nil {
		pkgs = map[string]any{"allow_update_index": p.AllowUpdateIndex, "allow_upgrade": p.AllowUpgrade, "allow_recover": p.AllowRecover}
		for _, k := range []string{"enabled", "manager"} {
			if v, ok := ggen.Sub(t.Values, "packages")[k]; ok {
				pkgs[k] = v
			}
		}
		ggen.SetOrDelete(pkgs, "install", ggen.Strings(p.Install))
		ggen.SetOrDelete(pkgs, "remove", ggen.Strings(p.Remove))
	}
	ggen.SetOrDelete(w, "packages", pkgs)
	return w
}
