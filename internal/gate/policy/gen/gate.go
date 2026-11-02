package gen

import (
	"embed"
	"fmt"
)

// The gate presets (POLICY §9.2): byte copies of examples/policies, which a
// test holds equal to them (go:embed cannot name a path with "..").
//
//go:embed presets/*.yaml
var presets embed.FS

// Preset returns the example file a gate preset renders from.
func Preset(name string) ([]byte, error) {
	switch name {
	case PresetReadOnly, PresetOperator, PresetAdmin:
		return presets.ReadFile("presets/" + name + ".yaml")
	}
	return nil, fmt.Errorf("unknown preset %q", name)
}

// RenderGate renders the gate policy for a (POLICY §9.3) from its preset,
// and checks that the result holds exactly the answers' values and the
// preset's.
func RenderGate(a *Answers) ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	src, err := Preset(a.Preset)
	if err != nil {
		return nil, err
	}
	t, err := ParseTemplate(src)
	if err != nil {
		return nil, err
	}
	o := &Out{}
	o.Header(t, a.Header)
	for _, n := range t.Nodes {
		renderGateNode(o, n, a)
	}
	b, err := o.Bytes()
	if err != nil {
		return nil, err
	}
	if err := CheckValues(b, gateValues(t, a)); err != nil {
		return nil, err
	}
	return b, nil
}

func renderGateNode(o *Out, n *Node, a *Answers) {
	switch n.Key {
	case "version", "max_tier", "limits", "redact":
		o.Verbatim(n)
	case "sandbox":
		o.Section(n, func(o *Out) {
			for _, k := range n.Kids {
				if k.Key == "landlock" && a.Landlock != "" {
					o.Value(k, a.Landlock)
				} else {
					o.Verbatim(k)
				}
			}
		})
	case "paths":
		o.Section(n, func(o *Out) {
			for _, k := range n.Kids {
				switch k.Key {
				case "read":
					list(o, k, a.Read, o.Plain)
				case "write":
					list(o, k, a.Write, o.Plain)
				case "deny":
					list(o, k, a.Deny, o.Quoted)
				default:
					o.Fail(fmt.Errorf("template: paths.%s is not known to policy new", k.Key))
				}
			}
		})
	case "services":
		if a.Services == nil {
			return
		}
		o.Section(n, func(o *Out) {
			for _, k := range n.Kids {
				switch k.Key {
				case "status":
					list(o, k, a.Services.Status, o.Quoted)
				case "control":
					c := a.Services.Control
					if c == nil {
						continue
					}
					o.Section(k, func(o *Out) {
						for _, kk := range k.Kids {
							switch kk.Key {
							case "units":
								list(o, kk, c.Units, o.Quoted)
							case "verbs":
								list(o, kk, c.Verbs, o.Plain)
							default:
								o.Fail(fmt.Errorf("template: services.control.%s is not known to policy new", kk.Key))
							}
						}
					})
				default:
					o.Fail(fmt.Errorf("template: services.%s is not known to policy new", k.Key))
				}
			}
		})
	case "journal":
		if a.Journal == nil {
			return
		}
		o.Section(n, func(o *Out) {
			for _, k := range n.Kids {
				switch k.Key {
				case "units":
					list(o, k, a.Journal.Units, o.Quoted)
				case "max_lines":
					o.Verbatim(k)
				default:
					o.Fail(fmt.Errorf("template: journal.%s is not known to policy new", k.Key))
				}
			}
		})
	case "git":
		if a.Git == nil {
			return
		}
		o.Section(n, func(o *Out) {
			for _, k := range n.Kids {
				if k.Key != "repos" {
					o.Fail(fmt.Errorf("template: git.%s is not known to policy new", k.Key))
					continue
				}
				o.Lines(k.Lead)
				o.Line(WithValue(k, ""))
				pad := spaces(k.Indent + 2)
				for _, r := range a.Git.Repos {
					o.Line(pad + "- path: " + o.Plain(r.Path))
					o.Line(pad + "  remote: " + o.Plain(r.Remote))
				}
			}
		})
	case "privileged":
		if a.Root == nil {
			return
		}
		o.Section(n, func(o *Out) {
			for _, k := range n.Kids {
				if k.Key == "broad_socket" && !a.UsesBroad() {
					continue
				}
				o.Verbatim(k)
			}
		})
	case "commands":
		if len(a.Commands) == 0 {
			return
		}
		o.Lines(n.Lead)
		o.Line(WithValue(n, ""))
		pad := spaces(n.Indent + 2)
		for _, c := range a.Commands {
			o.Comment(n.Indent+2, c.Comment)
			o.Line(pad + "- id: " + o.Plain(c.ID))
			o.Line(pad + "  path: " + o.Plain(c.Path))
			o.Line(pad + "  tier: " + o.Plain(c.Tier))
			if c.Description != "" {
				o.Line(pad + "  description: " + o.Quoted(c.Description))
			}
			if c.RootEquivalent {
				o.Line(pad + "  root_equivalent: true")
			}
			if c.ReadsPrivateKeys {
				o.Line(pad + "  reads_private_keys: true")
			}
			if len(c.Templates) == 0 {
				o.Line(pad + "  templates: []")
				continue
			}
			o.Line(pad + "  templates:")
			for _, tpl := range c.Templates {
				o.Line(pad + "    - " + o.Flow(tpl, o.Quoted))
			}
		}
	default:
		o.Fail(fmt.Errorf("template: %s is not known to policy new", n.Key))
	}
}

// list adds a flow-list key when l is not empty.
func list(o *Out, k *Node, l []string, q func(string) string) {
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

// gateValues is what the gate policy must hold: the preset's values, with
// every section the answers decide replaced by the answers' values.
func gateValues(t *Template, a *Answers) map[string]any {
	w := t.Clone()
	if a.Landlock != "" {
		if s := Sub(w, "sandbox"); s != nil {
			s["landlock"] = a.Landlock
		}
	}
	paths := map[string]any{}
	SetOrDelete(paths, "read", Strings(a.Read))
	SetOrDelete(paths, "write", Strings(a.Write))
	SetOrDelete(paths, "deny", Strings(a.Deny))
	SetOrDelete(w, "paths", paths)

	var services map[string]any
	if s := a.Services; s != nil {
		services = map[string]any{}
		SetOrDelete(services, "status", Strings(s.Status))
		if c := s.Control; c != nil {
			control := map[string]any{}
			SetOrDelete(control, "units", Strings(c.Units))
			SetOrDelete(control, "verbs", Strings(c.Verbs))
			SetOrDelete(services, "control", control)
		}
	}
	SetOrDelete(w, "services", services)

	var journal map[string]any
	if a.Journal != nil {
		journal = map[string]any{"units": Strings(a.Journal.Units)}
		if ml, ok := Sub(t.Values, "journal")["max_lines"]; ok {
			journal["max_lines"] = ml
		}
	}
	SetOrDelete(w, "journal", journal)

	var git map[string]any
	if a.Git != nil {
		repos := make([]any, len(a.Git.Repos))
		for i, r := range a.Git.Repos {
			repos[i] = map[string]any{"path": r.Path, "remote": r.Remote}
		}
		git = map[string]any{"repos": repos}
	}
	SetOrDelete(w, "git", git)

	var priv map[string]any
	if a.Root != nil {
		priv = Sub(w, "privileged")
		if priv != nil && !a.UsesBroad() {
			delete(priv, "broad_socket")
		}
	}
	SetOrDelete(w, "privileged", priv)

	cmds := make([]any, len(a.Commands))
	for i, c := range a.Commands {
		m := map[string]any{"id": c.ID, "path": c.Path, "tier": c.Tier, "templates": Templates(c.Templates)}
		if c.Description != "" {
			m["description"] = c.Description
		}
		if c.RootEquivalent {
			m["root_equivalent"] = true
		}
		if c.ReadsPrivateKeys {
			m["reads_private_keys"] = true
		}
		cmds[i] = m
	}
	SetOrDelete(w, "commands", cmds)
	return w
}
