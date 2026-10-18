package tools

import (
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func tool(name string) Tool {
	return Tool{Def: &mcp.Tool{Name: name}, Install: func(*mcp.Server) {}}
}

func names(regs []Registration) []string {
	out := make([]string, 0, len(regs))
	for _, r := range regs {
		out = append(out, r.Tool.Def.Name)
	}
	return out
}

func populated(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	for _, reg := range []struct {
		name string
		tier Tier
		priv bool
	}{
		{"shell_read_file", TierRead, false},
		{"shell_write_file", TierOperator, false},
		{"shell_delete_path", TierDestructive, false},
		{"shell_priv_read_file", TierRead, true},
		{"shell_priv_write_file", TierOperator, true},
		{"shell_priv_delete_path", TierDestructive, true},
	} {
		if err := r.Register(tool(reg.name), reg.tier, reg.priv); err != nil {
			t.Fatalf("Register(%s): %v", reg.name, err)
		}
	}
	return r
}

func TestEmptyRegistry(t *testing.T) {
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator, ProfileAdmin} {
		if got := NewRegistry().ToolsForProfile(p, nil); len(got) != 0 {
			t.Fatalf("empty registry returned %v for %s", names(got), p)
		}
	}
}

func TestProfileTierMapping(t *testing.T) {
	r := populated(t)
	cases := map[Profile][]string{
		ProfileReadOnly: {"shell_read_file"},
		ProfileOperator: {"shell_read_file", "shell_write_file"},
		ProfileAdmin: {
			"shell_delete_path", "shell_priv_delete_path", "shell_priv_read_file",
			"shell_priv_write_file", "shell_read_file", "shell_write_file",
		},
	}
	for p, want := range cases {
		if got := names(r.ToolsForProfile(p, nil)); !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", p, got, want)
		}
	}
}

func TestPrivilegedOnlyInAdmin(t *testing.T) {
	r := populated(t)
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator} {
		for _, reg := range r.ToolsForProfile(p, nil) {
			if reg.Privileged {
				t.Fatalf("privileged tool %s registered in %s", reg.Tool.Def.Name, p)
			}
		}
	}
	var priv int
	for _, reg := range r.ToolsForProfile(ProfileAdmin, nil) {
		if reg.Privileged {
			priv++
		}
	}
	if priv != 3 {
		t.Fatalf("admin has %d privileged tools, want 3", priv)
	}
}

func TestUnknownProfileGetsNothing(t *testing.T) {
	if got := populated(t).ToolsForProfile(Profile("root"), nil); len(got) != 0 {
		t.Fatalf("unknown profile got %v", names(got))
	}
}

func TestDisabledToolsRemoved(t *testing.T) {
	got := names(populated(t).ToolsForProfile(ProfileOperator, []string{"shell_write_file", "shell_not_a_tool"}))
	if !slices.Equal(got, []string{"shell_read_file"}) {
		t.Fatalf("got %v", got)
	}
}

func TestRegisterRejectsInvalid(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(tool("shell_read_file"), TierRead, false); err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		name string
		t    Tool
		tier Tier
		priv bool
	}{
		{"duplicate", tool("shell_read_file"), TierRead, false},
		{"zero tier", tool("shell_x_y"), Tier(0), false},
		{"unknown tier", tool("shell_x_y"), Tier(99), false},
		{"nil def", Tool{Install: func(*mcp.Server) {}}, TierRead, false},
		{"nil install", Tool{Def: &mcp.Tool{Name: "shell_a_b"}}, TierRead, false},
		{"no prefix", tool("read_file"), TierRead, false},
		{"privileged without priv prefix", tool("shell_chown_path"), TierOperator, true},
		{"priv prefix not privileged", tool("shell_priv_chown_path"), TierOperator, false},
		{"not snake case", tool("shell_Read-File"), TierRead, false},
		// A tool whose handler sends a different ceiling than its registration.
		{"defined at another tier", Tool{Def: &mcp.Tool{Name: "shell_c_d"}, Tier: TierRead, Install: func(*mcp.Server) {}}, TierOperator, false},
	}
	for _, b := range bad {
		if err := r.Register(b.t, b.tier, b.priv); err == nil {
			t.Errorf("%s: Register accepted invalid registration", b.name)
		}
	}
}

func TestParseProfile(t *testing.T) {
	for _, s := range []string{"read-only", "operator", "admin"} {
		if p, err := ParseProfile(s); err != nil || string(p) != s {
			t.Fatalf("ParseProfile(%q) = %q, %v", s, p, err)
		}
	}
	for _, s := range []string{"", "root", "Admin", "readonly"} {
		if _, err := ParseProfile(s); err == nil {
			t.Fatalf("ParseProfile(%q) accepted", s)
		}
	}
}

// TestRegisterForProfiles: a name may be registered once per set of
// profiles that do not overlap (shell_run_command at operator in the
// operator profile and at destructive in admin); each profile then sees
// exactly one registration, and All lists both.
func TestRegisterForProfiles(t *testing.T) {
	r := populated(t)
	op := Tool{Def: &mcp.Tool{Name: "shell_run_command"}, Tier: TierOperator, Install: func(*mcp.Server) {}}
	ad := Tool{Def: &mcp.Tool{Name: "shell_run_command"}, Tier: TierDestructive, Install: func(*mcp.Server) {}}
	if err := r.RegisterFor(op, TierOperator, []Profile{ProfileOperator}); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterFor(ad, TierDestructive, []Profile{ProfileAdmin}); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[Profile]Tier{ProfileOperator: TierOperator, ProfileAdmin: TierDestructive} {
		var got []Tier
		for _, g := range r.ToolsForProfile(p, nil) {
			if g.Tool.Def.Name == "shell_run_command" {
				got = append(got, g.Tier)
			}
		}
		if len(got) != 1 || got[0] != want {
			t.Fatalf("%s: shell_run_command at %v", p, got)
		}
	}
	if slices.Contains(names(r.ToolsForProfile(ProfileReadOnly, nil)), "shell_run_command") {
		t.Fatal("registered in read-only")
	}
	all := r.All()
	var tiers []Tier
	for _, g := range all {
		if g.Tool.Def.Name == "shell_run_command" {
			tiers = append(tiers, g.Tier)
		}
	}
	if len(all) != 8 || !slices.Equal(tiers, []Tier{TierOperator, TierDestructive}) {
		t.Fatalf("All: %v tiers %v", names(all), tiers)
	}
	// Disabled by name removes it from every profile.
	if slices.Contains(names(r.ToolsForProfile(ProfileAdmin, []string{"shell_run_command"})), "shell_run_command") {
		t.Fatal("not disabled")
	}
	bad := []struct {
		name     string
		tool     Tool
		tier     Tier
		profiles []Profile
	}{
		{"overlapping profiles", ad, TierDestructive, []Profile{ProfileAdmin}},
		{"no profiles", Tool{Def: &mcp.Tool{Name: "shell_x_y"}, Install: func(*mcp.Server) {}}, TierRead, nil},
		{"unknown profile", Tool{Def: &mcp.Tool{Name: "shell_x_y"}, Install: func(*mcp.Server) {}}, TierRead, []Profile{"root"}},
		{"tier above the profile", Tool{Def: &mcp.Tool{Name: "shell_x_y"}, Install: func(*mcp.Server) {}}, TierDestructive, []Profile{ProfileOperator}},
		{"name already registered for every profile", tool("shell_read_file"), TierRead, []Profile{ProfileAdmin}},
		{"privileged", tool("shell_priv_x_y"), TierOperator, []Profile{ProfileAdmin}},
	}
	for _, b := range bad {
		if err := r.RegisterFor(b.tool, b.tier, b.profiles); err == nil {
			t.Errorf("%s: accepted", b.name)
		}
	}
	// Register refuses a name registered for some profiles only.
	if err := r.Register(tool("shell_run_command"), TierOperator, false); err == nil {
		t.Fatal("Register accepted a name RegisterFor holds")
	}
}
