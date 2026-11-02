package gen_test

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"

	ggen "github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy/gen"
	"github.com/tyler-rich/shell-mcp/internal/privd/units"
)

var examples = filepath.Join("..", "..", "..", "..", "examples")

func readFile(t testing.TB, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: this repository's own files
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func adminAnswers(t *testing.T) *ggen.Answers {
	t.Helper()
	a, err := ggen.Decode(readFile(t, filepath.Join(examples, "policies", "admin.answers.yaml")))
	if err != nil || a == nil || a.Root == nil {
		t.Fatalf("admin.answers.yaml: %v", err)
	}
	return a
}

// TestPresetIsTheExample: the embedded privileged preset is
// examples/privileged/privileged.yaml byte for byte.
func TestPresetIsTheExample(t *testing.T) {
	if !bytes.Equal(gen.Preset(), readFile(t, filepath.Join(examples, "privileged", "privileged.yaml"))) {
		t.Error("internal/privd/policy/gen/privileged.yaml differs from examples/privileged/privileged.yaml: copy the example")
	}
}

// TestExampleReproduced: admin.answers.yaml renders
// examples/privileged/privileged.yaml byte for byte (POLICY §9.2).
func TestExampleReproduced(t *testing.T) {
	got, err := gen.Render(adminAnswers(t))
	if err != nil {
		t.Fatal(err)
	}
	want := readFile(t, filepath.Join(examples, "privileged", "privileged.yaml"))
	if !bytes.Equal(got, want) {
		t.Errorf("admin.answers.yaml does not render examples/privileged/privileged.yaml:\n%s", setupx.UnifiedDiff("example", "rendered", want, got))
	}
}

// TestRenderNeedsRoot: answers without root: have no privileged policy.
func TestRenderNeedsRoot(t *testing.T) {
	a := adminAnswers(t)
	a.Root = nil
	if b, err := gen.Render(a); err == nil || b != nil {
		t.Fatalf("rendered a privileged policy without root: %q", b)
	}
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return m
}

func sub(m map[string]any, keys ...string) any {
	var v any = m
	for _, k := range keys {
		mm, _ := v.(map[string]any)
		v = mm[k]
	}
	return v
}

// TestSharedValuesAgree is the property across both binaries' output
// (POLICY §9): for any answers with root:, the gate policy and the
// privileged policy agree exactly on the deny list, the client uid, the
// socket group and the socket paths, whatever else the answers hold.
func TestSharedValuesAgree(t *testing.T) {
	denies := []string{"/srv/app/secrets/**", "**/*.key", "/etc/example-app/secrets/**", "**/*.pem", "/srv/data/private/**", "/opt/x/**/token"}
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // G404: a fixed seed, so the property test is reproducible
	for i := range 300 {
		a := adminAnswers(t)
		a.Deny = nil
		for _, d := range denies {
			if r.IntN(2) == 0 {
				a.Deny = append(a.Deny, d)
			}
		}
		a.Account.UID = int64(1000 + r.IntN(60000))
		a.Root.SocketGroup.Name = fmt.Sprintf("grp-%d", r.IntN(1000))
		if r.IntN(2) == 0 {
			a.Root.Packages = nil
		}
		if r.IntN(2) == 0 {
			a.Root.Power = nil
		}
		if r.IntN(2) == 0 {
			a.Root.Commands = slices.DeleteFunc(slices.Clone(a.Root.Commands), func(c ggen.RootCommand) bool { return c.Unit == "broad" })
		}
		if r.IntN(3) == 0 {
			a.Landlock = ggen.LandlockBestEffort
		}
		gb, err := ggen.RenderGate(a)
		if err != nil {
			t.Fatalf("case %d: gate: %v", i, err)
		}
		pb, err := gen.Render(a)
		if err != nil {
			t.Fatalf("case %d: privileged: %v", i, err)
		}
		g, p := decode(t, gb), decode(t, pb)
		gd, pd := sub(g, "paths", "deny"), sub(p, "paths", "deny")
		if !reflect.DeepEqual(gd, pd) {
			t.Fatalf("case %d: deny lists differ: gate %v, privileged %v", i, gd, pd)
		}
		if len(a.Deny) > 0 && gd == nil {
			t.Fatalf("case %d: the deny list was dropped", i)
		}
		if got := sub(p, "client_uid"); got != int(a.Account.UID) {
			t.Fatalf("case %d: client_uid %v, want the account's uid %d", i, got, a.Account.UID)
		}
		if got := sub(p, "socket_group"); got != a.Root.SocketGroup.Name {
			t.Fatalf("case %d: socket_group %v, want %s", i, got, a.Root.SocketGroup.Name)
		}
		if got := sub(g, "privileged", "socket"); got != units.SocketPath {
			t.Fatalf("case %d: privileged.socket %v, want the units' %s", i, got, units.SocketPath)
		}
		broad := sub(p, "packages") != nil || sub(p, "power") != nil
		for _, c := range sub(p, "commands").([]any) {
			if c.(map[string]any)["unit"] == "broad" {
				broad = true
			}
		}
		got := sub(g, "privileged", "broad_socket")
		switch {
		case broad && got != units.BroadSocketPath:
			t.Fatalf("case %d: the privileged policy uses the broad unit but broad_socket is %v, want %s", i, got, units.BroadSocketPath)
		case !broad && got != nil:
			t.Fatalf("case %d: the privileged policy has no broad unit but broad_socket is %v", i, got)
		}
		if gl, pl := sub(g, "sandbox", "landlock"), sub(p, "sandbox", "landlock"); gl != pl {
			t.Fatalf("case %d: landlock %v and %v", i, gl, pl)
		}
	}
}
