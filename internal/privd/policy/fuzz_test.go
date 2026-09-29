//go:build linux

package policy_test

import (
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// FuzzParse: arbitrary bytes never panic the loader, and whatever it
// accepts keeps the invariants the helper and the unit generator rely on.
func FuzzParse(f *testing.F) {
	f.Add([]byte(head))
	f.Add([]byte(example))
	f.Add([]byte(head + "paths:\n  write: [/srv/app]\n  persistence:\n    - path: /etc/cron.d\n      acknowledge: x\n"))
	f.Add([]byte(head + "modes:\n  max: \"0750\"\nowners:\n  users: [root]\n"))
	f.Add([]byte(head + "sandbox:\n  landlock: best-effort\nbackups:\n  keep: 0\n"))
	f.Add([]byte("version: 1\n---\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		fx := newFixture(t)
		p, err := policy.Parse(data, "/etc/shell-mcp/privileged.yaml", &fx.opts)
		if err != nil {
			return
		}
		if p.ClientUID == 0 || p.ModesMax&0o7002 != 0 || p.Limits.MaxTimeoutS > 1800 || p.BackupsKeep > 100 || p.Packages.Enabled {
			t.Fatalf("accepted policy breaks an invariant: %+v", p)
		}
		for _, w := range p.Paths.WriteRoots() {
			if p.Paths.Protected.Covers(w) {
				t.Fatalf("write root %s is protected", w)
			}
		}
		for _, c := range p.Commands {
			if c.Unit != policy.UnitCore || c.ListB != 0 && c.Acknowledge == "" {
				t.Fatalf("command %+v", c)
			}
		}
	})
}
