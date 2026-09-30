//go:build linux

package sandbox

import (
	"testing"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// TestScopedSignals: from ABI 8 the ruleset scopes signals and abstract
// Unix sockets to the domain; UnscopedSignals (the helper with CAP_KILL)
// leaves signals unscoped and keeps abstract sockets scoped. Below ABI 8
// nothing is scoped either way.
func TestScopedSignals(t *testing.T) {
	for _, c := range []struct {
		abi                  int
		unscoped             bool
		wantSignal, wantAbst bool
	}{
		{8, false, true, true},
		{8, true, false, true},
		{9, true, false, true},
		{7, false, false, false},
		{7, true, false, false},
	} {
		cfg, _, err := build(&Rules{UnscopedSignals: c.unscoped}, c.abi)
		if err != nil {
			t.Fatal(err)
		}
		sig := cfg.Scoped&llsys.ScopeSignal != 0
		abst := cfg.Scoped&llsys.ScopeAbstractUnixSocket != 0
		if sig != c.wantSignal || abst != c.wantAbst {
			t.Errorf("ABI %d unscoped=%v: signal scoped %v, abstract scoped %v; want %v, %v", c.abi, c.unscoped, sig, abst, c.wantSignal, c.wantAbst)
		}
	}
}
