//go:build linux && !landlock_forcepsx

package sandbox

import "github.com/landlock-lsm/go-landlock/landlock"

// capABI is the ABI the sandbox plans for, given the kernel's: the kernel's
// own in every release build.
func capABI(v int) int { return v }

// restrict applies the ruleset to every thread. go-landlock chooses how from
// the kernel's ABI: psx below ABI 8, LANDLOCK_RESTRICT_SELF_TSYNC from 8
// (threadPath mirrors that choice).
func restrict(cfg landlock.Config, ll []landlock.Rule, _ *Rules, _ int) error {
	return cfg.Restrict(ll...)
}
