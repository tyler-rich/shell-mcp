//go:build linux && landlock_forcepsx

package sandbox

// The landlock_forcepsx test build. Every hosted runner now reports Landlock
// ABI 8, where go-landlock v0.11.0 always takes the TSYNC path and offers no
// way to choose psx, so this build makes the sandbox behave as on an ABI 7
// kernel: it plans as at ABI 7 (capABI) and applies the ruleset the way
// go-landlock's psx branch does (restrict.go, !useTsync). It is never a
// release build: there is no variable, flag or config key for it, and CI and
// scripts/ci-local.sh fail a release or image binary that contains the tag's
// name, which forcedPSX carries into every binary built with this file.

import (
	"errors"
	"fmt"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// forcedPSX names this build in its errors.
const forcedPSX = "landlock_forcepsx test build"

// capABI plans as at ABI 7 on a kernel at ABI 8 or above.
func capABI(v int) int { return min(v, abiTSync-1) }

// restrict creates the ruleset build configured, adds the same grants, and
// applies it as go-landlock does below ABI 8: no_new_privs and
// landlock_restrict_self on every thread through libcap/psx, so each thread
// gets its own domain. The go-landlock rules are not used: their contents
// are not readable, and grants is where build took them from.
func restrict(cfg landlock.Config, _ []landlock.Rule, r *Rules, abi int) error {
	attr := llsys.RulesetAttr{
		HandledAccessFS:  uint64(cfg.HandledAccessFS),
		HandledAccessNet: uint64(cfg.HandledAccessNet),
		Scoped:           uint64(cfg.Scoped),
	}
	fd, err := llsys.LandlockCreateRuleset(&attr, 0)
	if err != nil {
		return fmt.Errorf("%s: landlock_create_ruleset: %w", forcedPSX, err)
	}
	defer func() { _ = unix.Close(fd) }()
	paths, ports := grants(r, abi)
	for _, g := range paths {
		if err := addPath(fd, g); err != nil {
			return fmt.Errorf("%s: landlock_add_rule %q: %w", forcedPSX, g.path, err)
		}
	}
	for _, port := range ports {
		a := llsys.NetPortAttr{AllowedAccess: llsys.AccessNetConnectTCP, Port: uint64(port)}
		if err := llsys.LandlockAddNetPortRule(fd, &a, 0); err != nil {
			return fmt.Errorf("%s: landlock_add_rule port %d: %w", forcedPSX, port, err)
		}
	}
	if err := llsys.AllThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("%s: prctl(PR_SET_NO_NEW_PRIVS): %w", forcedPSX, err)
	}
	if err := llsys.AllThreadsLandlockRestrictSelf(fd, 0); err != nil {
		return fmt.Errorf("%s: landlock_restrict_self: %w", forcedPSX, err)
	}
	return nil
}

// addPath adds one path-beneath rule. A path removed since grants found it
// is skipped, as go-landlock's IgnoreIfMissing does.
func addPath(fd int, g pathGrant) error {
	pfd, err := unix.Open(g.path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(pfd) }()
	a := llsys.PathBeneathAttr{ParentFd: pfd, AllowedAccess: uint64(g.access)}
	return llsys.LandlockAddPathBeneathRule(fd, &a, 0)
}
