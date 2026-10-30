//go:build linux

package pkg

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The two unfinished states a recovery cannot finish (handoff N-36,
// S7-7): a reinstall of exactly the packages dpkg flagged reinstreq or
// left half-installed, pinned to the version dpkg's status names, and the
// hash a removal of exactly the unfinished packages adds to its preview.

// OpReinstall is a reinstall of packages that need one.
const OpReinstall Op = "reinstall"

// CheckNames validates the package names of an install, a reinstall or a
// removal: 1..MaxNames Debian names without duplicates, none ending in the
// suffix apt-get reads as the other operation ("-" on an install or a
// reinstall, "+" on a removal).
func CheckNames(op Op, names []string) error {
	switch op {
	case OpInstall, OpRemove, OpReinstall:
		return checkNames(op, names)
	}
	return fmt.Errorf("%s takes no package names", op)
}

// ReinstallArgs is the argv of a reinstall (simulate: -s): the package
// operations' common options, never a recommended package added or a
// package removed, and every package pinned, after "--", to the version
// dpkg's status names for it (apt-get install --reinstall name=version;
// apt 3.0.3 and 3.2.0, measured in S7-7). Every version is host data from
// dpkg's status and is checked here.
func ReinstallArgs(simulate bool, pins []Version) ([]string, error) {
	names := make([]string, 0, len(pins))
	for _, p := range pins {
		names = append(names, p.Name)
	}
	if err := checkNames(OpReinstall, names); err != nil {
		return nil, err
	}
	args := slices.Concat(common, []string{"--no-install-recommends", "--no-remove"})
	if simulate {
		args = append(args, "-s")
	}
	args = append(args, "install", "--reinstall", "--")
	for _, p := range pins {
		pin := p.Name + "=" + p.Version
		if !validPin(pin) {
			return nil, fmt.Errorf("%q is not a package pinned to a Debian version", pin)
		}
		args = append(args, pin)
	}
	return args, nil
}

const (
	reinstallDomain  = "shell-mcp priv pkg reinstall preview v1\x00"
	unfinishedDomain = "shell-mcp priv pkg preview unfinished v1\x00"
)

// appendState adds dpkg's unfinished state to a hash's input: every
// unfinished package's name, version, want, flag and state (sorted by
// name), and the journal's entry names (sorted), each length-prefixed and
// every list counted. Never what is derived from them (Recovery, Missing).
func appendState(b []byte, unfinished []UnfinishedPackage, journal []string) []byte {
	u := slices.Clone(unfinished)
	slices.SortFunc(u, func(a, b UnfinishedPackage) int { return strings.Compare(a.Name, b.Name) })
	j := slices.Clone(journal)
	slices.Sort(j)
	b = binary.AppendUvarint(b, uint64(len(u)))
	for _, p := range u {
		b = field(field(field(field(field(b, p.Name), p.Version), p.Want), p.Flag), p.State)
	}
	return list(b, j)
}

// ReinstallPreviewHash is the reinstall preview's preview_sha256: the
// privileged policy's SHA-256, the requested names, the canonical
// transaction with every version, the argv, and dpkg's unfinished state.
// Never stderr, the exit code or durations.
func ReinstallPreviewHash(policySHA string, names []string, t Transaction, argv []string, unfinished []UnfinishedPackage, journal []string) string {
	c := t.canon()
	b := field([]byte(reinstallDomain), policySHA)
	b = list(b, names)
	b = binary.AppendUvarint(b, uint64(len(c.Install)))
	for _, v := range c.Install {
		b = field(field(b, v.Name), v.Version)
	}
	b = binary.AppendUvarint(b, uint64(len(c.Upgrade)))
	for _, u := range c.Upgrade {
		b = field(field(field(b, u.Name), u.From), u.To)
	}
	b = binary.AppendUvarint(b, uint64(len(c.Remove)))
	for _, r := range c.Remove {
		b = field(field(b, r.Name), r.Version)
	}
	b = list(b, argv)
	b = appendState(b, unfinished, journal)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// UnfinishedPreviewHash binds a package preview's hash (PreviewHash) to
// dpkg's unfinished state, for a removal of exactly the unfinished
// packages: a domain of its own, so that it is never the clean preview's
// hash for the same transaction, the base hash and the state.
func UnfinishedPreviewHash(previewSHA string, unfinished []UnfinishedPackage, journal []string) string {
	b := field([]byte(unfinishedDomain), previewSHA)
	b = appendState(b, unfinished, journal)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// IsReinstall reports a reinstall's simulated transaction: exactly one
// version-preserving "upgrade" (apt's "Inst name [v] (v …)") per pin,
// at the pinned version, and nothing installed, changed or removed
// besides.
func IsReinstall(t Transaction, pins []Version) error {
	c := t.canon()
	want := make([]Upgrade, 0, len(pins))
	for _, p := range pins {
		want = append(want, Upgrade{Name: p.Name, From: p.Version, To: p.Version})
	}
	want = Transaction{Upgrade: want}.canon().Upgrade
	if len(c.Install)+len(c.Remove) == 0 && slices.Equal(c.Upgrade, want) {
		return nil
	}
	return errors.New("the transaction is not exactly the reinstall")
}
