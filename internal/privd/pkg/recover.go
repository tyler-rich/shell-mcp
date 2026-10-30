//go:build linux

package pkg

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// Recovering a database dpkg left unfinished (handoff N-14, S7-4): dpkg's
// state as dpkg itself sees it (the status file with its journal folded
// in), what each unfinished package needs, the recovery's fixed argv, its
// preview hash, and what a recovery settled.

// OpRecover is the recovery: dpkg --configure --pending.
const OpRecover Op = "recover"

// Recovery is what an unfinished package needs.
type Recovery string

// Recoveries.
const (
	// RecoverConfigure: dpkg --configure --pending finishes it.
	RecoverConfigure Recovery = "configure"
	// RecoverDependency: configuring cannot finish it while a dependency
	// is missing ("dependency problems - leaving unconfigured", dpkg
	// 1.22.22, measured).
	RecoverDependency Recovery = "dependency"
	// RecoverReinstall: it must be reinstalled (or removed); configuring
	// leaves it as it is (dpkg --configure --pending exits 0 and does not
	// touch a half-installed or reinstreq package, measured).
	RecoverReinstall Recovery = "reinstall"
)

// State is dpkg's database as dpkg sees it: Status with the journal's
// records applied, and Journal the journal's entry names (every entry,
// as PendingUpdates lists them).
type State struct {
	Status
	Journal []string
}

// Same reports whether two states are identical: every package entry and
// the journal's entries.
func (s State) Same(t State) bool {
	return s.Native == t.Native && maps.Equal(s.Packages, t.Packages) && slices.Equal(s.Journal, t.Journal)
}

// ErrJournal wraps an entry of dpkg's journal that could not be read: the
// journal exists, so dpkg was interrupted, whatever the entry holds.
var ErrJournal = errors.New("dpkg's journal")

// ReadState reads <dir>/status and folds dpkg's journal, <dir>/updates,
// over it as dpkg does when it opens its database: every entry whose name
// is all digits is one status record, applied in name order, a later
// record replacing an earlier one for the same package (dpkg 1.22.22,
// lib/dpkg/dbmodify.c; tmp.i, its padding file, is not a record). Each
// record is opened without following a symlink, must be a regular file
// holding exactly one valid stanza, and the records together are bounded
// as the status file is.
func ReadState(dir string) (State, error) {
	st, err := ReadStatus(dir)
	if err != nil {
		return State{}, err
	}
	j, err := PendingUpdates(dir)
	if err != nil {
		return State{}, err
	}
	total := 0
	for _, name := range j {
		if name == "" || strings.Trim(name, "0123456789") != "" {
			continue
		}
		b, err := readRecord(filepath.Join(dir, "updates", name), MaxStatusBytes-total)
		if err != nil {
			return State{}, fmt.Errorf("%w entry %s: %w", ErrJournal, name, err)
		}
		total += len(b)
		p, err := parseRecord(b)
		if err != nil {
			return State{}, fmt.Errorf("%w entry %s: %w", ErrJournal, name, err)
		}
		st.Packages[st.key(&p)] = p
	}
	return State{Status: st, Journal: j}, nil
}

func readRecord(path string, limit int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) //nolint:gosec // G304: dpkg's fixed journal directory
	if err != nil {
		return nil, fmt.Errorf("dpkg's journal: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("dpkg's journal holds an entry that is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("dpkg's journal: %w", err)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("dpkg's journal is larger than %d bytes", MaxStatusBytes)
	}
	return b, nil
}

// parseRecord parses one journal record: exactly one stanza.
func parseRecord(b []byte) (Package, error) {
	var stanzas []string
	for _, s := range strings.Split(string(b), "\n\n") {
		if strings.TrimSpace(s) != "" {
			stanzas = append(stanzas, s)
		}
	}
	if len(stanzas) != 1 || strings.IndexByte(string(b), 0) >= 0 {
		return Package{}, errors.New("not exactly one status record")
	}
	return parseStanza(stanzas[0])
}

// UnfinishedPackage is a package dpkg left part-way, and what it needs.
type UnfinishedPackage struct {
	Name, Version, Want, Flag, State string
	Recovery                         Recovery
	// Missing are the dependencies (one alternative group each, "a | b")
	// that no package on the system provides, for RecoverDependency.
	Missing []string
}

// UnfinishedPackages lists, sorted by name, the packages dpkg left
// part-way (Unfinished) with what each needs: a half-installed package or
// one flagged reinstreq a reinstall; one whose Pre-Depends or Depends name
// a group none of whose alternatives is on the system, by name or by a
// present package's Provides, a dependency; any other a configure. Version
// constraints are not compared, so a dependency reported missing is
// certainly missing; one present at the wrong version is not reported.
func (s Status) UnfinishedPackages() []UnfinishedPackage {
	provided := map[string]bool{}
	for k := range s.Packages {
		p := s.Packages[k]
		if !present(&p) {
			continue
		}
		provided[p.Name] = true
		_, _, provides := p.relations()
		for _, g := range depGroups(provides) {
			for _, n := range g {
				provided[n] = true
			}
		}
	}
	out := []UnfinishedPackage{}
	for _, k := range s.Unfinished() {
		p := s.Packages[k]
		u := UnfinishedPackage{Name: k, Version: p.Version, Want: p.Want, Flag: p.Flag, State: p.State, Recovery: RecoverConfigure}
		if p.Flag == "reinstreq" || p.State == "half-installed" {
			u.Recovery = RecoverReinstall
		} else {
			pre, dep, _ := p.relations()
			for _, g := range slices.Concat(depGroups(pre), depGroups(dep)) {
				if !slices.ContainsFunc(g, func(n string) bool { return provided[n] }) {
					u.Missing = append(u.Missing, strings.Join(g, " | "))
				}
			}
			if len(u.Missing) > 0 {
				u.Recovery = RecoverDependency
			}
		}
		out = append(out, u)
	}
	return out
}

// relations splits Relations into Pre-Depends, Depends and Provides.
func (p *Package) relations() (pre, dep, provides string) {
	f := strings.SplitN(p.Relations, "\x00", 3)
	for len(f) < 3 {
		f = append(f, "")
	}
	return f[0], f[1], f[2]
}

// depGroups parses a Depends, Pre-Depends or Provides value into its
// groups of alternative package names: version constraints ("(>= 1)"),
// architecture qualifiers (":any") and restrictions ("[…]", "<…>")
// dropped. A group with an alternative that is not a package name is
// left out (treated as satisfied: it is never reported missing).
func depGroups(v string) [][]string {
	var out [][]string
	for _, g := range strings.Split(v, ",") {
		if strings.TrimSpace(g) == "" {
			continue
		}
		var alts []string
		ok := true
		for _, a := range strings.Split(g, "|") {
			a = strings.TrimSpace(a)
			if i := strings.IndexAny(a, " \t([<"); i >= 0 {
				a = a[:i]
			}
			a, _, _ = strings.Cut(a, ":")
			if !ValidName(a) {
				ok = false
				break
			}
			alts = append(alts, a)
		}
		if ok && len(alts) > 0 {
			out = append(out, alts)
		}
	}
	return out
}

// RecoverArgs is the recovery's argv after the dpkg binary: existing
// configuration files kept, and every package dpkg left unfinished
// configured (--pending is -a; dpkg(1), 1.22.22).
func RecoverArgs() []string { return []string{"--force-confold", "--configure", "--pending"} }

const recoverDomain = "shell-mcp priv pkg recover preview v1\x00"

// RecoverPreviewHash is the recovery preview's preview_sha256: the
// privileged policy's SHA-256, the argv, every unfinished package's name,
// version, want, flag and state (sorted by name), and the journal's entry
// names (sorted), each length-prefixed and every list counted. Never what
// is derived from them (Recovery, Missing), stderr or durations.
func RecoverPreviewHash(policySHA string, argv []string, unfinished []UnfinishedPackage, journal []string) string {
	b := field([]byte(recoverDomain), policySHA)
	b = list(b, argv)
	b = appendState(b, unfinished, journal)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Configured is a package a recovery finished: unfinished before, and
// installed at the same version after; From is its state before.
type Configured struct {
	Name, Version, From string
}

// Recovered is what a recovery settled, from dpkg's state before and
// after it: the packages it configured, the ones still unfinished with
// what they need, and any other change (installs, version changes,
// removals), which a recovery never makes by itself.
type Recovered struct {
	Configured []Configured
	Still      []UnfinishedPackage
	Other      Transaction
}

// Settle compares dpkg's state before and after a recovery.
func Settle(before, after Status) Recovered {
	r := Recovered{Configured: []Configured{}, Still: after.UnfinishedPackages(), Other: Diff(before, after)}
	for _, b := range before.UnfinishedPackages() {
		if a, ok := after.Packages[b.Name]; ok && a.State == "installed" && a.Flag == "ok" && a.Version == b.Version {
			r.Configured = append(r.Configured, Configured{Name: b.Name, Version: b.Version, From: b.State})
		}
	}
	return r
}
