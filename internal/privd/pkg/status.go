//go:build linux

package pkg

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// dpkg's status file and what a package operation changed (S4c-7, handoff
// D5): a bounded, strict reader of the four fields the helper needs
// (Package, Status, Architecture, Version; dpkg 1.22.22 and 1.23.7), the
// unfinished-state check, and the diff that decides an operation's result.
// The transaction's canonical form, its hash and the pinned argv are here
// too, beside the simulation parser they extend.

// Bounds on dpkg's status file and its journal.
const (
	// MaxStatusBytes bounds the status file (a large host's is a few MiB).
	MaxStatusBytes = 64 << 20
	// MaxStatusPackages bounds its entries.
	MaxStatusPackages = 100000
	maxUpdates        = 1000
)

// Package is one dpkg status entry.
type Package struct {
	Name, Arch, Version string
	// Want, Flag and State are the three words of its Status field.
	Want, Flag, State string
}

// Status is dpkg's status file. Packages are keyed by apt's name for them:
// the package name, qualified with ":<arch>" only when its architecture is
// neither "all" nor Native (pkgCache::PkgIterator::FullName(true), apt
// 3.0.3 and 3.2.0), so that they compare with a simulation's names.
type Status struct {
	// Native is the native architecture: dpkg's own entry's.
	Native   string
	Packages map[string]Package
}

// Transaction is what a package operation changes: its simulation, or the
// diff of dpkg's status before and after it.
type Transaction struct {
	Install []Version
	Upgrade []Upgrade
	Remove  []Removal
}

var (
	wants  = []string{"unknown", "install", "hold", "deinstall", "purge"}
	flags  = []string{"ok", "reinstreq"}
	states = []string{"not-installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending", "installed"}
	// final are the states dpkg leaves a package in once it is done with it.
	final = []string{"not-installed", "config-files", "installed"}
)

// pinVersionRE is a version apt may be given in name=version: Debian's
// characters, starting with a digit (Debian Policy §5.6.12: an epoch or an
// upstream version), never ending in "-" (an empty revision, and apt's
// suffix for a removal).
var pinVersionRE = regexp.MustCompile(`^\d[A-Za-z0-9.+~:-]{0,127}$`)

// ReadStatus reads and parses <dir>/status: a regular file, opened without
// following a symlink, at most MaxStatusBytes.
func ReadStatus(dir string) (Status, error) {
	f, err := os.OpenFile(filepath.Join(dir, "status"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) //nolint:gosec // G304: dpkg's fixed administrative directory
	if err != nil {
		return Status{}, fmt.Errorf("dpkg's status file: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return Status{}, errors.New("dpkg's status file is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxStatusBytes+1))
	if err != nil {
		return Status{}, fmt.Errorf("dpkg's status file: %w", err)
	}
	return ParseStatus(b)
}

// ParseStatus parses dpkg's status file (host data): stanzas separated by
// blank lines, "Field: value" lines, continuation lines (starting with a
// space or tab) skipped. Every entry needs a valid Package name and a
// Status of three known words; Architecture and Version are validated
// where present, and required unless the package is not installed. A
// duplicate field or entry, or more than the bounds, is an error, and so is
// a file without dpkg's own entry, which names the native architecture.
func ParseStatus(b []byte) (Status, error) {
	if len(b) > MaxStatusBytes {
		return Status{}, fmt.Errorf("dpkg's status file is larger than %d bytes", MaxStatusBytes)
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return Status{}, errors.New("dpkg's status file holds a NUL byte")
	}
	var list []Package
	for _, stanza := range strings.Split(string(b), "\n\n") {
		if strings.TrimSpace(stanza) == "" {
			continue
		}
		if len(list) == MaxStatusPackages {
			return Status{}, fmt.Errorf("dpkg's status file has more than %d entries", MaxStatusPackages)
		}
		p, err := parseStanza(stanza)
		if err != nil {
			return Status{}, err
		}
		list = append(list, p)
	}
	st := Status{Packages: make(map[string]Package, len(list))}
	for _, p := range list {
		if p.Name == "dpkg" && p.State == "installed" {
			st.Native = p.Arch
		}
	}
	if st.Native == "" || st.Native == "all" {
		return Status{}, errors.New("dpkg's status file has no installed dpkg entry naming the native architecture")
	}
	for i := range list {
		p := list[i]
		k := st.key(&p)
		if _, dup := st.Packages[k]; dup {
			return Status{}, fmt.Errorf("dpkg's status file lists %s twice", k)
		}
		st.Packages[k] = p
	}
	return st, nil
}

func parseStanza(stanza string) (Package, error) {
	var p Package
	seen := map[string]bool{}
	for _, line := range strings.Split(stanza, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return Package{}, errors.New("dpkg's status file has a line that is not a field")
		}
		switch k {
		case "Package", "Status", "Architecture", "Version":
		default:
			continue
		}
		if seen[k] {
			return Package{}, fmt.Errorf("dpkg's status file has an entry with two %s fields", k)
		}
		seen[k] = true
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			if !ValidName(v) {
				return Package{}, errors.New("dpkg's status file has an entry whose name is not a Debian package name")
			}
			p.Name = v
		case "Status":
			f := strings.Fields(v)
			if len(f) != 3 || !slices.Contains(wants, f[0]) || !slices.Contains(flags, f[1]) || !slices.Contains(states, f[2]) {
				return Package{}, fmt.Errorf("dpkg's status file has an entry with an unknown status %q", v)
			}
			p.Want, p.Flag, p.State = f[0], f[1], f[2]
		case "Architecture":
			if !archRE.MatchString(v) {
				return Package{}, errors.New("dpkg's status file has an entry with an invalid architecture")
			}
			p.Arch = v
		case "Version":
			if !versionRE.MatchString(v) {
				return Package{}, errors.New("dpkg's status file has an entry with an invalid version")
			}
			p.Version = v
		}
	}
	switch {
	case p.Name == "":
		return Package{}, errors.New("dpkg's status file has an entry without a Package field")
	case p.State == "":
		return Package{}, fmt.Errorf("dpkg's status file has no Status for %s", p.Name)
	case p.State != "not-installed" && (p.Arch == "" || p.Version == ""):
		return Package{}, fmt.Errorf("dpkg's status file has no Architecture or Version for %s", p.Name)
	}
	return p, nil
}

func (s Status) key(p *Package) string {
	if p.Arch == "" || p.Arch == "all" || p.Arch == s.Native {
		return p.Name
	}
	return p.Name + ":" + p.Arch
}

// Unfinished lists, sorted, the packages dpkg left part-way: a state other
// than installed, config-files or not-installed, or the reinstreq flag.
func (s Status) Unfinished() []string {
	var out []string
	for k, p := range s.Packages {
		if !slices.Contains(final, p.State) || p.Flag == "reinstreq" {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// PendingUpdates lists dpkg's journal entries in <dir>/updates (sorted, at
// most maxUpdates): any entry there means dpkg was interrupted before it
// folded its journal into the status file. A missing directory is none.
func PendingUpdates(dir string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(dir, "updates"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dpkg's journal directory: %w", err)
	}
	out := make([]string, 0, min(len(ents), maxUpdates))
	for _, e := range ents[:min(len(ents), maxUpdates)] {
		out = append(out, e.Name())
	}
	return out, nil
}

// present: the package is on the system (dpkg has its files), in any state
// but not-installed and config-files.
func present(p *Package) bool { return p.State != "not-installed" && p.State != "config-files" }

// Diff is what changed from before to after: packages that became present
// (Install), present ones whose version changed (Upgrade, also for a
// downgrade), and ones no longer present (Remove; Purge is never set, since
// a removal of a package without configuration files leaves no entry
// either way). Canonical order.
func Diff(before, after Status) Transaction {
	var t Transaction
	for k, a := range after.Packages {
		b, ok := before.Packages[k]
		switch {
		case !present(&a):
		case !ok || !present(&b):
			t.Install = append(t.Install, Version{Name: k, Version: a.Version})
		case a.Version != b.Version:
			t.Upgrade = append(t.Upgrade, Upgrade{Name: k, From: b.Version, To: a.Version})
		}
	}
	for k, b := range before.Packages {
		if a, ok := after.Packages[k]; present(&b) && (!ok || !present(&a)) {
			t.Remove = append(t.Remove, Removal{Name: k, Version: b.Version})
		}
	}
	return t.canon()
}

// canon sorts every list by name (then by version), into new slices.
func (t Transaction) canon() Transaction {
	c := Transaction{Install: slices.Clone(t.Install), Upgrade: slices.Clone(t.Upgrade), Remove: slices.Clone(t.Remove)}
	slices.SortFunc(c.Install, func(a, b Version) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Version, b.Version))
	})
	slices.SortFunc(c.Upgrade, func(a, b Upgrade) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.From, b.From), strings.Compare(a.To, b.To))
	})
	slices.SortFunc(c.Remove, func(a, b Removal) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Version, b.Version))
	})
	return c
}

// Transaction returns the simulation's changes in canonical order.
func (s *Simulation) Transaction() Transaction {
	return Transaction{Install: s.Install, Upgrade: s.Upgrade, Remove: s.Remove}.canon()
}

// Empty reports a transaction that changes nothing.
func (t Transaction) Empty() bool { return len(t.Install)+len(t.Upgrade)+len(t.Remove) == 0 }

// Equal reports the same changes, list for list and version for version,
// in any order.
func (t Transaction) Equal(u Transaction) bool {
	a, b := t.canon(), u.canon()
	return slices.Equal(a.Install, b.Install) && slices.Equal(a.Upgrade, b.Upgrade) && slices.Equal(a.Remove, b.Remove)
}

const (
	previewDomain       = "shell-mcp priv pkg preview v1\x00"
	updatePreviewDomain = "shell-mcp priv pkg update index preview v1\x00"
)

// PreviewHash is a package preview's preview_sha256 (handoff D5, P-5): the
// privileged policy's SHA-256, the op, the requested names, the canonical
// install, upgrade and remove lists with every version (and the purge
// flag), and the simulated argv, each length-prefixed and every list
// counted. Never stderr, the exit code or durations.
func PreviewHash(policySHA string, op Op, names []string, t Transaction, argv []string) string {
	c := t.canon()
	b := []byte(previewDomain)
	b = field(b, policySHA)
	b = field(b, string(op))
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
		if r.Purge {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	b = list(b, argv)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// UpdatePreviewHash is the index update preview's preview_sha256 (handoff
// P-2e): the privileged policy's SHA-256 and the argv; never the sources
// (Q9).
func UpdatePreviewHash(policySHA string, argv []string) string {
	b := field([]byte(updatePreviewDomain), policySHA)
	b = list(b, argv)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func field(b []byte, s string) []byte {
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

func list(b []byte, l []string) []byte {
	b = binary.AppendUvarint(b, uint64(len(l)))
	for _, s := range l {
		b = field(b, s)
	}
	return b
}

// PinnedArgs is the argv a package operation runs (simulate: -s, the same
// argv simulated), pinned to the approved transaction t (handoff D5 §3):
//   - install: each requested name that t installs or upgrades as
//     name=version (one already at its version as it is: the simulation of
//     this argv must still resolve to t), with --no-remove; dependencies
//     are not pinned, so apt keeps marking them automatically installed;
//   - upgrade: install --only-upgrade --no-remove over exactly t's upgrade
//     list, each name=to, never apt-get upgrade;
//   - remove: the names, unpinned (there is no candidate to pin).
//
// Nothing to run (an empty transaction; for an upgrade or a removal, no
// upgrade or removal in it) is nil. Every version is
// host data from the simulation and is checked again here.
func PinnedArgs(op Op, simulate bool, names []string, t Transaction) ([]string, error) {
	var pins []string
	switch op {
	case OpInstall:
		if err := checkNames(op, names); err != nil {
			return nil, err
		}
		if t.Empty() {
			return nil, nil
		}
		for _, n := range names {
			pin := n // already at its version: passed as it is
			for _, v := range t.Install {
				if v.Name == n {
					pin = n + "=" + v.Version
				}
			}
			for _, u := range t.Upgrade {
				if u.Name == n {
					pin = n + "=" + u.To
				}
			}
			pins = append(pins, pin)
		}
	case OpUpgrade:
		if len(names) != 0 {
			return nil, fmt.Errorf("%s takes no package names", op)
		}
		for _, u := range t.canon().Upgrade {
			pins = append(pins, u.Name+"="+u.To)
		}
	case OpRemove:
		if len(t.Remove) == 0 {
			if err := checkNames(op, names); err != nil {
				return nil, err
			}
			return nil, nil
		}
		return Args(op, simulate, names)
	default:
		return nil, fmt.Errorf("%s cannot be pinned", op)
	}
	for _, p := range pins {
		if strings.Contains(p, "=") && !validPin(p) {
			return nil, fmt.Errorf("%q is not a package pinned to a Debian version", p)
		}
	}
	if len(pins) == 0 {
		return nil, nil
	}
	args := slices.Concat(common, []string{"--no-install-recommends", "--no-remove"})
	if op == OpUpgrade {
		args = append(args, "--only-upgrade")
	}
	if simulate {
		args = append(args, "-s")
	}
	args = append(args, "install", "--")
	return append(args, pins...), nil
}

func validPin(p string) bool {
	n, v, ok := strings.Cut(p, "=")
	return ok && validQualified(n) && pinVersionRE.MatchString(v) && !strings.HasSuffix(v, "-")
}

// Holder is a process holding the dpkg frontend lock.
type Holder struct {
	PID int
	// Comm is its command name (/proc/<pid>/comm, printable ASCII), "" when
	// it cannot be read.
	Comm string
}

// String names the holder as apt does: "<comm> (pid <pid>)".
func (h Holder) String() string {
	c := h.Comm
	if c == "" {
		c = "a process"
	}
	if h.PID <= 0 {
		return c
	}
	return fmt.Sprintf("%s (pid %d)", c, h.PID)
}

// LockHolder reports whether a process holds a lock on path (dpkg's
// frontend lock: an fcntl(2) record lock, which apt and dpkg take with
// F_SETLK), and which, from F_GETLK. A missing file is not held.
func LockHolder(path string) (Holder, bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) //nolint:gosec // G304: dpkg's fixed lock file
	if errors.Is(err, os.ErrNotExist) {
		return Holder{}, false, nil
	}
	if err != nil {
		return Holder{}, false, fmt.Errorf("dpkg's frontend lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0}
	if err := unix.FcntlFlock(f.Fd(), unix.F_GETLK, &lk); err != nil {
		return Holder{}, false, fmt.Errorf("dpkg's frontend lock: %w", err)
	}
	if lk.Type == unix.F_UNLCK {
		return Holder{}, false, nil
	}
	h := Holder{PID: int(lk.Pid)}
	if h.PID > 0 {
		h.Comm = comm(h.PID)
	}
	return h, true, nil
}

// comm is /proc/<pid>/comm as printable ASCII, "" when unreadable.
func comm(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil || len(b) > 64 {
		return ""
	}
	return printable(strings.TrimSpace(string(b)))
}

func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

// heldByRE is apt's "It is held by process <pid> (<name>)".
var heldByRE = regexp.MustCompile(`held by process (\d{1,10}) \(([^()\n]{1,64})\)`)

// HolderFromStderr is the lock holder apt named in its refusal.
func HolderFromStderr(stderr []byte) (Holder, bool) {
	m := heldByRE.FindSubmatch(stderr)
	if m == nil {
		return Holder{}, false
	}
	pid, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return Holder{}, false
	}
	return Holder{PID: pid, Comm: printable(string(m[2]))}, true
}
