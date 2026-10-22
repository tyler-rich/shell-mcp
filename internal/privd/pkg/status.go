//go:build linux

package pkg

import "errors"

// STUB (S4c-7 failing-tests commit): the API the tests call, inert.

// Bounds on dpkg's status file.
const (
	MaxStatusBytes    = 64 << 20
	MaxStatusPackages = 100000
	maxUpdates        = 1000
)

// Package is one dpkg status entry.
type Package struct {
	Name, Arch, Version string
	Want, Flag, State   string
}

// Status is dpkg's status file, parsed.
type Status struct {
	Native   string
	Packages map[string]Package
}

// Transaction is what a package operation changes.
type Transaction struct {
	Install []Version
	Upgrade []Upgrade
	Remove  []Removal
}

var errStub = errors.New("not implemented")

// ParseStatus parses dpkg's status file.
func ParseStatus([]byte) (Status, error) { return Status{}, errStub }

// ReadStatus reads and parses <dir>/status.
func ReadStatus(string) (Status, error) { return Status{}, errStub }

// Unfinished lists the packages dpkg left unfinished.
func (Status) Unfinished() []string { return nil }

// PendingUpdates lists dpkg's journal entries in <dir>/updates.
func PendingUpdates(string) ([]string, error) { return nil, nil }

// Diff is what changed from before to after.
func Diff(_, _ Status) Transaction { return Transaction{} }

// Transaction returns the simulation's changes.
func (s Simulation) Transaction() Transaction {
	return Transaction{Install: s.Install, Upgrade: s.Upgrade, Remove: s.Remove}
}

// Empty reports a transaction that changes nothing.
func (t Transaction) Empty() bool { return len(t.Install)+len(t.Upgrade)+len(t.Remove) == 0 }

// Equal reports two equal transactions.
func (Transaction) Equal(Transaction) bool { return true }

// PreviewHash is a package preview's preview_sha256.
func PreviewHash(string, Op, []string, Transaction, []string) string { return "" }

// UpdatePreviewHash is the index update preview's preview_sha256.
func UpdatePreviewHash(string, []string) string { return "" }

// PinnedArgs is the argv a package operation runs.
func PinnedArgs(op Op, simulate bool, names []string, _ Transaction) ([]string, error) {
	return Args(op, simulate, names)
}

// Holder is a process holding the dpkg frontend lock.
type Holder struct {
	PID  int
	Comm string
}

// LockHolder reports who holds the lock on path.
func LockHolder(string) (Holder, bool, error) { return Holder{}, false, nil }
