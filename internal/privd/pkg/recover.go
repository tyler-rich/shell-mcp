//go:build linux

package pkg

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
	// is missing.
	RecoverDependency Recovery = "dependency"
	// RecoverReinstall: it must be reinstalled (or removed); configuring
	// leaves it as it is.
	RecoverReinstall Recovery = "reinstall"
)

// State is dpkg's database as dpkg sees it: Status with the journal's
// entries applied, and Journal the journal's entry names.
type State struct {
	Status
	Journal []string
}

// ReadState reads <dir>/status and folds <dir>/updates over it.
func ReadState(dir string) (State, error) {
	st, err := ReadStatus(dir)
	if err != nil {
		return State{}, err
	}
	j, err := PendingUpdates(dir)
	if err != nil {
		return State{}, err
	}
	return State{Status: st, Journal: j}, nil
}

// UnfinishedPackage is a package dpkg left part-way, and what it needs.
type UnfinishedPackage struct {
	Name, Version, Want, Flag, State string
	Recovery                         Recovery
	// Missing are the dependencies (one alternative group each) that no
	// package on the system provides, for RecoverDependency.
	Missing []string
}

// UnfinishedPackages lists, sorted by name, the packages dpkg left
// part-way with what each needs.
func (s Status) UnfinishedPackages() []UnfinishedPackage { return nil }

// RecoverArgs is the recovery's argv after the dpkg binary.
func RecoverArgs() []string { return nil }

// RecoverPreviewHash is the recovery preview's preview_sha256.
func RecoverPreviewHash(_ string, _ []string, _ []UnfinishedPackage, _ []string) string { return "" }

// Configured is a package a recovery finished.
type Configured struct {
	Name, Version, From string
}

// Recovered is what a recovery settled, from dpkg's state before and
// after it.
type Recovered struct {
	Configured []Configured
	Still      []UnfinishedPackage
	Other      Transaction
}

// Settle compares dpkg's state before and after a recovery.
func Settle(_, _ Status) Recovered { return Recovered{} }
