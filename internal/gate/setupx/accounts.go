package setupx

import (
	"errors"
)

// Bounds on the user and group databases.
const (
	// MaxDatabaseBytes bounds /etc/passwd and /etc/group.
	MaxDatabaseBytes = 16 << 20
	// maxEntries bounds the entries of either.
	maxEntries = 1 << 20
	// maxMembers bounds one group's member list.
	maxMembers = 1 << 16
)

// Account is one /etc/passwd entry.
type Account struct {
	Name  string
	UID   uint32
	GID   uint32
	Home  string
	Shell string
}

// Group is one /etc/group entry.
type Group struct {
	Name    string
	GID     uint32
	Members []string
}

// Accounts are the local user and group databases. The gate reads only
// these files (D-020: a group known only through NSS has no name it can
// check), so the installers read them the same way, never NSS.
type Accounts struct {
	Users  []Account
	Groups []Group
}

// ErrDatabase is a malformed /etc/passwd or /etc/group.
var ErrDatabase = errors.New("malformed account database")

// lines splits a database into its entries: blank lines and # comments are
// skipped, and so are NIS compat entries (+ and -), which name no local
// account. Every other line must have exactly n colon-separated fields.
func lines(b []byte, n int, what string) ([][]string, error) {
	var stub0 [][]string
	var stub1 error
	return stub0, stub1
}

func parseID(s string) (uint32, bool) { var stub0 uint32; var stub1 bool; return stub0, stub1 }

// ParsePasswd parses /etc/passwd: name:password:uid:gid:gecos:home:shell.
func ParsePasswd(b []byte) ([]Account, error) {
	var stub0 []Account
	var stub1 error
	return stub0, stub1
}

// ParseGroup parses /etc/group: name:password:gid:member,member,….
func ParseGroup(b []byte) ([]Group, error) { var stub0 []Group; var stub1 error; return stub0, stub1 }

// User is the account named name.
func (a *Accounts) User(name string) (Account, bool) {
	var stub0 Account
	var stub1 bool
	return stub0, stub1
}

// UsersByUID is every account with uid (more than one is possible in a
// hand-edited file).
func (a *Accounts) UsersByUID(uid uint32) []Account { var stub0 []Account; return stub0 }

// Group is the group named name.
func (a *Accounts) Group(name string) (Group, bool) {
	var stub0 Group
	var stub1 bool
	return stub0, stub1
}

// GroupsByGID is every group with gid.
func (a *Accounts) GroupsByGID(gid uint32) []Group { var stub0 []Group; return stub0 }

// Supplementary is every group that lists user as a member, in file order.
func (a *Accounts) Supplementary(user string) []Group { var stub0 []Group; return stub0 }
