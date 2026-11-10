package setupx

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
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
	if len(b) > MaxDatabaseBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrDatabase, what, MaxDatabaseBytes)
	}
	var out [][]string
	for i, l := range bytes.Split(b, []byte("\n")) {
		s := strings.TrimSuffix(string(l), "\r")
		if s == "" || s[0] == '#' || s[0] == '+' || s[0] == '-' {
			continue
		}
		f := strings.Split(s, ":")
		if len(f) != n {
			return nil, fmt.Errorf("%w: %s line %d has %d fields, want %d", ErrDatabase, what, i+1, len(f), n)
		}
		if len(out) == maxEntries {
			return nil, fmt.Errorf("%w: %s has more than %d entries", ErrDatabase, what, maxEntries)
		}
		out = append(out, f)
	}
	return out, nil
}

func parseID(s string) (uint32, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 32)
	return uint32(v), err == nil
}

// ParsePasswd parses /etc/passwd: name:password:uid:gid:gecos:home:shell.
func ParsePasswd(b []byte) ([]Account, error) {
	ls, err := lines(b, 7, "/etc/passwd")
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(ls))
	for i, f := range ls {
		uid, ok1 := parseID(f[2])
		gid, ok2 := parseID(f[3])
		if f[0] == "" || !ok1 || !ok2 {
			return nil, fmt.Errorf("%w: /etc/passwd entry %d has an empty name or an id that is not a number", ErrDatabase, i+1)
		}
		out = append(out, Account{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]})
	}
	return out, nil
}

// ParseGroup parses /etc/group: name:password:gid:member,member,….
func ParseGroup(b []byte) ([]Group, error) {
	ls, err := lines(b, 4, "/etc/group")
	if err != nil {
		return nil, err
	}
	out := make([]Group, 0, len(ls))
	for i, f := range ls {
		gid, ok := parseID(f[2])
		if f[0] == "" || !ok {
			return nil, fmt.Errorf("%w: /etc/group entry %d has an empty name or a gid that is not a number", ErrDatabase, i+1)
		}
		g := Group{Name: f[0], GID: gid}
		if f[3] != "" {
			m := strings.Split(f[3], ",")
			if len(m) > maxMembers {
				return nil, fmt.Errorf("%w: /etc/group entry %d has more than %d members", ErrDatabase, i+1, maxMembers)
			}
			for _, n := range m {
				if n != "" {
					g.Members = append(g.Members, n)
				}
			}
		}
		out = append(out, g)
	}
	return out, nil
}

// User is the account named name.
func (a *Accounts) User(name string) (Account, bool) {
	for _, u := range a.Users {
		if u.Name == name {
			return u, true
		}
	}
	return Account{}, false
}

// UsersByUID is every account with uid (more than one is possible in a
// hand-edited file).
func (a *Accounts) UsersByUID(uid uint32) []Account {
	var out []Account
	for _, u := range a.Users {
		if u.UID == uid {
			out = append(out, u)
		}
	}
	return out
}

// Group is the group named name.
func (a *Accounts) Group(name string) (Group, bool) {
	for _, g := range a.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

// GroupsByGID is every group with gid.
func (a *Accounts) GroupsByGID(gid uint32) []Group {
	var out []Group
	for _, g := range a.Groups {
		if g.GID == gid {
			out = append(out, g)
		}
	}
	return out
}

// Supplementary is every group that lists user as a member, in file order.
func (a *Accounts) Supplementary(user string) []Group {
	var out []Group
	for _, g := range a.Groups {
		if slices.Contains(g.Members, user) {
			out = append(out, g)
		}
	}
	return out
}
