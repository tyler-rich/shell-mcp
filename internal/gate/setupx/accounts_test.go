package setupx_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// The databases below are invented, in the format of Debian's and Ubuntu's.
const (
	passwdFixture = "root:x:0:0:root:/root:/bin/bash\n# a comment\n\nsvc-shell:x:60123:60123::/var/lib/svc-shell:/bin/sh\n" +
		"+nisuser::::::\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
	groupFixture = "root:x:0:\nsystemd-journal:x:999:svc-shell\nsvc-shell:x:60123:\nsvc-shell-priv:x:60124:svc-shell\n" +
		"docker:x:998:alice,svc-shell,\n-nisgroup:::\n"
)

func TestParsePasswd(t *testing.T) {
	got, err := setupx.ParsePasswd([]byte(passwdFixture))
	if err != nil {
		t.Fatal(err)
	}
	want := []setupx.Account{
		{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"},
		{Name: "svc-shell", UID: 60123, GID: 60123, Home: "/var/lib/svc-shell", Shell: "/bin/sh"},
		{Name: "nobody", UID: 65534, GID: 65534, Home: "/nonexistent", Shell: "/usr/sbin/nologin"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed %+v", got)
	}
	for _, bad := range []string{"root:x:0:0:root:/root\n", "a:x:-1:0::/:/bin/sh\n", "a:x:4294967296:0::/:/bin/sh\n", "a:x:007:0::/:/bin/sh\n",
		":x:1:1::/:/bin/sh\n", "a:x::1::/:/bin/sh\n", strings.Repeat("x", setupx.MaxDatabaseBytes+1)} {
		if _, err := setupx.ParsePasswd([]byte(bad)); !errors.Is(err, setupx.ErrDatabase) {
			t.Errorf("%.40q: %v", bad, err)
		}
	}
}

func TestParseGroupAndLookups(t *testing.T) {
	groups, err := setupx.ParseGroup([]byte(groupFixture))
	if err != nil {
		t.Fatal(err)
	}
	users, _ := setupx.ParsePasswd([]byte(passwdFixture))
	a := &setupx.Accounts{Users: users, Groups: groups}
	if g, ok := a.Group("docker"); !ok || g.GID != 998 || !reflect.DeepEqual(g.Members, []string{"alice", "svc-shell"}) {
		t.Fatalf("docker %+v", g)
	}
	var names []string
	for _, g := range a.Supplementary("svc-shell") {
		names = append(names, g.Name)
	}
	if want := []string{"systemd-journal", "svc-shell-priv", "docker"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("supplementary %v, want %v", names, want)
	}
	if u, ok := a.User("svc-shell"); !ok || u.UID != 60123 {
		t.Fatalf("user %+v", u)
	}
	if len(a.UsersByUID(60123)) != 1 || len(a.GroupsByGID(60124)) != 1 || len(a.GroupsByGID(1)) != 0 {
		t.Fatal("lookups by id")
	}
	if _, ok := a.Group("nisgroup"); ok {
		t.Fatal("a NIS compat entry is not a local group")
	}
	for _, bad := range []string{"a:x:1\n", "a:x:x:\n", ":x:1:\n"} {
		if _, err := setupx.ParseGroup([]byte(bad)); !errors.Is(err, setupx.ErrDatabase) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// FuzzParsePasswd: never panics; every accepted entry has a name.
func FuzzParsePasswd(f *testing.F) {
	f.Add([]byte(passwdFixture))
	f.Add([]byte("a:x:1:1::/:/bin/sh"))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := setupx.ParsePasswd(b)
		if err != nil {
			return
		}
		for _, u := range got {
			if u.Name == "" || strings.Contains(u.Name, ":") {
				t.Fatalf("accepted %+v", u)
			}
		}
	})
}

// FuzzParseGroup: never panics; no accepted member is empty.
func FuzzParseGroup(f *testing.F) {
	f.Add([]byte(groupFixture))
	f.Add([]byte("a:x:1:b,,c"))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := setupx.ParseGroup(b)
		if err != nil {
			return
		}
		for _, g := range got {
			for _, m := range g.Members {
				if m == "" || strings.ContainsAny(m, ":,\n") {
					t.Fatalf("accepted member %q", m)
				}
			}
		}
	})
}
