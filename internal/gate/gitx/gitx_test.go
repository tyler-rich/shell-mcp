package gitx

import (
	"slices"
	"strings"
	"testing"
)

// Inputs are invented; the formats were checked against git 2.47.3.

func TestParseStatus(t *testing.T) {
	in := "# branch.oid 20ceddfc7fccd81da5283344cc0356ee9f2a8d81\x00# branch.head main\x00# branch.upstream origin/main\x00# branch.ab +2 -1\x00" +
		"# stash 3\x00" + // unknown headers are ignored
		"1 .M N... 100644 100644 100644 aaaa aaaa app.conf\x00" +
		"2 R. N... 100644 100644 100644 bbbb bbbb R100 ren.txt\x00a.txt\x00" +
		"u UU N... 100644 100644 100644 100644 cccc dddd eeee conflict.txt\x00" +
		"? sp ace.txt\x00? d/\x00! ignored.log\x00"
	st, truncated, err := ParseStatus([]byte(in), 100)
	if err != nil || truncated {
		t.Fatal(err, truncated)
	}
	if st.OID != "20ceddfc7fccd81da5283344cc0356ee9f2a8d81" || st.Branch != "main" || st.Upstream != "origin/main" || st.Ahead != 2 || st.Behind != 1 {
		t.Fatalf("headers %+v", st)
	}
	want := []Entry{{"changed", ".M", "app.conf", ""}, {"renamed", "R.", "ren.txt", "a.txt"}, {"unmerged", "UU", "conflict.txt", ""},
		{"untracked", "", "sp ace.txt", ""}, {"untracked", "", "d/", ""}, {"ignored", "", "ignored.log", ""}}
	if !slices.Equal(st.Entries, want) {
		t.Fatalf("entries\n got %+v\nwant %+v", st.Entries, want)
	}
	if _, cut, _ := ParseStatus([]byte(in), 2); !cut {
		t.Fatal("entry bound not applied")
	}
	for _, bad := range []string{"1 .M N... 100644\x00", "2 R. N... 1 1 1 a b R100 x\x00", "# branch.ab +x -1\x00", "z what\x00", "1 .M N... 100644 100644 100644 a b \x00"} {
		if _, _, err := ParseStatus([]byte(bad), 10); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if st, _, err := ParseStatus([]byte("# branch.oid (initial)\x00# branch.head (detached)\x00"), 10); err != nil || st.OID != "" || st.Branch != "(detached)" {
		t.Fatalf("initial/detached %+v %v", st, err)
	}
}

func TestParseLog(t *testing.T) {
	h := strings.Repeat("a", 40)
	in := h + "\x1fExample Dev\x1f2026-09-27T10:00:00+00:00\x1fbump port\x1e\n" + strings.Repeat("b", 40) + "\x1fX\x1f2026-09-26T10:00:00Z\x1fsubject with \x1f? no\x1e\n"
	cs, err := ParseLog([]byte(in))
	if err == nil {
		t.Fatalf("a subject containing the field separator must fail: %+v", cs)
	}
	cs, err = ParseLog([]byte(in[:strings.Index(in, "\n")+1]))
	if err != nil || len(cs) != 1 || cs[0].Hash != h || cs[0].Author != "Example Dev" || cs[0].Subject != "bump port" {
		t.Fatalf("%+v %v", cs, err)
	}
	if cs, err := ParseLog(nil); err != nil || len(cs) != 0 {
		t.Fatalf("empty %v %v", cs, err)
	}
	if _, err := ParseLog([]byte("short\x1fa\x1fb\x1fc\x1e")); err == nil {
		t.Fatal("bad hash accepted")
	}
}

func TestUnquoteAndClean(t *testing.T) {
	for in, want := range map[string]string{
		`plain`: "plain", `"n\303\251w.txt"`: "néw.txt", `"tab\there"`: "tab\there", `"q\"uote"`: `q"uote`, `"back\\slash"`: `back\slash`,
		`"nl\nx"`: "nl\nx", `sp ace.txt`: "sp ace.txt",
	} {
		if got, err := Unquote(in); err != nil || got != want {
			t.Errorf("Unquote(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{`"unterminated`, `"bad\q"`, `"\400"`, `"a"b`} {
		if _, err := Unquote(bad); err == nil {
			t.Errorf("Unquote(%q) accepted", bad)
		}
	}
	rm, skip, err := ParseClean([]byte("Would remove d/\nWould remove \"n\\303\\251w.txt\"\nWould remove sp ace.txt\nWould skip repository sub/\n"))
	if err != nil || !slices.Equal(rm, []string{"d/", "néw.txt", "sp ace.txt"}) || !slices.Equal(skip, []string{"sub/"}) {
		t.Fatalf("%q %q %v", rm, skip, err)
	}
	if _, _, err := ParseClean([]byte("Removing x\n")); err == nil {
		t.Fatal("unexpected line accepted")
	}
}

func TestConfigAllowlist(t *testing.T) {
	in := "core.repositoryformatversion\n0\x00core.filemode\ntrue\x00core.bare\nfalse\x00core.logallrefupdates\ntrue\x00" +
		"remote.origin.url\nhttps://git.example.test/org/deploy.git\x00remote.origin.fetch\n+refs/heads/*:refs/remotes/origin/*\x00" +
		"branch.main.remote\norigin\x00branch.Feature/X.merge\nrefs/heads/Feature/X\x00core.symlinks\x00"
	kvs, err := ParseConfig([]byte(in))
	if err != nil || len(kvs) != 9 {
		t.Fatalf("%+v %v", kvs, err)
	}
	if bad, ok := CheckConfig(kvs); !ok {
		t.Fatalf("clone defaults refused: %s", bad)
	}
	if v, ok := Value(kvs, "remote.origin.url"); !ok || v != "https://git.example.test/org/deploy.git" {
		t.Fatalf("url %q", v)
	}
	for _, key := range []string{"diff.x.textconv", "filter.x.clean", "filter.x.smudge", "diff.external", "core.askpass", "core.fsmonitor",
		"core.hookspath", "core.sshcommand", "core.pager", "core.editor", "core.worktree", "core.attributesfile", "include.path",
		"includeif.gitdir:/x/.path", "url.https://x/.insteadof", "http.sslverify", "http.proxy", "credential.helper",
		"remote.upstream.url", "remote.origin.pushurl", "remote.origin.uploadpack", "extensions.worktreeconfig", "gpg.program",
		"log.showsignature", "branch..merge", "branch.main.rebase", "alias.st", "protocol.file.allow", "safe.directory", "submodule.x.update"} {
		kv, err := ParseConfig([]byte(key + "\nx\x00"))
		if err != nil {
			t.Fatal(err)
		}
		if bad, ok := CheckConfig(append(slices.Clone(kvs), kv...)); ok || bad != key {
			t.Errorf("%s: ok=%v bad=%q", key, ok, bad)
		}
	}
	for _, bad := range []string{"no-terminator", "\nvalue\x00", "a.b\nv\x00c"} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("ParseConfig(%q) accepted", bad)
		}
	}
}

func FuzzParseStatus(f *testing.F) {
	f.Add([]byte("# branch.oid (initial)\x00# branch.head main\x001 .M N... 100644 100644 100644 a b f\x00? x\x00"))
	f.Add([]byte("2 R. N... 100644 100644 100644 b b R100 ren.txt\x00a.txt\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		st, _, err := ParseStatus(b, 64)
		if err == nil && (len(st.Entries) > 64 || st.Ahead < 0 || st.Behind < 0) {
			t.Fatalf("%+v", st)
		}
	})
}

func FuzzParseClean(f *testing.F) {
	f.Add([]byte("Would remove \"n\\303\\251w.txt\"\nWould skip repository a/\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		rm, skip, err := ParseClean(b)
		if err == nil && len(rm)+len(skip) > strings.Count(string(b), "\n")+1 {
			t.Fatal("more entries than lines")
		}
	})
}

func FuzzConfig(f *testing.F) {
	f.Add([]byte("core.bare\nfalse\x00branch.main.merge\nrefs/heads/main\x00include.path\nx\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		kvs, err := ParseConfig(b)
		if err != nil {
			return
		}
		bad, ok := CheckConfig(kvs)
		if ok {
			for _, kv := range kvs {
				k := kv.Key
				if strings.HasPrefix(k, "include") || strings.Contains(k, "filter.") || strings.Contains(k, "textconv") || strings.Contains(k, "insteadof") {
					t.Fatalf("allowed %q", k)
				}
			}
		} else if bad == "" {
			t.Fatal("refusal without a key")
		}
	})
}

func FuzzLogAndUnquote(f *testing.F) {
	f.Add([]byte(strings.Repeat("a", 40) + "\x1fA\x1f2026-09-27T10:00:00Z\x1fs\x1e\n"))
	f.Add([]byte(`"a\303\251\n"`))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = ParseLog(b)
		_, _ = Unquote(string(b))
	})
}
