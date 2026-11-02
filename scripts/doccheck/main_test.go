package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// Every document below is an invented fixture.

func TestSlug(t *testing.T) {
	for h, want := range map[string]string{
		"1. Two transports":                         "1-two-transports",
		"Read tier (profile ≥ `read-only`)":         "read-tier-profile--read-only",
		"Stack editors (DockHand, Portainer, …)":    "stack-editors-dockhand-portainer-",
		"`shell-mcp init`":                          "shell-mcp-init",
		"12.6 `shell-mcp doctor` *(container)*":     "126-shell-mcp-doctor-container",
		"5. Target hardening (normative; `docs/X`)": "5-target-hardening-normative-docsx",
		"§14 Decisions":                             "14-decisions",
		"Privileged tier (profile = `admin`; gate)": "privileged-tier-profile--admin-gate",
		"What_it does":                              "what_it-does",
	} {
		if got := slug(h); got != want {
			t.Errorf("slug(%q) = %q, want %q", h, got, want)
		}
	}
}

func TestRefs(t *testing.T) {
	for line, want := range map[string][]ref{
		"see POLICY §3 and §7.":                              {{"POLICY", "3"}, {"POLICY", "7"}},
		"(SECURITY §5 step 1, ARCHITECTURE §4.0)":            {{"SECURITY", "5"}, {"ARCHITECTURE", "4.0"}},
		"bare (§12.1) here":                                  {{"", "12.1"}},
		"`docs/TARGET-SETUP.md` §12.3":                       {{"TARGET-SETUP", "12.3"}},
		"[`../docs/CLIENTS.md`](../docs/CLIENTS.md) §1 says": {{"CLIENTS", "1"}},
		"PRIVILEGED §5.3 list A, §4a and §6":                 {{"PRIVILEGED", "5.3"}, {"PRIVILEGED", "4a"}, {"PRIVILEGED", "6"}},
		"handoff §6 and plan §2":                             {{"plan", "2"}},
		"ARCHIVE §14":                                        {{"ARCHIVE", "14"}},
		"no reference here":                                  nil,
		"](§)§0,§0":                                          nil, // FuzzRefs's finding: a list continuing another document's reference
	} {
		if got := refs(line); !slices.Equal(got, want) {
			t.Errorf("refs(%q) = %v, want %v", line, got, want)
		}
	}
}

var fixture = fstest.MapFS{
	"README.md": {Data: []byte("# Title\n\n## Quick start\n\nSee [setup](docs/TARGET-SETUP.md#12-the-install-commands), " +
		"[the start](#quick-start), [CLIENTS](docs/CLIENTS.md) and [the web](https://example.test/x).\n" +
		"TARGET-SETUP §12.1 and §12.2; CLIENTS §1.\n" +
		"```bash\n# a comment, not a heading\necho '[x](missing.md) TARGET-SETUP §99'\n```\n" +
		"`[y](missing-in-code.md)` and handoff §42 are not checked.\n")},
	"docs/TARGET-SETUP.md": {Data: []byte("# Target\n\n## 12. The install commands\n\n### 12.1 One\n\n### 12.2 Two\n\n" +
		"Back to [the readme](../README.md#quick-start); bare (§12.1).\n")},
	"docs/CLIENTS.md": {Data: []byte("# Clients\n\n## 1. Two transports\n")},
	"docs/BROKEN.md": {Data: []byte("# Broken\n\n## 1. One\n\n" +
		"[gone](NOPE.md), [no anchor](CLIENTS.md#3-approvals), [here](#nowhere).\n" +
		"CLIENTS §3, TARGET-SETUP §12.1 and §12.9, bare §2.\n" +
		"[`TARGET-SETUP.md`](TARGET-SETUP.md) §13.\n")},
}

func TestCheckGood(t *testing.T) {
	problems, err := check(fixture, []string{"README.md", "docs/TARGET-SETUP.md", "docs/CLIENTS.md"})
	if err != nil || len(problems) != 0 {
		t.Fatalf("problems %v, error %v", problems, err)
	}
}

func TestCheckBroken(t *testing.T) {
	problems, err := check(fixture, []string{"docs/BROKEN.md"})
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(problems, "\n")
	for _, want := range []string{
		"docs/BROKEN.md:5: NOPE.md: no such file",
		"docs/BROKEN.md:5: CLIENTS.md#3-approvals: no heading",
		"docs/BROKEN.md:5: #nowhere: no heading",
		"docs/BROKEN.md:6: CLIENTS §3: no such section",
		"docs/BROKEN.md:6: TARGET-SETUP §12.9: no such section",
		"docs/BROKEN.md:6: §2: no such section",
		"docs/BROKEN.md:7: TARGET-SETUP §13: no such section",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if len(problems) != 7 {
		t.Errorf("%d problems, want 7:\n%s", len(problems), all)
	}
}

func TestCheckMissingDocument(t *testing.T) {
	if _, err := check(fixture, []string{"docs/ABSENT.md"}); err == nil {
		t.Fatal("a document that does not exist was accepted")
	}
}

var sectionRE = regexp.MustCompile(`^\d+[a-z]?(\.\d+)*$`)

func FuzzRefs(f *testing.F) {
	for _, s := range []string{"POLICY §3 and §7", "(§12.1)", "[a](b.md) §2", "§", "§§1.", "TOOLS §4a.1.2, §x", "](§)§0,§0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		for _, r := range refs(line) {
			if !sectionRE.MatchString(r.section) || strings.ContainsAny(r.doc, " \t§") {
				t.Fatalf("ref %+v from %q", r, line)
			}
		}
	})
}

func FuzzSlug(f *testing.F) {
	for _, s := range []string{"1. Two transports", "Read tier (profile ≥ `read-only`)", "", "--", "Ünïcödé §"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, h string) {
		s := slug(h)
		if strings.ContainsAny(s, " \t\n`§") || strings.ToLower(s) != s {
			t.Fatalf("slug(%q) = %q", h, s)
		}
	})
}
