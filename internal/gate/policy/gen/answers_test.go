package gen_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
)

const minimal = "preset: read-only\naccount: { user: svc-shell, uid: 60123 }\nread: [/srv/app]\n"

// TestDecodeRefusals: every refusal of the answers file itself (POLICY
// §9.1, §9.2), each naming the key it concerns.
func TestDecodeRefusals(t *testing.T) {
	root := "root:\n  socket_group: { name: svc-shell-priv, gid: 60124 }\n  read: [/etc/example-app]\n"
	for _, c := range []struct {
		name, src, want string
	}{
		{"empty", "", "empty"},
		{"unknown key", minimal + "sudo: true\n", "field sudo not found"},
		{"unknown nested key", minimal + "services: { status: [a.service], restart: [a.service] }\n", "field restart not found"},
		{"unknown root key", strings.Replace(minimal, "read-only", "admin", 1) + root + "  shell: /bin/sh\n", "field shell not found"},
		{"wrong type", "preset: read-only\naccount: { user: svc-shell, uid: \"60123\" }\n", "cannot unmarshal"},
		{"wrong type list", minimal + "deny: \"**/*.key\"\n", "cannot unmarshal"},
		{"templates not lists", minimal + "commands:\n  - { id: a, path: /usr/bin/apt, tier: read, templates: [\"list\"] }\n", "cannot unmarshal"},
		{"duplicate key", minimal + "read: [/srv/other]\n", "already defined"},
		{"two documents", minimal + "---\n" + minimal, "single YAML document"},
		{"not a mapping", "- preset\n", "cannot unmarshal"},
		{"too large", minimal + "# " + strings.Repeat("x", gen.MaxAnswersBytes) + "\n", "larger than"},
		{"no preset", "account: { user: svc-shell, uid: 60123 }\n", "answers preset: is required"},
		{"unknown preset", strings.Replace(minimal, "read-only", "root", 1), "answers preset: is \"root\""},
		{"no account", "preset: read-only\n", "answers account: is required"},
		{"no uid", "preset: read-only\naccount: { user: svc-shell }\n", "answers account: is required"},
		{"bad user", strings.Replace(minimal, "user: svc-shell", "user: \"svc shell\"", 1), "answers account.user"},
		{"uid 0", strings.Replace(minimal, "uid: 60123", "uid: 0", 1), "answers account.uid: 0 is not in 1..4294967294"},
		{"uid negative", strings.Replace(minimal, "uid: 60123", "uid: -1", 1), "answers account.uid"},
		{"uid too large", strings.Replace(minimal, "uid: 60123", "uid: 4294967295", 1), "answers account.uid"},
		{"landlock unknown", minimal + "landlock: off\n", "answers landlock: is \"off\""},
		{"landlock empty", minimal + "landlock: \"\"\n", "answers landlock: is empty"},
		{"write under read-only", minimal + "write: [/srv/app/config]\n", "answers write: is not allowed under the read-only preset"},
		{"control under read-only", minimal + "services: { control: { units: [a.service], verbs: [restart] } }\n", "answers services.control: is not allowed under the read-only preset"},
		{"root under read-only", minimal + root, "answers root: is not allowed under the read-only preset"},
		{"root under operator", strings.Replace(minimal, "read-only", "operator", 1) + root, "answers root: is not allowed under the operator preset"},
		{"root without socket group", strings.Replace(minimal, "read-only", "admin", 1) + "root:\n  read: [/etc/example-app]\n", "answers root.socket_group: is required"},
		{"socket group without gid", strings.Replace(minimal, "read-only", "admin", 1) + "root:\n  socket_group: { name: g }\n", "answers root.socket_group: is required"},
		{"bad socket group", strings.Replace(minimal, "read-only", "admin", 1) + strings.Replace(root, "svc-shell-priv", "\"-x\"", 1), "answers root.socket_group.name"},
		{"socket gid 0", strings.Replace(minimal, "read-only", "admin", 1) + strings.Replace(root, "60124", "0", 1), "answers root.socket_group.gid: 0"},
		{"packages allow nothing", strings.Replace(minimal, "read-only", "admin", 1) + root + "  packages: { allow_upgrade: false }\n", "answers root.packages: allows nothing"},
		{"control character in a value", strings.Replace(minimal, "/srv/app", "\"/srv/a\\x07pp\"", 1), "answers read[0]"},
		{"line separator in a value", strings.Replace(minimal, "/srv/app", "\"/srv/a\\u2028pp\"", 1), "answers read[0]"},
		{"line separator in an acknowledge", strings.Replace(minimal, "read-only", "admin", 1) + root + "  power: { allowed: [reboot], acknowledge: \"ok\\u2029x\" }\n", "answers root.power.acknowledge"},
		{"header too long", strings.Repeat("# x\n", 65) + "\n" + minimal, "more than 64 lines"},
		{"header line too long", "# " + strings.Repeat("x", 300) + "\n\n" + minimal, "longer than 256 bytes"},
		{"header with a line separator", "# a" + string(rune(0x2028)) + "max_tier: destructive\n\n" + minimal, "field max_tier not found"},
		// yaml.v3 itself reads U+2028 as a line break, so the "comment"
		// ends there and max_tier is a key, which the strict schema refuses.
		{"command comment with a BOM", minimal + "commands:\n  # a" + string(rune(0xfeff)) + "b\n  - { id: a, path: /usr/bin/apt, tier: read, templates: [[\"list\"]] }\n", "U+FEFF"},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, err := gen.Decode([]byte(c.src))
			if err == nil {
				t.Fatalf("accepted: %+v", a)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
			var ae *gen.Error
			if !errors.As(err, &ae) {
				t.Fatalf("error %T is not an *gen.Error", err)
			}
		})
	}
}

// TestDecodeAccepts: what the presets allow decodes, and empty lists are
// absent.
func TestDecodeAccepts(t *testing.T) {
	for _, src := range []string{
		minimal,
		// git is read-tier under read-only (decided 2026-11-02).
		minimal + "git: { repos: [{ path: /srv/app/deploy, remote: https://git.example.test/org/deploy.git }] }\n",
		minimal + "services: { status: [a.service] }\njournal: { units: [a.service] }\nlandlock: best-effort\n",
		strings.Replace(minimal, "read-only", "operator", 1) + "write: [/srv/app/config]\nservices: { control: { units: [a.service], verbs: [restart] } }\n",
		strings.Replace(minimal, "read-only", "admin", 1) + "root:\n  socket_group: { name: svc-shell-priv, gid: 60124 }\n  packages: { allow_update_index: true }\n",
	} {
		if _, err := gen.Decode([]byte(src)); err != nil {
			t.Errorf("%v\n%s", err, src)
		}
	}
	a, err := gen.Decode([]byte(minimal + "write: []\ndeny: []\nservices: { status: [] }\njournal: { units: [] }\ngit: { repos: [] }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Write) != 0 || len(a.Deny) != 0 || a.Services != nil || a.Journal != nil || a.Git != nil {
		t.Fatalf("empty lists were not absent: %+v", a)
	}
}

// TestDecodeComments: the carried comments (POLICY §9.3) are the opening
// comment, the comment above each commands entry, the comment above root:
// and above each root.commands entry; nothing else.
func TestDecodeComments(t *testing.T) {
	src := "# Header line one.\n#\n#   indented\n\n# Not carried: it is about preset.\npreset: admin # not carried either\n" +
		"account: { user: svc-shell, uid: 60123 }\ncommands:\n  # About a.\n  - id: a\n    path: /usr/bin/apt\n    # Not carried: inside the entry.\n    tier: read\n    templates: [[\"list\"]]\n" +
		"  - { id: b, path: /usr/bin/apt, tier: read, templates: [[\"list\"]] }\n" +
		"# The privileged header.\nroot:\n  socket_group: { name: svc-shell-priv, gid: 60124 }\n  commands:\n    # About c.\n    - { id: c, path: /usr/bin/lsblk, tier: read, templates: [[\"--json\"]] }\n"
	a, err := gen.Decode([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if a.Header != "Header line one.\n\n  indented" {
		t.Errorf("header %q", a.Header)
	}
	if a.Commands[0].Comment != "About a." || a.Commands[1].Comment != "" {
		t.Errorf("command comments %q, %q", a.Commands[0].Comment, a.Commands[1].Comment)
	}
	if a.Root.Comment != "The privileged header." || a.Root.Commands[0].Comment != "About c." {
		t.Errorf("root comments %q, %q", a.Root.Comment, a.Root.Commands[0].Comment)
	}
	for _, s := range []string{a.Header, a.Commands[0].Comment, a.Root.Comment} {
		if strings.Contains(s, "carried") {
			t.Errorf("an uncarried comment was carried: %q", s)
		}
	}
}

// TestCheckComment: POLICY §9.3's rules on a carried comment.
func TestCheckComment(t *testing.T) {
	for _, ok := range []string{"", "a", "a\nb", "a\r\nb", "a\rb", "max_tier: destructive", "---", "# ## #", "café — 'quoted' \"x\""} {
		if err := gen.CheckComment(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"a\x00b", "a\tb", "a\x1b[31m", "a\x7f", "a\u0085b", "a" + string(rune(0x2028)) + "b", "a" + string(rune(0x2029)) + "b", string(rune(0xfeff)) + "a", "a\xffb",
		strings.Repeat("a\n", 64) + "a", strings.Repeat("x", 257)} {
		if err := gen.CheckComment(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
