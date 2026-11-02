package setup_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/gate/setup"
)

// TestParseFrom: the floors (handoff §7 Q1) at their boundaries, the
// WARN for anything wider than one address, and every refused form.
func TestParseFrom(t *testing.T) {
	for _, c := range []struct {
		in   string
		text string
		warn bool
	}{
		{"192.0.2.10", "192.0.2.10", false},
		{"192.0.2.10/32", "192.0.2.10/32", false},
		{"192.0.2.0/24", "192.0.2.0/24", true},
		{"2001:db8::1", "2001:db8::1", false},
		{"2001:db8::1/128", "2001:db8::1/128", false},
		{"2001:db8::/64", "2001:db8::/64", true},
		{"::ffff:192.0.2.10", "::ffff:192.0.2.10", false},
		{"::ffff:192.0.2.0/120", "::ffff:192.0.2.0/120", true},
		{"2001:DB8::2", "2001:db8::2", false},
	} {
		es, warns, err := setup.ParseFrom([]string{c.in})
		if err != nil || len(es) != 1 || es[0].Text != c.text || (len(warns) == 1) != c.warn {
			t.Errorf("%s: %+v %v %v", c.in, es, warns, err)
		}
		if c.warn && !strings.Contains(warns[0], "/32") && !strings.Contains(warns[0], "/128") {
			t.Errorf("%s: the WARN %q must suggest a single address", c.in, warns[0])
		}
	}
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, "empty"},
		{[]string{""}, "empty entry"},
		{[]string{"*"}, "wildcard"},
		{[]string{"192.0.2.*"}, "wildcard"},
		{[]string{"!192.0.2.10"}, "negation"},
		{[]string{"server.example.test"}, "host names are refused"},
		{[]string{"192.0.2.0/23"}, "floor for IPv4"},
		{[]string{"192.0.0.0/16"}, "floor for IPv4"},
		{[]string{"0.0.0.0/0"}, "floor for IPv4"},
		{[]string{"2001:db8::/63"}, "floor for IPv6"},
		{[]string{"::/0"}, "maps an IPv4 prefix"},
		{[]string{"::ffff:0:0/96"}, "maps an IPv4 prefix"},
		{[]string{"::ffff:192.0.0.0/119"}, "maps an IPv4 prefix"},
		{[]string{"::/64"}, "maps an IPv4 prefix"},
		{[]string{"192.0.2.1/24"}, "host bits"},
		{[]string{"fe80::1%eth0"}, "zone"},
		{[]string{"0.0.0.0"}, "unspecified"},
		{[]string{"192.0.2.10", "192.0.2.10/32"}, "twice"},
		{strings.Split("192.0.2.1,192.0.2.2,192.0.2.3,192.0.2.4,192.0.2.5,192.0.2.6,192.0.2.7,192.0.2.8,192.0.2.9", ","), "at most 8"},
	} {
		_, _, err := setup.ParseFrom(c.in)
		if !errors.Is(err, setup.ErrFrom) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.in, err, c.want)
		}
	}
}

// FuzzParseFrom: never panics; nothing accepted is wider than the floors.
func FuzzParseFrom(f *testing.F) {
	for _, s := range []string{"192.0.2.10", "192.0.2.0/24", "2001:db8::/64", "::ffff:192.0.2.0/120", "a,b", "*", "192.0.2.0/23"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		es, _, err := setup.ParseFrom(strings.Split(s, ","))
		if err != nil {
			return
		}
		for _, e := range es {
			p := e.Prefix
			switch {
			case p.Addr().Is4() && p.Bits() < 24, p.Addr().Is6() && !p.Addr().Is4In6() && p.Bits() < 64, p.Addr().Is4In6() && p.Bits() < 120:
				t.Fatalf("accepted %s", e.Text)
			}
		}
	})
}

// testKey is an invented Ed25519 public key (the base64 of its wire form),
// built from a fixed seed at run time so that no key-like literal is
// committed.
var testKey = func() string {
	k, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)).Public())
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(k.Marshal())
}()

// TestParsePubFile: the one line of an Ed25519 ssh_key.pub, and every
// refusal; a private key is refused without any of it in the message.
func TestParsePubFile(t *testing.T) {
	k, err := setup.ParsePubFile([]byte("ssh-ed25519 " + testKey + " shell-mcp\n"))
	if err != nil || !strings.HasPrefix(k.Fingerprint, "SHA256:") || k.Base64 != testKey {
		t.Fatalf("%+v %v", k, err)
	}
	body := "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU-SECRET"
	for _, c := range []struct{ in, want string }{
		{"-----BEGIN OPENSSH PRIVATE KEY-----\n" + body + "\n-----END OPENSSH PRIVATE KEY-----\n", "private key"},
		{"", "exactly one line"},
		{"ssh-ed25519 " + testKey + "\nssh-ed25519 " + testKey + "\n", "exactly one line"},
		{`restrict ssh-ed25519 ` + testKey, "options"},
		{"ssh-rsa AAAAB3NzaC1yc2E shell-mcp", "must be ssh-ed25519"},
		{"ssh-ed25519 !!!!", "base64"},
		{"ssh-ed25519 AAAA", "does not parse"},
		{"ssh-ed25519", "no key"},
	} {
		_, err := setup.ParsePubFile([]byte(c.in))
		if !errors.Is(err, setup.ErrKey) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%.40q: %v, want %q", c.in, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("the refusal echoes the private key: %v", err)
		}
	}
}

// TestKeyLines: install's own line passes its checks; every line that would
// weaken the keys file is refused.
func TestKeyLines(t *testing.T) {
	k, _ := setup.ParsePubFile([]byte("ssh-ed25519 " + testKey))
	line := setup.RenderKeyLine("192.0.2.10", "/etc/shell-mcp/read-only.yaml", "readonly", k)
	want := `restrict,from="192.0.2.10",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/read-only.yaml --principal readonly" ssh-ed25519 ` + testKey + " shell-mcp-readonly"
	if line != want {
		t.Fatalf("line\n%s\nwant\n%s", line, want)
	}
	check := func(s string) error {
		kl, err := setup.ParseKeyLine(s)
		if err != nil {
			return err
		}
		_, err = setup.CheckLine(kl)
		return err
	}
	if err := check(line); err != nil {
		t.Fatalf("install's own line: %v", err)
	}
	for _, ok := range []string{
		`from="192.0.2.10",restrict,command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/a.yaml" ssh-ed25519 ` + testKey,
		`restrict,no-pty,from="192.0.2.10,192.0.2.11",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/a.yaml --principal op" ssh-ed25519 ` + testKey + " c",
	} {
		if err := check(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	cmd := `command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/a.yaml"`
	for _, c := range []struct{ in, want string }{
		{`from="192.0.2.10",` + cmd + ` ssh-ed25519 ` + testKey, "no restrict"},
		{`restrict,` + cmd + ` ssh-ed25519 ` + testKey, "no from="},
		{`restrict,from="192.0.2.10" ssh-ed25519 ` + testKey, "no command="},
		{`restrict,from="192.0.0.0/16",` + cmd + ` ssh-ed25519 ` + testKey, "floor"},
		{`restrict,pty,from="192.0.2.10",` + cmd + ` ssh-ed25519 ` + testKey, "option pty"},
		{`restrict,environment="A=b",from="192.0.2.10",` + cmd + ` ssh-ed25519 ` + testKey, "option environment"},
		{`restrict,from="192.0.2.10",command="/bin/sh" ssh-ed25519 ` + testKey, "command= is not exactly"},
		{`restrict,from="192.0.2.10",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/a b.yaml" ssh-ed25519 ` + testKey, "command= is not exactly"},
		{`restrict,from="192.0.2.10",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/$(id).yaml" ssh-ed25519 ` + testKey, "characters"},
		{`restrict,from="192.0.2.10",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/a.yaml --principal Root;x" ssh-ed25519 ` + testKey, "principal"},
		{`restrict,from="192.0.2.10",` + cmd + ` ssh-rsa AAAAB3NzaC1yc2E`, "must be ssh-ed25519"},
		{`restrict,from="192.0.2.10,` + cmd + ` ssh-ed25519 ` + testKey, ""},
		{`restrict,from=192.0.2.10,` + cmd + ` ssh-ed25519 ` + testKey, "unquoted"},
		{`ssh-ed25519 ` + testKey, "no restrict"},
	} {
		err := check(c.in)
		if !errors.Is(err, setup.ErrKey) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.in, err, c.want)
		}
	}
}

// FuzzParseKeyLine: never panics; an accepted line keeps restrict, from=
// and the forced command.
func FuzzParseKeyLine(f *testing.F) {
	f.Add(`restrict,from="192.0.2.10",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/a.yaml --principal op" ssh-ed25519 ` + testKey + " c")
	f.Add(`a="\"",b ssh-ed25519 x`)
	f.Fuzz(func(t *testing.T, s string) {
		kl, err := setup.ParseKeyLine(s)
		if err != nil {
			return
		}
		if _, err := setup.CheckLine(kl); err != nil {
			return
		}
		var restrict, command bool
		for _, o := range kl.Options {
			restrict = restrict || o.Name == "restrict"
			command = command || (o.Name == "command" && strings.HasPrefix(o.Value, setup.GatePath+" serve --policy /"))
		}
		if !restrict || !command {
			t.Fatalf("accepted %q", s)
		}
	})
}

func TestParseSshdT(t *testing.T) {
	m, err := setup.ParseSshdT([]byte("port 22\nhostkey /etc/ssh/a\nhostkey /etc/ssh/b\nstrictmodes yes\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n"))
	if err != nil || len(m["hostkey"]) != 2 || m["strictmodes"][0] != "yes" || m["authorizedkeysfile"][0] != ".ssh/authorized_keys .ssh/authorized_keys2" {
		t.Fatalf("%v %v", m, err)
	}
	for _, bad := range []string{"", "Port 22\n", "port\n", " port 22\n"} {
		if _, err := setup.ParseSshdT([]byte(bad)); !errors.Is(err, setup.ErrSshdT) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// FuzzParseSshdT: never panics; every accepted keyword is lowercase.
func FuzzParseSshdT(f *testing.F) {
	f.Add([]byte("port 22\nstrictmodes yes\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := setup.ParseSshdT(b)
		if err != nil {
			return
		}
		for k := range m {
			if k == "" || strings.ToLower(k) != k {
				t.Fatalf("accepted keyword %q", k)
			}
		}
	})
}

func TestParseSize(t *testing.T) {
	for _, c := range []struct {
		in    string
		bytes uint64
	}{{"4G", 4 << 30}, {"6144M", 6144 << 20}, {"64M", 64 << 20}} {
		if b, s, err := setup.ParseSize(c.in); err != nil || b != c.bytes || s != c.in {
			t.Errorf("%s: %d %q %v", c.in, b, s, err)
		}
	}
	for _, bad := range []string{"", "4", "4g", "4GB", "-1G", "04G", "63M", "4T", "1048577G", "18446744073709551615G"} {
		if _, _, err := setup.ParseSize(bad); !errors.Is(err, setup.ErrSize) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for mb, want := range map[int]string{1024: "4G", 1536: "6G", 1000: "4000M", 128: "512M", 16384: "64G"} {
		if got := setup.DefaultSize(mb); got != want {
			t.Errorf("DefaultSize(%d) = %s, want %s", mb, got, want)
		}
	}
}

// FuzzParseSize: never panics; an accepted size is within its bounds.
func FuzzParseSize(f *testing.F) {
	f.Add("4G")
	f.Add("64M")
	f.Fuzz(func(t *testing.T, s string) {
		b, _, err := setup.ParseSize(s)
		if err == nil && (b < 64<<20 || b > 1<<50) {
			t.Fatalf("accepted %q as %d", s, b)
		}
	})
}
