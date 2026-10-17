package approvers

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Every seed here is generated at test time; names are invented.

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func randSeed(t *testing.T) string { return b32.EncodeToString(randBytes(t, MinSeedBytes)) }

// noSecret fails if the error's text contains any of the secrets, in any
// case.
func noSecret(t *testing.T, err error, secrets ...string) {
	t.Helper()
	msg := strings.ToLower(err.Error())
	for _, s := range secrets {
		if s != "" && strings.Contains(msg, strings.ToLower(s)) {
			t.Fatalf("error %q contains a secret", err)
		}
	}
	if strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("error %q is not one line", err)
	}
}

func TestParseValid(t *testing.T) {
	s1, s2 := randBytes(t, MinSeedBytes), randBytes(t, MaxSeedBytes)
	e1, e2 := b32.EncodeToString(s1), b32.EncodeToString(s2)
	for _, c := range []struct {
		name  string
		data  string
		max   int
		names []string
		seeds [][]byte
	}{
		{"one", "alice " + e1 + "\n", 1, []string{"alice"}, [][]byte{s1}},
		{"no final newline", "alice " + e1, 1, []string{"alice"}, [][]byte{s1}},
		{"crlf", "alice " + e1 + "\r\n", 1, []string{"alice"}, [][]byte{s1}},
		{"lower-case seed", "alice " + strings.ToLower(e1) + "\n", 1, []string{"alice"}, [][]byte{s1}},
		{"longest seed", "ops-1 " + e2 + "\n", 1, []string{"ops-1"}, [][]byte{s2}},
		{"two", "alice " + e1 + "\nbob " + e2 + "\n", 2, []string{"alice", "bob"}, [][]byte{s1, s2}},
		{"name bounds", "a " + e1 + "\nz" + strings.Repeat("9", 31) + " " + e2 + "\n", 8, []string{"a", "z" + strings.Repeat("9", 31)}, [][]byte{s1, s2}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse([]byte(c.data), c.max)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(got) != len(c.names) {
				t.Fatalf("got %d approvers, want %d", len(got), len(c.names))
			}
			for i, a := range got {
				if a.Name != c.names[i] || !bytes.Equal(a.Seed(), c.seeds[i]) {
					t.Fatalf("approver %d = %q, want %q with its seed", i, a.Name, c.names[i])
				}
			}
		})
	}
}

func TestParseRefuses(t *testing.T) {
	seed := randSeed(t)
	other := randSeed(t)
	// A name-shaped lower-case seed: a refusal that echoed names would leak it.
	nameShaped := "s" + strings.ToLower(b32.EncodeToString(randBytes(t, MinSeedBytes)))[:31]
	short := b32.EncodeToString(randBytes(t, MinSeedBytes-1))
	long := b32.EncodeToString(randBytes(t, MaxSeedBytes+1))
	padded := base32.StdEncoding.EncodeToString(randBytes(t, 21))
	// 21 bytes is 34 characters with 2 spare bits; set one of them.
	noncanonical := b32.EncodeToString(randBytes(t, 21))
	noncanonical = noncanonical[:33] + string(b32Next(noncanonical[33]))
	for _, c := range []struct {
		name, data, want string
		max              int
	}{
		{"empty", "", "no approver", 1},
		{"only a newline", "\n", "line 1", 1},
		{"blank line", "alice " + seed + "\n\nbob " + other + "\n", "line 2", 8},
		{"comment", "# approvers\nalice " + seed + "\n", "line 1", 8},
		{"upper-case name", "Alice " + seed + "\n", "line 1: name", 1},
		{"name starts with a digit", "1ops " + seed + "\n", "line 1: name", 1},
		{"name starts with a hyphen", "-ops " + seed + "\n", "line 1: name", 1},
		{"name too long", "a" + strings.Repeat("b", 32) + " " + seed + "\n", "line 1: name", 1},
		{"underscore", "ops_1 " + seed + "\n", "line 1: name", 1},
		{"empty name", " " + seed + "\n", "line 1", 1},
		{"no seed", "alice\n", "line 1", 1},
		{"seed alone", seed + "\n", "line 1", 1},
		{"tab", "alice\t" + seed + "\n", "line 1", 1},
		{"two spaces", "alice  " + seed + "\n", "line 1", 1},
		{"trailing space", "alice " + seed + " \n", "line 1", 1},
		{"three fields", "alice " + seed + " extra\n", "line 1", 1},
		{"padding", "alice " + padded + "\n", "line 1: seed", 1},
		{"not base32", "alice " + seed[:31] + "1\n", "line 1: seed", 1},
		{"non-canonical", "alice " + noncanonical + "\n", "line 1: seed", 1},
		{"short seed", "alice " + short + "\n", "line 1: seed is shorter than 160 bits", 1},
		{"long seed", "alice " + long + "\n", "line 1: seed", 1},
		{"nul", "alice " + seed + "\x00\n", "line 1", 1},
		{"not utf-8", "al\xffce " + seed + "\n", "line 1", 1},
		{"duplicate", "alice " + seed + "\nalice " + other + "\n", "line 2: duplicate approver name (also on line 1)", 8},
		{"duplicate seed-shaped name", nameShaped + " " + seed + "\n" + nameShaped + " " + other + "\n", "line 2: duplicate", 8},
		{"over the maximum", "alice " + seed + "\nbob " + other + "\n", "SHELL_MCP_APPROVAL_MAX_APPROVERS", 1},
		{"over the hard maximum", nine(seed), "SHELL_MCP_APPROVAL_MAX_APPROVERS", MaxApprovers},
		{"maximum out of range", "alice " + seed + "\n", "SHELL_MCP_APPROVAL_MAX_APPROVERS", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse([]byte(c.data), c.max)
			if err == nil {
				t.Fatalf("Parse accepted it: %d approvers", len(got))
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("error %T is not *Error", err)
			}
			noSecret(t, err, seed, other, nameShaped, short, long, padded, noncanonical, strings.TrimRight(padded, "="))
		})
	}
}

// nine is nine approvers, one more than any maximum allows.
func nine(seed string) string {
	var b strings.Builder
	for i := range MaxApprovers + 1 {
		fmt.Fprintf(&b, "a%d %s\n", i, seed)
	}
	return b.String()
}

// b32Next is the next character of the base32 alphabet after c.
func b32Next(c byte) byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	i := strings.IndexByte(alphabet, c)
	return alphabet[(i+1)%len(alphabet)]
}

func TestParseMaxApprovers(t *testing.T) {
	if n, err := ParseMaxApprovers("", false); err != nil || n != DefaultMaxApprovers {
		t.Fatalf("unset = %d, %v; want %d", n, err, DefaultMaxApprovers)
	}
	for i := 1; i <= MaxApprovers; i++ {
		if n, err := ParseMaxApprovers(fmt.Sprint(i), true); err != nil || n != i {
			t.Fatalf("%d = %d, %v", i, n, err)
		}
	}
	for _, v := range []string{"", "0", "9", "-1", "abc", "1.5", " 2", "2 ", "+2", "0x2"} {
		n, err := ParseMaxApprovers(v, true)
		if err == nil {
			t.Fatalf("%q accepted as %d", v, n)
		}
		if !strings.Contains(err.Error(), "SHELL_MCP_APPROVAL_MAX_APPROVERS") {
			t.Fatalf("error %q does not name the variable", err)
		}
	}
}

func writeFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approvers")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireModes(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("file modes are synthesized on Windows")
	}
}

func TestLoad(t *testing.T) {
	requireModes(t)
	seed := randBytes(t, MinSeedBytes)
	line := "alice " + b32.EncodeToString(seed) + "\n"
	for _, mode := range []os.FileMode{0o600, 0o400, 0o700} {
		got, err := Load(writeFile(t, line, mode), 1)
		if err != nil {
			t.Fatalf("mode %04o: %v", mode, err)
		}
		if len(got) != 1 || got[0].Name != "alice" || !bytes.Equal(got[0].Seed(), seed) {
			t.Fatalf("mode %04o: got %v", mode, got)
		}
	}
}

func TestLoadRefusesGroupOrOtherAccess(t *testing.T) {
	requireModes(t)
	seed := randSeed(t)
	for _, mode := range []os.FileMode{0o640, 0o620, 0o610, 0o604, 0o602, 0o601, 0o644, 0o660, 0o666} {
		_, err := Load(writeFile(t, "alice "+seed+"\n", mode), 1)
		if err == nil {
			t.Fatalf("mode %04o accepted", mode)
		}
		if !strings.Contains(err.Error(), "group or other") {
			t.Fatalf("mode %04o: error %q", mode, err)
		}
		noSecret(t, err, seed)
	}
}

func TestLoadRefuses(t *testing.T) {
	requireModes(t)
	seed := randSeed(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	big := writeFile(t, "alice "+seed+"\n"+strings.Repeat("x", 64<<10), 0o600)
	for _, c := range []struct{ name, path, want string }{
		{"missing", filepath.Join(dir, "missing"), "cannot read"},
		{"directory", dir, "not a regular file"},
		{"too large", big, "exceeds"},
		{"unparsable", writeFile(t, "Alice "+seed+"\n", 0o600), "line 1"},
		{"empty", writeFile(t, "", 0o600), "no approver"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(c.path, 1)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Load = %v, want an error containing %q", err, c.want)
			}
			if !strings.HasPrefix(err.Error(), "approvers file: ") {
				t.Fatalf("error %q lacks the source", err)
			}
			noSecret(t, err, seed)
		})
	}
}

func TestApproverNeverRendersSeed(t *testing.T) {
	seed := randBytes(t, MinSeedBytes)
	enc := b32.EncodeToString(seed)
	got, err := Parse([]byte("alice "+enc+"\n"), 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("Parse = %d approvers, %v", len(got), err)
	}
	a := got[0]
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "approver", a, "list", got)
	js, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	out := fmt.Sprintf("%v %+v %#v %s %q %x", a, a, a, a, a, a) + fmt.Sprint(got) + string(js) + logged.String()
	if !strings.Contains(out, "alice") {
		t.Fatalf("the name is missing from %q", out)
	}
	for _, s := range []string{enc, strings.ToLower(enc), fmt.Sprintf("%x", seed), string(seed)} {
		if strings.Contains(out, s) {
			t.Fatalf("a rendering contains the seed: %q", out)
		}
	}
}

func TestSeedsAndSeedCopies(t *testing.T) {
	seed := randBytes(t, MinSeedBytes)
	got, err := Parse([]byte("alice "+b32.EncodeToString(seed)+"\n"), 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("Parse = %d approvers, %v", len(got), err)
	}
	s := got[0].Seed()
	s[0] ^= 0xff
	if !bytes.Equal(got[0].Seed(), seed) {
		t.Fatal("changing Seed's result changed the approver")
	}
	m := Seeds(got)
	if len(m) != 1 || !bytes.Equal(m["alice"], seed) {
		t.Fatalf("Seeds = %d entries", len(m))
	}
}

func TestURI(t *testing.T) {
	seed := []byte("12345678901234567890") // RFC 6238 Appendix B test seed
	want := "otpauth://totp/shell-mcp:alice?secret=" + b32.EncodeToString(seed) + "&issuer=shell-mcp&algorithm=SHA1&digits=6&period=30"
	if got := URI("alice", seed); got != want {
		t.Fatalf("URI = %q\nwant  %q", got, want)
	}
	if got := EncodeSeed(seed); got != b32.EncodeToString(seed) || strings.Contains(got, "=") {
		t.Fatalf("EncodeSeed = %q", got)
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"a", "alice", "ops-1", "a" + strings.Repeat("0", 31)} {
		if !ValidName(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{"", "Alice", "1a", "-a", "a_b", "a b", "a" + strings.Repeat("0", 32), "ä"} {
		if ValidName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}
