package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
)

// The seed below is the RFC 6238 Appendix B SHA-1 test seed, a published
// test value; every other seed is generated at test time. Names are invented.

var rfcSeed = []byte("12345678901234567890")

func terminalEnv(r io.Reader) approverEnv {
	return approverEnv{rand: r, isTerminal: func(io.Writer) bool { return true }}
}

func approver(t *testing.T, env approverEnv, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = cmdApprover(args, &out, &errb, env)
	return code, out.String(), errb.String()
}

func requireFileModes(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("file modes are synthesized on Windows")
	}
}

// auditLines decodes stderr's JSON lines.
func auditLines(t *testing.T, stderr string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(stderr), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("stderr line %q is not JSON: %v", l, err)
		}
		lines = append(lines, m)
	}
	return lines
}

// noSeedIn fails if s carries the seed, the URI or anything otpauth-shaped.
func noSeedIn(t *testing.T, what, s string, seed []byte) {
	t.Helper()
	enc := approvers.EncodeSeed(seed)
	for _, bad := range []string{enc, strings.ToLower(enc), string(seed), "otpauth", "secret="} {
		if strings.Contains(s, bad) {
			t.Fatalf("%s carries the seed or URI: %q", what, s)
		}
	}
}

// goldenRows reads one case's matrix from the QR encoder's golden fixtures.
func goldenRows(t *testing.T, id string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "internal", "approval", "qr", "testdata", "golden.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	var rows []string
	in := false
	for sc.Scan() {
		l := sc.Text()
		switch {
		case l == "case "+id:
			in = true
		case !in:
		case l == "end":
			return rows
		case strings.HasPrefix(l, "#") || strings.HasPrefix(l, "."):
			rows = append(rows, l)
		}
	}
	t.Fatalf("golden case %s not found", id)
	return nil
}

// qrRows reads the half-block QR code out of the command's output, without
// its quiet zone, as golden rows.
func qrRows(t *testing.T, stdout string) []string {
	t.Helper()
	const pre, post = "\x1b[97;40m", "\x1b[0m"
	var grid [][]byte
	for _, l := range strings.Split(stdout, "\n") {
		if !strings.HasPrefix(l, pre) {
			continue
		}
		var top, bottom []byte
		for _, g := range strings.TrimSuffix(strings.TrimPrefix(l, pre), post) {
			switch g { // light modules are the foreground colour
			case '█':
				top, bottom = append(top, '.'), append(bottom, '.')
			case '▀':
				top, bottom = append(top, '.'), append(bottom, '#')
			case '▄':
				top, bottom = append(top, '#'), append(bottom, '.')
			case ' ':
				top, bottom = append(top, '#'), append(bottom, '#')
			default:
				t.Fatalf("unexpected glyph %q", g)
			}
		}
		grid = append(grid, top, bottom)
	}
	const quiet = 4
	if len(grid) < 2*quiet+21 {
		t.Fatalf("no QR code in the output (%d rows)", len(grid))
	}
	n := len(grid[0]) - 2*quiet
	rows := []string{}
	for y := quiet; y < quiet+n; y++ {
		rows = append(rows, string(grid[y][quiet:quiet+n]))
	}
	return rows
}

func TestApproverAdd(t *testing.T) {
	requireFileModes(t)
	path := filepath.Join(t.TempDir(), "approvers")
	code, stdout, stderr := approver(t, terminalEnv(bytes.NewReader(rfcSeed)), "add", "--name", "alice", "--file", path)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}

	// The URI, once, as its own line.
	uri := approvers.URI("alice", rfcSeed)
	if want := "otpauth://totp/shell-mcp:alice?secret=" + approvers.EncodeSeed(rfcSeed) + "&issuer=shell-mcp&algorithm=SHA1&digits=6&period=30"; uri != want {
		t.Fatalf("URI %q", uri)
	}
	if n := strings.Count(stdout, uri); n != 1 {
		t.Fatalf("the URI appears %d times", n)
	}
	if !strings.Contains(stdout, "\n"+uri+"\n") {
		t.Fatal("the URI is not on a line of its own")
	}
	if strings.Index(stdout, "\x1b[97;40m") > strings.Index(stdout, uri) {
		t.Fatal("the URI is not below the QR code")
	}

	// The QR code is the golden matrix of that URI.
	got, want := qrRows(t, stdout), goldenRows(t, "uri-alice")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the QR code differs from the golden matrix:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// The file.
	b, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "alice "+approvers.EncodeSeed(rfcSeed)+"\n" {
		t.Fatalf("file %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}

	// The audit line: name and file only.
	lines := auditLines(t, stderr)
	if len(lines) != 1 || lines[0]["msg"] != "approver enrolled" || lines[0]["name"] != "alice" || lines[0]["file"] != path {
		t.Fatalf("audit lines %v", lines)
	}
	for k := range lines[0] {
		if k != "time" && k != "level" && k != "msg" && k != "name" && k != "file" {
			t.Fatalf("audit line carries %q", k)
		}
	}
	noSeedIn(t, "stderr", stderr, rfcSeed)
}

func TestApproverAddRefusesWithoutTerminal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvers")
	env := approverEnv{rand: bytes.NewReader(rfcSeed), isTerminal: func(io.Writer) bool { return false }}
	code, stdout, stderr := approver(t, env, "add", "--name", "alice", "--file", path)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "terminal") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	noSeedIn(t, "stderr", stderr, rfcSeed)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the file was written without a terminal: %v", err)
	}
}

// TestApproverAddRefusesPipe: the real terminal check, with stdout a pipe.
func TestApproverAddRefusesPipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvers")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	var errb bytes.Buffer
	code := cmdApprover([]string{"add", "--name", "alice", "--file", path}, w, &errb, processApproverEnv)
	_ = w.Close()
	piped, _ := io.ReadAll(r)
	if code != 1 || len(piped) != 0 {
		t.Fatalf("exit %d, piped %q", code, piped)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the file was written with stdout a pipe")
	}
}

func TestApproverAddRefusals(t *testing.T) {
	requireFileModes(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "approvers")
	if code, _, stderr := approver(t, terminalEnv(rand.Reader), "add", "--name", "alice", "--file", path); code != 0 {
		t.Fatalf("first add: exit %d: %s", code, stderr)
	}
	before, _ := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"duplicate", []string{"--name", "alice", "--allow-multiple"}, "already enrolled"},
		{"second without allow-multiple", []string{"--name", "bob"}, "--allow-multiple"},
	} {
		t.Run(c.name, func(t *testing.T) {
			seed := make([]byte, 20)
			_, _ = rand.Read(seed)
			args := append([]string{"add", "--file", path}, c.args...)
			code, stdout, stderr := approver(t, terminalEnv(bytes.NewReader(seed)), args...)
			if code != 1 || stdout != "" || !strings.Contains(stderr, c.want) {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			noSeedIn(t, "stderr", stderr, seed)
			if after, _ := os.ReadFile(path); !bytes.Equal(before, after) { //nolint:gosec // G304: the test's own temporary file
				t.Fatal("a refused add changed the file")
			}
		})
	}

	t.Run("group-readable", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "approvers")
		if err := os.WriteFile(p, before, 0o600); err != nil { //nolint:gosec // G703: the test's own temporary file
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o640); err != nil { //nolint:gosec // G302: a deliberately insecure test fixture mode
			t.Fatal(err)
		}
		code, stdout, stderr := approver(t, terminalEnv(rand.Reader), "add", "--name", "bob", "--file", p, "--allow-multiple")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "group or other") {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})

	t.Run("allow-multiple", func(t *testing.T) {
		code, stdout, stderr := approver(t, terminalEnv(rand.Reader), "add", "--name", "bob", "--file", path, "--allow-multiple")
		if code != 0 || !strings.Contains(stdout, "shell-mcp:bob?") {
			t.Fatalf("exit %d: %s", code, stderr)
		}
	})
}

func TestApproverAddRandomFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvers")
	code, stdout, _ := approver(t, terminalEnv(bytes.NewReader(rfcSeed[:10])), "add", "--name", "alice", "--file", path)
	if code != 1 || stdout != "" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a short seed was written")
	}
}

func TestApproverUsage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvers")
	env := terminalEnv(rand.Reader)
	for _, args := range [][]string{
		{},
		{"enrol"},
		{"add"},
		{"add", "--name", "alice"},
		{"add", "--file", path},
		{"add", "--name", "alice", "--file", path, "extra"},
		{"add", "--name", "Alice", "--file", path},
		{"remove", "--name", "alice"},
		{"remove", "--file", path},
		{"list"},
		{"list", "--file", path, "--name", "alice"},
	} {
		code, stdout, _ := approver(t, env, args...)
		if code == 0 || stdout != "" {
			t.Fatalf("%v: exit %d, stdout %q", args, code, stdout)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a usage error wrote the file")
	}
}

func TestApproverRemoveAndList(t *testing.T) {
	requireFileModes(t)
	path := filepath.Join(t.TempDir(), "approvers")
	env := terminalEnv(rand.Reader)
	for _, n := range []string{"alice", "bob"} {
		if code, _, stderr := approver(t, env, "add", "--name", n, "--file", path, "--allow-multiple"); code != 0 {
			t.Fatalf("add %s: %s", n, stderr)
		}
	}
	content, _ := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file

	code, stdout, stderr := approver(t, env, "list", "--file", path)
	if code != 0 || stdout != "alice\nbob\n" || stderr != "" {
		t.Fatalf("list: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	code, stdout, stderr = approver(t, env, "remove", "--name", "alice", "--file", path)
	if code != 0 || stdout != "" {
		t.Fatalf("remove: exit %d: %s", code, stderr)
	}
	lines := auditLines(t, stderr)
	if len(lines) != 1 || lines[0]["msg"] != "approver removed" || lines[0]["name"] != "alice" || lines[0]["file"] != path {
		t.Fatalf("audit lines %v", lines)
	}
	if code, stdout, _ = approver(t, env, "list", "--file", path); code != 0 || stdout != "bob\n" {
		t.Fatalf("list after remove: %q", stdout)
	}
	if after, _ := os.ReadFile(path); !bytes.HasSuffix(content, after) { //nolint:gosec // G304: the test's own temporary file
		t.Fatal("remove changed the remaining line")
	}

	if code, _, stderr = approver(t, env, "remove", "--name", "alice", "--file", path); code != 1 || !strings.Contains(stderr, "no approver") {
		t.Fatalf("removing an unknown approver: exit %d, %q", code, stderr)
	}
}

func TestRunDispatchesApprover(t *testing.T) {
	requireFileModes(t)
	path := filepath.Join(t.TempDir(), "approvers")
	if code, _, stderr := approver(t, terminalEnv(rand.Reader), "add", "--name", "alice", "--file", path); code != 0 {
		t.Fatal(stderr)
	}
	var out, errb bytes.Buffer
	lookup := func(string) (string, bool) { return "", false }
	if code := run(context.Background(), nil, []string{"approver", "list", "--file", path}, lookup, &out, &errb); code != 0 || out.String() != "alice\n" {
		t.Fatalf("run approver list: exit %d, %q, %q", code, out.String(), errb.String())
	}
}

func TestIsTerminal(t *testing.T) {
	if isTerminal(&bytes.Buffer{}) {
		t.Fatal("a buffer is a terminal")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if isTerminal(w) {
		t.Fatal("a pipe is a terminal")
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if isTerminal(f) {
		t.Fatal("a regular file is a terminal")
	}
	if runtime.GOOS == "linux" {
		null, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = null.Close() }()
		if isTerminal(null) {
			t.Fatal("/dev/null (a character device) is a terminal")
		}
	}
}
