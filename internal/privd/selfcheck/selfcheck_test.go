//go:build linux

package selfcheck_test

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/selfcheck"
)

// An invented /proc/self/status in the proc_pid_status(5) format.
func status(uid, nnp, capBnd string) string {
	return "Name:\tshell-mcp-privd\nUmask:\t0077\nState:\tR (running)\nTgid:\t4242\nPid:\t4242\nPPid:\t1\n" +
		"Uid:\t" + uid + "\t" + uid + "\t" + uid + "\t" + uid + "\nGid:\t0\t0\t0\t0\n" +
		"CapInh:\t0000000000000000\nCapPrm:\t000000000000000f\nCapEff:\t000000000000000f\nCapBnd:\t" + capBnd + "\n" +
		"CapAmb:\t0000000000000000\nNoNewPrivs:\t" + nnp + "\nSeccomp:\t2\nSeccomp_filters:\t3\n"
}

func check(t *testing.T, err error, want string) {
	t.Helper()
	var se *selfcheck.Error
	switch {
	case want == "" && err != nil:
		t.Fatalf("refused: %v", err)
	case want == "":
	case !errors.As(err, &se):
		t.Fatalf("err %v (%T), want a *selfcheck.Error %q", err, err, want)
	case se.Check != want:
		t.Fatalf("check %q (%v), want %q", se.Check, err, want)
	}
}

func parse(t *testing.T, s string) *selfcheck.Status {
	t.Helper()
	st, err := selfcheck.ParseStatus([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return &st
}

func TestParseStatus(t *testing.T) {
	st := parse(t, status("0", "1", "000000000000000f"))
	if st.UIDs != [4]uint32{0, 0, 0, 0} || !st.NoNewPrivs || st.CapBnd != 0xf {
		t.Fatalf("%+v", st)
	}
	for name, s := range map[string]string{
		"no NoNewPrivs":  strings.Replace(status("0", "1", "f"), "NoNewPrivs:\t1\n", "", 1),
		"no CapBnd":      strings.Replace(status("0", "1", "000000000000000f"), "CapBnd:\t000000000000000f\n", "", 1),
		"no Uid":         strings.Replace(status("0", "1", "f"), "Uid:\t0\t0\t0\t0\n", "", 1),
		"bad CapBnd":     status("0", "1", "zz"),
		"short Uid":      strings.Replace(status("0", "1", "f"), "Uid:\t0\t0\t0\t0\n", "Uid:\t0\t0\n", 1),
		"bad NoNewPrivs": status("0", "yes", "f"),
		"repeated field": status("0", "1", "f") + "NoNewPrivs:\t1\n",
		"empty":          "",
	} {
		if _, err := selfcheck.ParseStatus([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProcess(t *testing.T) {
	check(t, selfcheck.Process(parse(t, status("0", "1", "f"))), "")
	check(t, selfcheck.Process(parse(t, status("1000", "1", "f"))), "uid")
	check(t, selfcheck.Process(parse(t, status("0", "0", "f"))), "no_new_privs")
	// Any non-zero id among real, effective, saved and filesystem.
	mixed := strings.Replace(status("0", "1", "f"), "Uid:\t0\t0\t0\t0", "Uid:\t0\t0\t0\t60123", 1)
	check(t, selfcheck.Process(parse(t, mixed)), "uid")
}

func TestCapabilities(t *testing.T) {
	base := []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER"}
	if m, err := selfcheck.CapabilityMask(append(base, "CAP_SYS_BOOT")); err != nil || m != 0xf|1<<22 {
		t.Fatalf("mask %x %v", m, err)
	}
	if _, err := selfcheck.CapabilityMask([]string{"CAP_NOPE"}); err == nil {
		t.Fatal("unknown capability accepted")
	}
	check(t, selfcheck.Capabilities(parse(t, status("0", "1", "000000000000000f")), base), "")
	// A subset (systemd drops more, e.g. ProtectClock) is fine.
	check(t, selfcheck.Capabilities(parse(t, status("0", "1", "0000000000000003")), base), "")
	check(t, selfcheck.Capabilities(parse(t, status("0", "1", "0000000000400000")), append(base, "CAP_SYS_BOOT")), "")
	// Broader than the unit: CAP_SYS_ADMIN (21) not declared, or everything.
	check(t, selfcheck.Capabilities(parse(t, status("0", "1", "000000000020000f")), base), "capabilities")
	check(t, selfcheck.Capabilities(parse(t, status("0", "1", "000001ffffffffff")), base), "capabilities")
}

func TestStdin(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) }()
	check(t, selfcheck.Stdin(fds[0]), "")

	dg, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(dg[0]); _ = unix.Close(dg[1]) }()
	check(t, selfcheck.Stdin(dg[0]), "stdin")

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	lf, err := l.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lf.Close() }()
	check(t, selfcheck.Stdin(int(lf.Fd())), "stdin")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	check(t, selfcheck.Stdin(int(r.Fd())), "stdin")
	check(t, selfcheck.Stdin(1<<20), "stdin")
}

func TestBinary(t *testing.T) {
	d := gatetest.SecureDir(t)
	exe := filepath.Join(d, "shell-mcp-privd")
	gatetest.WriteFile(t, exe, "invented helper binary", 0o755)
	check(t, selfcheck.Binary(gatetest.Trust(), exe), "")
	if err := os.Chmod(exe, 0o775); err != nil { //nolint:gosec // G302: a deliberately insecure or test fixture mode
		t.Fatal(err)
	}
	check(t, selfcheck.Binary(gatetest.Trust(), exe), "binary")
	check(t, selfcheck.Binary(gatetest.Trust(), filepath.Join(d, "missing")), "binary")
	gatetest.Mkdir(t, filepath.Join(d, "dir"), 0o755)
	check(t, selfcheck.Binary(gatetest.Trust(), filepath.Join(d, "dir")), "binary")
}

func TestHash(t *testing.T) {
	h := strings.Repeat("ab", 32)
	check(t, selfcheck.Hash(h, h), "")
	check(t, selfcheck.Hash(h, ""), "policy_hash")
	check(t, selfcheck.Hash(h, strings.ToUpper(h)), "policy_hash")
	check(t, selfcheck.Hash(h, strings.Repeat("cd", 32)), "policy_hash")
	check(t, selfcheck.Hash(h, h+" "), "policy_hash")
	check(t, selfcheck.Hash("", ""), "policy_hash")
}

// The unit's SHELL_MCP_PRIVD_CLIENT_UID is the only input to the peer
// check: exactly one canonical decimal uid in 1..4294967294 (root may never
// be the client, and 4294967295 is (uid_t)-1). Anything else refuses.
func TestUnitClientUID(t *testing.T) {
	for in, want := range map[string]uint32{"60123": 60123, "1": 1, "4294967294": 4294967294, "4200001": 4200001} {
		got, err := selfcheck.UnitClientUID(in)
		check(t, err, "")
		if got != want {
			t.Fatalf("%q = %d, want %d", in, got, want)
		}
	}
	for _, in := range []string{"", "0", "00", "-1", "+1", "01", " 1", "1 ", "1\n", "4294967295", "4294967296",
		"99999999999", "1e3", "0x10", "1_000", "６０１２３", "60123,60124"} {
		got, err := selfcheck.UnitClientUID(in)
		check(t, err, selfcheck.CheckUnitClientUID)
		if got != 0 {
			t.Fatalf("%q returned %d with its error", in, got)
		}
	}
}
