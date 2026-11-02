//go:build linux

package execx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func validCredential() *Credential {
	return &Credential{UID: 4200006, GID: 4200007, Groups: []uint32{4200008, 4200009}}
}

// TestCredentialRefusal: Run refuses root's ids, the overflow id, group 0,
// a duplicate group and more than MaxCredentialGroups groups.
func TestCredentialRefusal(t *testing.T) {
	if why := credentialRefusal(validCredential()); why != "" {
		t.Fatalf("a valid credential: refused %q", why)
	}
	if why := credentialRefusal(&Credential{UID: 4200006, GID: 4200007}); why != "" {
		t.Fatalf("no supplementary groups: refused %q", why)
	}
	many := make([]uint32, MaxCredentialGroups)
	for i := range many {
		many[i] = uint32(4300000 + i)
	}
	if why := credentialRefusal(&Credential{UID: 4200006, GID: 4200007, Groups: many}); why != "" {
		t.Fatalf("%d groups: refused %q", MaxCredentialGroups, why)
	}
	for _, c := range []struct {
		name string
		mod  func(*Credential)
		want string
	}{
		{"uid 0", func(c *Credential) { c.UID = 0 }, "uid 0"},
		{"gid 0", func(c *Credential) { c.GID = 0 }, "gid 0"},
		{"overflow uid", func(c *Credential) { c.UID = math.MaxUint32 }, "uid 4294967295"},
		{"overflow gid", func(c *Credential) { c.GID = math.MaxUint32 }, "gid 4294967295"},
		{"group 0", func(c *Credential) { c.Groups = []uint32{4200008, 0} }, "group 0"},
		{"overflow group", func(c *Credential) { c.Groups = []uint32{math.MaxUint32} }, "group 4294967295"},
		{"duplicate group", func(c *Credential) { c.Groups = []uint32{4200008, 4200009, 4200008} }, "group 4200008 twice"},
		{"too many groups", func(c *Credential) { c.Groups = append(append([]uint32(nil), many...), 4400000) }, "65 supplementary groups"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cr := validCredential()
			c.mod(cr)
			if why := credentialRefusal(cr); !strings.Contains(why, c.want) {
				t.Fatalf("refusal %q, want %q", why, c.want)
			}
		})
	}
}

// TestCredentialSwitchRefusal: the trampoline switches only while it runs
// as uid 0, real and effective, whatever Run checked.
func TestCredentialSwitchRefusal(t *testing.T) {
	if why := credentialSwitchRefusal(0, 0); why != "" {
		t.Fatalf("as root: refused %q", why)
	}
	for _, c := range [][2]int{{60123, 60123}, {0, 60123}, {60123, 0}} {
		if why := credentialSwitchRefusal(c[0], c[1]); !strings.Contains(why, "not running as uid 0") {
			t.Fatalf("uid %d, euid %d: %q", c[0], c[1], why)
		}
	}
}

// observed is what a correct switch to validCredential reads back.
func observed() *observedCreds {
	th := func(tid string) threadCreds {
		return threadCreds{TID: tid, UID: [4]uint64{4200006, 4200006, 4200006, 4200006}, GID: [4]uint64{4200007, 4200007, 4200007, 4200007},
			Groups: []uint64{4200009, 4200008}}
	}
	return &observedCreds{RUID: 4200006, EUID: 4200006, SUID: 4200006, RGID: 4200007, EGID: 4200007, SGID: 4200007,
		Groups: []uint64{4200009, 4200008}, Threads: []threadCreds{th("100"), th("101")}}
}

// TestCredentialMismatch: after the switch every id, the group list (as a
// set), every thread and the capability sets must be exactly the account's;
// anything else refuses the command.
func TestCredentialMismatch(t *testing.T) {
	want := validCredential()
	if why := credentialMismatch(want, observed()); why != "" {
		t.Fatalf("a correct switch: refused %q", why)
	}
	for _, c := range []struct {
		name string
		mod  func(*observedCreds)
		want string
	}{
		{"real uid", func(o *observedCreds) { o.RUID = 0 }, "uid"},
		{"saved uid", func(o *observedCreds) { o.SUID = 0 }, "uid"},
		{"effective gid", func(o *observedCreds) { o.EGID = 0 }, "gid"},
		{"saved gid", func(o *observedCreds) { o.SGID = 0 }, "gid"},
		{"leftover group 0", func(o *observedCreds) { o.Groups = append(o.Groups, 0) }, "groups"},
		{"a group missing", func(o *observedCreds) { o.Groups = o.Groups[:1] }, "groups"},
		{"permitted capability", func(o *observedCreds) { o.Permitted = 1 << 21 }, "capabilities"},
		{"effective capability", func(o *observedCreds) { o.Effective = 1 }, "capabilities"},
		{"no threads read", func(o *observedCreds) { o.Threads = nil }, "thread"},
		{"a thread kept uid 0", func(o *observedCreds) { o.Threads[1].UID = [4]uint64{0, 0, 0, 0} }, "thread 101"},
		{"a thread kept fsuid 0", func(o *observedCreds) { o.Threads[1].UID[3] = 0 }, "thread 101"},
		{"a thread kept gid 0", func(o *observedCreds) { o.Threads[0].GID[1] = 0 }, "thread 100"},
		{"a thread kept group 0", func(o *observedCreds) { o.Threads[0].Groups = []uint64{0, 4200008, 4200009} }, "thread 100"},
		{"a thread kept a permitted capability", func(o *observedCreds) { o.Threads[0].Prm = 1 }, "thread 100"},
		{"a thread kept an ambient capability", func(o *observedCreds) { o.Threads[1].Amb = 1 << 7 }, "thread 101"},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := observed()
			c.mod(o)
			if why := credentialMismatch(want, o); !strings.Contains(why, c.want) {
				t.Fatalf("mismatch %q, want %q", why, c.want)
			}
		})
	}
	// No supplementary groups: an empty list on both sides.
	empty := &Credential{UID: 4200006, GID: 4200007}
	o := observed()
	o.Groups = nil
	for i := range o.Threads {
		o.Threads[i].Groups = nil
	}
	if why := credentialMismatch(empty, o); why != "" {
		t.Fatalf("no groups: refused %q", why)
	}
}

// legacyEncoding is the SMX2 encoding exactly as it was before the
// credential option, written out independently of encodeConfig.
func legacyEncoding(c *trampolineConfig) []byte {
	b := []byte("SMX2")
	str := func(s string) { b = binary.LittleEndian.AppendUint32(b, uint32(len(s))); b = append(b, s...) } //nolint:gosec // G115: test sizes
	list := func(l []string) {
		b = binary.LittleEndian.AppendUint32(b, uint32(len(l))) //nolint:gosec // G115: test sizes
		for _, s := range l {
			str(s)
		}
	}
	str(c.Path)
	list(c.Argv)
	list(c.Env)
	str(c.Dir)
	b = binary.LittleEndian.AppendUint32(b, c.Files)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(c.Limits))) //nolint:gosec // G115: test sizes
	for _, l := range c.Limits {
		b = binary.LittleEndian.AppendUint32(b, l.Resource)
		b = binary.LittleEndian.AppendUint64(b, l.Max)
	}
	return b
}

// TestNilCredentialEncodesAsBefore: without a credential the trampoline
// gets exactly the bytes it got before the option existed (SMX2), so every
// existing caller's command is unchanged. (A guard: it passes before and
// after the option.)
func TestNilCredentialEncodesAsBefore(t *testing.T) {
	c := validConfig()
	got, err := encodeConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if want := legacyEncoding(c); !bytes.Equal(got, want) {
		t.Fatalf("nil credential encodes as\n%x\nwant\n%x", got, want)
	}
}

// TestConfigRoundTripCredential: a credential travels to the trampoline
// (as SMX3) and back exactly.
func TestConfigRoundTripCredential(t *testing.T) {
	c := validConfig()
	c.Cred = validCredential()
	b, err := encodeConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(b[:4]) != "SMX3" {
		t.Fatalf("magic %q, want SMX3", b[:4])
	}
	got, err := decodeConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("round trip:\n%+v\nwant\n%+v", got, c)
	}
	c.Cred = &Credential{UID: 4200006, GID: 4200007}
	if b, err = encodeConfig(c); err != nil {
		t.Fatal(err)
	}
	if got, err = decodeConfig(b); err != nil || got.Cred == nil || len(got.Cred.Groups) != 0 {
		t.Fatalf("no groups: %+v %v", got, err)
	}
}

// TestConfigDecodeStrictCredential: the decoder refuses a credential that
// Run would refuse, and an SMX2 command never carries one.
func TestConfigDecodeStrictCredential(t *testing.T) {
	enc := func(cr *Credential) []byte {
		c := validConfig()
		b := legacyEncoding(c)
		// Rebuild as SMX3: the credential sits between the descriptor count
		// and the limits.
		tail := 4 + 12*len(c.Limits)
		head, limits := b[:len(b)-tail], b[len(b)-tail:]
		out := append([]byte("SMX3"), head[4:]...)
		out = binary.LittleEndian.AppendUint32(out, cr.UID)
		out = binary.LittleEndian.AppendUint32(out, cr.GID)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(cr.Groups))) //nolint:gosec // G115: test sizes
		for _, g := range cr.Groups {
			out = binary.LittleEndian.AppendUint32(out, g)
		}
		return append(out, limits...)
	}
	if c, err := decodeConfig(enc(validCredential())); err != nil || !reflect.DeepEqual(c.Cred, validCredential()) {
		t.Fatalf("control: %+v %v", c, err)
	}
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"uid 0", enc(&Credential{UID: 0, GID: 4200007})},
		{"gid 0", enc(&Credential{UID: 4200006, GID: 0})},
		{"group 0", enc(&Credential{UID: 4200006, GID: 4200007, Groups: []uint32{0}})},
		{"duplicate group", enc(&Credential{UID: 4200006, GID: 4200007, Groups: []uint32{4200008, 4200008}})},
		{"too many groups", enc(&Credential{UID: 4200006, GID: 4200007, Groups: make([]uint32, MaxCredentialGroups+1)})},
		{"truncated credential", enc(validCredential())[:60]},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := decodeConfig(c.b); !errors.Is(err, errConfig) {
				t.Fatalf("decoded: %v", err)
			}
		})
	}
}

// FuzzDecodeConfigCredential: FuzzDecodeConfig's property from an SMX3
// seed: the decoder never panics, never accepts a credential Run would
// refuse, and re-encodes whatever it accepts to the same bytes.
func FuzzDecodeConfigCredential(f *testing.F) {
	c := validConfig()
	c.Cred = validCredential()
	good, err := encodeConfig(c)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte("SMX3"))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := decodeConfig(b)
		if err != nil {
			return
		}
		if c.Cred != nil {
			if why := credentialRefusal(c.Cred); why != "" {
				t.Fatalf("accepted a credential Run refuses (%s): %x", why, b)
			}
		}
		again, err := encodeConfig(c)
		if err != nil {
			t.Fatalf("accepted %x but cannot encode it: %v", b, err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("accepted %x, re-encodes as %x", b, again)
		}
	})
}

// statusFixture is a task status file (proc_pid_status(5)) as Linux 6.x
// writes it, with the credential lines of a switched thread (invented).
const statusFixture = "Name:\tshell-mcp-gate\nUmask:\t0022\nState:\tR (running)\nTgid:\t4242\nPid:\t4243\n" +
	"Uid:\t4200006\t4200006\t4200006\t4200006\nGid:\t4200007\t4200007\t4200007\t4200007\nFDSize:\t64\n" +
	"Groups:\t4200008 4200009 \nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n" +
	"CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\n"

// TestParseThreadStatus: the read-back takes each credential line exactly
// once and refuses a status file it cannot read completely.
func TestParseThreadStatus(t *testing.T) {
	th, err := parseThreadStatus("4243", []byte(statusFixture))
	if err != nil {
		t.Fatal(err)
	}
	want := threadCreds{TID: "4243", UID: [4]uint64{4200006, 4200006, 4200006, 4200006}, GID: [4]uint64{4200007, 4200007, 4200007, 4200007},
		Groups: []uint64{4200008, 4200009}}
	if !reflect.DeepEqual(th, want) {
		t.Fatalf("parsed %+v, want %+v", th, want)
	}
	root := strings.NewReplacer("4200006", "0", "CapPrm:\t0000000000000000", "CapPrm:\t000001ffffffffff").Replace(statusFixture)
	if th, err = parseThreadStatus("1", []byte(root)); err != nil || th.UID != [4]uint64{} || th.Prm != 0x1ffffffffff {
		t.Fatalf("root's thread: %+v %v", th, err)
	}
	if th, err = parseThreadStatus("1", []byte(strings.Replace(statusFixture, "Groups:\t4200008 4200009 ", "Groups:\t", 1))); err != nil || th.Groups != nil {
		t.Fatalf("no groups: %+v %v", th, err)
	}
	for _, c := range []struct{ name, in string }{
		{"no Uid", strings.Replace(statusFixture, "Uid:", "Xid:", 1)},
		{"no CapAmb", strings.Replace(statusFixture, "CapAmb:", "CapXmb:", 1)},
		{"Uid twice", statusFixture + "Uid:\t0\t0\t0\t0\n"},
		{"three uids", strings.Replace(statusFixture, "Uid:\t4200006\t", "Uid:\t", 1)},
		{"a uid that is not a number", strings.Replace(statusFixture, "Uid:\t4200006", "Uid:\tx", 1)},
		{"a uid above 32 bits", strings.Replace(statusFixture, "Uid:\t4200006", "Uid:\t4294967296", 1)},
		{"a short capability set", strings.Replace(statusFixture, "CapEff:\t0000000000000000", "CapEff:\t0", 1)},
		{"a capability set that is not hex", strings.Replace(statusFixture, "CapEff:\t0000000000000000", "CapEff:\t000000000000000g", 1)},
		{"oversized", statusFixture + strings.Repeat("x", maxStatusBytes)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseThreadStatus("1", []byte(c.in)); !errors.Is(err, errThreadStatus) {
				t.Fatalf("parsed: %v", err)
			}
		})
	}
}

// FuzzParseThreadStatus: the parser never panics, and what it accepts has
// every id within 32 bits.
func FuzzParseThreadStatus(f *testing.F) {
	f.Add([]byte(statusFixture))
	f.Add([]byte("Uid:\t0\t0\t0\t0\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		th, err := parseThreadStatus("1", b)
		if err != nil {
			return
		}
		for _, x := range append(append(th.UID[:], th.GID[:]...), th.Groups...) {
			if x > math.MaxUint32 {
				t.Fatalf("accepted id %d", x)
			}
		}
	})
}

// TestUserTasksHighUID: RLIMIT_NPROC counts the tasks of a uid above
// 2147483647 (the account a Spec.Credential names), carried as the
// kernel's uint32 end to end: with any narrowing to int on the way, a
// 32-bit build would count another (negative) uid's tasks, none, and the
// command's limit would not bound what the account already runs.
func TestUserTasksHighUID(t *testing.T) {
	const high = 3000000000
	d := t.TempDir()
	for p, s := range map[string]string{
		"sys/kernel/pid_max": "32768\n",
		"100/status":         "Name:\ta\nUid:\t3000000000\t3000000000\t3000000000\t3000000000\nThreads:\t3\n",
		"101/status":         "Name:\tb\nUid:\t4294967294\t4294967294\t4294967294\t4294967294\nThreads:\t9\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(d, p)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, p), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := userTasksIn(d, high); err != nil || n != 3 {
		t.Fatalf("tasks of uid %d: %d %v, want 3", uint32(high), n, err)
	}
	l, err := childLimits(256, d, high)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(l, childLimit{Resource: unix.RLIMIT_NPROC, Max: 3 + ChildExtraTasks}) {
		t.Fatalf("limits %+v, want RLIMIT_NPROC %d", l, 3+ChildExtraTasks)
	}
}

// sysStub is an AllThreadsSyscall stand-in that records each call and
// answers fail for the trap in failOn (0: none).
type sysStub struct {
	calls  [][4]uintptr
	failOn uintptr
	fail   syscall.Errno
}

func (s *sysStub) call(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	s.calls = append(s.calls, [4]uintptr{trap, a1, a2, a3})
	if trap == s.failOn || s.failOn == ^uintptr(0) {
		return 0, 0, s.fail
	}
	return 0, 0, 0
}

// TestSetIDsPattern: the three calls in order with the ids widened, and for
// no groups setgroups(0, NULL), exactly as syscall.Setgroups passes it
// (Go 1.27.3, syscall_linux.go: AllThreadsSyscall(_SYS_setgroups, 0, 0, 0)).
func TestSetIDsPattern(t *testing.T) {
	s := &sysStub{}
	if step, err := setIDsWith(&Credential{UID: 4200006, GID: 4200007, Groups: []uint32{4200008}}, s.call); err != nil {
		t.Fatalf("%s: %v", step, err)
	}
	if len(s.calls) != 3 || s.calls[0][0] != syscall.SYS_SETGROUPS || s.calls[0][1] != 1 || s.calls[0][2] == 0 ||
		s.calls[1] != [4]uintptr{syscall.SYS_SETGID, 4200007, 0, 0} || s.calls[2] != [4]uintptr{syscall.SYS_SETUID, 4200006, 0, 0} {
		t.Fatalf("calls %v", s.calls)
	}
	s = &sysStub{}
	if _, err := setIDsWith(&Credential{UID: 4200006, GID: 4200007}, s.call); err != nil || s.calls[0] != [4]uintptr{syscall.SYS_SETGROUPS, 0, 0, 0} {
		t.Fatalf("no groups: calls %v %v", s.calls, err)
	}
}

// TestSetIDsNotSupported: AllThreadsSyscall's ENOTSUP (a binary with cgo)
// stops the switch at setgroups, before any id changes, and is returned.
func TestSetIDsNotSupported(t *testing.T) {
	s := &sysStub{failOn: syscall.SYS_SETGROUPS, fail: syscall.ENOTSUP}
	step, err := setIDsWith(validCredential(), s.call)
	if step != "setgroups" || !errors.Is(err, syscall.ENOTSUP) || len(s.calls) != 1 {
		t.Fatalf("%s %v, calls %v", step, err, s.calls)
	}
}

// TestCredentialSupported: support is probed through AllThreadsSyscall, and
// its ENOTSUP is a refusal naming cgo and the remedy.
func TestCredentialSupported(t *testing.T) {
	if err := credentialSupportedWith((&sysStub{}).call); err != nil {
		t.Fatalf("supported: %v", err)
	}
	err := credentialSupportedWith((&sysStub{failOn: ^uintptr(0), fail: syscall.ENOTSUP}).call)
	if err == nil || !strings.Contains(err.Error(), "cgo") || !strings.Contains(err.Error(), "CGO_ENABLED=0") || !errors.Is(err, syscall.ENOTSUP) {
		t.Fatalf("ENOTSUP: %v", err)
	}
}

// TestBecomeAccountReportsErrno: the trampoline answers Run with the switch's
// own errno (ENOTSUP here, a binary with cgo), not a generic EPERM, and no id
// changed. Root only: becomeAccount refuses everyone else first.
func TestBecomeAccountReportsErrno(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		if os.Getenv("SHELL_MCP_REQUIRE_ROOT_TESTS") == "1" {
			t.Fatal("SHELL_MCP_REQUIRE_ROOT_TESTS=1 but the test process is not root")
		}
		t.Skip("needs a root test process")
	}
	why, errno := becomeAccountWith(validCredential(), os.Getppid(), (&sysStub{failOn: syscall.SYS_SETGROUPS, fail: syscall.ENOTSUP}).call)
	if errno != syscall.ENOTSUP || !strings.Contains(why, "setgroups") || os.Getuid() != 0 {
		t.Fatalf("%q %v, uid %d", why, errno, os.Getuid())
	}
}
