package totp

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Seeds are generated at test time, except the RFC 6238 Appendix B SHA-1
// test seed below, which is a published test value.

var rfcSeed = []byte("12345678901234567890")

// The handoff's values (S4B-APPROVAL.md §6.4), written out rather than taken
// from the package, so a changed constant fails these tests.
const (
	specMaxWrong     = 3
	specWindow       = time.Minute
	specFirstLockout = 15 * time.Minute
	specMaxLockout   = 24 * time.Hour
	specMinSeedBytes = 20
)

// TestRFC6238Vectors: the SHA-1 rows of RFC 6238 Appendix B, at their eight
// digits, and the six-digit codes Generate derives from them.
func TestRFC6238Vectors(t *testing.T) {
	vectors := []struct {
		unix int64
		step int64
		code string
	}{
		{59, 0x1, "94287082"},
		{1111111109, 0x23523EC, "07081804"},
		{1111111111, 0x23523ED, "14050471"},
		{1234567890, 0x273EF07, "89005924"},
		{2000000000, 0x3F940AA, "69279037"},
		{20000000000, 0x27BC86AA, "65353130"},
	}
	for _, v := range vectors {
		at := time.Unix(v.unix, 0).UTC()
		if got := stepAt(at); got != v.step {
			t.Errorf("stepAt(%d) = %#x, want %#x", v.unix, got, v.step)
		}
		if got := hotp(rfcSeed, counter(v.step), 8); got != v.code {
			t.Errorf("8-digit code at %d = %q, want %q", v.unix, got, v.code)
		}
		if got, want := Generate(rfcSeed, at), v.code[2:]; got != want {
			t.Errorf("Generate at %d = %q, want %q", v.unix, got, want)
		}
	}
}

// counter is a step as the HOTP counter; the tests' steps are never negative.
func counter(s int64) uint64 {
	if s < 0 {
		return 0
	}
	return uint64(s)
}

// fakeClock is the injectable clock.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// base is a step boundary plus 5 s, so small advances stay in one step.
var base = time.Unix(1_800_000_000-1_800_000_000%30+5, 0).UTC()

// newSeed returns a fresh random seed whose codes for steps around at are
// pairwise distinct, so a test never passes or fails by a code collision.
func newSeed(t *testing.T, at time.Time) []byte {
	t.Helper()
	for range 100 {
		seed := make([]byte, specMinSeedBytes)
		if _, err := rand.Read(seed); err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		cur := stepAt(at)
		distinct := true
		for s := cur - 40; s <= cur+40; s++ {
			c := hotp(seed, counter(s), Digits)
			if seen[c] {
				distinct = false
				break
			}
			seen[c] = true
		}
		if distinct {
			return seed
		}
	}
	t.Fatal("no seed with distinct codes")
	return nil
}

type fixture struct {
	clock *fakeClock
	v     *Verifier
	seeds map[string][]byte
}

func newFixture(t *testing.T, names ...string) *fixture {
	t.Helper()
	if len(names) == 0 {
		names = []string{"alice"}
	}
	f := &fixture{clock: &fakeClock{t: base}, seeds: map[string][]byte{}}
	for _, n := range names {
		f.seeds[n] = newSeed(t, base)
	}
	v, err := New(f.seeds, f.clock.now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.v = v
	return f
}

// codeAt is the approver's correct code for the step offset steps from now.
func (f *fixture) codeAt(name string, offset int64) string {
	return hotp(f.seeds[name], counter(stepAt(f.clock.t)+offset), Digits)
}

// wrong is a well-formed code that matches no step in the accepted window.
func (f *fixture) wrong(name string) string {
	valid := map[string]bool{}
	for o := int64(-1); o <= 1; o++ {
		valid[f.codeAt(name, o)] = true
	}
	n, _ := strconv.Atoi(f.codeAt(name, 0))
	for {
		n = (n + 1) % 1_000_000
		c := fmt.Sprintf("%06d", n)
		if !valid[c] {
			return c
		}
	}
}

func (f *fixture) expect(t *testing.T, name, code string, want Result) Outcome {
	t.Helper()
	got := f.v.Verify(name, code)
	if got.Result != want {
		t.Fatalf("Verify(%s) at %s = %v, want %v", name, f.clock.t.Format(time.RFC3339), got.Result, want)
	}
	return got
}

func TestCurrentStepAccepted(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	if out := f.expect(t, "alice", f.codeAt("alice", 0), Accepted); out.Lockout != nil {
		t.Fatalf("accepted with lockout %+v", out.Lockout)
	}
}

func TestSkewOneStepOnly(t *testing.T) {
	for _, c := range []struct {
		name   string
		offset int64
		want   Result
	}{
		{"one step behind", -1, Accepted},
		{"one step ahead", 1, Accepted},
		{"two steps behind", -2, BadCode},
		{"two steps ahead", 2, BadCode},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.clock.advance(10 * Period)
			f.expect(t, "alice", f.codeAt("alice", c.offset), c.want)
		})
	}
}

// TestStepAcceptedOnce: approve and decline both go through Verify with the
// approver's one state, so a step's code accepted for one decision is refused
// for the next, whichever it is.
func TestStepAcceptedOnce(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	code := f.codeAt("alice", 0)
	f.expect(t, "alice", code, Accepted)   // e.g. an approve
	f.expect(t, "alice", code, ReusedCode) // e.g. a decline, same step
	f.clock.advance(Period)
	f.expect(t, "alice", code, ReusedCode) // still inside the skew window
}

func TestStepBeforeLastAcceptedRefused(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	f.expect(t, "alice", f.codeAt("alice", 1), Accepted) // the step ahead
	f.expect(t, "alice", f.codeAt("alice", 0), ReusedCode)
	f.expect(t, "alice", f.codeAt("alice", -1), ReusedCode)
}

func TestStepCurrentAtStartRefused(t *testing.T) {
	f := newFixture(t)
	f.expect(t, "alice", f.codeAt("alice", 0), ReusedCode)
	f.expect(t, "alice", f.codeAt("alice", -1), ReusedCode)
	f.clock.advance(Period - 10*time.Second) // still the start step
	f.expect(t, "alice", f.codeAt("alice", 0), ReusedCode)
	f.clock.advance(10 * time.Second) // the next step
	f.expect(t, "alice", f.codeAt("alice", 0), Accepted)
}

// lockOut sends specMaxWrong wrong codes and then the one that locks the
// approver out, and returns the lockout it started.
func (f *fixture) lockOut(t *testing.T) *Lockout {
	t.Helper()
	const name = "alice"
	for i := range specMaxWrong {
		if out := f.expect(t, name, f.wrong(name), BadCode); out.Lockout != nil {
			t.Fatalf("wrong code %d started a lockout", i+1)
		}
		f.clock.advance(time.Second)
	}
	out := f.expect(t, name, f.wrong(name), BadCode)
	if out.Lockout == nil || !out.Lockout.Started {
		t.Fatalf("wrong code %d did not start a lockout: %+v", specMaxWrong+1, out.Lockout)
	}
	return out.Lockout
}

func TestFourthWrongCodeLocksOut(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	lo := f.lockOut(t)
	if want := f.clock.t.Add(specFirstLockout); !lo.Until.Equal(want) || lo.Consecutive != 1 {
		t.Fatalf("lockout = %+v, want until %s, consecutive 1", lo, want)
	}

	// A correct code during the lockout is refused.
	f.clock.advance(Period)
	out := f.expect(t, "alice", f.codeAt("alice", 0), Locked)
	if out.Lockout == nil || out.Lockout.Started || !out.Lockout.Until.Equal(lo.Until) || out.Lockout.Consecutive != 1 {
		t.Fatalf("locked outcome = %+v", out.Lockout)
	}
	f.clock.t = lo.Until.Add(-time.Second)
	f.expect(t, "alice", f.codeAt("alice", 0), Locked)
	f.clock.t = lo.Until
	f.expect(t, "alice", f.codeAt("alice", 0), Accepted)
}

// TestLockedCodesUnchecked: during a lockout nothing is checked or counted,
// so wrong codes neither extend the lockout nor count towards the next.
func TestLockedCodesUnchecked(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	lo := f.lockOut(t)
	for range 20 {
		out := f.expect(t, "alice", f.wrong("alice"), Locked)
		if !out.Lockout.Until.Equal(lo.Until) || out.Lockout.Consecutive != 1 {
			t.Fatalf("lockout changed during the lockout: %+v", out.Lockout)
		}
	}
	f.clock.t = lo.Until
	for range specMaxWrong {
		if out := f.expect(t, "alice", f.wrong("alice"), BadCode); out.Lockout != nil {
			t.Fatalf("codes sent during the lockout were counted: %+v", out.Lockout)
		}
	}
}

func TestWrongCodesRollingWindow(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	start := f.clock.t
	for range specMaxWrong {
		f.expect(t, "alice", f.wrong("alice"), BadCode)
	}
	// The first three fall out of the window just after 60 s.
	f.clock.t = start.Add(specWindow + time.Second)
	if out := f.expect(t, "alice", f.wrong("alice"), BadCode); out.Lockout != nil {
		t.Fatalf("a wrong code after the window started a lockout")
	}
	f.clock.advance(time.Second)
	f.expect(t, "alice", f.wrong("alice"), BadCode)
	f.clock.advance(time.Second)
	f.expect(t, "alice", f.wrong("alice"), BadCode)
	f.clock.advance(time.Second)
	// Three wrong codes inside the last 60 s, so this fourth one locks.
	if out := f.expect(t, "alice", f.wrong("alice"), BadCode); out.Lockout == nil || !out.Lockout.Started {
		t.Fatalf("the fourth wrong code within 60 s did not lock out")
	}
}

func TestFourthWrongCodeJustInsideWindow(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	start := f.clock.t
	for range specMaxWrong {
		f.expect(t, "alice", f.wrong("alice"), BadCode)
	}
	f.clock.t = start.Add(specWindow - time.Millisecond)
	if out := f.expect(t, "alice", f.wrong("alice"), BadCode); out.Lockout == nil {
		t.Fatal("the fourth wrong code 59.999 s after the first did not lock out")
	}
}

func TestMalformedCodesCountAsWrong(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	for _, c := range []string{"", "12345", "1234567", "abcdef"} {
		f.expect(t, "alice", c, BadCode)
	}
	f.expect(t, "alice", f.codeAt("alice", 0), Locked)
}

func TestLockoutDoublesUpToCap(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	want := []time.Duration{
		15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour,
		8 * time.Hour, 16 * time.Hour, 24 * time.Hour, 24 * time.Hour, 24 * time.Hour,
	}
	for i, d := range want {
		lo := f.lockOut(t)
		if got := lo.Until.Sub(f.clock.t); got != d || lo.Consecutive != i+1 {
			t.Fatalf("lockout %d: %s (consecutive %d), want %s (consecutive %d)", i+1, got, lo.Consecutive, d, i+1)
		}
		f.clock.t = lo.Until
	}
}

func TestLockoutCapHoldsForManyLockouts(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	for i := range 70 { // past any shift width
		lo := f.lockOut(t)
		if d := lo.Until.Sub(f.clock.t); d <= 0 || d > specMaxLockout {
			t.Fatalf("lockout %d lasts %s", i+1, d)
		}
		f.clock.t = lo.Until
	}
}

func TestSuccessResets(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)

	// The wrong-code count.
	for range specMaxWrong - 1 {
		f.expect(t, "alice", f.wrong("alice"), BadCode)
	}
	f.expect(t, "alice", f.codeAt("alice", 0), Accepted)
	for range specMaxWrong {
		if out := f.expect(t, "alice", f.wrong("alice"), BadCode); out.Lockout != nil {
			t.Fatal("wrong codes before a success still counted")
		}
	}

	// The consecutive-lockout count.
	f.clock.advance(2 * specWindow)
	lo := f.lockOut(t)
	f.clock.t = lo.Until
	lo = f.lockOut(t)
	if lo.Consecutive != 2 {
		t.Fatalf("second lockout consecutive = %d", lo.Consecutive)
	}
	f.clock.t = lo.Until
	f.expect(t, "alice", f.codeAt("alice", 0), Accepted)
	f.clock.advance(Period)
	lo = f.lockOut(t)
	if lo.Consecutive != 1 || lo.Until.Sub(f.clock.t) != specFirstLockout {
		t.Fatalf("lockout after a success = %+v, want consecutive 1 lasting %s", lo, specFirstLockout)
	}
}

func TestApproversIndependent(t *testing.T) {
	f := newFixture(t, "alice", "bob")
	f.clock.advance(5 * Period)

	// Last accepted step.
	f.expect(t, "alice", f.codeAt("alice", 1), Accepted)
	f.expect(t, "bob", f.codeAt("bob", 0), Accepted)

	// Wrong codes and lockouts.
	f.clock.advance(Period)
	f.lockOut(t)
	f.expect(t, "alice", f.codeAt("alice", 1), Locked)
	f.expect(t, "bob", f.codeAt("bob", 0), Accepted)
	for range specMaxWrong {
		if out := f.expect(t, "bob", f.wrong("bob"), BadCode); out.Lockout != nil {
			t.Fatal("alice's wrong codes counted for bob")
		}
	}

	// One approver's code is not the other's.
	f.clock.advance(Period)
	f.expect(t, "bob", f.codeAt("alice", 0), BadCode)
}

func TestUnknownApproverRefused(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	f.expect(t, "mallory", f.codeAt("alice", 0), BadCode)
	f.expect(t, "", f.codeAt("alice", 0), BadCode)
	f.expect(t, "alice", f.codeAt("alice", 0), Accepted)
}

func TestNewRefuses(t *testing.T) {
	now := func() time.Time { return base }
	short := make([]byte, specMinSeedBytes-1)
	for _, c := range []struct {
		name  string
		seeds map[string][]byte
	}{
		{"no approvers", map[string][]byte{}},
		{"short seed", map[string][]byte{"alice": short}},
		{"empty name", map[string][]byte{"": make([]byte, specMinSeedBytes)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := New(c.seeds, now); err == nil {
				t.Fatal("New accepted it")
			}
		})
	}
	if _, err := New(map[string][]byte{"alice": make([]byte, specMinSeedBytes)}, nil); err == nil {
		t.Fatal("New accepted a nil clock")
	}
}

// TestNewCopiesSeeds: changing the caller's seed afterwards changes nothing.
func TestNewCopiesSeeds(t *testing.T) {
	seed := newSeed(t, base)
	keep := append([]byte(nil), seed...)
	clock := &fakeClock{t: base}
	v, err := New(map[string][]byte{"alice": seed}, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	for i := range seed {
		seed[i] = 0
	}
	clock.advance(5 * Period)
	if got := v.Verify("alice", hotp(keep, counter(stepAt(clock.t)), Digits)); got.Result != Accepted {
		t.Fatalf("Verify after the caller's seed changed = %v", got.Result)
	}
}

func TestParseCode(t *testing.T) {
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"123456", "123456", true},
		{"000000", "000000", true},
		{"123 456", "123456", true},
		{" 123456 ", "123456", true},
		{"12345", "", false},
		{"1234567", "", false},
		{"12345a", "", false},
		{"123\t456", "", false},
		{"123-456", "", false},
		{"１２３４５６", "", false},
		{"", "", false},
		{strings.Repeat(" ", 30) + "123456", "", false},
	} {
		got, ok := ParseCode(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseCode(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestResultString(t *testing.T) {
	for r, want := range map[Result]string{Accepted: "accepted", BadCode: "bad_code", ReusedCode: "reused_code", Locked: "locked", 0: "unknown"} {
		if got := r.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", int(r), got, want)
		}
	}
}

// TestReusedCodesNotCounted: a code for an already-used step is refused but
// is not a wrong code, so it neither starts nor brings closer a lockout.
func TestReusedCodesNotCounted(t *testing.T) {
	f := newFixture(t)
	f.clock.advance(5 * Period)
	code := f.codeAt("alice", 0)
	f.expect(t, "alice", code, Accepted)
	for range 10 {
		if out := f.expect(t, "alice", code, ReusedCode); out.Lockout != nil {
			t.Fatalf("a reused code started a lockout: %+v", out.Lockout)
		}
	}
	for range specMaxWrong {
		if out := f.expect(t, "alice", f.wrong("alice"), BadCode); out.Lockout != nil {
			t.Fatal("reused codes counted towards the lockout")
		}
	}
}

// TestParametersAreTheHandoffs: the exported parameters are the handoff's.
func TestParametersAreTheHandoffs(t *testing.T) {
	if Digits != 6 || Period != 30*time.Second || Skew != 1 || MaxWrong != specMaxWrong || WrongWindow != specWindow ||
		FirstLockout != specFirstLockout || MaxLockout != specMaxLockout || MinSeedBytes != specMinSeedBytes {
		t.Fatal("a TOTP parameter differs from handoff §6.4")
	}
}
