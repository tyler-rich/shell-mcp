//go:build linux

package policy_test

import (
	"strings"
	"testing"
)

// reads_private_keys in the privileged policy (handoff N-35), as in the
// gate's: the opt-in parsed, and the warning for an opted-in range or
// filter program, which runs as root. Every binary is an invented
// fixture, never executed.

func TestReadsPrivateKeys(t *testing.T) {
	f := newFixture(t)
	tool := f.exe(t, "report-tool", "invented report tool\n")
	p := f.mustLoad(t, head+"commands:\n"+cmd("x", tool, "    reads_private_keys: true\n"))
	if c, _ := p.Command("x"); !c.ReadsPrivateKeys {
		t.Fatalf("reads_private_keys not set: %+v", c)
	}
	if c, _ := f.mustLoad(t, head+"commands:\n"+cmd("x", tool, "")).Command("x"); c.ReadsPrivateKeys {
		t.Fatal("reads_private_keys set by default")
	}
	tail := f.exe(t, "tail", "invented tail, a few bytes\n")
	for _, extra := range []string{"    reads_private_keys: true\n", ""} {
		p := f.mustLoad(t, head+"commands:\n"+cmd("x", tail, extra))
		var hits []string
		for _, w := range p.Warnings {
			if strings.Contains(w, "reads_private_keys") {
				hits = append(hits, w)
			}
		}
		want := 0
		if extra != "" {
			want = 1
		}
		if len(hits) != want || want == 1 && (!strings.Contains(hits[0], "as root") || !strings.Contains(hits[0], "matched tail by written name")) {
			t.Fatalf("%q: warnings %q", extra, hits)
		}
	}
}
