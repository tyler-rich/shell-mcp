//go:build linux

package ops

import (
	"encoding/json/v2"
	"testing"
)

// FuzzExecBroad: the gate's priv_exec routing label parser never panics,
// and when it accepts args, a plain decode of the same bytes agrees on the
// label (what the helper's strict decode then reads too).
func FuzzExecBroad(f *testing.F) {
	for _, s := range []string{`{}`, `{"unit":"broad"}`, `{"unit":"core"}`, `{"unit":null}`, `{"unit":"x"}`,
		`{"unit":"core","unit":"broad"}`, `{"command_id":"a","args":["b"],"unit":"broad"}`, `[]`, `{"unit":7}`, ``} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		broad, err := execBroad(b)
		if err != nil || len(b) == 0 {
			return
		}
		var a struct {
			Unit string `json:"unit"`
		}
		if json.Unmarshal(b, &a) != nil {
			t.Fatalf("execBroad accepted %q, which does not decode", b)
		}
		if broad != (a.Unit == "broad") {
			t.Fatalf("execBroad(%q) = %v, label %q", b, broad, a.Unit)
		}
	})
}
