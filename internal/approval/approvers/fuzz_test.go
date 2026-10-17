package approvers

import (
	"strings"
	"testing"
)

// FuzzParse: an accepted file holds 1..max approvers with valid, distinct
// names and seeds within bounds, one per line; a refusal is one line and
// never repeats a line of the input.
func FuzzParse(f *testing.F) {
	// Invented seeds: all-'A' and all-'B' base32 strings are not secrets.
	a, b := strings.Repeat("A", 32), strings.Repeat("B", 32)
	for _, s := range []string{
		"alice " + a + "\n",
		"alice " + a + "\nbob " + b + "\n",
		"alice " + a + "\r\n",
		"alice " + strings.ToLower(a),
		"alice " + a + "\nalice " + b + "\n",
		"Alice " + a + "\n",
		"alice " + a[:26] + "\n",
		"alice " + a + "==\n",
		"",
		"\n",
		"alice\t" + a,
	} {
		f.Add([]byte(s), 2)
	}
	notBase32 := func(r rune) bool { return (r < 'a' || r > 'z') && (r < '2' || r > '7') }
	f.Fuzz(func(t *testing.T, data []byte, max int) {
		got, err := Parse(data, max)
		if err != nil {
			msg := err.Error()
			if strings.ContainsAny(msg, "\r\n") {
				t.Fatalf("refusal %q is not one line", msg)
			}
			// Any seed-shaped run of the input (16 or more base32
			// characters, either case) must not appear in the refusal. The
			// refusals' own words are all shorter than that.
			lower := strings.ToLower(msg)
			for _, run := range strings.FieldsFunc(strings.ToLower(string(data)), notBase32) {
				if len(run) >= 16 && strings.Contains(lower, run) {
					t.Fatalf("refusal %q repeats input %q", msg, run)
				}
			}
			return
		}
		if max < 1 || max > MaxApprovers || len(got) < 1 || len(got) > max {
			t.Fatalf("accepted %d approvers with max %d", len(got), max)
		}
		seen := map[string]bool{}
		for _, a := range got {
			s := a.Seed()
			if !ValidName(a.Name) || seen[a.Name] || len(s) < MinSeedBytes || len(s) > MaxSeedBytes {
				t.Fatalf("accepted approver %q with a %d-byte seed", a.Name, len(s))
			}
			seen[a.Name] = true
			if !strings.Contains(string(data), a.Name+" ") {
				t.Fatalf("approver %q is not in the input", a.Name)
			}
		}
	})
}
