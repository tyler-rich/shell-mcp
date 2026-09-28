package polkit

import (
	"os"
	"strings"
	"testing"
)

var zeroHash = strings.Repeat("0", 64)

func TestRuleGolden(t *testing.T) {
	got, err := Rule(Spec{User: "svc-shell", Units: []string{"example-app.service", "example-worker@1.service"},
		Verbs: []string{"restart", "reload"}, PolicySHA256: zeroHash})
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/two-units.rules")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("rule differs from testdata/two-units.rules:\n%s", got)
	}
	// Deterministic.
	again, _ := Rule(Spec{User: "svc-shell", Units: []string{"example-app.service", "example-worker@1.service"},
		Verbs: []string{"restart", "reload"}, PolicySHA256: zeroHash})
	if again != got {
		t.Fatal("not deterministic")
	}
}

func TestRuleEscapedUnit(t *testing.T) {
	// systemd-escaped names contain a backslash; it must reach JavaScript
	// as one backslash inside a string literal.
	got, err := Rule(Spec{User: "svc-shell", Units: []string{`example\x2dapp.service`}, Verbs: []string{"start"}, PolicySHA256: zeroHash})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"example\x2dapp.service": ["start"]`) {
		t.Fatalf("escaping:\n%s", got)
	}
}

func TestRuleRefusals(t *testing.T) {
	ok := Spec{User: "svc-shell", Units: []string{"example-app.service"}, Verbs: []string{"restart"}, PolicySHA256: zeroHash}
	cases := map[string]func(s *Spec){
		"glob *":         func(s *Spec) { s.Units = []string{"example-*.service"} },
		"glob ?":         func(s *Spec) { s.Units = []string{"example-?.service"} },
		"glob [":         func(s *Spec) { s.Units = []string{"example-[ab].service"} },
		"one glob":       func(s *Spec) { s.Units = []string{"example-app.service", "*"} },
		"no suffix":      func(s *Spec) { s.Units = []string{"example-app"} },
		"leading dash":   func(s *Spec) { s.Units = []string{"-x.service"} },
		"slash":          func(s *Spec) { s.Units = []string{"a/b.service"} },
		"quote":          func(s *Spec) { s.Units = []string{`a".service`} },
		"empty unit":     func(s *Spec) { s.Units = []string{""} },
		"duplicate unit": func(s *Spec) { s.Units = []string{"a.service", "a.service"} },
		"no units":       func(s *Spec) { s.Units = nil },
		"bad verb":       func(s *Spec) { s.Verbs = []string{"enable"} },
		"no verbs":       func(s *Spec) { s.Verbs = nil },
		"duplicate verb": func(s *Spec) { s.Verbs = []string{"stop", "stop"} },
		"root":           func(s *Spec) { s.User = "root" },
		"empty user":     func(s *Spec) { s.User = "" },
		"quoted user":    func(s *Spec) { s.User = `svc"x` },
		"spaced user":    func(s *Spec) { s.User = "svc shell" },
		"bad hash":       func(s *Spec) { s.PolicySHA256 = "abc" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := ok
			s.Units = append([]string(nil), ok.Units...)
			s.Verbs = append([]string(nil), ok.Verbs...)
			mutate(&s)
			if out, err := Rule(s); err == nil {
				t.Fatalf("accepted:\n%s", out)
			}
		})
	}
	if _, err := Rule(ok); err != nil {
		t.Fatal(err)
	}
}
