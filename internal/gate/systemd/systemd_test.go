package systemd

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// Outputs below are invented and only mimic systemctl's formats (verified
// against systemd 257 and 259 sources, see docs/ARCHIVE.md).

func TestValidUnit(t *testing.T) {
	for _, u := range []string{"example-app.service", "example-worker@1.service", `example\x2dapp.service`, "srv-app.mount", "a.timer", "dbus.socket"} {
		if !ValidUnit(u) {
			t.Errorf("%q refused", u)
		}
	}
	for _, u := range []string{"", "example-app", "123", "-x.service", "a/b.service", "example-*.service", "example-?.service",
		"example-[ab].service", "a.b", "a service.service", "a.service\n", strings.Repeat("a", 300) + ".service", "a.Service"} {
		if ValidUnit(u) {
			t.Errorf("%q accepted", u)
		}
	}
}

func TestParseShow(t *testing.T) {
	want := []string{"Id", "LoadState", "ActiveState", "MainPID", "Description"}
	out := "MainPID=42\nId=example-app.service\nLoadState=loaded\nActiveState=active\nDescription=Example = app\n"
	got, err := ParseShow([]byte(out), want)
	if err != nil || got["MainPID"] != "42" || got["Description"] != "Example = app" || len(got) != 5 {
		t.Fatalf("%v %v", got, err)
	}
	// Missing properties are allowed (systemctl omits unknown ones).
	if got, err := ParseShow([]byte("Id=x.service\n"), want); err != nil || len(got) != 1 {
		t.Fatalf("partial: %v %v", got, err)
	}
	for name, bad := range map[string]string{
		"unrequested":   "Id=x.service\nFragmentPath=/etc/x\n",
		"duplicate":     "Id=a.service\nId=b.service\n",
		"no equals":     "Id\n",
		"bad key":       "I d=x\n",
		"blank between": "Id=x.service\n\nLoadState=loaded\n",
		"too long":      "Description=" + strings.Repeat("x", MaxValue+1) + "\n",
	} {
		if _, err := ParseShow([]byte(bad), want); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseListUnits(t *testing.T) {
	out := `[{"unit":"example-app.service","load":"loaded","active":"active","sub":"running","description":"Example app"},` +
		`{"unit":"example-worker.service","load":"loaded","active":"failed","sub":"failed","job":"start","description":"Worker"}]` + "\n"
	us, err := ParseListUnits([]byte(out))
	if err != nil || len(us) != 2 || us[1].Active != "failed" || us[1].Job != "start" || us[0].Description != "Example app" {
		t.Fatalf("%+v %v", us, err)
	}
	if us, err := ParseListUnits([]byte("[]\n")); err != nil || len(us) != 0 {
		t.Fatalf("empty: %v %v", us, err)
	}
	for _, bad := range []string{"", "{}", `[{"unit":1}]`, `[{"load":"loaded"}]`, `[{"unit":"a.service","load":"l","active":"a","sub":"s"}]`,
		"not json", `[{"unit":"a.service","load":"l","active":"a","sub":"s","description":"d"}] trailing`} {
		if _, err := ParseListUnits([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestJournalTime(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"2026-09-27T10:00:00Z":      "@1790503200",
		"2026-09-27T12:00:00+02:00": "@1790503200",
		"-15m":                      "@1790509500",
		"-2h":                       "@1790503200",
		"-1d":                       "@1790424000",
		"-30s":                      "@1790510370",
		"-1w":                       "@1789905600",
	}
	for in, want := range cases {
		if got, err := JournalTime(in, now); err != nil || got != want {
			t.Errorf("JournalTime(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"yesterday", "2026-09-27 10:00:00", "2026-09-27", "+15m", "-15", "-15min", "-0m", "15m",
		"@1790510400", "-99999999d", "2026-09-27T10:00:00Z; rm", "--since", "-1y", "1969-12-31T23:59:59Z"} {
		if got, err := JournalTime(bad, now); err == nil {
			t.Errorf("JournalTime(%q) accepted: %q", bad, got)
		}
	}
}

func TestPriority(t *testing.T) {
	for _, p := range []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"} {
		if !ValidPriority(p) {
			t.Errorf("%s refused", p)
		}
	}
	for _, p := range []string{"", "error", "0", "7", "warn", "err..info", "-p"} {
		if ValidPriority(p) {
			t.Errorf("%s accepted", p)
		}
	}
	if !slices.Contains(ShowProperties, "ActiveState") || !slices.Contains(ShowProperties, "NRestarts") {
		t.Fatalf("properties %v", ShowProperties)
	}
}

func FuzzParseShow(f *testing.F) {
	f.Add([]byte("Id=x.service\nMainPID=1\n"))
	f.Add([]byte("Description=a=b\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := ParseShow(b, ShowProperties)
		if err != nil {
			return
		}
		for k, v := range got {
			if !slices.Contains(ShowProperties, k) || strings.ContainsAny(v, "\n") || len(v) > MaxValue {
				t.Fatalf("%q=%q", k, v)
			}
		}
	})
}

func FuzzParseListUnits(f *testing.F) {
	f.Add([]byte(`[{"unit":"a.service","load":"loaded","active":"active","sub":"running","description":"d"}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		us, err := ParseListUnits(b)
		if err == nil && len(us) > MaxUnits {
			t.Fatalf("%d units", len(us))
		}
	})
}

func FuzzJournalTime(f *testing.F) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	f.Add("2026-09-27T10:00:00Z")
	f.Add("-15m")
	f.Fuzz(func(t *testing.T, s string) {
		got, err := JournalTime(s, now)
		if err != nil {
			return
		}
		if !strings.HasPrefix(got, "@") || strings.ContainsAny(got[1:], "-+ ;") || len(got) > 13 { // "@" + at most 12 digits (year 9999)
			t.Fatalf("%q -> %q", s, got)
		}
	})
}
