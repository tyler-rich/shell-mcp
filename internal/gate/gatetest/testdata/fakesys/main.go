//go:build linux

// Command fakesys is a test stand-in for systemctl and journalctl (chosen by
// its base name). It is built by the gate tests (CGO_ENABLED=0), appends its
// argv as one JSON line to the log file baked in with -ldflags, and answers
// from invented canned data selected by the unit name. Real systemd,
// journald and polkit behaviour is proven on a systemd host (S1c); this
// only stands in for the command-line contract, which was verified against
// the systemd 257 and 259 sources. Never shipped.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// logPath is set with -ldflags "-X main.logPath=…".
var logPath = ""

func main() {
	if logPath != "" {
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil { //nolint:gosec // G304: test log path baked in by the test
			b, _ := json.Marshal(os.Args[1:])
			_, _ = f.Write(append(b, '\n'))
			_ = f.Close()
		}
	}
	args := os.Args[1:]
	switch filepath.Base(os.Args[0]) {
	case "systemctl":
		os.Exit(systemctl(args))
	case "journalctl":
		os.Exit(journalctl(args))
	case "git":
		// Log the exact environment as a second line, then fail: tests
		// assert what the gate passes to git, not what git does.
		if logPath != "" {
			if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600); err == nil { //nolint:gosec // G304: test log path baked in by the test
				env := os.Environ()
				slices.Sort(env)
				b, _ := json.Marshal(env)
				_, _ = f.Write(append(b, '\n'))
				_ = f.Close()
			}
		}
		fmt.Fprintln(os.Stderr, "fakesys: git stand-in")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "fakesys: unknown name")
	os.Exit(2)
}

func last(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[len(args)-1]
}

var props = map[string]string{
	"Id": "example-app.service", "Description": "Example app api_key=abc123", "LoadState": "loaded", "ActiveState": "active",
	"SubState": "running", "UnitFileState": "enabled", "MainPID": "4242", "ActiveEnterTimestamp": "Sat 2026-09-26 10:00:00 UTC",
	"StateChangeTimestamp": "Sat 2026-09-26 10:00:00 UTC", "MemoryCurrent": "[not set]", "NRestarts": "3", "Result": "success",
}

func systemctl(args []string) int {
	unit := last(args)
	switch {
	case len(args) > 0 && args[0] == "show":
		want := ""
		for i, a := range args {
			if a == "-p" && i+1 < len(args) {
				want = args[i+1]
			}
		}
		switch unit {
		case "example-badout.service":
			fmt.Println("this is not key=value")
			return 0
		case "example-extra.service":
			fmt.Println("FragmentPath=/etc/systemd/system/example-extra.service")
			return 0
		}
		keys := strings.Split(want, ",")
		slices.Sort(keys) // systemd's order is not the -p order
		for _, k := range keys {
			v, ok := props[k]
			if !ok {
				continue
			}
			switch {
			case unit == "example-missing.service" && k == "LoadState":
				v = "not-found"
			case unit == "example-missing.service" && (k == "ActiveState" || k == "SubState"):
				v = "inactive"
			case k == "Id":
				v = unit
			}
			fmt.Printf("%s=%s\n", k, v)
		}
		return 0
	case len(args) > 0 && args[0] == "list-units":
		units := []map[string]string{
			{"unit": "example-app.service", "load": "loaded", "active": "active", "sub": "running", "description": "Example app"},
			{"unit": "example-worker.service", "load": "loaded", "active": "failed", "sub": "failed", "description": "Example worker"},
			{"unit": "other.service", "load": "loaded", "active": "active", "sub": "running", "description": "Not in the policy"},
		}
		if slices.Contains(args, "--state=failed") {
			units = units[1:2]
		}
		b, _ := json.Marshal(units)
		fmt.Println(string(b))
		return 0
	case len(args) > 1 && args[0] == "--no-ask-password":
		verb := args[1]
		switch unit {
		case "example-denied.service": // polkit says no: AccessDenied → EXIT_NOPERMISSION
			fmt.Fprintf(os.Stderr, "Failed to %s %s: Access denied\nSee system logs and 'systemctl status %s' for details.\n", verb, unit, unit)
			return 4
		case "example-challenge.service": // polkit challenge without interaction (systemd 257 wording)
			fmt.Fprintf(os.Stderr, "Failed to %s %s: Interactive authentication required.\nSee system logs and 'systemctl status %s' for details.\n", verb, unit, unit)
			return 1
		case "example-challenge2.service": // the same, systemd 259 wording
			fmt.Fprintf(os.Stderr, "Failed to %s %s: Access denied as the requested operation requires interactive authentication. "+
				"However, interactive authentication has not been enabled by the calling program.\n", verb, unit)
			return 1
		case "example-broken.service":
			fmt.Fprintf(os.Stderr, "Job for %s failed because the control process exited with error code.\n", unit)
			return 1
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "fakesys: unexpected systemctl arguments")
	return 2
}

func journalctl(args []string) int {
	unit := last(args)
	if unit == "example-noperm.service" {
		fmt.Fprintln(os.Stderr, "No journal files were opened due to insufficient permissions.")
		return 1
	}
	n := 10
	for i, a := range args {
		if a == "-n" && i+1 < len(args) {
			n, _ = strconv.Atoi(args[i+1])
		}
	}
	for i := 0; i < n && i < 50; i++ {
		fmt.Printf("2026-09-27T10:00:%02d+00:00 target-a %s[4242]: line %d api_key=abc123\n", i%60, strings.TrimSuffix(unit, ".service"), i)
	}
	fmt.Fprintln(os.Stderr, "Hint: You are currently not seeing messages from other users and the system.")
	return 0
}
