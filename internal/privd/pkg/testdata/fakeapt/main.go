//go:build linux

// Command fakeapt is a test stand-in for apt-get, built by the helper's
// tests (CGO_ENABLED=0). Each run appends its argv and its exact
// environment as one JSON line to the log file baked in with -ldflags, and
// then behaves as the mode file next to the log says. Real apt and dpkg are
// exercised by the runner-host e2e job with a local repository; this only
// stands in for the command-line contract, verified against the apt 3.0.3
// and 3.1.16 sources. Invented output; never shipped.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// logPath is set with -ldflags "-X main.logPath=…".
var logPath = ""

func main() {
	env := os.Environ()
	slices.Sort(env)
	if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil { //nolint:gosec // G304: test log path baked in by the test
		b, _ := json.Marshal(map[string][]string{"args": os.Args[1:], "env": env})
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
	mode, _ := os.ReadFile(logPath + ".mode") //nolint:gosec // G304: test control file
	fields := strings.Fields(string(mode))
	if len(fields) == 0 {
		fields = []string{"ok"}
	}
	simulate := slices.Contains(os.Args[1:], "-s")
	switch fields[0] {
	case "ok":
		fmt.Println("Reading package lists...")
		fmt.Println("fake apt-get: done")
	case "lock": // held for the first N runs
		n, _ := strconv.Atoi(fields[1])
		c, _ := os.ReadFile(logPath + ".count") //nolint:gosec // G304: test control file
		k, _ := strconv.Atoi(strings.TrimSpace(string(c)))
		_ = os.WriteFile(logPath+".count", []byte(strconv.Itoa(k+1)), 0o600)
		if k < n {
			lock()
		}
		fmt.Println("fake apt-get: done after the lock")
	case "lockforever":
		lock()
	case "listslock":
		fmt.Fprintln(os.Stderr, "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 4242 (apt-get)")
		fmt.Fprintln(os.Stderr, "E: Unable to lock directory /var/lib/apt/lists/")
		os.Exit(100)
	case "sim":
		if !simulate {
			fmt.Println("fake apt-get: not a simulation")
			return
		}
		fmt.Print(`Reading package lists...
Building dependency tree...
The following NEW packages will be installed:
  example-hello example-lib
Inst example-lib (2.1-1 Invented:1.0/stable [all])
Inst example-hello [1.0] (1.1 Invented:1.0/stable [all]) []
Inst example-arch:i386 (3.0-2 Invented:1.0/stable [i386])
Remv example-old [0.9-1]
Purg example-gone [0.1]
Conf example-lib (2.1-1 Invented:1.0/stable [all])
Conf example-hello (1.1 Invented:1.0/stable [all])
Inst broken line without version
`)
	case "fail":
		fmt.Fprintln(os.Stderr, "E: Unable to locate package example-missing")
		os.Exit(100)
	case "secret":
		// An invented key-shaped block, assembled at run time so that no
		// key literal is committed (secret scanners).
		fmt.Println("-----BEGIN " + "OPENSSH PRIVATE KEY-----")
		fmt.Println("aW52ZW50ZWQgdGVzdCBrZXkgbWF0ZXJpYWw=")
		fmt.Println("-----END " + "OPENSSH PRIVATE KEY-----")
	case "flood":
		fmt.Print(strings.Repeat("y", 1<<20))
	}
}

func lock() {
	fmt.Fprintln(os.Stderr, "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 (apt-get)")
	fmt.Fprintln(os.Stderr, "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?")
	os.Exit(100)
}
