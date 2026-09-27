package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestStubsExit2(t *testing.T) {
	for _, c := range []string{"serve", "check-policy", "polkit"} {
		var out, errb bytes.Buffer
		if code := run([]string{c}, &out, &errb); code != 2 {
			t.Fatalf("%s exit %d, want 2", c, code)
		}
		if want := c + " arrives in Session 1"; !strings.Contains(errb.String(), want) || out.Len() != 0 {
			t.Fatalf("%s: stdout %q stderr %q", c, out.String(), errb.String())
		}
	}
}

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "shell-mcp-gate dev") {
		t.Fatalf("version: exit %d, %q", code, out.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"exec"}, &out, &errb); code != 2 {
		t.Fatalf("unknown command exit %d", code)
	}
}
