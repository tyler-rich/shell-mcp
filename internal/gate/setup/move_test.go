//go:build linux

package setup_test

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/setup"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx/setuptest"
)

// shell-mcp-gate move-key (TARGET-SETUP §12.1, "Moving a key between
// accounts"): one key line moved byte for byte from one account's keys
// file to another's, with the polkit rules, sshd's checks, the reload and a
// rollback, as one transaction.

const opKey = "/root/in/op.pub"

// moveHost is a host install took to two accounts: svc-shell (the drop-in's
// first account) with the read-only key (principal readonly) and the
// operator key (principal op, services.control, so svc-shell has
// 60-shell-mcp.rules), and svc-shell-std with the key web (read-only).
func moveHost(t *testing.T) *host {
	t.Helper()
	h, _ := newHost(t)
	withPolicies(h)
	if r := install(t, h); r.code != 0 {
		t.Fatalf("svc-shell: %d\n%s", r.code, r.out)
	}
	putKey(t, h, opKey)
	if r := install(t, h, "--policy", opPath, "--key", opKey, "--principal", "op"); r.code != 0 {
		t.Fatalf("svc-shell op: %d\n%s", r.code, r.out)
	}
	putKey(t, h, stdKey)
	if r := install(t, h, stdFlags()...); r.code != 0 {
		t.Fatalf("svc-shell-std: %d\n%s", r.code, r.out)
	}
	return h
}

func moveArgs(principal string, extra ...string) []string {
	return append([]string{"--principal", principal, "--from-user", "svc-shell", "--to-user", stdUser}, extra...)
}

func move(t *testing.T, h *host, args ...string) result {
	t.Helper()
	o, err := setup.ParseMoveFlags(args)
	if err != nil {
		t.Fatalf("flags %v: %v", args, err)
	}
	var out, aud bytes.Buffer
	before := h.Snapshot()
	h.order, h.runAs, h.loaded = nil, nil, nil
	code := setup.MoveKey(o, h, &out, &setupx.Auditor{Stderr: &aud, Component: "gate", DryRun: o.DryRun})
	var lines []string
	if aud.Len() > 0 {
		lines = strings.Split(strings.TrimSuffix(aud.String(), "\n"), "\n")
	}
	if l := h.Temps(); len(l) > 0 {
		t.Fatalf("temp files left: %v", l)
	}
	return result{code, out.String(), lines, before}
}

// handMove is TARGET-SETUP §7's "Moving a line", as its commands do it:
// grep -F the principal's line out of the source (the moved lines), cat the
// destination and them into the new destination, grep -vF the rest back
// into the source.
func handMove(src, dst, principal string) (newSrc, newDst string) {
	needle := `--principal ` + principal + `"`
	var moved string
	for _, l := range strings.SplitAfter(src, "\n") {
		switch {
		case l == "":
		case strings.Contains(l, needle):
			moved += l
		default:
			newSrc += l
		}
	}
	return newSrc, dst + moved
}

// TestMoveKey: the line moves byte for byte, exactly as the hand steps
// move it; check-policy runs as the destination account before anything is
// written; the destination is written first, then the source; sshd is
// checked for both accounts and reloaded; the audit names the fingerprint,
// never the key. The same flags again report only unchanged.
func TestMoveKey(t *testing.T) {
	h := moveHost(t)
	src, _ := h.Get(keysPath)
	dst, _ := h.Get(stdKeys)
	wantSrc, wantDst := handMove(src, dst, "readonly")
	r := move(t, h, moveArgs("readonly")...)
	if r.code != 0 {
		t.Fatalf("exit %d:\n%s", r.code, r.out)
	}
	for p, w := range map[string]string{keysPath: wantSrc, stdKeys: wantDst} {
		if got, _ := h.Get(p); got != w {
			t.Errorf("%s:\n%q\nwant (the hand steps)\n%q", p, got, w)
		}
		if e := h.Files[p]; e.UID != 0 || e.GID != 0 || e.Mode != 0o644 {
			t.Errorf("%s: %+v", p, e)
		}
	}
	if !reflect.DeepEqual(h.runAs, []*execx.Credential{{UID: 60125, GID: 60125}}) {
		t.Fatalf("check-policy ran as %+v", h.runAs)
	}
	if !slices.Contains(h.loaded, polPath+" /var/lib/svc-shell-std") {
		t.Fatalf("the line's policy was not loaded for the destination: %v", h.loaded)
	}
	for _, seq := range [][]string{
		{"check-policy", "write " + stdKeys, "write " + keysPath, "sshd -t"},
		{"sshd -t", "sshd -T -C user=svc-shell,host=client.example.test,addr=192.0.2.10", "/usr/bin/systemctl reload ssh.service"},
		{"sshd -t", "sshd -T -C user=svc-shell-std,host=client.example.test,addr=192.0.2.10", "/usr/bin/systemctl reload ssh.service"},
	} {
		if !inOrder(h.order, seq) {
			t.Errorf("not in order %q:\n%s", seq, strings.Join(h.order, "\n"))
		}
	}
	audit := strings.Join(r.audit, "\n")
	for _, s := range []string{`"object":"key","path":"` + stdKeys, `"object":"key","path":"` + keysPath, `"principal":"readonly"`, `"fingerprint":"SHA256:`} {
		if !strings.Contains(audit, s) {
			t.Errorf("audit lacks %s:\n%s", s, audit)
		}
	}
	line, _ := h.Get(keyPath)
	if strings.Contains(audit, strings.Fields(line)[1]) || strings.Contains(r.out, strings.Fields(line)[1]) {
		t.Fatal("the key is in the audit or the output")
	}
	if !strings.Contains(r.out, "SHELL_MCP_TARGET_USER") {
		t.Errorf("no note about the server's target user:\n%s", r.out)
	}
	// Again: already moved, only unchanged.
	again := move(t, h, moveArgs("readonly")...)
	if again.code != 0 || !strings.Contains(again.out, "nothing to do: every item unchanged") || !reflect.DeepEqual(h.Snapshot(), again.before) {
		t.Fatalf("second run %d:\n%s", again.code, again.out)
	}
	for _, o := range h.order {
		if strings.HasPrefix(o, "write ") || strings.HasSuffix(o, "reload ssh.service") {
			t.Fatalf("the second run ran %q", o)
		}
	}
}

// TestMoveKeyDryRun: nothing is written or run but what reads; the plan is
// shown with both files' diffs.
func TestMoveKeyDryRun(t *testing.T) {
	h := moveHost(t)
	r := move(t, h, moveArgs("readonly", "--dry-run")...)
	if r.code != 0 || !reflect.DeepEqual(h.Snapshot(), r.before) {
		t.Fatalf("exit %d, changed %v:\n%s", r.code, !reflect.DeepEqual(h.Snapshot(), r.before), r.out)
	}
	for _, o := range h.order {
		if !strings.HasPrefix(o, "sshd -T") && !strings.HasPrefix(o, "/usr/bin/systemctl is-active") {
			t.Fatalf("the dry run ran %q", o)
		}
	}
	for _, s := range []string{"file " + stdKeys + " root:root 0644: replace", "file " + keysPath + " root:root 0644: replace", "would run /usr/bin/systemctl reload ssh.service",
		"would run /usr/local/bin/shell-mcp-gate check-policy --policy " + polPath + " as svc-shell-std"} {
		if !strings.Contains(r.out, s) {
			t.Errorf("dry run lacks %q:\n%s", s, r.out)
		}
	}
	if len(r.audit) != 0 {
		t.Fatalf("a dry run audited %v", r.audit)
	}
}

// TestMoveKeyLastLine: moving every line leaves the source empty (the hand
// steps' grep -v writes an empty file), still root:root 0644; a new
// destination keys file is created.
func TestMoveKeyLastLine(t *testing.T) {
	h := moveHost(t)
	delete(h.Files, stdKeys)
	for _, p := range []string{"readonly", "op"} {
		if r := move(t, h, moveArgs(p)...); r.code != 0 {
			t.Fatalf("%s: %d\n%s", p, r.code, r.out)
		}
	}
	if got, ok := h.Get(keysPath); !ok || got != "" || h.Files[keysPath].Mode != 0o644 {
		t.Fatalf("source %q %v", got, ok)
	}
	if got, _ := h.Get(stdKeys); strings.Count(got, "\n") != 2 || !strings.HasSuffix(got, "shell-mcp-op\n") {
		t.Fatalf("destination:\n%s", got)
	}
}

// TestMoveKeyHalfDone: the same line, byte for byte, in both files is a
// move half done (install created the destination with the key being
// moved): it is removed from the source, and the destination is unchanged.
func TestMoveKeyHalfDone(t *testing.T) {
	h := moveHost(t)
	src, _ := h.Get(keysPath)
	ro := strings.SplitAfter(src, "\n")[0]
	appendTo(h, stdKeys, strings.TrimSuffix(ro, "\n"))
	dst, _ := h.Get(stdKeys)
	r := move(t, h, moveArgs("readonly")...)
	if r.code != 0 || !strings.Contains(r.out, stdKeys+": unchanged") {
		t.Fatalf("exit %d:\n%s", r.code, r.out)
	}
	if got, _ := h.Get(stdKeys); got != dst {
		t.Fatalf("destination changed:\n%s", got)
	}
	if got, _ := h.Get(keysPath); got != strings.TrimPrefix(src, ro) {
		t.Fatalf("source:\n%s", got)
	}
}

// TestMoveKeyPolkit: the destination gets its rule for the moved policy;
// the source's rule goes when it is exactly the moved policy's and no
// remaining line needs it, stays when a remaining line uses it, stays when
// install did not write it for the moved policy, and the move is refused
// when a remaining line needs another rule. Into the drop-in's first
// account, the rule is 60-shell-mcp.rules.
func TestMoveKeyPolkit(t *testing.T) {
	t.Run("moved: the destination's rule written, the source's removed", func(t *testing.T) {
		h := moveHost(t)
		r := move(t, h, moveArgs("op")...)
		if r.code != 0 {
			t.Fatalf("exit %d:\n%s", r.code, r.out)
		}
		if got, _ := h.Get(stdRule); got != rule(t, stdUser, operatorPolicy()) || h.Files[stdRule].Mode != 0o644 || h.Files[stdRule].UID != 0 {
			t.Fatalf("%s: %q", stdRule, got)
		}
		if _, ok := h.Get(setup.PolkitRule); ok {
			t.Fatal("svc-shell's rule left although none of its keys has services.control")
		}
		if !inOrder(h.order, []string{"write " + stdRule, "write " + stdKeys, "write " + keysPath, "sshd -t"}) {
			t.Fatalf("order:\n%s", strings.Join(h.order, "\n"))
		}
		if !strings.Contains(strings.Join(r.audit, "\n"), `"action":"remove","object":"polkit","path":"`+setup.PolkitRule) {
			t.Fatalf("no audit of the removal:\n%s", strings.Join(r.audit, "\n"))
		}
		if again := move(t, h, moveArgs("op")...); again.code != 0 || !strings.Contains(again.out, "nothing to do") {
			t.Fatalf("again %d:\n%s", again.code, again.out)
		}
	})
	t.Run("another key keeps the source's rule", func(t *testing.T) {
		h := moveHost(t)
		putKey(t, h, "/root/in/op2.pub")
		if r := install(t, h, "--policy", opPath, "--key", "/root/in/op2.pub", "--principal", "op2"); r.code != 0 {
			t.Fatalf("op2: %d\n%s", r.code, r.out)
		}
		if r := move(t, h, moveArgs("op")...); r.code != 0 || !strings.Contains(r.out, setup.PolkitRule+": unchanged") {
			t.Fatalf("exit %d:\n%s", r.code, r.out)
		}
		if got, _ := h.Get(setup.PolkitRule); got != rule(t, "svc-shell", operatorPolicy()) {
			t.Fatal("svc-shell's rule removed or changed although op2 needs it")
		}
	})
	t.Run("a rule install did not write for the moved policy stays", func(t *testing.T) {
		h := moveHost(t)
		h.Put(setup.PolkitRule, "// hand-written\n", 0o644, 0, 0)
		if r := move(t, h, moveArgs("op")...); r.code != 0 {
			t.Fatalf("exit %d:\n%s", r.code, r.out)
		}
		if got, _ := h.Get(setup.PolkitRule); got != "// hand-written\n" {
			t.Fatal("a rule install did not write was changed")
		}
	})
	t.Run("a remaining key needs another rule", func(t *testing.T) {
		h := moveHost(t)
		other := operatorPolicy()
		other.Services.ControlUnits = []string{"other-app.service"}
		other.SHA256 = "3333333333333333333333333333333333333333333333333333333333333333"
		h.pols["/etc/shell-mcp/other.yaml"] = other
		l := strings.Fields(putKey(t, h, "/root/in/other.pub"))
		appendTo(h, keysPath, `restrict,from="192.0.2.10",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/other.yaml --principal other" `+l[0]+" "+l[1]+" shell-mcp-other")
		r := move(t, h, moveArgs("op")...)
		if got := refusals(t, r); r.code != 1 || !slices.Equal(got, []string{"polkit_conflict"}) || !reflect.DeepEqual(h.Snapshot(), r.before) {
			t.Fatalf("exit %d, %v:\n%s", r.code, got, r.out)
		}
	})
	t.Run("into the drop-in's first account", func(t *testing.T) {
		h := moveHost(t)
		if r := move(t, h, moveArgs("op")...); r.code != 0 {
			t.Fatalf("to svc-shell-std: %d\n%s", r.code, r.out)
		}
		r := move(t, h, "--principal", "op", "--from-user", stdUser, "--to-user", "svc-shell")
		if r.code != 0 {
			t.Fatalf("back: %d\n%s", r.code, r.out)
		}
		if got, _ := h.Get(setup.PolkitRule); got != rule(t, "svc-shell", operatorPolicy()) {
			t.Fatalf("svc-shell's rule:\n%s", got)
		}
		if _, ok := h.Get(stdRule); ok {
			t.Fatal("svc-shell-std's rule left")
		}
	})
}

// TestMoveKeyRefusals: each refused before anything is written, audited.
func TestMoveKeyRefusals(t *testing.T) {
	journal := func(h *host) {
		p := *h.pol
		p.Journal.Units = []string{"example-app.service"}
		h.pols[polPath] = &p
	}
	member := func(group string, gid string) func(*host) {
		return func(h *host) {
			if gid != "" {
				_, _ = h.Fake.Simulate(setupx.Groupadd, []string{"--gid", gid, group})
			}
			_, _ = h.Fake.Simulate(setupx.Usermod, []string{"-aG", group, stdUser})
		}
	}
	for _, c := range []struct {
		name   string
		mod    func(*host)
		args   []string
		reason string
		text   string
	}{
		{"not root", func(h *host) { h.EUID = 1000 }, nil, "not_root", "runs as root only"},
		{"a forced command", func(h *host) { h.Env["SSH_ORIGINAL_COMMAND"] = "x" }, nil, "forced_command", "never runs as an SSH forced command"},
		{"another binary", func(h *host) { h.Exe = "/tmp/shell-mcp-gate" }, nil, "binary_path", "not /usr/local/bin/shell-mcp-gate"},
		{"principal", nil, moveArgs("Read_Only"), "principal", "--principal"},
		{"the same account", nil, []string{"--principal", "readonly", "--from-user", "svc-shell", "--to-user", "svc-shell"}, "same_account", "the same account"},
		{"no such destination account", nil, []string{"--principal", "readonly", "--from-user", "svc-shell", "--to-user", "svc-shell-ops"}, "no_account", "svc-shell-ops does not exist"},
		{"no line", nil, moveArgs("nobody"), "key_not_found", "no line of /etc/ssh/authorized_keys.d/svc-shell names --principal nobody"},
		{"two lines", func(h *host) {
			l := strings.Fields(putKey(t, h, "/root/in/dup.pub"))
			appendTo(h, keysPath, `restrict,from="192.0.2.10",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/read-only.yaml --principal readonly" `+l[0]+" "+l[1]+" shell-mcp-readonly")
		}, nil, "key_ambiguous", "2 lines"},
		{"in the destination with other bytes", func(h *host) {
			l := strings.Fields(mustGet(h, keyPath))
			appendTo(h, stdKeys, `restrict,from="192.0.2.11",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/read-only.yaml --principal readonly" `+l[0]+" "+l[1]+" shell-mcp-readonly")
		}, nil, "key_in_destination", "already holds this key"},
		{"a forwarding policy", func(h *host) { h.pols[polPath] = adminPolicy() }, nil, "forwarding", "privileged.enabled"},
		{"the destination in the helper's socket group", member("svc-shell-priv", "60124"), nil, "supplementary_group", "member of svc-shell-priv"},
		{"the destination in docker", member("docker", ""), nil, "privileged_group", "member of docker, a privileged group"},
		{"a journal section, the destination not in systemd-journal", journal, nil, "missing_group", "not a member of systemd-journal"},
		{"the destination has no block", func(h *host) { h.Put(dropPath, string(setup.DropIn("svc-shell")), 0o644, 0, 0) }, nil, "no_block", "no Match block"},
		{"the drop-in edited", func(h *host) {
			d := mustGet(h, dropPath)
			h.Put(dropPath, strings.Replace(d, "PermitTTY no", "PermitTTY yes", 1), 0o644, 0, 0)
		}, nil, "file_differs", "exists with other content"},
		{"the source keys file world-writable", func(h *host) { h.Files[keysPath].Mode = 0o666 }, nil, "keys_file_insecure", "must be a regular root:root 0644 file"},
		{"a line without restrict in the destination", func(h *host) {
			appendTo(h, stdKeys, `from="192.0.2.10",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/a.yaml" ssh-ed25519 `+testKey)
		}, nil, "keys_file_line", "line 2: key refused: the line has no restrict option"},
		{"the policy does not load", func(h *host) { h.polErr = errors.New("unknown key foo") }, nil, "policy_invalid", "unknown key foo"},
		{"the destination's rule differs", func(h *host) { h.Put(stdRule, "// hand-written\n", 0o644, 0, 0) }, moveArgs("op"), "file_differs", stdRule + " exists with other content"},
		{"strictmodes no", func(h *host) { h.strictModes = "no" }, nil, "strictmodes", "StrictModes must stay yes"},
		{"no systemd", func(h *host) { h.Systemd = false }, nil, "no_systemd", "systemd is not running as PID 1"},
		{"no sshd running", func(h *host) { h.sshService = false }, nil, "no_sshd", "neither ssh.service nor ssh.socket is active"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := moveHost(t)
			if c.mod != nil {
				c.mod(h)
			}
			args := c.args
			if args == nil {
				args = moveArgs("readonly")
			}
			r := move(t, h, args...)
			if got := refusals(t, r); r.code != 1 || !slices.Contains(got, c.reason) || !strings.Contains(r.out, c.text) {
				t.Fatalf("exit %d, refusals %v, want %s with %q:\n%s", r.code, got, c.reason, c.text, r.out)
			}
			if !reflect.DeepEqual(h.Snapshot(), r.before) {
				t.Fatal("a refused run changed the filesystem")
			}
			for _, o := range h.order {
				if strings.HasPrefix(o, "write") || o == "check-policy" {
					t.Fatalf("a refused run ran %q", o)
				}
			}
		})
	}
}

func mustGet(h *host, p string) string {
	v, _ := h.Get(p)
	return v
}

// TestMoveKeyRollback: a failure after the first write restores both keys
// files and both polkit rules, with no temp file left.
func TestMoveKeyRollback(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*host)
		want string
	}{
		{"the destination's block is not in force", func(h *host) {
			h.sshdOverrideFor = map[string]map[string]string{stdUser: {"permittty": "yes"}}
		}, "the Match block is not in force"},
		{"sshd -t fails", func(h *host) {
			prev := h.Programs
			h.Programs = func(f *setuptest.Fake, prog string, args []string) (setupx.Output, error) {
				if prog == setupx.Sshd && slices.Equal(args, []string{"-t"}) {
					return setuptest.Failed("bad configuration"), nil
				}
				return prev(f, prog, args)
			}
		}, "bad configuration"},
		{"the source cannot be written", func(h *host) { h.FailWrite[keysPath] = errNoSpace }, "no space"},
		{"the source's rule cannot be removed", func(h *host) { h.FailRemove[setup.PolkitRule] = errNoSpace }, "no space"},
		{"a read-back of the destination fails", func(h *host) { h.FailCommitted[stdKeys] = errors.New("read-back differs") }, "read-back differs"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := moveHost(t)
			c.mod(h)
			r := move(t, h, moveArgs("op")...)
			if r.code != 1 || !strings.Contains(r.out, c.want) || !strings.Contains(r.out, "every file this run changed was restored") {
				t.Fatalf("exit %d:\n%s", r.code, r.out)
			}
			if !reflect.DeepEqual(h.Snapshot(), r.before) {
				after := h.Snapshot()
				for p := range after {
					if !reflect.DeepEqual(after[p], r.before[p]) {
						t.Errorf("%s not restored", p)
					}
				}
				for p := range r.before {
					if _, ok := after[p]; !ok {
						t.Errorf("%s not restored", p)
					}
				}
			}
			for _, o := range h.order {
				if strings.HasSuffix(o, "reload ssh.service") {
					t.Fatal("reloaded after a failure")
				}
			}
		})
	}
	t.Run("check-policy as the destination FAILs", func(t *testing.T) {
		h := moveHost(t)
		h.checkOutFor = map[uint32]setupx.Output{60125: {Stdout: []byte("FAIL install: ...\n"), Exit: 1}}
		r := move(t, h, moveArgs("readonly")...)
		if r.code != 1 || !strings.Contains(r.out, "check-policy as svc-shell-std reports FAIL") || !reflect.DeepEqual(h.Snapshot(), r.before) {
			t.Fatalf("exit %d:\n%s", r.code, r.out)
		}
		for _, o := range h.order {
			if strings.HasPrefix(o, "write") {
				t.Fatalf("wrote after check-policy FAILed: %q", o)
			}
		}
	})
}

// TestMoveKeyFlags: the required flags, nothing else.
func TestMoveKeyFlags(t *testing.T) {
	o, err := setup.ParseMoveFlags(moveArgs("readonly", "--dry-run", "--no-reload"))
	if err != nil || *o != (setup.MoveOptions{Principal: "readonly", FromUser: "svc-shell", ToUser: stdUser, DryRun: true, NoReload: true}) {
		t.Fatalf("%+v %v", o, err)
	}
	for _, args := range [][]string{
		{"--from-user", "svc-shell", "--to-user", stdUser},
		{"--principal", "readonly", "--to-user", stdUser},
		{"--principal", "readonly", "--from-user", "svc-shell"},
		moveArgs("readonly", "extra"),
		moveArgs("readonly", "--key", "/root/in/x.pub"),
	} {
		if _, err := setup.ParseMoveFlags(args); !errors.Is(err, setup.ErrUsage) {
			t.Errorf("%v: %v, want a usage error", args, err)
		}
	}
}

// TestMoveKeyNoReload: --no-reload moves and checks, and leaves the reload
// to the operator.
func TestMoveKeyNoReload(t *testing.T) {
	h := moveHost(t)
	h.Systemd = false
	r := move(t, h, moveArgs("readonly", "--no-reload")...)
	if r.code != 0 || !strings.Contains(r.out, "--no-reload: reload sshd yourself") {
		t.Fatalf("exit %d:\n%s", r.code, r.out)
	}
	for _, o := range h.order {
		if strings.HasPrefix(o, "/usr/bin/systemctl") {
			t.Fatalf("ran %q", o)
		}
	}
}
