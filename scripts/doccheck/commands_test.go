package main

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// Every document and --help text below is an invented fixture, shaped like
// the real ones.

func TestSplitCommands(t *testing.T) {
	for in, want := range map[string][][]string{
		`shell-mcp-gate install --policy /etc/x.yaml --from 192.0.2.10`:     {{"shell-mcp-gate", "install", "--policy", "/etc/x.yaml", "--from", "192.0.2.10"}},
		`docker run --rm "$IMAGE" init --dir /secrets`:                      {{"docker", "run", "--rm", "$IMAGE", "init", "--dir", "/secrets"}},
		`x --host-key 'ssh-ed25519 SHA256:<the value after "=">' > out.yml`: {{"x", "--host-key", `ssh-ed25519 SHA256:<the value after "=">`}},
		`docker exec <container> /shell-mcp doctor`:                         {{"docker", "exec", "<container>", "/shell-mcp", "doctor"}},
		`x <the flags you used before> --approve-host a.example.test`:       {{"x", "<the flags you used before>", "--approve-host", "a.example.test"}},
		`docker compose logs shell-mcp 2>&1 | grep 'authentication failed'`: {{"docker", "compose", "logs", "shell-mcp"}, {"grep", "authentication failed"}},
		`cd release && sha256sum -c SHA256SUMS && cd ..`:                    {{"cd", "release"}, {"sha256sum", "-c", "SHA256SUMS"}, {"cd", ".."}},
		`a --out - # a comment`:                                             {{"a", "--out", "-"}},
		`V=X.Y.Z`:                                                           {{"V=X.Y.Z"}},
		`echo "a \"b\" c"; b`:                                               {{"echo", `a "b" c`}, {"b"}},
	} {
		if got := splitCommands(in); !slices.EqualFunc(got, want, slices.Equal) {
			t.Errorf("splitCommands(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInvoke(t *testing.T) {
	for in, want := range map[string]string{ //nolint:gosec // G101: command lines and the names parsed from them, not credentials
		`shell-mcp-gate policy new --answers a.yaml --out -`:                     "shell-mcp-gate policy new|--answers --out",
		`/usr/local/libexec/shell-mcp-privd install --policy p --dry-run`:        "shell-mcp-privd install|--policy --dry-run",
		`docker run --rm -it -v "$PWD/s:/s" "$IMAGE" init --dir /s`:              "shell-mcp init|--dir",
		`docker run --rm "$IMAGE" init compose --image "$IMAGE" --form=bind`:     "shell-mcp init compose|--image --form",
		`docker compose exec shell-mcp /shell-mcp doctor --mcp-url u`:            "shell-mcp doctor|--mcp-url",
		`docker exec <c> /shell-mcp doctor`:                                      "shell-mcp doctor|",
		`x <the flags> --approve-host h`:                                         "",
		`install -o root -m 0755 r/shell-mcp-gate /usr/local/bin/shell-mcp-gate`: "",
		`docker run --rm ghcr.io/tyler-rich/shell-mcp:<v>@sha256:<d> init`:       "shell-mcp init|",
		`cosign verify "ghcr.io/tyler-rich/shell-mcp@$DIGEST"`:                   "",
		`shell-mcp-src/scripts/verify-release.sh 1 --dir release`:                "",
	} {
		words := splitCommands(in)[0]
		inv, ok := invoke(command{words: words})
		got := ""
		if ok {
			got = strings.Join(append([]string{inv.bin}, inv.sub...), " ") + "|" + strings.Join(inv.flags, " ")
		}
		if got != want {
			t.Errorf("invoke(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeHelp answers like the real binaries: the root usage for the binary,
// a subcommand's own usage, exit 2 for an unknown first word, and a
// parent's usage for an unknown second word.
func fakeHelp(bin string, args []string) (out string, code int, err error) {
	root := map[string]string{
		"shell-mcp":      "commands:\n  doctor   run check\n  init     secrets (init), or compose file (init compose)\n  approver (add, remove, list)\n",
		"shell-mcp-gate": "commands:\n  install --policy <file>\n  policy new --answers <file>\n  host-key  print the pin\n",
	}[bin]
	subs := map[string]string{
		"shell-mcp doctor":          "usage: shell-mcp doctor [--json] [--mcp-url <u>] [--ca-file <f>]",
		"shell-mcp init":            "usage: shell-mcp init --dir <dir> [--approver <name>]",
		"shell-mcp init compose":    "usage: shell-mcp init compose --image <i> --mcp-host <n> [--profile p] [--approve-host <n>]",
		"shell-mcp approver":        "commands:\n  add --name <n> --file <f>\n",
		"shell-mcp approver add":    "commands:\n  add --name <n> --file <f>\n",
		"shell-mcp-gate install":    "usage: shell-mcp-gate install --policy <f> --from <a> [--dry-run]",
		"shell-mcp-gate policy new": "usage: shell-mcp-gate policy new --answers <f> --out <f>|-",
		"shell-mcp-gate host-key":   "usage: shell-mcp-gate host-key",
	}
	args = slices.DeleteFunc(slices.Clone(args), func(a string) bool { return a == "--help" })
	if len(args) == 0 {
		return root, 0, nil
	}
	for n := len(args); n > 0; n-- {
		if h, ok := subs[bin+" "+strings.Join(args[:n], " ")]; ok {
			return h, 0, nil
		}
	}
	return "unknown command\n" + root, 2, nil
}

func TestCheckCommands(t *testing.T) {
	readme := "# x\n\n## Quick start\n\n" +
		"Run `shell-mcp-gate host-key`; `--from` is the server's address.\n\n" +
		"```bash\n" +
		"docker run --rm -it --network none \"$IMAGE\" init --dir /secrets --approver alice\n" + // line 8
		"shell-mcp-gate install --policy /etc/p.yaml \\\n" + // line 9
		"  --form 192.0.2.10 --dry-run\n" +
		"shell-mcp-gate polcy new --answers a.yaml --out -\n" + // line 11
		"docker run --rm \"$IMAGE\" init compse --dir /x\n" + // line 12
		"docker run --rm \"$IMAGE\" init compose --image \"$IMAGE\" --mcp-host m.example.test > docker-compose.yml\n" + // line 13
		"```\n\n" +
		"Add `--approve-hots` for approvals.\n\n" + // line 16
		"```text\n--profile operator --aprove-host a.example.test\n```\n\n" + // line 19
		"```bash\ndocker compose exec shell-mcp /shell-mcp doctor --mcp-url https://m.example.test/mcp\n```\n\n" +
		"## Next\n\n```bash\nshell-mcp-gate install --nonsense\n```\n"
	clients := "# c\n\n### 3.2 Setting it up\n\n```bash\n" +
		"docker run --rm -it \"$IMAGE\" approver add --name alice --file /run/secrets/approvers\n```\n\n## 4. Next\n"
	fsys := fstest.MapFS{
		"README.md":       {Data: []byte(readme)},
		"docs/CLIENTS.md": {Data: []byte(clients)},
	}
	problems, checked, err := checkCommands(fsys, fakeHelp)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"README.md:9: `shell-mcp-gate install --policy /etc/p.yaml --form 192.0.2.10 --dry-run`: --form is not a flag of `shell-mcp-gate install` (its --help)",
		"README.md:11: `shell-mcp-gate polcy new --answers a.yaml --out -`: `shell-mcp-gate polcy new --help` exits 2: no such subcommand",
		"README.md:12: `docker run --rm \"$IMAGE\" init compse --dir /x`: \"compse\" is not a subcommand of `shell-mcp init` (its --help)",
		"README.md:19: `--profile operator --aprove-host a.example.test`: --aprove-host is not a flag of `shell-mcp init compose` (its --help)",
		"README.md:16: `--approve-hots`: --approve-hots is a flag of no command in README.md's section (their --help)",
	}
	if !slices.Equal(problems, want) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
	// Every command of both sections was checked, and nothing after the
	// quick start's section (the --nonsense line).
	if len(checked) != 11 {
		t.Errorf("checked %d commands, want 11:\n%s", len(checked), strings.Join(checked, "\n"))
	}
	for _, c := range checked {
		if strings.Contains(c, "nonsense") {
			t.Errorf("checked a command outside the section: %s", c)
		}
	}
}

func TestCheckCommandsMissingSection(t *testing.T) {
	fsys := fstest.MapFS{"README.md": {Data: []byte("# x\n\n## Install\n")}, "docs/CLIENTS.md": {Data: []byte("# c\n")}}
	if _, _, err := checkCommands(fsys, fakeHelp); err == nil || !strings.Contains(err.Error(), "Quick start") {
		t.Errorf("a README without its quick start: err %v, want one naming the heading", err)
	}
}

func TestHelpHas(t *testing.T) {
	h := "usage: x --dir <dir> [--dry-run] --out <f>|-"
	for w, want := range map[string]bool{"--dir": true, "--dry-run": true, "--dry": false, "--out": true, "--di": false, "--dir-x": false} {
		if got := helpHas(h, w); got != want {
			t.Errorf("helpHas(%q) = %v, want %v", w, got, want)
		}
	}
}
