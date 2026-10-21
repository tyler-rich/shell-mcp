//go:build linux

package ops_test

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// FuzzPrivExecPreviewMatchesExec: for any arguments and cwd, through the
// real request handling, priv_exec_preview and priv_exec resolve alike: a
// preview refused with a code and message is an exec refused with the same
// ones; a preview that resolves is an exec that runs with its hash and runs
// exactly the previewed argv (the probe echoes it), and the same without a
// hash, since the command is read tier. The command has a template for
// every placeholder type the privileged policy allows: literal, regex,
// int, enum, path:read and path:write. One directory on the chain of the
// extra write root (its ancestor, the root, an intermediate directory or a
// parent) may be open for the iteration (handoff N-10): then no path
// placeholder and no cwd whose chain from / to its parent holds it ever
// resolves.
func FuzzPrivExecPreviewMatchesExec(f *testing.F) {
	fx := newFixture(f, execCommands(), chainCommands())
	anc, root := chainRoot(fx)
	b := filepath.Join(root, "a", "b")
	gatetest.Mkdir(f, filepath.Join(b, "c"), 0o755)
	gatetest.WriteFile(f, filepath.Join(b, "t"), "t\n", 0o644)
	opens := []string{"", anc, root, filepath.Join(root, "a"), b}
	for _, s := range []string{
		"echo\x00abc\x0042", "echo\x00abc\x00100", "echo\x00alpha\x00READ/hello.txt", "echo\x00beta\x00READ/secrets/token",
		"echo\x00fixed\x00WRITE/new.txt", "echo\x00fixed\x00WRITE/../x", "echo\x00fixed\x00WRITE", "echo\x00UPPER\x001",
		"echo\x00beta\x00/etc/passwd", "echo\x00gamma\x00READ/hello.txt", "echo\x00fixed\x00-WRITE", "echo", "",
		"echo\x00alpha\x00CHAIN/a/b/t", "echo\x00fixed\x00CHAIN/a/b/new", "echo\x00fixed\x00CHAIN/a/b/t", "echo\x00fixed\x00CHAIN",
		"echo\x00alpha\x00CHAIN/a",
	} {
		for _, o := range []uint8{0, 1, 2, 3, 4} {
			f.Add(s, uint8(0), o)
			f.Add(s, uint8(3), o)
			f.Add(s, uint8(6), o)
		}
	}
	cwds := []string{"", fx.read, fx.write, "/etc", fx.read + "/hello.txt", fx.write + "/missing", filepath.Join(b, "c"), root}
	f.Fuzz(func(t *testing.T, raw string, cwdSel, openSel uint8) {
		fx.t = t
		args := strings.Split(strings.NewReplacer("READ", fx.read, "WRITE", fx.write, "CHAIN", root).Replace(raw), "\x00")
		if len(args) > 6 {
			return
		}
		open := opens[int(openSel)%len(opens)]
		if open != "" {
			if err := os.Chmod(open, 0o777); err != nil { //nolint:gosec // G302: another account's write access, simulated
				t.Fatal(err)
			}
			defer func() { _ = os.Chmod(open, 0o755) }() //nolint:gosec // G302: a directory, closed again
		}
		req := m{"command_id": "probe-all", "args": args}
		if c := cwds[int(cwdSel)%len(cwds)]; c != "" {
			req["cwd"] = c
		}
		pr := fx.serve("priv_exec_preview", req)
		er := fx.serve("priv_exec", req)
		if !pr.OK {
			if er.OK || er.Error == nil || pr.Error == nil || er.Error.Code != pr.Error.Code || er.Error.Message != pr.Error.Message {
				t.Fatalf("preview refused %+v, exec %+v (data %s)", pr.Error, er.Error, er.Data)
			}
			return
		}
		var p execPreview
		if err := json.Unmarshal(pr.Data, &p); err != nil || !hex64.MatchString(p.PreviewSHA256) {
			t.Fatalf("preview %s: %v", pr.Data, err)
		}
		if open != "" {
			for _, x := range append(slices.Clone(p.Argv[1:]), p.Cwd) {
				if strings.HasPrefix(x, "/") && pathx.Within(open, path.Dir(x)) {
					t.Fatalf("%q resolved with the directory %s on its chain open", x, open)
				}
			}
		}
		bound := m{"command_id": "probe-all", "args": args, "expected_preview_sha256": p.PreviewSHA256}
		if c, ok := req["cwd"]; ok {
			bound["cwd"] = c
		}
		br := fx.serve("priv_exec", bound)
		for _, r := range []response{er, br} {
			var d execData
			if !r.OK || json.Unmarshal(r.Data, &d) != nil {
				t.Fatalf("preview %+v resolved, exec %+v %s", p, r.Error, r.Data)
			}
			// Output is redacted (an argument shaped like a secret is masked);
			// the argv the helper reports is not.
			echoed := d.Stdout == strings.Join(p.Argv[2:], "\n")+"\n" || strings.Contains(d.Stdout, redact.Mask)
			if !slices.Equal(d.Argv, p.Argv) || len(p.Argv) < 2 || !echoed {
				t.Fatalf("previewed %q, ran %q printing %q", p.Argv, d.Argv, d.Stdout)
			}
		}
	})
}
