//go:build linux

package ops_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// FuzzPrivExecPreviewMatchesExec: for any arguments and cwd, through the
// real request handling, priv_exec_preview and priv_exec resolve alike: a
// preview refused with a code and message is an exec refused with the same
// ones; a preview that resolves is an exec that runs with its hash and runs
// exactly the previewed argv (the probe echoes it), and the same without a
// hash, since the command is read tier. The command has a template for
// every placeholder type the privileged policy allows: literal, regex,
// int, enum, path:read and path:write.
func FuzzPrivExecPreviewMatchesExec(f *testing.F) {
	fx := newFixture(f, execCommands())
	for _, s := range []string{
		"echo\x00abc\x0042", "echo\x00abc\x00100", "echo\x00alpha\x00READ/hello.txt", "echo\x00beta\x00READ/secrets/token",
		"echo\x00fixed\x00WRITE/new.txt", "echo\x00fixed\x00WRITE/../x", "echo\x00fixed\x00WRITE", "echo\x00UPPER\x001",
		"echo\x00beta\x00/etc/passwd", "echo\x00gamma\x00READ/hello.txt", "echo\x00fixed\x00-WRITE", "echo", "",
	} {
		f.Add(s, uint8(0))
		f.Add(s, uint8(3))
	}
	cwds := []string{"", fx.read, fx.write, "/etc", fx.read + "/hello.txt", fx.write + "/missing"}
	f.Fuzz(func(t *testing.T, raw string, cwdSel uint8) {
		fx.t = t
		args := strings.Split(strings.NewReplacer("READ", fx.read, "WRITE", fx.write).Replace(raw), "\x00")
		if len(args) > 6 {
			return
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
