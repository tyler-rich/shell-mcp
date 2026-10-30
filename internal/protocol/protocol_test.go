package protocol

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func decodeErr(t *testing.T, in string) *DecodeError {
	t.Helper()
	req, err := DecodeRequest(strings.NewReader(in))
	if err == nil {
		t.Fatalf("DecodeRequest(%q) = %+v, want error", in, req)
	}
	var de *DecodeError
	if !errors.As(err, &de) {
		t.Fatalf("DecodeRequest(%q) error %T %v, want *DecodeError", in, err, err)
	}
	return de
}

func TestDecodeRequestValid(t *testing.T) {
	in := `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000000","ceiling":"destructive","op":"read_file","args":{"path":"/srv/app/x","max_bytes":10},"timeout_ms":3000}` + "\n"
	req, err := DecodeRequest(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if req.V != 2 || req.Op != "read_file" || req.TimeoutMS != 3000 || req.ID != "0b5c0000-0000-4000-8000-000000000000" {
		t.Fatalf("decoded %+v", req)
	}
	var args struct {
		Path     string `json:"path"`
		MaxBytes int    `json:"max_bytes"`
	}
	if err := DecodeArgs(req.Args, &args); err != nil || args.Path != "/srv/app/x" || args.MaxBytes != 10 {
		t.Fatalf("args %+v %v", args, err)
	}
}

func TestDecodeRequestRejects(t *testing.T) {
	cases := map[string]string{
		"duplicate op":          `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello","op":"write_file"}`,
		"duplicate nested key":  `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"read_file","args":{"path":"/a","path":"/b"}}`,
		"unknown field":         `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello","extra":1}`,
		"trailing data":         `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello"} x`,
		"second value":          `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello"}{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello"}`,
		"empty":                 ``,
		"not an object":         `[1]`,
		"invalid utf8":          "{\"v\":1,\"id\":\"a\",\"op\":\"hel\xfflo\"}",
		"case-insensitive name": `{"V":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello"}`,
		"bad id":                `{"v":2,"id":"a b","ceiling":"destructive","op":"hello"}`,
		"long id":               `{"v":2,"id":"` + strings.Repeat("a", IDBytes+1) + `","op":"hello"}`,
		"missing op":            `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001"}`,
		"args not object":       `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello","args":[1]}`,
		"negative timeout":      `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello","timeout_ms":-1}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if de := decodeErr(t, in); de.Code != CodeBadRequest {
				t.Fatalf("code %q, want %q (%s)", de.Code, CodeBadRequest, de.Msg)
			}
		})
	}
}

// TestDecodeRequestCeiling: every request names its tier ceiling, one of
// read, operator or destructive (ARCHITECTURE §4.1). A request without one,
// or with any other value, is bad_request before anything else about it is
// looked at.
func TestDecodeRequestCeiling(t *testing.T) {
	for _, c := range []string{"read", "operator", "destructive"} {
		in := `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"` + c + `","op":"hello"}` + "\n"
		req, err := DecodeRequest(strings.NewReader(in))
		if err != nil || req.Ceiling != c {
			t.Errorf("ceiling %q: %+v %v", c, req, err)
		}
	}
	for name, in := range map[string]string{
		"missing":          `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","op":"hello"}`,
		"missing, exec":    `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","op":"exec","args":{"command_id":"probe-op","args":[]}}`,
		"empty":            `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"","op":"hello"}`,
		"null":             `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":null,"op":"hello"}`,
		"admin (reserved)": `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"admin","op":"hello"}`,
		"excluded":         `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"excluded","op":"hello"}`,
		"uppercase":        `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"READ","op":"hello"}`,
		"padded":           `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":" read","op":"hello"}`,
		"profile name":     `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read-only","op":"hello"}`,
		"number":           `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":1,"op":"hello"}`,
		"list":             `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":["read"],"op":"hello"}`,
		"duplicate":        `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","ceiling":"destructive","op":"hello"}`,
	} {
		t.Run(name, func(t *testing.T) {
			de := decodeErr(t, in+"\n")
			if de.Code != CodeBadRequest {
				t.Fatalf("code %q, want %q (%s)", de.Code, CodeBadRequest, de.Msg)
			}
		})
	}
	// Another version is reported as such, ceiling or not.
	if de := decodeErr(t, `{"v":3,"id":"0b5c0000-0000-4000-8000-000000000001","op":"hello"}`+"\n"); de.Code != CodeProtocolMismatch {
		t.Fatalf("v3 without a ceiling: %q", de.Code)
	}
}

func TestDecodeRequestVersionMismatch(t *testing.T) {
	for _, in := range []string{
		`{"v":3,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello"}`,
		`{"v":3,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello","new_field":true}`, // a newer protocol's field must not mask the mismatch
		`{"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello"}`,
	} {
		if de := decodeErr(t, in); de.Code != CodeProtocolMismatch {
			t.Errorf("%s: code %q, want %q", in, de.Code, CodeProtocolMismatch)
		}
	}
}

func TestDecodeRequestTooLarge(t *testing.T) {
	pad := strings.Repeat(" ", MaxRequestBytes)
	if de := decodeErr(t, `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello"}`+pad); de.Code != CodeTooLarge {
		t.Fatalf("code %q", de.Code)
	}
	// Exactly at the limit is accepted.
	body := `{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello"}`
	if _, err := DecodeRequest(strings.NewReader(body + strings.Repeat(" ", MaxRequestBytes-len(body)))); err != nil {
		t.Fatalf("at limit: %v", err)
	}
}

// A reader that never ends must not be read past the limit.
type endless struct{ n int }

func (e *endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	e.n += len(p)
	return len(p), nil
}

func TestDecodeRequestBoundedRead(t *testing.T) {
	r := &endless{}
	if _, err := DecodeRequest(r); err == nil {
		t.Fatal("endless input accepted")
	}
	if r.n > MaxRequestBytes+64<<10 {
		t.Fatalf("read %d bytes from an endless reader", r.n)
	}
}

// The request is one newline-terminated line: the gate must not wait for
// EOF from a client that keeps its stdin open.
func TestDecodeRequestStopsAtNewline(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	go func() {
		_, _ = pw.Write([]byte(`{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello"}` + "\n"))
	}()
	done := make(chan error, 1)
	go func() {
		_, err := DecodeRequest(pr)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DecodeRequest waited for EOF after the newline")
	}
	// A pretty-printed (multi-line) request is cut at its first newline.
	if de := decodeErr(t, "{\n\"v\":1,\"id\":\"a\",\"op\":\"hello\"}\n"); de.Code != CodeBadRequest {
		t.Fatalf("multi-line request: %s", de.Code)
	}
}

func TestDecodeArgsStrict(t *testing.T) {
	var a struct {
		Path string `json:"path"`
	}
	if err := DecodeArgs([]byte(`{"path":"/a","mode":"0600"}`), &a); err == nil {
		t.Fatal("unknown arg accepted")
	}
	if err := DecodeArgs([]byte(`{"path":"/a","path":"/b"}`), &a); err == nil {
		t.Fatal("duplicate arg accepted")
	}
	var b struct {
		Path string `json:"path"`
	}
	if err := DecodeArgs(nil, &b); err != nil || b.Path != "" {
		t.Fatalf("absent args: %v %+v", err, b)
	}
	if err := DecodeArgs([]byte(`null`), &b); err != nil {
		t.Fatalf("null args: %v", err)
	}
}

func TestEncodeResponse(t *testing.T) {
	data, err := Marshal(map[string]any{"x": 1})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	resp := &Response{V: Version, ID: "a", OK: true, Data: data, Gate: &GateInfo{Version: "dev", Principal: "p"}}
	if err := EncodeResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
		t.Fatalf("not one newline-terminated line: %q", out)
	}
	if !strings.Contains(out, `"warnings":[]`) {
		t.Fatalf("warnings must encode as [] not null: %s", out)
	}
	big := &Response{V: Version, ID: "a", OK: true, Warnings: []string{strings.Repeat("a", MaxResponseBytes)}}
	buf.Reset()
	if err := EncodeResponse(&buf, big); !errors.Is(err, ErrResponseTooLarge) || buf.Len() != 0 {
		t.Fatalf("oversize response: err %v, wrote %d", err, buf.Len())
	}
}

func TestCodesClosedSet(t *testing.T) {
	want := []string{"protocol_mismatch", "bad_request", "unknown_op", "tier_denied", "policy_denied", "path_denied",
		"not_found", "not_a_directory", "is_a_directory", "too_large", "exists", "template_mismatch", "not_authorized",
		"sandbox_unavailable", "privileged_disabled", "helper_unavailable", "helper_refused", "backup_failed",
		"exec_failed", "timeout", "verify_failed", "install_insecure", "internal",
		// The helper's own self-checks (PRIVILEGED §7), answered to the
		// authenticated gate before the request is read.
		"helper_install_insecure", "helper_policy_invalid", "helper_policy_mismatch",
		"helper_client_uid_mismatch", "helper_capabilities_broad",
		// The helper's Landlock refusal (PRIVILEGED §7 step 3), distinct from the
		// gate's own sandbox_unavailable.
		"helper_sandbox_unavailable",
		// An operation that reached the other unit's helper instance (the
		// helper is authoritative for routing).
		"helper_wrong_unit",
		// A privileged request that can change the host whose outcome is
		// unknown (handoff must-fix (b), S4c-6).
		"outcome_unknown"}
	if !slices.Equal(Codes, want) {
		t.Fatalf("Codes = %v", Codes)
	}
	// PRIVILEGED §6: the core operations, priv_exec, the four package
	// operations, their three read-tier previews, priv_power,
	// priv_backup_check (handoff P-11), the chown and chmod previews
	// (P-2b), the delete and restore previews (P-2a, P-2c), the exec
	// preview (P-2d), the index update preview (P-2e), and the power preview
	// and cancel (P-2f, P-13), the policy summary (P-8), and the hash op
	// for overwrite previews (handoff N-5), and the recovery and its preview
	// (handoff N-14), and the reinstall and its preview (handoff N-36).
	if len(PrivOps) != 36 || !slices.Contains(PrivOps, OpPrivPkgRecover) || !slices.Contains(PrivOps, OpPrivPkgRecoverPreview) ||
		!slices.Contains(PrivOps, OpPrivPkgReinstall) || !slices.Contains(PrivOps, OpPrivPkgReinstallPreview) {
		t.Fatalf("PrivOps has %d entries", len(PrivOps))
	}
}

// The request id is written into the gate's and the helper's audit lines,
// which join on it, so only its documented format is accepted: a UUID v4
// in lowercase canonical form (8-4-4-4-12 hex digits, version 4, variant
// 10xx), exactly IDBytes long.
func TestDecodeRequestIDIsUUIDv4(t *testing.T) {
	for _, id := range []string{
		"0b5c0000-0000-4000-8000-000000000000",
		"f47ac10b-58cc-4372-a567-0e02b2c3d479",
		"00000000-0000-4000-b000-000000000000",
		"ffffffff-ffff-4fff-9fff-ffffffffffff",
	} {
		in := `{"v":2,"id":"` + id + `","ceiling":"destructive","op":"hello"}` + "\n"
		req, err := DecodeRequest(strings.NewReader(in))
		if err != nil || req.ID != id {
			t.Errorf("valid id %q: %v", id, err)
		}
	}
	for name, id := range map[string]string{
		"short label":        "a",
		"uppercase":          "F47AC10B-58CC-4372-A567-0E02B2C3D479",
		"version 1":          "f47ac10b-58cc-1372-a567-0e02b2c3d479",
		"version 5":          "f47ac10b-58cc-5372-a567-0e02b2c3d479",
		"variant 0xxx":       "f47ac10b-58cc-4372-7567-0e02b2c3d479",
		"variant 110x":       "f47ac10b-58cc-4372-c567-0e02b2c3d479",
		"no hyphens":         "f47ac10b58cc4372a5670e02b2c3d479",
		"braces":             "{f47ac10b-58cc-4372-a567-0e02b2c3d479}",
		"urn prefix":         "urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479",
		"trailing char":      "f47ac10b-58cc-4372-a567-0e02b2c3d4790",
		"one short":          "f47ac10b-58cc-4372-a567-0e02b2c3d47",
		"hyphen misplaced":   "f47ac10b5-8cc-4372-a567-0e02b2c3d479",
		"non-hex":            "g47ac10b-58cc-4372-a567-0e02b2c3d479",
		"newline":            "f47ac10b-58cc-4372-a567-0e02b2c3d47\n",
		"empty":              "",
		"label with dots":    "req.1",
		"64-char label":      strings.Repeat("a", 64),
		"all-zero nil uuid":  "00000000-0000-0000-0000-000000000000",
		"space inside":       "f47ac10b-58cc-4372-a567 0e02b2c3d479",
		"trailing space pad": "f47ac10b-58cc-4372-a567-0e02b2c3d47 ",
	} {
		t.Run(name, func(t *testing.T) {
			in := `{"v":2,"id":"` + id + `","ceiling":"destructive","op":"hello"}` + "\n"
			if de := decodeErr(t, in); de.Code != CodeBadRequest {
				t.Fatalf("code %q, want %q", de.Code, CodeBadRequest)
			}
		})
	}
}

func TestIDBytes(t *testing.T) {
	if IDBytes != 36 {
		t.Fatalf("IDBytes = %d, want 36", IDBytes)
	}
}

const respID = "0b5c0000-0000-4000-8000-000000000003"

func TestDecodeResponse(t *testing.T) {
	ok := `{"v":2,"id":"` + respID + `","ok":true,"data":{"x":1},"warnings":["w"],"gate":{"version":"dev","principal":"p","duration_ms":1}}` + "\n"
	r, err := DecodeResponse(strings.NewReader(ok))
	if err != nil || !r.OK || r.ID != respID || string(r.Data) != `{"x":1}` || len(r.Warnings) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	fail := `{"v":2,"id":"","ok":false,"error":{"code":"sandbox_unavailable","message":"m"},"warnings":[]}` + "\n"
	if r, err := DecodeResponse(strings.NewReader(fail)); err != nil || r.OK || r.Error.Code != CodeSandboxUnavailable {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := DecodeResponse(strings.NewReader("")); !errors.Is(err, ErrNoResponse) {
		t.Fatalf("empty: %v", err)
	}
	for name, in := range map[string]string{
		"not json":           "nope\n",
		"unknown field":      `{"v":2,"id":"` + respID + `","ok":true,"warnings":[],"extra":1}` + "\n",
		"duplicate key":      `{"v":2,"v":2,"id":"` + respID + `","ok":true,"warnings":[]}` + "\n",
		"wrong version":      `{"v":3,"id":"` + respID + `","ok":true,"warnings":[]}` + "\n",
		"ok with error":      `{"v":2,"id":"` + respID + `","ok":true,"error":{"code":"internal","message":"m"},"warnings":[]}` + "\n",
		"failure no error":   `{"v":2,"id":"` + respID + `","ok":false,"warnings":[]}` + "\n",
		"unknown code":       `{"v":2,"id":"` + respID + `","ok":false,"error":{"code":"root_now","message":"m"},"warnings":[]}` + "\n",
		"bad id":             `{"v":2,"id":"x","ok":true,"warnings":[]}` + "\n",
		"ok without id":      `{"v":2,"id":"","ok":true,"warnings":[]}` + "\n",
		"two values":         `{"v":2,"id":"` + respID + `","ok":true,"warnings":[]} {}` + "\n",
		"too large":          `{"v":2,"id":"` + respID + `","ok":true,"warnings":["` + strings.Repeat("a", MaxResponseBytes) + `"]}` + "\n",
		"multi-line message": `{"v":2,"id":"` + respID + `","ok":false,"error":{"code":"internal","message":"a\nb"},"warnings":[]}` + "\n",
	} {
		if _, err := DecodeResponse(strings.NewReader(in)); err == nil || errors.Is(err, ErrNoResponse) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	// Bounded: an endless peer is not read past the limit.
	e := &endless{}
	if _, err := DecodeResponse(e); err == nil || e.n > MaxResponseBytes+64<<10 {
		t.Fatalf("endless: %v after %d bytes", err, e.n)
	}
}

func TestPrivMayChange(t *testing.T) {
	for _, c := range []struct {
		op, ceiling string
		want        bool
	}{
		{OpPrivStat, TierDestructive, false},
		{OpPrivReadFile, TierRead, false},
		{OpPrivExecPreview, TierDestructive, false},
		{OpPrivDeletePreview, TierDestructive, false},
		{OpPrivPkgInstallPreview, TierOperator, false},
		{OpPrivPkgUpdateIndexPreview, TierOperator, false},
		{OpPrivPkgUpdateIndex, TierOperator, true},
		{OpPrivPkgInstall, TierOperator, true},
		{OpPrivPkgRecover, TierOperator, true},
		{OpPrivPkgRecoverPreview, TierOperator, false},
		{OpPrivPkgReinstall, TierOperator, true},
		{OpPrivPkgReinstallPreview, TierOperator, false},
		{OpPrivWriteFile, TierOperator, true},
		{OpPrivDelete, TierDestructive, true},
		{OpPrivRestoreBackup, TierOperator, true},
		{OpPrivPower, TierDestructive, true},
		{"priv_power_preview", TierDestructive, false},
		{"priv_power_cancel", TierRead, true},
		{OpPrivExec, TierRead, false},
		{OpPrivExec, TierOperator, true},
		{OpPrivExec, TierDestructive, true},
		{"priv_unknown", TierRead, true},
	} {
		if got := PrivMayChange(c.op, c.ceiling); got != c.want {
			t.Errorf("PrivMayChange(%s, %s) = %v, want %v", c.op, c.ceiling, got, c.want)
		}
	}
}
