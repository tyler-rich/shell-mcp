package protocol

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
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
	in := `{"v":1,"id":"0b5c0000-0000-4000-8000-000000000000","op":"read_file","args":{"path":"/srv/app/x","max_bytes":10},"timeout_ms":3000}` + "\n"
	req, err := DecodeRequest(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if req.V != 1 || req.Op != "read_file" || req.TimeoutMS != 3000 || req.ID != "0b5c0000-0000-4000-8000-000000000000" {
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
		"duplicate op":          `{"v":1,"id":"a","op":"hello","op":"write_file"}`,
		"duplicate nested key":  `{"v":1,"id":"a","op":"read_file","args":{"path":"/a","path":"/b"}}`,
		"unknown field":         `{"v":1,"id":"a","op":"hello","extra":1}`,
		"trailing data":         `{"v":1,"id":"a","op":"hello"} x`,
		"second value":          `{"v":1,"id":"a","op":"hello"}{"v":1,"id":"b","op":"hello"}`,
		"empty":                 ``,
		"not an object":         `[1]`,
		"invalid utf8":          "{\"v\":1,\"id\":\"a\",\"op\":\"hel\xfflo\"}",
		"case-insensitive name": `{"V":1,"id":"a","op":"hello"}`,
		"bad id":                `{"v":1,"id":"a b","op":"hello"}`,
		"long id":               `{"v":1,"id":"` + strings.Repeat("a", MaxIDBytes+1) + `","op":"hello"}`,
		"missing op":            `{"v":1,"id":"a"}`,
		"args not object":       `{"v":1,"id":"a","op":"hello","args":[1]}`,
		"negative timeout":      `{"v":1,"id":"a","op":"hello","timeout_ms":-1}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if de := decodeErr(t, in); de.Code != CodeBadRequest {
				t.Fatalf("code %q, want %q (%s)", de.Code, CodeBadRequest, de.Msg)
			}
		})
	}
}

func TestDecodeRequestVersionMismatch(t *testing.T) {
	for _, in := range []string{
		`{"v":2,"id":"a","op":"hello"}`,
		`{"v":2,"id":"a","op":"hello","new_field":true}`, // a newer protocol's field must not mask the mismatch
		`{"id":"a","op":"hello"}`,
	} {
		if de := decodeErr(t, in); de.Code != CodeProtocolMismatch {
			t.Errorf("%s: code %q, want %q", in, de.Code, CodeProtocolMismatch)
		}
	}
}

func TestDecodeRequestTooLarge(t *testing.T) {
	pad := strings.Repeat(" ", MaxRequestBytes)
	if de := decodeErr(t, `{"v":1,"id":"a","op":"hello"}`+pad); de.Code != CodeTooLarge {
		t.Fatalf("code %q", de.Code)
	}
	// Exactly at the limit is accepted.
	body := `{"v":1,"id":"a","op":"hello"}`
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
		"exec_failed", "timeout", "verify_failed", "install_insecure", "internal"}
	if !slices.Equal(Codes, want) {
		t.Fatalf("Codes = %v", Codes)
	}
	if len(PrivOps) != 17 {
		t.Fatalf("PrivOps has %d entries", len(PrivOps))
	}
}
