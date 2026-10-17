package envelope

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// All names and values below are invented test fixtures.

func TestServerCodesAreTheClosedSet(t *testing.T) {
	want := []string{
		"validation_error", "unknown_target", "target_unreachable", "host_key_mismatch", "auth_failed_ssh",
		"gate_unavailable", "protocol_mismatch", "approval_pending", "approval_declined", "approval_invalid", "approval_unavailable",
		"timeout", "profile_denied",
	}
	if !slices.Equal(ServerCodes, want) {
		t.Fatalf("ServerCodes = %v, want %v", ServerCodes, want)
	}
	all := Codes()
	for _, c := range append(slices.Clone(want), protocol.Codes...) {
		if !IsCode(c) || !slices.Contains(all, c) {
			t.Fatalf("%q missing from the closed set", c)
		}
	}
	if !slices.IsSorted(all) || len(slices.Compact(slices.Clone(all))) != len(all) {
		t.Fatalf("Codes() is not sorted and unique: %v", all)
	}
	for _, c := range []string{"", "ok", "unknown", "PATH_DENIED", "internal_error"} {
		if IsCode(c) {
			t.Fatalf("%q accepted as a code", c)
		}
	}
}

type data struct {
	Name string `json:"name"`
}

func TestSuccessShape(t *testing.T) {
	v := true
	e := Success("app-host", data{Name: "x"})
	e.Verified = &v
	e.Gate = &Gate{Version: "0.1.0", Principal: "operator-key", MaxTier: "operator", PolicySHA256: "ab12"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ok":true,"target":"app-host","data":{"name":"x"},"verified":true,"warnings":[],"gate":{"version":"0.1.0","principal":"operator-key","max_tier":"operator","policy_sha256":"ab12"}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

func TestFailureShape(t *testing.T) {
	e := Failure[data]("app-host", &Error{Code: "path_denied", Message: "path is outside every root"})
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ok":false,"target":"app-host","error":{"code":"path_denied","message":"path is outside every root"}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

func TestFailureMessageIsOneBoundedLine(t *testing.T) {
	e := Failure[data]("app-host", Errorf(CodeTargetUnreachable, "dial: %s", "line one\nline two\r\n"+strings.Repeat("x", 2000)))
	if strings.ContainsAny(e.Error.Message, "\r\n") || len(e.Error.Message) > MaxMessageBytes {
		t.Fatalf("message not one bounded line: %q (%d bytes)", e.Error.Message, len(e.Error.Message))
	}
	if !strings.HasPrefix(e.Error.Message, "dial: line one line two") {
		t.Fatalf("message = %q", e.Error.Message)
	}
}

func TestUnknownCodeBecomesInternal(t *testing.T) {
	e := Failure[data]("app-host", &Error{Code: "made_up", Message: "x"})
	if e.Error.Code != protocol.CodeInternal {
		t.Fatalf("code = %q", e.Error.Code)
	}
}

func TestErrorUnwrapsFromChains(t *testing.T) {
	inner := Errorf(CodeHostKeyMismatch, "host key not pinned")
	if got := AsError(wrap{inner}); got != inner {
		t.Fatalf("AsError = %v", got)
	}
	if got := AsError(errString("plain")); got.Code != protocol.CodeInternal {
		t.Fatalf("plain error became %q", got.Code)
	}
}

type wrap struct{ err error }

func (w wrap) Error() string { return "wrapped: " + w.err.Error() }
func (w wrap) Unwrap() error { return w.err }

type errString string

func (e errString) Error() string { return string(e) }

func TestFromGateResponse(t *testing.T) {
	ok := &protocol.Response{V: 1, ID: "0b5c0000-0000-4000-8000-000000000001", OK: true,
		Data: []byte(`{"name":"from-gate"}`), Warnings: []string{"w1"},
		Gate: &protocol.GateInfo{Version: "0.1.0", Principal: "readonly-key", PolicySHA256: "cd34", MaxTier: "read", DurationMS: 3}}
	e := FromGate[data]("app-host", ok)
	if !e.OK || e.Data == nil || e.Data.Name != "from-gate" || !slices.Equal(e.Warnings, []string{"w1"}) ||
		e.Gate == nil || e.Gate.Principal != "readonly-key" || e.Gate.PolicySHA256 != "cd34" {
		t.Fatalf("envelope = %+v", e)
	}
	// Gate codes pass through unchanged, including the helper's self-checks.
	for _, code := range []string{protocol.CodePathDenied, protocol.CodeHelperPolicyMismatch, protocol.CodeSandboxUnavailable} {
		bad := &protocol.Response{V: 1, OK: false, Error: &protocol.Error{Code: code, Message: "m"}}
		e := FromGate[data]("app-host", bad)
		if e.OK || e.Error == nil || e.Error.Code != code || e.Error.Message != "m" {
			t.Fatalf("%s: envelope = %+v", code, e)
		}
	}
	// Data that does not decode into the tool's type is a protocol mismatch.
	odd := &protocol.Response{V: 1, ID: "0b5c0000-0000-4000-8000-000000000001", OK: true, Data: []byte(`{"name":1}`)}
	if e := FromGate[data]("app-host", odd); e.OK || e.Error.Code != CodeProtocolMismatch {
		t.Fatalf("undecodable data: %+v", e)
	}
	unknownField := &protocol.Response{V: 1, ID: "0b5c0000-0000-4000-8000-000000000001", OK: true, Data: []byte(`{"name":"x","extra":1}`)}
	if e := FromGate[data]("app-host", unknownField); e.OK || e.Error.Code != CodeProtocolMismatch {
		t.Fatalf("unknown field: %+v", e)
	}
}
