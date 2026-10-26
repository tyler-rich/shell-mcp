package protocol

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Protocol version 2 (ARCHITECTURE §4; handoff N-22's protocol decision):
// a refusal of another version names the peer's version, so each side can
// say which one to upgrade; a refusal of a version 1 request is framed in
// version 1, which a 0.1.0 peer decodes.

func TestVersion2(t *testing.T) {
	if Version != 2 {
		t.Fatalf("Version %d, want 2", Version)
	}
}

func peerOf(t *testing.T, err error) *DecodeError {
	t.Helper()
	var de *DecodeError
	if !errors.As(err, &de) {
		t.Fatalf("error %T %v, want *DecodeError", err, err)
	}
	return de
}

// TestDecodeRequestPeer: a request of another version is protocol_mismatch
// with the version it sent, unknown fields of that version or not; one
// without a version has peer 0.
func TestDecodeRequestPeer(t *testing.T) {
	for in, peer := range map[string]int{
		`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"hello"}`:              1,
		`{"v":3,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"hello","later":true}`: 3,
		`{"v":3,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"hello"}`:              3,
		`{"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"hello"}`:                    0,
		`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","op":"hello","args":{"anything":1}}`:         1,
	} {
		_, err := DecodeRequest(strings.NewReader(in + "\n"))
		if de := peerOf(t, err); de.Code != CodeProtocolMismatch || de.Peer != peer {
			t.Errorf("%s: %+v, want protocol_mismatch from version %d", in, de, peer)
		}
	}
}

// TestDecodeResponsePeer: a response of another version is
// protocol_mismatch with its version, checked before strict decoding, so
// a newer peer's unknown fields do not hide it; one whose version is not
// a number is malformed.
func TestDecodeResponsePeer(t *testing.T) {
	for in, peer := range map[string]int{
		`{"v":1,"id":"","ok":false,"error":{"code":"protocol_mismatch","message":"unsupported protocol version"},"warnings":[]}`: 1,
		`{"v":1,"id":"` + respID + `","ok":true,"data":{},"warnings":[]}`:                                                        1,
		`{"v":3,"id":"","ok":false,"error":{"code":"protocol_mismatch","message":"m"},"warnings":[],"later":1}`:                  3,
		`{"v":3,"id":"` + respID + `","ok":true,"data":{},"warnings":[],"later":{"x":1}}`:                                        3,
	} {
		_, err := DecodeResponse(strings.NewReader(in + "\n"))
		if de := peerOf(t, err); de.Code != CodeProtocolMismatch || de.Peer != peer {
			t.Errorf("%s: %+v, want protocol_mismatch from version %d", in, de, peer)
		}
	}
	for _, in := range []string{`{"v":"2","id":"","ok":true,"warnings":[]}`, `{"id":"` + respID + `","ok":true,"warnings":[]}`} {
		_, err := DecodeResponse(strings.NewReader(in + "\n"))
		if de := peerOf(t, err); de.Peer != 0 {
			t.Errorf("%s: peer %d", in, de.Peer)
		}
	}
}

func TestFrameVersion(t *testing.T) {
	for peer, want := range map[int]int{0: 2, 1: 1, 2: 2, 3: 2, -1: 2, 1 << 20: 2} {
		if got := FrameVersion(peer); got != want {
			t.Errorf("FrameVersion(%d) = %d, want %d", peer, got, want)
		}
	}
}

// TestVersion1FrameDecodesAsVersion1: a refusal framed for a version 1
// peer decodes under version 1's rules (what a 0.1.0 server and gate run),
// with its code and message intact.
func TestVersion1FrameDecodesAsVersion1(t *testing.T) {
	var out bytes.Buffer
	msg := "this gate speaks protocol version 2 and the request is version 1: upgrade the server"
	resp := &Response{V: FrameVersion(1), Error: &Error{Code: CodeProtocolMismatch, Message: msg},
		Gate: &GateInfo{Version: "0.2.0", Principal: "readonly-key", PolicySHA256: "ab", MaxTier: "read", DurationMS: 1}}
	if err := EncodeResponse(&out, resp); err != nil {
		t.Fatal(err)
	}
	r, err := decodeResponse(bytes.NewReader(out.Bytes()), 1)
	if err != nil || r.Error.Code != CodeProtocolMismatch || r.Error.Message != msg {
		t.Fatalf("version 1 decoded %q as %+v, %v", out.String(), r, err)
	}
}
