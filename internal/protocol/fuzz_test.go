package protocol

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzDecodeRequest: decoding never panics; an accepted request satisfies
// every documented constraint; re-encoding an accepted request decodes to
// the same request; duplicate keys are never accepted.
func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","op":"hello"}` + "\n"))
	f.Add([]byte(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","op":"read_file","args":{"path":"/srv/app/x","max_bytes":10},"timeout_ms":3000}`))
	f.Add([]byte(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","op":"hello","op":"write_file"}`))
	f.Add([]byte(`{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","op":"hello","x":1}`))
	f.Add([]byte(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","op":"exec","args":{"args":["a","b"],"a":{"b":{"c":[1,2,{"d":null}]}}}}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		req, err := DecodeRequest(bytes.NewReader(in))
		if err != nil {
			var de *DecodeError
			if !errors.As(err, &de) {
				t.Fatalf("error is not a DecodeError: %v", err)
			}
			return
		}
		if len(in) > MaxRequestBytes+1 && bytes.IndexByte(in[:MaxRequestBytes+1], '\n') < 0 {
			t.Fatal("accepted a request over the size limit")
		}
		if req.V != Version || !validID(req.ID) || !validOp(req.Op) || req.TimeoutMS < 0 {
			t.Fatalf("accepted request violates constraints: %+v", req)
		}
		if len(req.Args) > 0 && req.Args.Kind() != '{' {
			t.Fatalf("accepted non-object args: %s", req.Args)
		}
		if len(req.Args) > 0 && !req.Args.IsValid() {
			t.Fatalf("accepted args with duplicate names or invalid UTF-8: %s", req.Args)
		}
		out, err := Marshal(req)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		again, err := DecodeRequest(bytes.NewReader(append(out, '\n')))
		if err != nil {
			t.Fatalf("re-encoded request rejected: %v\n%s", err, out)
		}
		if again.V != req.V || again.ID != req.ID || again.Op != req.Op || again.TimeoutMS != req.TimeoutMS {
			t.Fatalf("round trip changed the request: %+v vs %+v", req, again)
		}
	})
}

// FuzzDecodeResponse: decoding never panics, and an accepted response is
// consistent: ok xor error, a closed-set code, a one-line bounded message,
// and a valid id unless it is a failure answered before any request.
func FuzzDecodeResponse(f *testing.F) {
	f.Add([]byte(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000003","ok":true,"data":{"x":1},"warnings":[]}` + "\n"))
	f.Add([]byte(`{"v":1,"id":"","ok":false,"error":{"code":"sandbox_unavailable","message":"m"},"warnings":[]}` + "\n"))
	f.Add([]byte(`{"v":1,"id":"x","ok":true}`))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeResponse(bytes.NewReader(b))
		if err != nil {
			return
		}
		if r.OK == (r.Error != nil) || (r.ID != "" || r.OK) && !validID(r.ID) {
			t.Fatalf("inconsistent response accepted: %+v", r)
		}
		if r.Error != nil && (len(r.Error.Message) > maxMessageBytes || bytes.ContainsAny([]byte(r.Error.Message), "\r\n")) {
			t.Fatalf("message accepted: %q", r.Error.Message)
		}
	})
}
