package gateclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// DefaultGrace is how long past the tool's time budget the client waits for
// the gate's answer. The gate enforces the budget itself (timeout_ms,
// clamped by its policy) and waits up to the budget plus 15 s for the
// privileged helper; the grace covers that and the SSH round trip.
const DefaultGrace = 20 * time.Second

// Opener opens an SSH session to a target (*sshx.Client).
type Opener interface {
	Session(context.Context) (*sshx.Session, error)
}

// Options configure a Client.
type Options struct {
	Grace  time.Duration
	Logger *slog.Logger
}

// Client is the client side of the gate protocol (ARCHITECTURE §4): one
// request per SSH session.
type Client struct {
	o Options
}

// New returns a client.
func New(o Options) *Client {
	if o.Grace <= 0 {
		o.Grace = DefaultGrace
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Client{o: o}
}

// Call sends one request for op with args and returns the gate's response,
// failure or not. budget is sent as timeout_ms; the call gives up budget +
// Grace after it starts. The error, for transport and protocol failures
// only, is an *envelope.Error:
//   - the request over 2 MiB: validation_error, before anything is sent;
//   - SSH failures: the sshx codes (target_unreachable, host_key_mismatch,
//     auth_failed_ssh, timeout, gate_unavailable);
//   - nothing answered: gate_unavailable; no answer in time: timeout;
//   - another protocol version, a malformed response or one whose id is
//     not the request's: protocol_mismatch; a response over 4 MiB: too_large.
//
// A failure the gate answered before reading the request (its install and
// sandbox refusals, and the helper's self-check codes it passes through)
// has no id and is returned as a response with its code. The gate may
// answer and exit before the request is fully written; the failed write
// does not hide that answer.
func (c *Client) Call(ctx context.Context, o Opener, op string, args any, budget time.Duration) (*protocol.Response, error) {
	id, line, err := encode(op, args, budget)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget+c.o.Grace)
	defer cancel()

	s, err := o.Session(ctx)
	if err != nil {
		return nil, transportError(err)
	}
	defer func() { _ = s.Close() }()
	stdin, err := s.StdinPipe()
	if err != nil {
		return nil, envelope.Errorf(envelope.CodeGateUnavailable, "cannot open the session's input")
	}
	stdout, err := s.StdoutPipe()
	if err != nil {
		return nil, envelope.Errorf(envelope.CodeGateUnavailable, "cannot open the session's output")
	}
	if err := s.Start(protocol.Hello); err != nil {
		return nil, envelope.Errorf(envelope.CodeGateUnavailable, "the target refused to run the gate")
	}

	type result struct {
		resp *protocol.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		r, err := protocol.DecodeResponse(stdout)
		done <- result{r, err}
	}()
	go func() {
		// A write error (the gate closed its input, or the session ended)
		// is not the outcome: the gate may already have answered.
		if _, werr := stdin.Write(line); werr != nil {
			c.o.Logger.Debug("gate request not fully written", "op", op, "id", id, "error", werr.Error())
		}
		_ = stdin.Close()
	}()

	select {
	case <-ctx.Done():
		return nil, envelope.Errorf(envelope.CodeTimeout, "the gate did not answer within the time budget")
	case r := <-done:
		return check(ctx, id, r.resp, r.err)
	}
}

func encode(op string, args any, budget time.Duration) (id string, line []byte, err error) {
	id = NewID()
	req := protocol.Request{V: protocol.Version, ID: id, Op: op, TimeoutMS: budget.Milliseconds()}
	if args != nil {
		if req.Args, err = protocol.Marshal(args); err != nil {
			return "", nil, envelope.Errorf(envelope.CodeValidationError, "the request arguments cannot be encoded")
		}
	}
	out, err := protocol.Marshal(req)
	if err != nil {
		return "", nil, envelope.Errorf(envelope.CodeValidationError, "the request cannot be encoded")
	}
	if len(out)+1 > protocol.MaxRequestBytes {
		return "", nil, envelope.Errorf(envelope.CodeValidationError, "the request exceeds 2 MiB")
	}
	return id, append(out, '\n'), nil
}

func check(ctx context.Context, id string, resp *protocol.Response, err error) (*protocol.Response, error) {
	var de *protocol.DecodeError
	switch {
	case errors.Is(err, protocol.ErrNoResponse):
		return nil, envelope.Errorf(envelope.CodeGateUnavailable, "the gate closed the session without a response")
	case errors.As(err, &de):
		switch de.Code {
		case protocol.CodeTooLarge:
			return nil, envelope.Errorf(protocol.CodeTooLarge, "the gate's response exceeds 4 MiB")
		case protocol.CodeProtocolMismatch:
			return nil, envelope.Errorf(envelope.CodeProtocolMismatch, "the gate speaks another protocol version (this server speaks version %d)", protocol.Version)
		}
		return nil, envelope.Errorf(envelope.CodeProtocolMismatch, "the gate's response is malformed")
	case err != nil:
		if ctx.Err() != nil {
			return nil, envelope.Errorf(envelope.CodeTimeout, "the gate did not answer within the time budget")
		}
		return nil, envelope.Errorf(envelope.CodeGateUnavailable, "the gate's response could not be read")
	case resp.ID != "" && resp.ID != id:
		return nil, envelope.Errorf(envelope.CodeProtocolMismatch, "the gate's response id does not match the request")
	}
	// An empty id is only accepted on a failure (protocol.DecodeResponse):
	// a refusal answered before the request was read.
	return resp, nil
}

func transportError(err error) error {
	var e *envelope.Error
	if errors.As(err, &e) {
		return e
	}
	return envelope.Errorf(envelope.CodeGateUnavailable, "cannot open an SSH session to the target")
}

// NewID returns a fresh request id: a random UUID v4 in lowercase canonical
// form (ARCHITECTURE §4.1).
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24+)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}
