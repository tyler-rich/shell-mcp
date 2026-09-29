//go:build linux

package ops

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// helperConnectTimeout bounds the connect to the helper's socket (systemd
// accepts it; the instance starts after).
const helperConnectTimeout = 5 * time.Second

// DialHelper is the production helper dialer: a Unix stream connection to
// the socket named by the policy (privileged.socket, beneath
// /run/shell-mcp). The gate's Landlock grant covers exactly that socket's
// directory (POLICY §4a).
func DialHelper(ctx context.Context, socket string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", socket)
}

// forward sends the request to the privileged helper and returns its
// answer (ARCHITECTURE §3 step 4, PRIVILEGED §3). The request goes out as
// received — the same v, id, op and timeout_ms, and the args bytes
// unchanged — and one bounded, strictly decoded response comes back.
// Failures map to closed-set codes: no connection is helper_unavailable; a
// connection closed without a byte (a refused peer or a failed self-check)
// is helper_refused; no answer by the request's timeout plus the grace is
// timeout; anything malformed is helper_unavailable. A helper error passes
// through with its own code. The envelope's gate block stays the gate's.
func (s *server) forward() *protocol.Response {
	dial := s.o.DialHelper
	if dial == nil {
		dial = DialHelper
	}
	ctx, cancel := context.WithTimeout(context.Background(), helperConnectTimeout)
	conn, err := dial(ctx, s.p.Privileged.Socket)
	cancel()
	if err != nil {
		return s.errResp(errf(protocol.CodeHelperUnavailable, "the privileged helper's socket cannot be reached"))
	}
	defer func() { _ = conn.Close() }()
	grace := s.o.HelperGrace
	if grace <= 0 {
		grace = DefaultHelperGrace
	}
	_ = conn.SetDeadline(time.Now().Add(s.timeout() + grace))

	line, err := protocol.Marshal(s.req)
	if err != nil {
		return s.errResp(errf(protocol.CodeInternal, "request could not be encoded"))
	}
	if _, err = conn.Write(append(line, '\n')); err != nil {
		return s.forwardErr(err)
	}
	resp, err := protocol.DecodeResponse(conn)
	if err != nil {
		return s.forwardErr(err)
	}
	if resp.ID != s.req.ID && (resp.OK || resp.ID != "") {
		return s.errResp(errf(protocol.CodeHelperUnavailable, "the privileged helper answered a different request"))
	}
	return &protocol.Response{OK: resp.OK, Data: resp.Data, Error: resp.Error, Warnings: resp.Warnings}
}

func (s *server) forwardErr(err error) *protocol.Response {
	var ne net.Error
	switch {
	case errors.Is(err, protocol.ErrNoResponse):
		return s.errResp(errf(protocol.CodeHelperRefused, "the privileged helper refused the connection (see its journal on the host)"))
	case errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return s.errResp(errf(protocol.CodeTimeout, "the privileged helper did not answer in time"))
	}
	return s.errResp(errf(protocol.CodeHelperUnavailable, "the privileged helper's response could not be read"))
}
