//go:build linux

package ops

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"os"
	"slices"
	"syscall"
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

// broadOps go to the broad unit's socket (PRIVILEGED §5.2, §6).
var broadOps = []string{
	protocol.OpPrivPkgUpdateIndex, protocol.OpPrivPkgInstall, protocol.OpPrivPkgUpgrade, protocol.OpPrivPkgRemove,
	protocol.OpPrivPkgInstallPreview, protocol.OpPrivPkgUpgradePreview, protocol.OpPrivPkgRemovePreview, protocol.OpPrivPower,
}

// route picks the helper socket for a privileged op: privileged.broad_socket
// for the package operations, their previews and priv_power, and for
// priv_exec when its `unit` argument is "broad" (the server supplies it: the
// gate cannot read the privileged policy to learn a command's unit);
// privileged.socket for everything else. This only picks the door: each
// helper instance refuses an operation meant for the other unit
// (helper_wrong_unit), so a wrong or forged label never runs anything in
// the wrong sandbox. The args are read here, never rewritten.
func (s *server) route(op string) (string, error) {
	broad := slices.Contains(broadOps, op)
	if op == protocol.OpPrivExec {
		b, err := execBroad(s.req.Args)
		if err != nil {
			return "", err
		}
		broad = b
	}
	if !broad {
		return s.p.Privileged.Socket, nil
	}
	if s.p.Privileged.BroadSocket == "" {
		return "", errf(protocol.CodePrivilegedDisabled, "this operation runs in the privileged helper's broad unit, and this gate policy sets no privileged.broad_socket")
	}
	return s.p.Privileged.BroadSocket, nil
}

// execBroad reads priv_exec's routing label: absent, null, "" or "core" is
// the core unit, "broad" the broad unit, anything else bad_request.
// encoding/json/v2 rejects duplicate names by default, so the gate and the
// helper can never read two different labels from one request.
func execBroad(args []byte) (bool, error) {
	var a struct {
		Unit *string `json:"unit"`
	}
	if len(args) > 0 && json.Unmarshal(args, &a) != nil {
		return false, errf(protocol.CodeBadRequest, "args are not a strict object of known fields with the expected types")
	}
	switch {
	case a.Unit == nil, *a.Unit == "", *a.Unit == "core":
		return false, nil
	case *a.Unit == "broad":
		return true, nil
	}
	return false, errf(protocol.CodeBadRequest, "unit must be core or broad")
}

// forward sends the request to the privileged helper and returns its
// answer (ARCHITECTURE §3 step 4, PRIVILEGED §3). The request goes out as
// received — the same v, id, op and timeout_ms, and the args bytes
// unchanged — and one bounded, strictly decoded response comes back.
// Failures map to closed-set codes: no connection is helper_unavailable; a
// connection closed without a byte — only a peer that failed the helper's
// SO_PEERCRED check gets that (PRIVILEGED §7) — is helper_refused, also
// when it arrives as a reset because the helper never read the request; no
// answer by the request's timeout plus the grace is timeout; anything
// malformed is helper_unavailable. A helper error passes through with its
// own code, including the helper_* self-check codes, which the helper
// answers before reading the request (without an id, and possibly before
// the request is even sent). The envelope's gate block stays the gate's.
func (s *server) forward(socket string) *protocol.Response {
	dial := s.o.DialHelper
	if dial == nil {
		dial = DialHelper
	}
	ctx, cancel := context.WithTimeout(context.Background(), helperConnectTimeout)
	conn, err := dial(ctx, socket)
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
	if _, err = conn.Write(append(line, '\n')); err != nil &&
		!errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) {
		return s.forwardErr(err)
	}
	// On EPIPE or a reset the helper closed before taking the request: it
	// either refused the peer (nothing to read) or answered a self-check
	// failure first (its answer is queued on this end). Read either way.
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
