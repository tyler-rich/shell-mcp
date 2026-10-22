//go:build linux

package ops

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"os"
	"slices"
	"sync/atomic"
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
	protocol.OpPrivPkgInstallPreview, protocol.OpPrivPkgUpgradePreview, protocol.OpPrivPkgRemovePreview, protocol.OpPrivPkgUpdateIndexPreview,
	protocol.OpPrivPower,
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
// received — the same v, id, ceiling and op, and the args bytes unchanged
// — except timeout_ms, which is the timeout the gate waits for: the
// request's, clamped to the policy's max_timeout_s, or default_timeout_s
// when it has none. So the helper's deadline is never later than the
// gate's, and the gate does not answer timeout while the helper's command
// or apt transaction is still within its own (handoff P-7). One bounded,
// strictly decoded response comes back.
// Before it gives up, at the deadline less the stop wait, the gate shuts
// down its sending side: the helper reads that as a hang-up, stops a
// running command and answers, and the gate reads on until the deadline,
// so its answer is the helper's unless the helper fails to stop the
// command in that time (handoff must-fix (a)).
// Failures map to closed-set codes: no connection is helper_unavailable. For
// a request that can change the host (protocol.PrivMayChange), every
// failure to get an answer after the request was written — none by the
// deadline, a close without a byte, a malformed or mismatched answer — is
// outcome_unknown: the operation may have run on the host (must-fix (b)).
// For any other request: a connection closed without a byte — only a peer
// that failed the helper's SO_PEERCRED check gets that (PRIVILEGED §7) — is
// helper_refused, also when it arrives as a reset because the helper never
// read the request; no answer by the request's timeout plus the grace is
// timeout; anything malformed is helper_unavailable. A helper error passes
// through with its own code, including the helper_* self-check codes, which
// the helper answers before reading the request (without an id, and
// possibly before the request is even sent). The response's gate block
// stays the gate's; the helper's own block (its policy hash and unit) is
// passed on as the response's helper block, as received (handoff P-1).
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
	timeout := s.timeout()
	deadline := time.Now().Add(timeout + grace)
	_ = conn.SetDeadline(deadline)

	fwd := *s.req
	fwd.TimeoutMS = timeout.Milliseconds()
	line, err := protocol.Marshal(&fwd)
	if err != nil {
		return s.errResp(errf(protocol.CodeInternal, "request could not be encoded"))
	}
	_, err = conn.Write(append(line, '\n'))
	if err != nil && !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) {
		return s.forwardErr(err, false, false)
	}
	// On EPIPE or a reset the helper closed before taking the request: it
	// either refused the peer (nothing to read) or answered a self-check
	// failure first (its answer is queued on this end). Read either way.
	wrote := err == nil
	var hungUp atomic.Bool
	if cw, ok := conn.(interface{ CloseWrite() error }); ok && wrote {
		stop := min(DefaultHelperStopWait, grace/2)
		t := time.AfterFunc(time.Until(deadline.Add(-stop)), func() {
			hungUp.Store(true)
			_ = cw.CloseWrite()
		})
		defer t.Stop()
	}
	resp, err := protocol.DecodeResponse(conn)
	if err != nil {
		return s.forwardErr(err, wrote, hungUp.Load())
	}
	if resp.ID != s.req.ID && (resp.OK || resp.ID != "") {
		if wrote && protocol.PrivMayChange(s.req.Op, s.req.Ceiling) {
			return s.errResp(errf(protocol.CodeOutcomeUnknown, "the privileged helper answered a different request after this one was sent; the operation may have run on the host"))
		}
		return s.errResp(errf(protocol.CodeHelperUnavailable, "the privileged helper answered a different request"))
	}
	return &protocol.Response{OK: resp.OK, Data: resp.Data, Error: resp.Error, Warnings: resp.Warnings, Helper: resp.Gate}
}

// forwardErr maps a failure to get the helper's answer. wrote says the
// request was written; hungUp that the gate had already told the helper it
// stopped waiting.
func (s *server) forwardErr(err error, wrote, hungUp bool) *protocol.Response {
	var ne net.Error
	noAnswer := errors.Is(err, protocol.ErrNoResponse)
	late := errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
	if wrote && protocol.PrivMayChange(s.req.Op, s.req.Ceiling) {
		// The request may have run: outcome_unknown, never a refusal.
		switch {
		case late:
			return s.errResp(errf(protocol.CodeOutcomeUnknown, "the privileged helper did not answer in time, nor confirm that the operation ended; it may still be running, or complete, on the host"))
		case noAnswer && hungUp:
			return s.errResp(errf(protocol.CodeOutcomeUnknown, "the privileged helper did not answer in time and closed the connection when the gate stopped waiting; the operation may have run on the host before it ended"))
		case noAnswer:
			return s.errResp(errf(protocol.CodeOutcomeUnknown, "the privileged helper closed the connection without an answer after the request was sent: "+
				"it refused the connection (see its journal on the host) or ended while running the operation, which may have changed the host"))
		}
		return s.errResp(errf(protocol.CodeOutcomeUnknown, "the privileged helper's answer could not be read after the request was sent; the operation may have run on the host"))
	}
	switch {
	case noAnswer && hungUp:
		return s.errResp(errf(protocol.CodeTimeout, "the privileged helper did not answer in time"))
	case noAnswer:
		return s.errResp(errf(protocol.CodeHelperRefused, "the privileged helper refused the connection (see its journal on the host)"))
	case late:
		return s.errResp(errf(protocol.CodeTimeout, "the privileged helper did not answer in time"))
	}
	return s.errResp(errf(protocol.CodeHelperUnavailable, "the privileged helper's response could not be read"))
}
