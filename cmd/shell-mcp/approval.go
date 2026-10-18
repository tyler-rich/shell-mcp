package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
	"github.com/tyler-rich/shell-mcp/internal/approval/notify"
	"github.com/tyler-rich/shell-mcp/internal/approval/page"
	"github.com/tyler-rich/shell-mcp/internal/approval/totp"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/tools"
)

// sweepInterval is how often expired approval records are swept (and their
// expiry logged) when nothing else touches the store.
const sweepInterval = 30 * time.Second

// approvalRuntime is the approval state of a serving process: the store
// (web and confirm-argument), and for web the approval listener and the
// optional notifier. All of it is in memory: a restart forgets every
// record (D-006).
type approvalRuntime struct {
	store    *approval.Store
	server   *http.Server
	notifier *notify.Notifier
}

// newApprovalRuntime builds the approval store and, for web, the approval
// listener (docs/handoff/S4B-APPROVAL.md §6.5): loopback, or native TLS, or
// only the peers in SHELL_MCP_TRUSTED_PROXIES. Config already refused every
// other combination; the listener is not started here.
func newApprovalRuntime(cfg *config.Config, logger *slog.Logger) (*approvalRuntime, error) {
	ar := &approvalRuntime{}
	method := approval.Method(cfg.ApprovalMethod)
	if method == approval.MethodNone || method == "" {
		return ar, nil
	}
	ar.store = approval.NewStore(approval.Options{TTL: cfg.ApprovalTTL, Method: method, Logger: logger})
	if method != approval.MethodWeb {
		return ar, nil
	}
	if cfg.ApprovalNotifyURL != "" {
		n, err := notify.New(cfg.ApprovalNotifyURL, cfg.ApprovalNotifyToken.Reveal(), logger)
		if err != nil {
			return nil, fmt.Errorf("SHELL_MCP_APPROVAL_NOTIFY_URL: %w", err)
		}
		ar.notifier = n
	}
	v, err := totp.New(approvers.Seeds(cfg.Approvers), time.Now)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cfg.Approvers))
	for _, a := range cfg.Approvers {
		names = append(names, a.Name)
	}
	pc := &page.Config{
		PublicURL: cfg.ApprovalPublicURL, Store: ar.store, Verifier: v, Approvers: names,
		TrustedProxies: cfg.TrustedProxies, RateLimitPerMin: cfg.RateLimitPerMin, Logger: logger,
		// Relying on a TLS-terminating proxy, the listener serves only it.
		ProxyOnly: !config.IsLoopbackBind(cfg.ApprovalBind) && cfg.ApprovalTLSCert == nil,
		OnLockout: ar.notifyLockout,
	}
	if ar.server, err = page.NewServer(pc, net.JoinHostPort(cfg.ApprovalBind, strconv.Itoa(cfg.ApprovalPort)), cfg.ApprovalTLSCert); err != nil {
		return nil, err
	}
	return ar, nil
}

// start runs the sweeper and, for web, binds and serves the approval
// listener. stop shuts both down.
func (ar *approvalRuntime) start(ctx context.Context, logger *slog.Logger) (stop func(), err error) {
	ctx, cancel := context.WithCancel(ctx)
	if ar.store != nil {
		go ar.store.Run(ctx, sweepInterval)
	}
	if ar.server == nil {
		return cancel, nil
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", ar.server.Addr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("approval listener: %w", err)
	}
	go func() {
		var serr error
		if ar.server.TLSConfig != nil {
			serr = ar.server.ServeTLS(ln, "", "")
		} else {
			serr = ar.server.Serve(ln)
		}
		if serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			logger.Error("approval listener stopped", "error", serr.Error())
		}
	}()
	logger.Info("serving the approval page", "addr", ar.server.Addr, "tls", ar.server.TLSConfig != nil)
	return func() {
		cancel()
		sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer scancel()
		_ = ar.server.Shutdown(sctx)
	}, nil
}

// notifyRequest pushes a new approval request: the tool's title, the
// target, the server's summary, the expiry and a view link to the page,
// never an action that approves or declines.
func (ar *approvalRuntime) notifyRequest(r *approval.Record, url string) {
	if ar.notifier == nil {
		return
	}
	ar.notifier.Send(&notify.Message{
		Title:   "Approval requested: " + r.ToolTitle + " on " + r.Target,
		Message: r.Description + "\nExpires " + r.ExpiresAt.UTC().Format(time.RFC3339) + "\nApproval id " + r.ID,
		ViewURL: url, Tags: []string{"lock"}, Priority: 4,
	})
}

// notifyLockout pushes an approver lockout.
func (ar *approvalRuntime) notifyLockout(approver string, until time.Time, consecutive int) {
	if ar.notifier == nil {
		return
	}
	ar.notifier.Send(&notify.Message{
		Title:   "Approver locked out: " + approver,
		Message: "Too many wrong codes. Locked until " + until.UTC().Format(time.RFC3339) + " (lockout " + strconv.Itoa(consecutive) + ").",
		Tags:    []string{"warning"}, Priority: 4,
	})
}

// catalogueDeps reads the two settings that change tool schemas,
// SHELL_MCP_APPROVAL_METHOD and SHELL_MCP_APPROVAL_TIERS, with serve's
// rules, so `shell-mcp tools` prints what that configuration serves.
func catalogueDeps(lookup config.LookupFunc) (*tools.Deps, error) {
	d := &tools.Deps{ApprovalMethod: approval.MethodNone, ApprovalTiers: []string{"destructive"}}
	if v, ok := lookup("SHELL_MCP_APPROVAL_METHOD"); ok {
		m := approval.Method(strings.TrimSpace(v))
		if m != approval.MethodNone && m != approval.MethodWeb && m != approval.MethodConfirm {
			return nil, fmt.Errorf("SHELL_MCP_APPROVAL_METHOD must be one of none, web, confirm-argument (got %q)", v)
		}
		d.ApprovalMethod = m
	}
	if v, ok := lookup("SHELL_MCP_APPROVAL_TIERS"); ok {
		var tiers []string
		for _, t := range strings.Split(v, ",") {
			t = strings.TrimSpace(t)
			if t != "" && t != "operator" && t != "destructive" {
				return nil, fmt.Errorf("SHELL_MCP_APPROVAL_TIERS: unknown tier %q (allowed: operator, destructive)", t)
			}
			if t != "" && !slices.Contains(tiers, t) {
				tiers = append(tiers, t)
			}
		}
		if !slices.Contains(tiers, "destructive") {
			return nil, errors.New("SHELL_MCP_APPROVAL_TIERS must include destructive")
		}
		d.ApprovalTiers = tiers
	}
	return d, nil
}
