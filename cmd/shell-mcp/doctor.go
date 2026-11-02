package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/gateclient"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
	"github.com/tyler-rich/shell-mcp/internal/tools"
)

// doctor runs everything check does, then the checks check should not make
// silently (handoff §4.E): the secret files' modes, the helper's sockets,
// the trusted proxies against this container's routes, the approval page at
// its public URL and the MCP endpoint without a token. Every row comes from
// a probe; what doctor cannot see is a NOTE that says so. It writes nothing
// and never sends the token anywhere.

// doctorEnv is what doctor reads from the machine besides the configuration:
// the routing tables and the interfaces' addresses. Tests replace it.
type doctorEnv struct {
	routeFile      string
	route6File     string
	interfaceAddrs func() ([]netip.Prefix, error)
	now            func() time.Time
}

func defaultDoctorEnv() doctorEnv {
	return doctorEnv{routeFile: "/proc/net/route", route6File: "/proc/net/ipv6_route", interfaceAddrs: interfacePrefixes, now: time.Now}
}

// interfacePrefixes are the addresses of this machine's (or container's)
// interfaces, each with its network's prefix length.
func interfacePrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := []netip.Prefix{}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		ones, _ := n.Mask.Size()
		if ok {
			out = append(out, netip.PrefixFrom(ip.Unmap(), ones))
		}
	}
	return out, nil
}

const (
	statusOK   = "ok"
	statusWarn = "WARN"
	statusFail = "FAIL"
	statusNote = "NOTE"

	doctorHTTPTimeout = 10 * time.Second
	// certWarnDays: a certificate closer to its end than this is a WARN.
	certWarnDays = 14
	// maxDoctorFile bounds what doctor reads from a file (routes, --ca-file).
	maxDoctorFile = 1 << 20
)

// The documents' sections each remedy names.
const (
	fixConfig  = `docs/ARCHITECTURE.md §5 lists every variable; the secrets: deploy/README.md, "Secrets"`
	fixInit    = `deploy/README.md, "Secrets"`
	fixProxies = "list only the proxy's own fixed address on the network it shares with the server (docs/CLIENTS.md §1)"
	fixCaddy   = "deploy/caddy/README.md"
)

type doctorRow struct {
	Status    string `json:"status"`
	Component string `json:"component"`
	Detail    string `json:"detail"`
	Fix       string `json:"fix,omitempty"`
}

type doctorReport struct {
	OK   bool        `json:"ok"`
	Rows []doctorRow `json:"rows"`
}

func (r *doctorReport) add(status, component, detail, fix string) {
	r.Rows = append(r.Rows, doctorRow{Status: status, Component: component, Detail: detail, Fix: fix})
	if status == statusFail {
		r.OK = false
	}
}

// cmdDoctor runs `shell-mcp doctor`.
func cmdDoctor(ctx context.Context, args []string, lookup config.LookupFunc, stdout, stderr io.Writer) int {
	return runDoctor(ctx, args, lookup, stdout, stderr, defaultDoctorEnv())
}

func runDoctor(ctx context.Context, args []string, lookup config.LookupFunc, stdout, stderr io.Writer, de doctorEnv) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "print the result as one JSON object")
	mcpURL := fs.String("mcp-url", "", "the MCP endpoint's public URL, https://<name>/mcp: checked without a token")
	caFile := fs.String("ca-file", "", "PEM file of the CA that signs the proxy's certificates (default: the system's roots)")
	fs.Usage = func() {
		_, _ = io.WriteString(stderr, `usage: shell-mcp doctor [--json] [--mcp-url https://<name>/mcp] [--ca-file <file>]

Runs check, then checks the secret files, the privileged helper's sockets, the
trusted proxies, the approval page and the MCP endpoint (without a token), and
names the step that fixes each failure. Run it in the server's container:
docker compose exec shell-mcp /shell-mcp doctor. Exit 1 on any FAIL.
`)
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	var mcp *url.URL
	if *mcpURL != "" {
		u, err := parseMCPURL(*mcpURL)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "shell-mcp: doctor: --mcp-url: %v\n", err)
			return 2
		}
		mcp = u
	}
	var roots *x509.CertPool
	if *caFile != "" {
		pool, err := readCAFile(*caFile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "shell-mcp: doctor: --ca-file: %v\n", err)
			return 2
		}
		roots = pool
	}

	rep := &doctorReport{OK: true, Rows: []doctorRow{}}
	cfg, err := config.Load(lookup)
	if err != nil {
		rep.add(statusFail, "configuration", "serve would refuse to start: "+err.Error(), fixConfig)
		return rep.write(*jsonOut, stdout, stderr)
	}
	rep.add(statusOK, "configuration", fmt.Sprintf("loaded as serve loads it: profile %s, %d target(s), approvals %s",
		cfg.Profile, len(cfg.Targets), approvalMethod(cfg)), "")
	statted := doctorSecrets(rep, lookup)
	for _, w := range cfg.Warnings {
		switch src, _, ok := strings.Cut(w, " is readable by group or other"); {
		case ok && slices.Contains(statted, src):
		case ok:
			rep.add(statusFail, "secret "+src, w, "chmod 0600, owned by the server's uid ("+fixInit+")")
		default:
			rep.add(statusWarn, "configuration", w, fixConfig)
		}
	}
	doctorTargets(ctx, rep, cfg, stderr)
	doctorProxies(rep, cfg, de)
	client := doctorClient(roots)
	doctorApproval(ctx, rep, cfg, client, de)
	doctorMCP(ctx, rep, mcp, client, de)
	return rep.write(*jsonOut, stdout, stderr)
}

func approvalMethod(cfg *config.Config) string {
	if cfg.ApprovalMethod == "" {
		return "none"
	}
	return cfg.ApprovalMethod
}

func (r *doctorReport) write(jsonOut bool, stdout, stderr io.Writer) int {
	if jsonOut {
		if code := writeJSON(r, stdout, stderr); code != 0 {
			return code
		}
	} else {
		fails, warns := 0, 0
		for _, row := range r.Rows {
			_, _ = fmt.Fprintf(stdout, "%-4s %s: %s\n", row.Status, row.Component, row.Detail)
			if row.Fix != "" {
				_, _ = fmt.Fprintf(stdout, "     fix: %s\n", row.Fix)
			}
			switch row.Status {
			case statusFail:
				fails++
			case statusWarn:
				warns++
			}
		}
		switch {
		case fails == 0 && warns == 0:
			_, _ = io.WriteString(stdout, "doctor: ok\n")
		case fails == 0:
			_, _ = fmt.Fprintf(stdout, "doctor: ok, %d WARN\n", warns)
		default:
			_, _ = fmt.Fprintf(stdout, "doctor: %d FAIL, %d WARN\n", fails, warns)
		}
	}
	if !r.OK {
		return 1
	}
	return 0
}

// doctorSecrets checks each secret file named by a *_FILE variable: a
// regular file, no group or other access (a FAIL here; serve only warns),
// owned by this process's uid. It returns the variables it checked.
func doctorSecrets(rep *doctorReport, lookup config.LookupFunc) []string {
	checked := []string{}
	for _, name := range []string{"SHELL_MCP_TOKEN_FILE", "SHELL_MCP_SSH_KEY_FILE", "SHELL_MCP_APPROVERS_FILE",
		"SHELL_MCP_APPROVAL_TLS_KEY_FILE", "SHELL_MCP_APPROVAL_NOTIFY_TOKEN_FILE"} {
		path, ok := lookup(name)
		if !ok || path == "" {
			continue
		}
		checked = append(checked, name)
		comp := "secret " + name
		fi, err := os.Stat(path)
		if err != nil {
			rep.add(statusWarn, comp, path+": cannot be read: "+err.Error(), fixInit)
			continue
		}
		mode := fmt.Sprintf("%04o", fi.Mode().Perm())
		uid, known := fileOwner(fi)
		owner := "owner unknown"
		if known {
			owner = "owner uid " + strconv.FormatUint(uint64(uid), 10)
		}
		switch {
		case !fi.Mode().IsRegular():
			rep.add(statusFail, comp, path+" is not a regular file", fixInit)
		case fi.Mode().Perm()&0o077 != 0:
			rep.add(statusFail, comp, fmt.Sprintf("%s: mode %s gives group or other access (%s)", path, mode, owner),
				"chmod 0600 "+path+" on the host, owned by the server's uid ("+fixInit+")")
		case known && int64(uid) != int64(os.Geteuid()):
			rep.add(statusWarn, comp, fmt.Sprintf("%s: mode %s, %s, not this process's uid %d", path, mode, owner, os.Geteuid()),
				"the secrets belong to the server's uid, 65532 in the image ("+fixInit+")")
		default:
			rep.add(statusOK, comp, fmt.Sprintf("%s: mode %s, %s (this process)", path, mode, owner), "")
		}
	}
	return checked
}

// doctorTargets runs check's probe per target and then the helper's
// sockets, each a read request.
func doctorTargets(ctx context.Context, rep *doctorReport, cfg *config.Config, stderr io.Writer) {
	logger := newLogger(cfg, stderr)
	pool, err := sshx.NewPool(cfg, sshx.Options{Logger: logger})
	if err != nil {
		rep.add(statusFail, "targets", err.Error(), fixConfig)
		return
	}
	defer pool.Close()
	d := &tools.Deps{
		Targets: cfg.Targets, Logger: logger, DefaultTimeout: cfg.DefaultTimeout,
		Opener: func(name string) (gateclient.Opener, bool) {
			c, ok := pool.Get(name)
			return c, ok
		},
		Gate: gateclient.New(gateclient.Options{Logger: logger}),
	}
	profile, perr := tools.ParseProfile(cfg.Profile)
	reg, rerr := tools.Catalogue(&tools.Deps{})
	if err := errors.Join(perr, rerr); err != nil {
		rep.add(statusFail, "targets", err.Error(), fixConfig)
		return
	}
	regs := reg.ToolsForProfile(profile, cfg.DisableTools)
	for _, t := range cfg.Targets {
		comp := "target " + t.Name
		res, e := tools.Probe(ctx, d, t.Name)
		if e != nil {
			rep.add(statusFail, comp, e.Code+": "+e.Message, targetFix(e.Code))
			continue
		}
		pin := ""
		if c, ok := pool.Get(t.Name); ok {
			pin = c.VerifiedHostKey()
		}
		served := tools.EffectiveTools(regs, res.Gate.MaxTier, res.Privileged.Enabled, res.Privileged.MaxTier)
		sb := res.Sandbox
		detail := fmt.Sprintf("host key verified (%s); gate %s, protocol %d, principal %s, policy sha256 %s, max_tier %s; "+
			"sandbox %s, Landlock ABI %d (kernel %d), applied %t; %d tools of profile %s",
			pin, res.Gate.Version, res.Gate.Protocol, res.Gate.Principal, res.Gate.PolicySHA256, res.Gate.MaxTier,
			sb.Mode, sb.EffectiveABI, sb.KernelABI, sb.Applied, len(served), cfg.Profile)
		if !sb.Applied || sb.Mode != "required" {
			rep.add(statusWarn, comp, detail, "the target's kernel needs Landlock ABI 4 (docs/TARGET-SETUP.md §0); best-effort is the policy's choice (docs/POLICY.md §4a)")
		} else {
			rep.add(statusOK, comp, detail, "")
		}
		doctorHelper(ctx, rep, d, t.Name, res.Privileged.Enabled)
	}
}

func targetFix(code string) string {
	switch code {
	case envelope.CodeHostKeyMismatch:
		return "pin the target's own host key: run shell-mcp-gate host-key on the target and set SHELL_MCP_TARGET_HOST_KEYS to what it prints " +
			"(docs/TARGET-SETUP.md §12.2); never pin what the network shows"
	case envelope.CodeAuthFailedSSH:
		return "the target did not accept this server's key: install ssh_key.pub with shell-mcp-gate install --key, with --from this server's address " +
			"as the target sees it (docs/TARGET-SETUP.md §12.1)"
	case envelope.CodeTargetUnreachable, envelope.CodeTimeout:
		return "check SHELL_MCP_TARGET_HOST and SHELL_MCP_TARGET_PORT, the network, and that sshd runs on the target (docs/TARGET-SETUP.md §7)"
	case envelope.CodeGateUnavailable:
		return "sshd ran the forced command and nothing answered: install the gate at /usr/local/bin/shell-mcp-gate (docs/TARGET-SETUP.md §3), " +
			"and read sshd's log on the target"
	case envelope.CodeProtocolMismatch:
		return "upgrade the side the message names: the server, the gate and the helper together (README.md, Upgrading)"
	case protocol.CodeInstallInsecure:
		return "on the target, shell-mcp-gate check-policy as the service account names the cause (docs/TARGET-SETUP.md §5, §12.1)"
	case protocol.CodeSandboxUnavailable:
		return "the target's kernel lacks Landlock ABI 4 (docs/TARGET-SETUP.md §0); best-effort is the policy's choice (docs/POLICY.md §4a)"
	}
	return "docs/TARGET-SETUP.md §10, and the gate's log on the target: journalctl -t shell-mcp-gate"
}

// doctorHelper probes the core socket (priv_policy) and then the broad one
// through a read operation the policy allows (handoff §4.E, §7 Q9).
func doctorHelper(ctx context.Context, rep *doctorReport, d *tools.Deps, target string, forwarding bool) {
	if !forwarding {
		rep.add(statusNote, "helper "+target, "privileged forwarding is off in this target's gate policy: no helper to probe", "")
		return
	}
	core, broad := "helper "+target+" core", "helper "+target+" broad"
	hp, e := tools.ProbeHelper(ctx, d, target)
	if e != nil {
		rep.add(statusFail, core, e.Code+": "+e.Message, helperFix(e.Code))
		rep.add(statusNote, broad, "not probed: the core socket did not answer, so the helper's policy (and the operation to send) is unknown", "")
		return
	}
	rep.add(statusOK, core, fmt.Sprintf("helper %s answered priv_policy on the core socket (unit %s), privileged policy sha256 %s",
		hp.Version, hp.Unit, hp.PolicySHA256), "")
	op, args, reason := tools.BroadProbeOp(hp.Summary)
	if op == "" {
		if reason != "" && strings.HasPrefix(reason, "not probed") {
			reason += "; the socket's state shows on the first broad call, and on the target in systemctl status shell-mcp-privd-broad.socket"
		}
		rep.add(statusNote, broad, reason, "")
		return
	}
	bp, e := tools.ProbeHelperBroad(ctx, d, target, op, args)
	if e != nil {
		rep.add(statusFail, broad, e.Code+": "+e.Message, helperFix(e.Code))
		return
	}
	what := op
	if b, err := json.Marshal(args); err == nil && string(b) != "{}" {
		what += " " + string(b)
	}
	detail := fmt.Sprintf("helper %s answered %s on the broad socket (unit %s); the broad unit logs every request it serves at WARN", bp.Version, what, bp.Unit)
	if bp.Refusal != nil {
		detail += fmt.Sprintf("; it refused the preview itself (%s: %s), which shows the socket works", bp.Refusal.Code, bp.Refusal.Message)
	}
	rep.add(statusOK, broad, detail, "")
}

func helperFix(code string) string {
	switch code {
	case protocol.CodeHelperUnavailable:
		return "the socket is not listening: run shell-mcp-privd install on the target (docs/TARGET-SETUP.md §12.3)"
	case protocol.CodeHelperRefused:
		return "the helper refused the gate's account: the privileged policy's client_uid must be the service account's uid, and the account a member of " +
			"its socket group (docs/TARGET-SETUP.md §12.3, §12.1)"
	case protocol.CodeHelperPolicyMismatch:
		return "the privileged policy changed since its units were generated: run shell-mcp-privd install --accept <its sha256> again " +
			"(docs/TARGET-SETUP.md §12.3)"
	case protocol.CodeProtocolMismatch:
		return "upgrade the side the message names: the server, the gate and the helper together (README.md, Upgrading), then shell-mcp-privd install " +
			"if the release notes change the units (docs/TARGET-SETUP.md §12.3)"
	case protocol.CodePrivilegedDisabled, protocol.CodeHelperWrongUnit:
		return "the gate policy's privileged section: socket /run/shell-mcp/privd.sock, broad_socket /run/shell-mcp/privd-broad.sock " +
			"(docs/TARGET-SETUP.md §9.5, §12.3)"
	}
	return "the helper's self-checks (docs/PRIVILEGED.md §7); on the target, journalctl -t shell-mcp-privd, then shell-mcp-privd install " +
		"(docs/TARGET-SETUP.md §12.3)"
}

// doctorProxies is CLIENTS §1's rule checked statically: each entry a
// single address on a network this container is attached to, and never
// one of its gateways. Whether the server then sees the real client is the
// log-line procedure, which doctor cannot run.
func doctorProxies(rep *doctorReport, cfg *config.Config, de doctorEnv) {
	if len(cfg.TrustedProxies) == 0 {
		rep.add(statusNote, "trusted proxies", "SHELL_MCP_TRUSTED_PROXIES is empty: X-Forwarded-For is never believed, so behind a proxy "+
			"every client shares the proxy's address for the rate limits and the lockout", "docs/CLIENTS.md §1")
		return
	}
	gws, gwErr := gateways(de)
	nets, ifErr := de.interfaceAddrs()
	for _, p := range cfg.TrustedProxies {
		name := p.String()
		if p.IsSingleIP() {
			name = p.Addr().String()
		}
		comp := "trusted proxy " + name
		gw := slices.IndexFunc(gws, p.Contains)
		switch {
		case gwErr != nil:
			rep.add(statusFail, comp, "this container's routing table could not be read ("+gwErr.Error()+"), so whether the entry is its network's gateway is unknown", fixProxies)
		case gw >= 0:
			rep.add(statusFail, comp, fmt.Sprintf("holds %s, a gateway of this container's network: anything that reaches the server through a port Docker "+
				"publishes can appear to come from the gateway and name any client it likes in X-Forwarded-For", gws[gw]), fixProxies)
		case !p.IsSingleIP():
			rep.add(statusWarn, comp, "a prefix, not a single address: every address in it is believed", fixProxies)
		case ifErr != nil:
			rep.add(statusWarn, comp, "this container's interfaces could not be read ("+ifErr.Error()+")", fixProxies)
		case !slices.ContainsFunc(nets, func(n netip.Prefix) bool { return n.Masked().Contains(p.Addr()) }):
			rep.add(statusWarn, comp, "not on a network this container is attached to, so no proxy at that address connects to the server directly", fixProxies)
		default:
			rep.add(statusOK, comp, "a single address on a network this container is attached to, and not its gateway", "")
		}
	}
	rep.add(statusNote, "trusted proxies", "checked statically; whether the server sees each client's own address is the log-line check, "+
		"run once through the proxy", "docs/CLIENTS.md §1; "+fixCaddy)
}

// gateways are the next hops of every route through a gateway, from the
// IPv4 table and, when the kernel has one, the IPv6 table.
func gateways(de doctorEnv) ([]netip.Addr, error) {
	b, err := readBounded(de.routeFile)
	if err != nil {
		return nil, err
	}
	out, err := parseRoute(b)
	if err != nil {
		return nil, err
	}
	b6, err := readBounded(de.route6File)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	} else if err != nil {
		return nil, err
	}
	v6, err := parseIPv6Route(b6)
	if err != nil {
		return nil, err
	}
	return append(out, v6...), nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: /proc's routing tables, or the --ca-file the operator names
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxDoctorFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDoctorFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxDoctorFile)
	}
	return b, nil
}

// rtfGateway is RTF_GATEWAY (linux/route.h, and ipv6_route's flags).
const rtfGateway = 0x0002

// parseRoute returns the gateways of /proc/net/route: a header line, then
// one route per line, Iface, Destination, Gateway and Flags first. The
// kernel prints the gateway as the 32-bit value in host byte order.
func parseRoute(b []byte) ([]netip.Addr, error) {
	lines := strings.Split(string(b), "\n")
	if !strings.HasPrefix(lines[0], "Iface") {
		return nil, errors.New("not a /proc/net/route table")
	}
	out := []netip.Addr{}
	for i, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 4 || len(f[2]) != 8 {
			return nil, fmt.Errorf("route line %d is malformed", i+2)
		}
		gw, err1 := strconv.ParseUint(f[2], 16, 32)
		flags, err2 := strconv.ParseUint(f[3], 16, 32)
		if err := errors.Join(err1, err2); err != nil {
			return nil, fmt.Errorf("route line %d is malformed", i+2)
		}
		if flags&rtfGateway == 0 {
			continue
		}
		var a [4]byte
		binary.NativeEndian.PutUint32(a[:], uint32(gw))
		if addr := netip.AddrFrom4(a); !addr.IsUnspecified() && !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	return out, nil
}

// parseIPv6Route returns the next hops of /proc/net/ipv6_route: per line
// the destination and its prefix length, the source and its prefix length,
// the next hop, metric, reference count, use, flags and the interface.
func parseIPv6Route(b []byte) ([]netip.Addr, error) {
	out := []netip.Addr{}
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 10 || len(f[4]) != 32 || len(f[8]) != 8 {
			return nil, fmt.Errorf("ipv6 route line %d is malformed", i+1)
		}
		hop, err1 := hex.DecodeString(f[4])
		flags, err2 := strconv.ParseUint(f[8], 16, 32)
		if err := errors.Join(err1, err2); err != nil {
			return nil, fmt.Errorf("ipv6 route line %d is malformed", i+1)
		}
		if flags&rtfGateway == 0 {
			continue
		}
		if addr := netip.AddrFrom16([16]byte(hop)); !addr.IsUnspecified() && !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	return out, nil
}

// --- HTTP probes --------------------------------------------------------------

func parseMCPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return nil, errors.New("must be an absolute http:// or https:// URL with a host and no user information, such as https://mcp.example.test/mcp")
	}
	return u, nil
}

func readCAFile(path string) (*x509.CertPool, error) {
	b, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("holds no PEM certificate")
	}
	return pool, nil
}

// doctorClient uses no proxy variables, follows no redirect, and trusts the
// system's roots or --ca-file's.
func doctorClient(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: doctorHTTPTimeout,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// answer is what a probe's request got.
type answer struct {
	status int
	header http.Header
	cert   string
	warn   bool
}

func doctorRequest(ctx context.Context, client *http.Client, method, u, body string, de doctorEnv) (*answer, error) {
	var rd io.Reader = http.NoBody
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	a := &answer{status: res.StatusCode, header: res.Header}
	if res.TLS != nil && len(res.TLS.PeerCertificates) > 0 {
		c := res.TLS.PeerCertificates[0]
		days := int(c.NotAfter.Sub(de.now()).Hours() / 24)
		a.cert = fmt.Sprintf("certificate valid for %s until %s (%d days)", req.URL.Hostname(), c.NotAfter.UTC().Format(time.DateOnly), days)
		a.warn = days < certWarnDays
	} else {
		a.cert = "no TLS (http://)"
	}
	return a, nil
}

// requestFailure is the row of a request that got no answer: a certificate
// that does not verify, or nothing reachable.
func requestFailure(rep *doctorReport, comp, host string, err error, fix string) {
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	if errors.As(err, &cv) || errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) {
		rep.add(statusFail, comp, "the certificate of "+host+" does not verify: "+err.Error(),
			"the proxy's TLS for that name ("+fixCaddy+"); a private CA: --ca-file")
		return
	}
	rep.add(statusFail, comp, "unreachable: "+err.Error(), fix)
}

// approvalPage reports whether h carries the approval page's own headers
// (internal/approval/page sets them on every response).
func approvalPage(h http.Header) bool {
	return strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") && h.Get("X-Frame-Options") == "DENY" &&
		strings.Contains(h.Get("Cache-Control"), "no-store")
}

const proxyRefused = "without the server's own headers: the proxy refused this container's address, so the server itself was not reached; " +
	"check from a LAN or VPN machine"

// doctorApproval fetches the approval page at its public URL (handoff
// §4.E).
func doctorApproval(ctx context.Context, rep *doctorReport, cfg *config.Config, client *http.Client, de doctorEnv) {
	const comp = "approval page"
	if cfg.ApprovalMethod != "web" {
		rep.add(statusNote, comp, "SHELL_MCP_APPROVAL_METHOD is "+approvalMethod(cfg)+": there is no approval page", "")
		return
	}
	u := cfg.ApprovalPublicURL + "/"
	host := strings.TrimPrefix(strings.TrimPrefix(cfg.ApprovalPublicURL, "https://"), "http://")
	fix := "the proxy forwards " + host + " to the server's approval port, 8081 by default (" + fixCaddy + "; docs/CLIENTS.md §3.2)"
	a, err := doctorRequest(ctx, client, http.MethodGet, u, "", de)
	switch {
	case err != nil:
		requestFailure(rep, comp, host, err, fix)
	case approvalPage(a.header) && a.status == http.StatusOK:
		status := statusOK
		if a.warn {
			status = statusWarn
		}
		rep.add(status, comp, "GET "+u+" answered 200 from the approval page; "+a.cert, "")
	case approvalPage(a.header) && a.status == http.StatusForbidden:
		rep.add(statusFail, comp, "the approval page answered 403: it serves only the proxies in SHELL_MCP_TRUSTED_PROXIES, and this request reached it from another address",
			"set SHELL_MCP_TRUSTED_PROXIES to the proxy's fixed address (docs/CLIENTS.md §1, §3.2)")
	case approvalPage(a.header) && a.status == http.StatusMisdirectedRequest:
		rep.add(statusFail, comp, "the approval page answered 421: it answers only for SHELL_MCP_APPROVAL_PUBLIC_URL's host, which the proxy must pass on",
			"docs/CLIENTS.md §3.2; "+fixCaddy)
	case approvalPage(a.header):
		rep.add(statusFail, comp, fmt.Sprintf("the approval page answered %d", a.status), "docs/CLIENTS.md §3.2")
	case a.status >= 300 && a.status < 400:
		rep.add(statusFail, comp, fmt.Sprintf("answered %d, a redirect to %q (not followed), without the approval page's headers", a.status, a.header.Get("Location")),
			"SHELL_MCP_APPROVAL_PUBLIC_URL is the page's own https:// origin, and the proxy serves the page there (docs/CLIENTS.md §3.2)")
	case a.status == http.StatusForbidden:
		rep.add(statusWarn, comp, "answered 403 "+proxyRefused+"; "+a.cert, fixCaddy+"; the curl of docs/CLIENTS.md §1")
	default:
		rep.add(statusFail, comp, fmt.Sprintf("answered %d without the approval page's headers (Content-Security-Policy frame-ancestors 'none', "+
			"X-Frame-Options DENY, Cache-Control no-store): another service answers on that name", a.status), fix)
	}
	rep.add(statusNote, comp+" reach", "doctor cannot show that the page is unreachable from outside your LAN or VPN: check that from outside", fixCaddy)
}

// doctorMCP sends one POST without a token to --mcp-url: it must answer
// 401 with the server's challenge (a request without a token does not
// count toward the lockout, ARCHITECTURE §3).
func doctorMCP(ctx context.Context, rep *doctorReport, u *url.URL, client *http.Client, de doctorEnv) {
	const comp = "mcp endpoint"
	if u == nil {
		rep.add(statusNote, comp, "not checked: give --mcp-url https://<the name clients use>/mcp", "")
		return
	}
	fix := "the proxy forwards " + u.Host + " to the server's port, 8080 by default (" + fixCaddy + ")"
	a, err := doctorRequest(ctx, client, http.MethodPost, u.String(), `{"jsonrpc":"2.0","id":1,"method":"ping"}`, de)
	switch {
	case err != nil:
		requestFailure(rep, comp, u.Hostname(), err, fix)
	case a.status == http.StatusUnauthorized && a.header.Get("WWW-Authenticate") == `Bearer realm="shell-mcp"`:
		status := statusOK
		if a.warn {
			status = statusWarn
		}
		rep.add(status, comp, "POST "+u.String()+" without a token answered 401 with the server's challenge; "+a.cert, "")
	case a.status == http.StatusUnauthorized:
		rep.add(statusFail, comp, `answered 401 without WWW-Authenticate: Bearer realm="shell-mcp": another service answers there`, fix)
	case a.status == http.StatusMisdirectedRequest:
		rep.add(statusFail, comp, "answered 421: "+u.Hostname()+" is missing from SHELL_MCP_ALLOWED_HOSTS", "add it to SHELL_MCP_ALLOWED_HOSTS (docs/CLIENTS.md §1)")
	case a.status == http.StatusForbidden:
		rep.add(statusWarn, comp, "answered 403 "+proxyRefused+"; "+a.cert, fixCaddy+"; the curl of docs/CLIENTS.md §1")
	case a.status == http.StatusTooManyRequests:
		rep.add(statusWarn, comp, "answered 429: rate limited or locked out", "docs/CLIENTS.md §7")
	case a.status >= 200 && a.status < 300:
		rep.add(statusFail, comp, fmt.Sprintf("answered %d to a request without a token: the endpoint is not behind the bearer token", a.status),
			"SHELL_MCP_AUTH_MODE=bearer (docs/SECURITY.md §3)")
	default:
		rep.add(statusFail, comp, fmt.Sprintf("answered %d", a.status), fix)
	}
}
