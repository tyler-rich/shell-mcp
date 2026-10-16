// Command shell-mcp is the MCP server: it authenticates MCP clients, exposes
// the tools of its profile and forwards operations over SSH to
// shell-mcp-gate on each target.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/auth"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/gateclient"
	"github.com/tyler-rich/shell-mcp/internal/redact"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
	"github.com/tyler-rich/shell-mcp/internal/tools"
	"github.com/tyler-rich/shell-mcp/internal/transport"
)

// Set with -ldflags "-X main.version=… -X main.commit=…".
var (
	version = "dev"
	commit  = "dev"
)

const (
	healthcheckTimeout = 3 * time.Second
	shutdownTimeout    = 10 * time.Second
	// maxStdioLine bounds one JSON-RPC message on stdio, like the HTTP body cap.
	maxStdioLine = transport.MaxBodyBytes
)

const usage = `usage: shell-mcp <command> [flags]

commands:
  serve        start the MCP server (HTTP, or stdio with --transport stdio)
  check        connect to every target, verify its host key and gate, and print the result
  tools        print the tool catalogue (with schema hashes)
  healthcheck  exit 0 if the local /healthz answers {"status":"ok"}
  version      print version information
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Stdin, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, stdin io.Reader, args []string, lookup config.LookupFunc, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdServe(ctx, args[1:], lookup, stdin, stdout, stderr)
	case "check":
		return cmdCheck(ctx, args[1:], lookup, stdout, stderr)
	case "tools":
		return cmdTools(args[1:], stdout, stderr)
	case "healthcheck":
		url, err := healthcheckURL(lookup)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "shell-mcp: %v\n", err)
			return 1
		}
		return healthcheck(ctx, url)
	case "version":
		diag := ""
		if tools.DiagBuild {
			diag = ", diagnostic build: not for release"
		}
		_, _ = fmt.Fprintf(stdout, "shell-mcp %s (commit %s, %s%s)\n", version, commit, runtime.Version(), diag)
		return 0
	case "-h", "--help", "help":
		_, _ = io.WriteString(stdout, usage)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "shell-mcp: unknown command %q\n%s", args[0], usage)
	return 2
}

func loadConfig(lookup config.LookupFunc, stderr io.Writer) (*config.Config, bool) {
	cfg, err := config.Load(lookup)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp: invalid configuration: %v\n", err)
		return nil, false
	}
	return cfg, true
}

func cmdServe(ctx context.Context, args []string, lookup config.LookupFunc, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	transportFlag := fs.String("transport", "", "override SHELL_MCP_TRANSPORT (http or stdio)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	if *transportFlag != "" {
		base := lookup
		lookup = func(k string) (string, bool) {
			if k == "SHELL_MCP_TRANSPORT" {
				return *transportFlag, true
			}
			return base(k)
		}
	}

	cfg, ok := loadConfig(lookup, stderr)
	if !ok {
		return 1
	}
	logger := newLogger(cfg, stderr)
	for _, w := range cfg.Warnings {
		logger.Warn(w)
	}
	if tools.DiagBuild {
		logger.Warn("diagnostic build: carries shell_diag_elicit; not for release")
	}

	if cfg.Transport == "stdio" {
		server, cleanup, err := newMCPServer(cfg, logger)
		if err != nil {
			logger.Error("refusing to start", "reason", err.Error())
			return 1
		}
		defer cleanup()
		logger.Info("serving MCP over stdio", "profile", cfg.Profile)
		t := &mcp.IOTransport{Reader: readCloser{stdin}, Writer: nopWriteCloser{stdout}, MaxLineLength: maxStdioLine}
		if runErr := server.Run(ctx, t); runErr != nil && !errors.Is(runErr, context.Canceled) && !errors.Is(runErr, io.EOF) {
			logger.Error("stdio transport stopped", "error", runErr.Error())
			return 1
		}
		return 0
	}

	srv, cleanup, err := newHTTPServer(cfg, logger)
	if err != nil {
		logger.Error("refusing to start", "reason", err.Error())
		return 1
	}
	defer cleanup()
	return serveHTTP(ctx, srv, logger)
}

// readCloser and nopWriteCloser adapt the process's stdin and stdout; the
// transport's MaxLineLength bounds each inbound message.
type readCloser struct{ r io.Reader }

func (r readCloser) Read(p []byte) (int, error) { return r.r.Read(p) }
func (r readCloser) Close() error {
	if c, ok := r.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

type nopWriteCloser struct{ w io.Writer }

func (w nopWriteCloser) Write(p []byte) (int, error) { return w.w.Write(p) }
func (nopWriteCloser) Close() error                  { return nil }

// newHTTPServer builds the HTTP server: the middleware chain in front of the
// SDK's stateless Streamable HTTP handler.
func newHTTPServer(cfg *config.Config, logger *slog.Logger) (*http.Server, func(), error) {
	server, cleanup, err := newMCPServer(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	srv, err := transport.New(cfg, mcpHTTPHandler(server, logger), &transport.Options{Logger: logger})
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return srv, cleanup, nil
}

// mcpHTTPHandler serves MCP as stateless Streamable HTTP with JSON responses
// (D-014): no sessions, no server-initiated streams.
func mcpHTTPHandler(server *mcp.Server, logger *slog.Logger) http.Handler {
	return mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: transport.MaxBodyBytes, Logger: logger},
	)
}

// newDeps builds what the tools need: one SSH client per target and the
// gate client. cleanup closes the SSH clients.
func newDeps(cfg *config.Config, logger *slog.Logger) (*tools.Deps, func(), error) {
	pool, err := sshx.NewPool(cfg, sshx.Options{Logger: logger})
	if err != nil {
		return nil, nil, err
	}
	principal := auth.Principal{Name: auth.PrincipalBearer, Profile: cfg.Profile}
	if cfg.AuthMode == "none" {
		principal.Name = auth.PrincipalUnauthenticated
	}
	d := &tools.Deps{
		Targets:       cfg.Targets,
		DefaultTarget: cfg.DefaultTarget,
		Opener: func(name string) (gateclient.Opener, bool) {
			c, ok := pool.Get(name)
			return c, ok
		},
		Gate:           gateclient.New(gateclient.Options{Logger: logger}),
		Principal:      principal,
		Logger:         logger,
		DefaultTimeout: cfg.DefaultTimeout,
		MaxTimeout:     cfg.MaxTimeout,
		MaxOutputBytes: cfg.MaxOutputBytes,
		Redactor:       redact.New(cfg.RedactPatterns),
		ApprovalTiers:  cfg.ApprovalTiers,
	}
	return d, pool.Close, nil
}

// newMCPServer registers, once, the tools of the configured profile minus
// SHELL_MCP_DISABLE_TOOLS (D-005). Nothing registers a tool later.
func newMCPServer(cfg *config.Config, logger *slog.Logger) (*mcp.Server, func(), error) {
	profile, err := tools.ParseProfile(cfg.Profile)
	if err != nil {
		return nil, nil, err
	}
	d, cleanup, err := newDeps(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	reg, err := tools.Catalogue(d)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "shell-mcp", Version: version}, nil)
	for _, r := range reg.ToolsForProfile(profile, cfg.DisableTools) {
		r.Tool.Install(server)
	}
	return server, cleanup, nil
}

func serveHTTP(ctx context.Context, srv *http.Server, logger *slog.Logger) int {
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	logger.Info("serving MCP over HTTP", "addr", srv.Addr)

	select {
	case err := <-errc:
		logger.Error("HTTP server stopped", "error", err.Error())
		return 1
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown", "error", err.Error())
		return 1
	}
	return 0
}

func newLogger(cfg *config.Config, w io.Writer) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

// checkReport is the output of `shell-mcp check`.
type checkReport struct {
	OK      bool             `json:"ok"`
	Config  config.Effective `json:"config"`
	Targets []targetCheck    `json:"targets"`
}

type targetCheck struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	OK      bool   `json:"ok"`
	HostKey string `json:"host_key_verified,omitempty"`
	*tools.ProbeResult
	// Tools are the profile's tools this target's gate can serve (by its
	// max_tier and privileged forwarding).
	Tools []string        `json:"tools,omitempty"`
	Error *envelope.Error `json:"error,omitempty"`
}

// cmdCheck connects to every target, verifies its host key, calls the
// gate's hello and prints what it found. It exits 1 if any target fails.
func cmdCheck(ctx context.Context, args []string, lookup config.LookupFunc, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		_, _ = io.WriteString(stderr, "shell-mcp: check takes no arguments\n")
		return 2
	}
	cfg, ok := loadConfig(lookup, stderr)
	if !ok {
		return 1
	}
	logger := newLogger(cfg, stderr)
	pool, err := sshx.NewPool(cfg, sshx.Options{Logger: logger})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp: %v\n", err)
		return 1
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
	profile, err := tools.ParseProfile(cfg.Profile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp: %v\n", err)
		return 1
	}
	reg, err := tools.Catalogue(&tools.Deps{})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp: %v\n", err)
		return 1
	}
	regs := reg.ToolsForProfile(profile, cfg.DisableTools)

	report := checkReport{OK: true, Config: cfg.Effective(), Targets: []targetCheck{}}
	for _, t := range cfg.Targets {
		tc := targetCheck{Name: t.Name, Host: t.Host, Port: t.Port, User: t.User}
		res, e := tools.Probe(ctx, d, t.Name)
		if c, ok := pool.Get(t.Name); ok && e == nil {
			tc.HostKey = c.VerifiedHostKey()
		}
		if e != nil {
			tc.Error = e
			report.OK = false
		} else {
			tc.OK, tc.ProbeResult = true, res
			tc.Tools = tools.EffectiveTools(regs, res.Gate.MaxTier, res.Privileged.Enabled)
		}
		report.Targets = append(report.Targets, tc)
	}
	if code := writeJSON(report, stdout, stderr); code != 0 {
		return code
	}
	if !report.OK {
		return 1
	}
	return 0
}

// catalogueEntry is one row of `shell-mcp tools`. The schema hashes are the
// SHA-256 of each schema's canonical JSON (object keys sorted), so any
// change to a tool's contract changes the catalogue.
type catalogueEntry struct {
	Name               string               `json:"name"`
	Title              string               `json:"title"`
	Tier               string               `json:"tier"`
	Privileged         bool                 `json:"privileged"`
	Annotations        *mcp.ToolAnnotations `json:"annotations"`
	Description        string               `json:"description"`
	InputSchemaSHA256  string               `json:"input_schema_sha256"`
	OutputSchemaSHA256 string               `json:"output_schema_sha256"`
}

func cmdTools(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		_, _ = io.WriteString(stderr, "shell-mcp: tools takes no arguments\n")
		return 2
	}
	reg, err := tools.Catalogue(&tools.Deps{})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp: %v\n", err)
		return 1
	}
	entries := []catalogueEntry{}
	for _, r := range reg.ToolsForProfile(tools.ProfileAdmin, nil) {
		def := r.Tool.Def
		in, err1 := schemaHash(def.InputSchema)
		out, err2 := schemaHash(def.OutputSchema)
		if err := errors.Join(err1, err2); err != nil {
			_, _ = fmt.Fprintf(stderr, "shell-mcp: %s: %v\n", def.Name, err)
			return 1
		}
		entries = append(entries, catalogueEntry{
			Name: def.Name, Title: def.Title, Tier: r.Tier.String(), Privileged: r.Privileged,
			Annotations: def.Annotations, Description: def.Description, InputSchemaSHA256: in, OutputSchemaSHA256: out,
		})
	}
	return writeJSON(entries, stdout, stderr)
}

// schemaHash is the SHA-256 of v's canonical JSON: marshalled, decoded into
// generic values and marshalled again, which sorts every object's keys.
func schemaHash(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var generic any
	if uerr := json.Unmarshal(b, &generic); uerr != nil {
		return "", uerr
	}
	if b, err = json.Marshal(generic); err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func writeJSON(v any, stdout, stderr io.Writer) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp: %v\n", err)
		return 1
	}
	_, _ = stdout.Write(append(b, '\n'))
	return 0
}

// healthcheckURL returns the loopback /healthz URL for SHELL_MCP_PORT. It
// reads nothing else, so the healthcheck never touches secrets.
func healthcheckURL(lookup config.LookupFunc) (string, error) {
	port := 8080
	if v, ok := lookup("SHELL_MCP_PORT"); ok {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return "", fmt.Errorf("SHELL_MCP_PORT must be an integer between 1 and 65535 (got %q)", v)
		}
		port = p
	}
	return "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + transport.HealthzPath, nil
}

var healthyBody = []byte(`{"status":"ok"}`)

// healthcheck returns 0 only for status 200 with body exactly
// {"status":"ok"}. It uses no proxy and follows no redirects.
func healthcheck(ctx context.Context, url string) int {
	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return 1
	}
	client := &http.Client{
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := client.Do(req)
	if err != nil {
		return 1
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, int64(len(healthyBody))+1))
	if err != nil || res.StatusCode != http.StatusOK || !bytes.Equal(body, healthyBody) {
		return 1
	}
	return 0
}
