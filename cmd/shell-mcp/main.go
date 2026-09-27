// Command shell-mcp is the MCP server: it authenticates MCP clients, exposes
// the tools of its profile and forwards operations over SSH to
// shell-mcp-gate on each target.
package main

import (
	"bytes"
	"context"
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

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/tools"
	"github.com/tyler-rich/shell-mcp/internal/transport"
)

// Set with -ldflags "-X main.version=… -X main.commit=…".
var (
	version = "dev"
	commit  = "dev"
)

const (
	maxRequestBodyBytes = 1 << 20
	healthcheckTimeout  = 3 * time.Second
	shutdownTimeout     = 10 * time.Second
)

const usage = `usage: shell-mcp <command> [flags]

commands:
  serve        start the MCP server (HTTP, or stdio with --transport stdio)
  check        validate the configuration and print it with secrets masked
  tools        print the tool catalogue
  healthcheck  exit 0 if the local /healthz answers {"status":"ok"}
  version      print version information
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, lookup config.LookupFunc, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdServe(ctx, args[1:], lookup, stderr)
	case "check":
		return cmdCheck(args[1:], lookup, stdout, stderr)
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
		_, _ = fmt.Fprintf(stdout, "shell-mcp %s (commit %s, %s)\n", version, commit, runtime.Version())
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

func cmdServe(ctx context.Context, args []string, lookup config.LookupFunc, stderr io.Writer) int {
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
	if cfg.AuthMode != "none" {
		logger.Error("refusing to start", "reason", transport.ErrBearerNotImplemented.Error())
		return 1
	}

	server, err := newMCPServer(cfg)
	if err != nil {
		logger.Error("refusing to start", "reason", err.Error())
		return 1
	}

	if cfg.Transport == "stdio" {
		logger.Info("serving MCP over stdio", "profile", cfg.Profile)
		if runErr := server.Run(ctx, &mcp.StdioTransport{}); runErr != nil && !errors.Is(runErr, context.Canceled) {
			logger.Error("stdio transport stopped", "error", runErr.Error())
			return 1
		}
		return 0
	}

	srv, err := transport.New(cfg, mcpHTTPHandler(server, logger))
	if err != nil {
		logger.Error("refusing to start", "reason", err.Error())
		return 1
	}
	return serveHTTP(ctx, srv, logger)
}

// mcpHTTPHandler serves MCP as stateless Streamable HTTP with JSON responses
// (D-014): no sessions, no server-initiated streams.
func mcpHTTPHandler(server *mcp.Server, logger *slog.Logger) http.Handler {
	return mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: maxRequestBodyBytes, Logger: logger},
	)
}

func newMCPServer(cfg *config.Config) (*mcp.Server, error) {
	profile, err := tools.ParseProfile(cfg.Profile)
	if err != nil {
		return nil, err
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "shell-mcp", Version: version}, nil)
	for _, reg := range tools.NewRegistry().ToolsForProfile(profile, cfg.DisableTools) {
		reg.Tool.Install(server)
	}
	return server, nil
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

func cmdCheck(args []string, lookup config.LookupFunc, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		_, _ = io.WriteString(stderr, "shell-mcp: check takes no arguments\n")
		return 2
	}
	cfg, ok := loadConfig(lookup, stderr)
	if !ok {
		return 1
	}
	return writeJSON(cfg.Effective(), stdout, stderr)
}

// catalogueEntry is one row of the `tools` catalogue. Session 2 adds the
// description and schema hashes.
type catalogueEntry struct {
	Name       string `json:"name"`
	Tier       string `json:"tier"`
	Privileged bool   `json:"privileged"`
}

func cmdTools(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		_, _ = io.WriteString(stderr, "shell-mcp: tools takes no arguments\n")
		return 2
	}
	entries := []catalogueEntry{}
	for _, reg := range tools.NewRegistry().ToolsForProfile(tools.ProfileAdmin, nil) {
		entries = append(entries, catalogueEntry{Name: reg.Tool.Def.Name, Tier: reg.Tier.String(), Privileged: reg.Privileged})
	}
	return writeJSON(entries, stdout, stderr)
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
