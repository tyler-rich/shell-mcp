package main

import (
	"context"
	"flag"
	"io"
	"net/netip"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/config"
)

// doctorEnv is what doctor reads from the machine besides the configuration:
// the routing tables and the interfaces' addresses. Tests replace it.
type doctorEnv struct {
	routeFile      string
	route6File     string
	interfaceAddrs func() ([]netip.Prefix, error)
	now            func() time.Time
}

func defaultDoctorEnv() doctorEnv {
	return doctorEnv{routeFile: "/proc/net/route", route6File: "/proc/net/ipv6_route", now: time.Now}
}

// cmdDoctor runs `shell-mcp doctor`.
func cmdDoctor(ctx context.Context, args []string, lookup config.LookupFunc, stdout, stderr io.Writer) int {
	return runDoctor(ctx, args, lookup, stdout, stderr, defaultDoctorEnv())
}

func runDoctor(_ context.Context, args []string, _ config.LookupFunc, _, stderr io.Writer, _ doctorEnv) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	_ = fs.Bool("json", false, "print the result as one JSON object")
	_ = fs.String("mcp-url", "", "the MCP endpoint's public URL")
	_ = fs.String("ca-file", "", "PEM file of the CA that signs the proxy's certificates")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	return 0
}

// parseRoute returns the gateways of /proc/net/route.
func parseRoute([]byte) ([]netip.Addr, error) { return nil, nil }

// parseIPv6Route returns the next hops of /proc/net/ipv6_route.
func parseIPv6Route([]byte) ([]netip.Addr, error) { return nil, nil }
