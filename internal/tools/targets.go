package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
)

type noArgs struct{}

type targetsData struct {
	Targets []targetInfo `json:"targets" jsonschema:"The configured targets, in configuration order."`
}

type targetInfo struct {
	Name string `json:"name" jsonschema:"Target name, used as the target argument of other tools."`
	Host string `json:"host" jsonschema:"SSH host name or IP address as configured."`
	Port int    `json:"port" jsonschema:"SSH port."`
	User string `json:"user" jsonschema:"SSH user on the target."`
}

// listTargets is server-only: it reports the configuration and contacts
// nothing.
func listTargets(d *Deps) Tool {
	return define(d, spec[noArgs, targetsData]{
		name:        "shell_list_targets",
		title:       "List targets",
		description: "Lists the configured SSH targets with their name, host, port and user, without contacting them.",
		tier:        TierRead,
		run: func(context.Context, *mcp.CallToolRequest, noArgs) envelope.Envelope[targetsData] {
			out := targetsData{Targets: make([]targetInfo, 0, len(d.Targets))}
			for _, t := range d.Targets {
				out.Targets = append(out.Targets, targetInfo{Name: t.Name, Host: t.Host, Port: t.Port, User: t.User})
			}
			return envelope.Success("", out)
		},
	})
}
