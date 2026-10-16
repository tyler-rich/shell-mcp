//go:build shellmcp_diag

package tools

import (
	"context"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
)

// DiagBuild reports whether this binary carries the elicitation diagnostic
// tool (build tag shellmcp_diag). Release builds and CI's image never do.
const DiagBuild = true

// The diagnostic asks one harmless yes/no question through MCP elicitation
// and reports what the client did, so the maintainer can see, per client,
// whether the approval flow of D-006 can work. Nothing runs either way.
const (
	diagInputID = "diag"
	diagState   = "shell-mcp-diag-v1"
	diagMessage = "shell-mcp elicitation diagnostic: answer yes or no. Nothing runs either way."
)

// DiagData is shell_diag_elicit's data.
type DiagData struct {
	Round               int    `json:"round" jsonschema:"1: the first call (a question was asked, or could not be); 2: the call retried with the client's answer."`
	ProtocolVersion     string `json:"protocol_version" jsonschema:"The protocol revision of this request."`
	ClientName          string `json:"client_name" jsonschema:"The client's declared name."`
	ClientVersion       string `json:"client_version" jsonschema:"The client's declared version."`
	ElicitationDeclared bool   `json:"elicitation_declared" jsonschema:"Whether the client declared the elicitation capability."`
	FormDeclared        bool   `json:"form_declared" jsonschema:"Whether it declared form mode."`
	URLDeclared         bool   `json:"url_declared" jsonschema:"Whether it declared URL mode."`
	Action              string `json:"action,omitempty" jsonschema:"The user's action: accept, decline or cancel."`
	Answer              *bool  `json:"answer,omitempty" jsonschema:"The yes/no answer, when accepted."`
	RequestStateEchoed  bool   `json:"request_state_echoed" jsonschema:"Whether the retry carried the request state unchanged."`
	Note                string `json:"note" jsonschema:"What this means for approvals."`
}

func registerDiag(r *Registry, d *Deps) error {
	in := &jsonschema.Schema{Type: "object", Properties: map[string]*jsonschema.Schema{}}
	closedObject(in)
	out, err := jsonschema.For[envelope.Envelope[DiagData]](nil)
	if err != nil {
		return err
	}
	def := &mcp.Tool{
		Name:        "shell_diag_elicit",
		Title:       "Elicitation diagnostic",
		Description: "Asks a harmless yes/no question through MCP elicitation and reports whether the client asked the user and what came back.",
		Annotations: annotations("Elicitation diagnostic", TierRead, true),
		InputSchema: in, OutputSchema: out,
	}
	handler := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		res, env := diagRound(req)
		d.audit(ctx, def.Name, "", map[string]any{}, "ok", nil, time.Since(start))
		if res != nil {
			return res, nil
		}
		return result(env)
	}
	return r.Register(Tool{Def: def, Install: func(s *mcp.Server) { s.AddTool(def, handler) }}, TierRead, false)
}

// diagRound returns either the input-required result (first round, client
// declared elicitation) or the envelope to send.
func diagRound(req *mcp.CallToolRequest) (*mcp.CallToolResult, envelope.Envelope[DiagData]) {
	data := DiagData{Round: 1, ProtocolVersion: req.ProtocolVersion()}
	if ci := req.ClientInfo(); ci != nil {
		data.ClientName, data.ClientVersion = ci.Name, ci.Version
	}
	if caps := req.ClientCapabilities(); caps != nil && caps.Elicitation != nil {
		data.ElicitationDeclared = true
		data.FormDeclared = caps.Elicitation.Form != nil
		data.URLDeclared = caps.Elicitation.URL != nil
	}
	if resp, ok := req.Params.InputResponses[diagInputID]; ok {
		data.Round = 2
		data.RequestStateEchoed = req.Params.RequestState == diagState
		if er, ok := resp.(*mcp.ElicitResult); ok {
			data.Action = er.Action
			if b, ok := er.Content["answer"].(bool); ok && er.Action == "accept" {
				data.Answer = &b
			}
		}
		data.Note = "the client asked the user and returned the answer: approvals through elicitation can work with this client"
		return nil, envelope.Success("", data)
	}
	if !data.ElicitationDeclared {
		data.Note = "the client did not declare elicitation on this request: approvals would be refused with approval_unavailable"
		return nil, envelope.Success("", data)
	}
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"answer": map[string]any{"type": "boolean", "title": "Yes or no", "description": "Any answer is fine; nothing runs."},
		},
		"required": []string{"answer"},
	}
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{diagInputID: &mcp.ElicitParams{Mode: "form", Message: diagMessage, RequestedSchema: schema}},
		RequestState:  diagState,
	}, envelope.Envelope[DiagData]{}
}
