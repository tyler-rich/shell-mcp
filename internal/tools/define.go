package tools

import (
	"context"
	stdjson "encoding/json"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/envelope"
)

// spec describes one tool. Every tool is installed with the SDK's raw
// AddTool so that this package, not the SDK, decodes and validates the
// arguments: every failure, a malformed argument included, is an envelope
// with a code from the closed set, never a protocol error or free text.
type spec[In, Out any] struct {
	name, title, description string
	tier                     Tier
	// privileged: a shell_priv_* tool, forwarded to the host's privileged
	// helper (registered in the admin profile only).
	privileged bool
	// idempotent is the idempotentHint for operator tools; read tools are
	// always idempotent and destructive ones never.
	idempotent bool
	// schema adjusts the inferred input schema (descriptions are inferred
	// from the jsonschema tags; bounds are set here).
	schema func(*jsonschema.Schema)
	// audit returns the arguments that may be logged: ids, paths and unit
	// names only, never content.
	audit func(In) map[string]any
	// summary describes a success in one line for the text block: counts
	// and flags only, never a string that came from the host or the caller.
	summary func(*Out) string
	run     func(ctx context.Context, req *mcp.CallToolRequest, in In) envelope.Envelope[Out]

	// Approval (D-006), required for operator and destructive tools.
	// approvalArgs returns the canonical arguments: the typed input with
	// defaults applied, without the target (bound on its own, as resolved)
	// and without approval_id and confirm. describe is the one-line
	// description the approval page shows, generated from those arguments
	// and the resolved target. preview computes the preview from the gate's
	// read operations. precondition, when set, passes what the preview saw
	// to the operation (expected_sha256).
	approvalArgs func(In) any
	describe     func(in In, target string) string
	preview      func(ctx context.Context, in In, target string) (*preview, *envelope.Error)
	precondition func(in *In, p *preview)
	// tierFromPreview: whether a call needs approval follows the tier of
	// the operation its preview resolved (shell_run_command: the command's
	// tier), not the tool's; the operation then runs at that tier's
	// ceiling when approved, and at the highest tier that needs no
	// approval otherwise (perTierCall).
	tierFromPreview bool
	// precheck, when set, validates what needs the server's settings (its
	// timeout and output limits) before anything is sent.
	precheck func(in *In) *envelope.Error
}

// validator is implemented by inputs with checks beyond their types.
type validator interface {
	validate() *envelope.Error
}

func closedObject(s *jsonschema.Schema) {
	s.AdditionalProperties = &jsonschema.Schema{Not: &jsonschema.Schema{}}
}

// define builds the Tool for s. It panics only on a programming error in a
// tool's own types (caught by the tests and at startup).
func define[In, Out any](d *Deps, s spec[In, Out]) Tool {
	in, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("tools: %s: input schema: %v", s.name, err))
	}
	in.Type = "object"
	closedObject(in)
	if s.schema != nil {
		s.schema(in)
	}
	out, err := jsonschema.For[envelope.Envelope[Out]](nil)
	if err != nil {
		panic(fmt.Sprintf("tools: %s: output schema: %v", s.name, err))
	}
	canGate := gateable(s.tier)
	if canGate {
		if s.approvalArgs == nil || s.describe == nil || s.preview == nil {
			panic(fmt.Sprintf("tools: %s: a gateable tool needs approvalArgs, describe and preview", s.name))
		}
		approvalSchema(in, d.method() == approval.MethodConfirm)
	} else {
		delete(out.Properties, "approval")
	}
	def := &mcp.Tool{
		Name: s.name, Title: s.title, Description: s.description,
		Annotations: annotations(s.title, s.tier, s.idempotent), InputSchema: in, OutputSchema: out,
	}
	if canGate && d.gated(s.tier, s.privileged) {
		// Client-side defence in depth (handoff §3 a.2): Claude Code shows
		// the permission prompt on every call. The server cannot verify it.
		def.Meta = mcp.Meta{"anthropic/requiresUserInteraction": true}
	}
	handler := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		// Every gate request this call makes carries the tool's tier as its
		// ceiling.
		ctx = withCeiling(ctx, s.tier)
		var args In
		var env envelope.Envelope[Out]
		auditArgs := map[string]any{}
		raw := req.Params.Arguments
		var ap approvalInput
		var apErr *envelope.Error
		if canGate {
			raw, ap, apErr = splitApproval(raw, d.method() == approval.MethodConfirm)
		}
		decodeErr := decodeArgs(raw, &args)
		if decodeErr == nil && s.audit != nil {
			auditArgs = s.audit(args)
		}
		gated := canGate && d.gated(s.tier, s.privileged)
		var apOutcome approvalOutcome
		apID := ""
		switch {
		case gated && d.method() == approval.MethodNone && !s.tierFromPreview:
			// First: whatever the arguments, nothing is sent.
			env = envelope.Failure[Out]("", d.unavailable(s.tier))
		case apErr != nil:
			env = envelope.Failure[Out]("", apErr)
		case decodeErr != nil:
			env = envelope.Failure[Out]("", decodeErr)
		default:
			if v, ok := any(&args).(validator); ok {
				if e := v.validate(); e != nil {
					env = envelope.Failure[Out]("", e)
				}
			}
			if env.Error == nil && s.precheck != nil {
				if e := s.precheck(&args); e != nil {
					env = envelope.Failure[Out]("", e)
				}
			}
			switch {
			case env.Error != nil:
			case s.tierFromPreview:
				env, apOutcome, apID = perTierCall(ctx, d, s, req, args, ap)
			case gated:
				env, apOutcome, apID = approveCall(ctx, d, s, req, args, ap, nil)
			case ap.given:
				env = envelope.Failure[Out]("", envelope.Errorf(envelope.CodeValidationError,
					"this call needs no approval; call again without approval_id and confirm"))
			default:
				env = s.run(ctx, req, args)
			}
		}
		d.audit(ctx, s.name, env.Target, auditArgs, outcome(env.OK, env.Error), env.Exec, time.Since(start), apID, apOutcome)
		return result(env, summarize(env, s.summary))
	}
	return Tool{Def: def, Tier: s.tier, Install: func(srv *mcp.Server) { srv.AddTool(def, handler) }}
}

// decodeArgs strictly decodes the call's arguments: one JSON object of the
// input's fields with their types, no unknown or duplicate fields. Absent
// arguments are an empty object.
func decodeArgs(raw stdjson.RawMessage, v any) *envelope.Error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = stdjson.RawMessage("{}")
	}
	if raw.Kind() != '{' { // json.RawMessage is jsontext.Value (Go 1.27)
		return envelope.Errorf(envelope.CodeValidationError, "arguments must be a JSON object")
	}
	if err := json.Unmarshal(raw, v, json.RejectUnknownMembers(true)); err != nil {
		return envelope.Errorf(envelope.CodeValidationError, "arguments must be this tool's fields with their documented types (no other fields)")
	}
	return nil
}

func outcome(ok bool, e *envelope.Error) string {
	if ok {
		return "ok"
	}
	if e == nil {
		return "internal"
	}
	return e.Code
}

// summarize is the text block's first line: "ok: <summary>" or
// "error: <code>". It never carries host or caller text, so a client that
// shows only the first line shows nothing a host could have written.
func summarize[Out any](env envelope.Envelope[Out], f func(*Out) string) string {
	switch {
	case !env.OK && env.Error != nil:
		return "error: " + env.Error.Code
	case !env.OK:
		return "error: internal"
	case f == nil || env.Data == nil:
		return "ok"
	}
	return "ok: " + f(env.Data)
}

// result is the tool result: the envelope as structuredContent, and a text
// block of the summary line followed by the same JSON (clients that pass
// only text to the model still see the data); isError for a failure.
func result[Out any](env envelope.Envelope[Out], summary string) (*mcp.CallToolResult, error) {
	b, err := stdjson.Marshal(env)
	if err != nil {
		env = envelope.Failure[Out](env.Target, envelope.Errorf("internal", "the result could not be encoded"))
		summary = "error: internal"
		if b, err = stdjson.Marshal(env); err != nil {
			return nil, err
		}
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: summary + "\n" + string(b)}},
		StructuredContent: stdjson.RawMessage(b), // the SDK sends RawMessage unchanged
		IsError:           !env.OK,
	}, nil
}

// annotations per TOOLS.md: read → read-only, not destructive, idempotent,
// open world; operator → not read-only, not destructive, idempotent per
// tool, open world; destructive → destructive, not idempotent, open world.
func annotations(title string, tier Tier, idempotent bool) *mcp.ToolAnnotations {
	t, f := true, false
	a := &mcp.ToolAnnotations{Title: title, OpenWorldHint: &t}
	switch tier {
	case TierRead:
		a.ReadOnlyHint, a.DestructiveHint, a.IdempotentHint = true, &f, true
	case TierOperator:
		a.DestructiveHint, a.IdempotentHint = &f, idempotent
	case TierDestructive:
		a.DestructiveHint = &t
	}
	return a
}

// audit writes the one JSON line per tool call (S-11): principal, target,
// tool, sanitized arguments, outcome code, exit code and duration. It never
// carries tokens, keys, content, output, stdin or environment values.
func (d *Deps) audit(ctx context.Context, tool, target string, args map[string]any, outcome string, exec *envelope.Exec, dur time.Duration,
	approvalID string, approvalOut approvalOutcome) {
	logger := d.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	for k, v := range args {
		if s, ok := v.(string); ok && len(s) > maxAuditValue {
			args[k] = s[:maxAuditValue]
		}
	}
	var exit any
	if exec != nil && exec.ExitCode != nil {
		exit = *exec.ExitCode
	}
	attrs := []slog.Attr{
		slog.String("principal", d.Principal.Name), slog.String("target", target), slog.String("tool", tool),
		slog.Any("args", args), slog.String("outcome", outcome), slog.Any("exit_code", exit),
		slog.Int64("duration_ms", dur.Milliseconds()),
	}
	if approvalOut != "" {
		attrs = append(attrs, slog.String("approval_id", approvalID), slog.String("approval_outcome", string(approvalOut)))
	}
	logger.LogAttrs(ctx, slog.LevelInfo, "tool call", attrs...)
}

// maxAuditValue bounds a logged argument (SECURITY §2, log injection).
const maxAuditValue = 512
