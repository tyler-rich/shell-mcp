package tools

import (
	"context"
	"strconv"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The power tools (docs/TOOLS.md, privileged tier: power; handoff
// docs/handoff/S4C-PRIVILEGED.md S4c-8: P-2f, P-3, P-13).
// shell_priv_reboot_host (destructive, always approval-gated) uses the
// helper's priv_power_preview (the action, the unit logind will start and
// the delay) as its approval preview, bound with both policies' hashes, and
// the re-call sends priv_power with the fresh preview's preview_sha256. The
// helper answers first and asks logind after the delay (PRIVILEGED §6,
// "Power"). shell_priv_cancel_power (read tier, so never gated, though it
// changes the host) sends priv_power_cancel. Admin profile only.

// PowerAction is shell_priv_reboot_host's data.
type PowerAction struct {
	Action       string `json:"action" jsonschema:"reboot or poweroff."`
	TargetUnit   string `json:"target_unit" jsonschema:"The unit logind will start: reboot.target or poweroff.target."`
	ScheduledAt  string `json:"scheduled_at" jsonschema:"When the action will be requested from logind, in UTC (RFC 3339)."`
	DelaySeconds int64  `json:"delay_seconds" jsonschema:"Seconds between this answer and the request."`
	Cancel       string `json:"cancel" jsonschema:"How to stop the action before scheduled_at."`
}

// PowerCancel is shell_priv_cancel_power's data.
type PowerCancel struct {
	Cancelled   bool   `json:"cancelled" jsonschema:"True: the action will not be requested."`
	RequestID   string `json:"request_id" jsonschema:"The request id of the cancelled action, as in the helper's journal."`
	Action      string `json:"action" jsonschema:"reboot or poweroff."`
	ScheduledAt string `json:"scheduled_at" jsonschema:"When it would have been requested, in UTC (RFC 3339)."`
}

type privRebootIn struct {
	targetArg
	Action          string `json:"action" jsonschema:"reboot or poweroff."`
	expectedPreview string
}

func (in *privRebootIn) validate() *envelope.Error {
	if in.Action != "reboot" && in.Action != "poweroff" {
		return invalid("action must be reboot or poweroff")
	}
	return nil
}

type privCancelPowerIn struct {
	targetArg
}

type powerActionWire struct {
	Action string `json:"action"`
}

type powerBoundWire struct {
	Action                string `json:"action"`
	ExpectedPreviewSHA256 string `json:"expected_preview_sha256"`
}

type powerPreviewWire struct {
	Action        string `json:"action"`
	Target        string `json:"target"`
	DelayS        int64  `json:"delay_s"`
	PolicySHA256  string `json:"policy_sha256"`
	PreviewSHA256 string `json:"preview_sha256"`
}

type powerResultWire struct {
	Action      string `json:"action"`
	Target      string `json:"target"`
	ScheduledAt string `json:"scheduled_at"`
	DelayS      int64  `json:"delay_s"`
	Cancel      string `json:"cancel"`
}

// powerVerb is the action as the descriptions say it.
var powerVerb = map[string]string{"reboot": "reboot", "poweroff": "power off"}

func privRebootHost(d *Deps) Tool {
	return define(d, spec[privRebootIn, PowerAction]{
		name: "shell_priv_reboot_host", title: "Reboot or power off as root",
		description: "Reboots or powers off the host as root: answers at once with the time the action will be requested from logind, 60 seconds later, unless it is cancelled, or blocked by a package operation or an inhibitor lock, first.",
		tier:        TierDestructive, privileged: true,
		schema: func(s *jsonschema.Schema) {
			boundCommon(s)
			enumIn(s, "action", "reboot", "poweroff")
		},
		audit: func(in privRebootIn) map[string]any { return map[string]any{"target": in.Target, "action": in.Action} },
		summary: func(r *PowerAction) string {
			return "as root: " + powerVerb[r.Action] + " scheduled in " + strconv.FormatInt(r.DelaySeconds, 10) + " s"
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privRebootIn) envelope.Envelope[PowerAction] {
			if in.expectedPreview == "" {
				return envelope.Failure[PowerAction](in.Target, envelope.Errorf("internal", "a power action needs the hash of an approved preview; nothing was sent"))
			}
			r := fetch[powerResultWire](ctx, d, in.Target, protocol.OpPrivPower, powerBoundWire{Action: in.Action, ExpectedPreviewSHA256: in.expectedPreview}, d.budget())
			if !r.OK {
				return envelope.Failure[PowerAction](r.Target, r.Error)
			}
			x := r.Data
			if x.Action != in.Action || x.Target != in.Action+".target" || x.ScheduledAt == "" {
				return envelope.Failure[PowerAction](r.Target, envelope.Errorf("internal", "the helper's answer does not name the approved action; check the host"))
			}
			out := PowerAction{Action: x.Action, TargetUnit: x.Target, ScheduledAt: x.ScheduledAt, DelaySeconds: x.DelayS, Cancel: x.Cancel}
			capText(d.redactor(), &out.Cancel, d.maxOutput())
			env := envelope.Success(r.Target, out)
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
		approvalArgs: func(in privRebootIn) any {
			return struct {
				Action string `json:"action"`
			}{in.Action}
		},
		describe: func(in privRebootIn, target string) string { return "As root, " + powerVerb[in.Action] + " " + target },
		describePreview: func(in privRebootIn, target string, p *preview) string {
			return "As root, " + powerVerb[in.Action] + " " + target + " " + strconv.Itoa(p.count) + " s after the call"
		},
		preview: func(ctx context.Context, in privRebootIn, target string) (*preview, *envelope.Error) {
			resp, e := d.call(ctx, target, protocol.OpPrivPowerPreview, powerActionWire{Action: in.Action}, d.budget())
			if e != nil {
				return nil, e
			}
			env := envelope.FromGate[powerPreviewWire](target, resp)
			if !env.OK {
				return nil, env.Error
			}
			policy, e := privPolicy(resp)
			if e != nil {
				return nil, e
			}
			x := env.Data
			if !sha256RE.MatchString(x.PreviewSHA256) || x.Action != in.Action || x.Target != in.Action+".target" || x.DelayS <= 0 || x.DelayS > 3600 {
				return nil, envelope.Errorf("internal", "the helper's preview has no valid preview_sha256, or does not describe the requested action")
			}
			value := map[string]any{"action": x.Action, "target_unit": x.Target, "delay_seconds": x.DelayS, "preview_sha256": x.PreviewSHA256}
			return &preview{value: value, policy: policy, contentSHA256: x.PreviewSHA256, count: int(x.DelayS)}, nil
		},
		precondition: func(in *privRebootIn, p *preview) { in.expectedPreview = p.contentSHA256 },
	})
}

func privCancelPower(d *Deps) Tool {
	return define(d, spec[privCancelPowerIn, PowerCancel]{
		name: "shell_priv_cancel_power", title: "Cancel a scheduled reboot or power-off",
		description: "Cancels, as root, the reboot or power-off the host's privileged helper scheduled and has not yet requested; returns the cancelled action and its time.",
		tier:        TierRead, privileged: true, changesState: true,
		schema:  boundCommon,
		audit:   func(in privCancelPowerIn) map[string]any { return map[string]any{"target": in.Target} },
		summary: func(*PowerCancel) string { return "as root: cancelled" },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privCancelPowerIn) envelope.Envelope[PowerCancel] {
			return fetch[PowerCancel](ctx, d, in.Target, protocol.OpPrivPowerCancel, noArgsWire{}, d.budget())
		},
	})
}
