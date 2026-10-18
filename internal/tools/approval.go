package tools

import (
	"context"
	stdjson "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/envelope"
)

// Human approval through the tools (D-006; docs/handoff/S4B-APPROVAL.md
// §6.1–§6.3, §6.6). A tool that can be approval-gated (tier operator or
// destructive) has an optional approval_id input whatever the
// configuration, and a confirm input under confirm-argument. Whether a call
// is gated is decided at call time: destructive tools always, and the tiers
// SHELL_MCP_APPROVAL_TIERS lists.

// approvalInput is what a call says about approval.
type approvalInput struct {
	ID      string
	Confirm bool
	// given reports whether approval_id or confirm was present at all.
	given bool
}

// approvalOutcome is the tool call line's approval_outcome.
type approvalOutcome string

const (
	outcomePending  approvalOutcome = "pending"
	outcomeUsed     approvalOutcome = "used"
	outcomeInvalid  approvalOutcome = "invalid"
	outcomeDeclined approvalOutcome = "declined"
)

// gateable reports whether tools of tier t can be approval-gated, and so
// carry the approval inputs.
func gateable(t Tier) bool { return t == TierOperator || t == TierDestructive }

// gated reports whether a call of a tool of tier t needs approval.
func (d *Deps) gated(t Tier) bool {
	return t == TierDestructive || t == TierOperator && slices.Contains(d.ApprovalTiers, t.String())
}

func (d *Deps) method() approval.Method {
	if d.ApprovalMethod == "" {
		return approval.MethodNone
	}
	return d.ApprovalMethod
}

// unavailable is the refusal of a gated call when the server collects no
// approvals.
func (d *Deps) unavailable(t Tier) *envelope.Error {
	return envelope.Errorf(envelope.CodeApprovalUnavailable,
		"%s tools need a human approval and this server collects none (SHELL_MCP_APPROVAL_METHOD=none); nothing was sent to the target", t)
}

// approvalSchema adds the approval inputs to a gateable tool's schema.
func approvalSchema(s *jsonschema.Schema, confirm bool) {
	if s.Properties == nil {
		s.Properties = map[string]*jsonschema.Schema{}
	}
	s.Properties["approval_id"] = &jsonschema.Schema{
		Type:        "string",
		Description: "The approval id of an earlier call that returned approval_pending: call again with the same arguments and this id once the approval was given. Omit it on a first call.",
		Pattern:     approval.IDPattern, MinLength: new(approval.IDLength), MaxLength: new(approval.IDLength),
	}
	if confirm {
		s.Properties["confirm"] = &jsonschema.Schema{
			Type:        "boolean",
			Description: "With approval_id: approve the pending request (SHELL_MCP_APPROVAL_METHOD=confirm-argument). Default false.",
		}
	}
}

// splitApproval takes approval_id (and, under confirm-argument, confirm)
// out of a gateable tool's arguments. What remains is decoded strictly as
// the tool's input, so a confirm under another method is an unknown field.
func splitApproval(raw stdjson.RawMessage, confirm bool) (stdjson.RawMessage, approvalInput, *envelope.Error) {
	var in approvalInput
	if len(raw) == 0 || string(raw) == "null" || raw.Kind() != '{' {
		return raw, in, nil // decodeArgs reports a non-object
	}
	var m map[string]jsontext.Value
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw, in, envelope.Errorf(envelope.CodeValidationError, "arguments must be this tool's fields with their documented types (no other fields)")
	}
	if v, ok := m["approval_id"]; ok {
		delete(m, "approval_id")
		in.given = true
		if err := json.Unmarshal(v, &in.ID); err != nil || !approval.ParseID(in.ID) {
			return raw, in, envelope.Errorf(envelope.CodeValidationError,
				"approval_id must be the 26-character id (a-z, 2-7) of the approval object an earlier call returned")
		}
	}
	if v, ok := m["confirm"]; ok && confirm {
		delete(m, "confirm")
		in.given = true
		if err := json.Unmarshal(v, &in.Confirm); err != nil {
			return raw, in, envelope.Errorf(envelope.CodeValidationError, "confirm must be true or false")
		}
		if in.ID == "" {
			return raw, in, envelope.Errorf(envelope.CodeValidationError, "confirm needs approval_id: call without both first to request an approval")
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw, in, envelope.Errorf(envelope.CodeValidationError, "arguments must be a JSON object")
	}
	return out, in, nil
}

// preview is a server-computed preview of what a call would change, built
// from the gate's read operations. value is what is hashed and shown;
// policy is the gate policy's SHA-256 reported with it; contentSHA256 is
// the previewed content's hash, passed as a precondition where the
// operation supports one (expected_sha256); absent says the preview saw no
// file there (passed as expect_absent).
type preview struct {
	value         any
	policy        string
	contentSHA256 string
	absent        bool
	// tier is the tier of the operation the preview resolved, when the
	// tool's gating follows it (spec.tierFromPreview); 0 otherwise.
	tier Tier
}

// policyAcc collects the policy hashes of a preview's requests.
type policyAcc struct {
	v       string
	changed bool
}

func (p *policyAcc) add(h string) {
	switch {
	case h == "":
	case p.v == "":
		p.v = h
	case p.v != h:
		p.changed = true
	}
}

func (p *policyAcc) result(value any, content string) (*preview, *envelope.Error) {
	if p.changed {
		return nil, envelope.Errorf(envelope.CodeApprovalInvalid, "the target's policy changed while the preview was computed; call the tool again")
	}
	return &preview{value: value, policy: p.v, contentSHA256: content}, nil
}

// absentResult is result for a preview that saw no file at the path.
func (p *policyAcc) absentResult(value any) (*preview, *envelope.Error) {
	r, e := p.result(value, "")
	if r != nil {
		r.absent = true
	}
	return r, e
}

// plainRE is a path or name simple enough to appear in a description: no
// spaces, controls or other characters that could be read as prose.
var plainRE = regexp.MustCompile(`^/?[A-Za-z0-9._/@+=,:~-]{1,255}$`)

// plain returns s for a description when it is plain, else what to say
// instead; the value itself is always on the page's arguments table.
func plain(s, instead string) string {
	if plainRE.MatchString(s) {
		return s
	}
	return instead
}

func (d *Deps) approvalURL(id string) string {
	if d.method() != approval.MethodWeb || d.ApprovalPublicURL == "" {
		return ""
	}
	return d.ApprovalPublicURL + "/approvals/" + id
}

func (d *Deps) approvalObject(r *approval.Record, status approval.Status) *envelope.Approval {
	return &envelope.Approval{ID: r.ID, Status: string(status), URL: d.approvalURL(r.ID),
		ExpiresAt: r.ExpiresAt.UTC().Format(time.RFC3339), Summary: r.Description}
}

// pendingMessage is the approval_pending text: server-generated words, the
// configured origin and the record id, nothing from the host or the
// caller.
func (d *Deps) pendingMessage(id string) string {
	if d.method() == approval.MethodConfirm {
		return "Approval required. Call this tool again with the same arguments, approval_id " + id + " and confirm true."
	}
	return "Approval required. Show the user this URL exactly as written, without changing or shortening it: " + d.approvalURL(id) +
		". The approver opens it from their bookmark or the server's notification, checks the operation, and approves with a code. " +
		"Then call this tool again with the same arguments and approval_id " + id + "."
}

func pendingEnvelope[Out any](d *Deps, target string, r *approval.Record) envelope.Envelope[Out] {
	env := envelope.Failure[Out](target, envelope.Errorf(envelope.CodeApprovalPending, "%s", d.pendingMessage(r.ID)))
	env.Approval = d.approvalObject(r, approval.StatusPending)
	return env
}

// targeted is implemented by every input (they embed targetArg).
type targeted interface{ targetName() string }

func (a targetArg) targetName() string { return a.Target }

// approveCall runs a gated call: a first call computes the preview and
// creates (or finds) the approval record; a re-call with approval_id goes
// through the store's checks, then a fresh preview that must hash the same,
// then the operation with the preview's precondition.
// first, when given, is the first call's preview, already computed.
func approveCall[In, Out any](ctx context.Context, d *Deps, s spec[In, Out], req *mcp.CallToolRequest, in In, ap approvalInput, first *preview) (envelope.Envelope[Out], approvalOutcome, string) {
	tn := ""
	if t, ok := any(in).(targeted); ok {
		tn = t.targetName()
	}
	tg, e := d.resolve(tn)
	if e != nil {
		return envelope.Failure[Out](tn, e), "", ap.ID
	}
	if d.Approvals == nil {
		return envelope.Failure[Out](tg.Name, d.unavailable(s.tier)), "", ap.ID
	}
	canon := s.approvalArgs(in)
	argsHash, err := approval.HashOf(canon)
	if err != nil {
		return envelope.Failure[Out](tg.Name, envelope.Errorf("internal", "the arguments could not be hashed")), "", ap.ID
	}
	b := approval.Binding{Principal: d.Principal.Name, Tool: s.name, Target: tg.Name, ArgsSHA256: argsHash}

	if ap.ID == "" {
		p := first
		if p == nil {
			var perr *envelope.Error
			if p, perr = s.preview(ctx, in, tg.Name); perr != nil {
				return envelope.Failure[Out](tg.Name, perr), "", ""
			}
		}
		ph, err1 := approval.HashOf(p.value)
		argFields, err2 := approval.Fields(canon, approval.MaxArgsBytes)
		prevFields, err3 := approval.Fields(p.value, approval.MaxPreviewBytes)
		if err := errors.Join(err1, err2, err3); err != nil {
			return envelope.Failure[Out](tg.Name, envelope.Errorf("internal", "the preview could not be encoded")), "", ""
		}
		rec, created, err := d.Approvals.RequestNew(&approval.Request{
			Binding: b, PreviewSHA256: ph, PolicySHA256: p.policy, ToolTitle: s.title, TargetHost: tg.Host,
			Description: s.describe(in, tg.Name), Args: argFields, Preview: prevFields,
		})
		switch {
		case errors.Is(err, approval.ErrTooManyPending):
			return envelope.Failure[Out](tg.Name, envelope.Errorf(envelope.CodeApprovalUnavailable,
				"too many pending approvals for this principal (%d); wait for a decision or an expiry", approval.MaxPendingPerPrincipal)), "", ""
		case errors.Is(err, approval.ErrStoreFull):
			return envelope.Failure[Out](tg.Name, envelope.Errorf(envelope.CodeApprovalUnavailable, "the approval store is full; try again later")), "", ""
		case err != nil:
			return envelope.Failure[Out](tg.Name, envelope.Errorf("internal", "the approval could not be recorded")), "", ""
		}
		if created && d.Notify != nil && d.method() == approval.MethodWeb {
			d.Notify(&rec, d.approvalURL(rec.ID))
		}
		return pendingEnvelope[Out](d, tg.Name, &rec), outcomePending, rec.ID
	}

	confirmAs := ""
	if ap.Confirm {
		confirmAs = approval.ConfirmApprover
	}
	res := d.Approvals.Use(ctx, ap.ID, b, confirmAs, "")
	switch res.Outcome {
	case approval.OutcomePending:
		return pendingEnvelope[Out](d, tg.Name, &res.Record), outcomePending, ap.ID
	case approval.OutcomeDeclined:
		env := envelope.Failure[Out](tg.Name, envelope.Errorf(envelope.CodeApprovalDeclined, "the approver declined this operation; nothing was sent to the target"))
		env.Approval = d.approvalObject(&res.Record, approval.StatusDeclined)
		return env, outcomeDeclined, ap.ID
	case approval.OutcomeUsed:
	default:
		env := envelope.Failure[Out](tg.Name, envelope.Errorf(envelope.CodeApprovalInvalid, "%s", res.Reason))
		if res.Known {
			env.Approval = d.approvalObject(&res.Record, res.Record.Status)
		}
		return env, outcomeInvalid, ap.ID
	}

	// The record is used from here on, whatever happens next.
	rec := res.Record
	p, e := s.preview(ctx, in, tg.Name)
	if e != nil {
		env := envelope.Failure[Out](tg.Name, e)
		env.Approval = d.approvalObject(&rec, approval.StatusUsed)
		return env, outcomeUsed, ap.ID
	}
	if ph, err := approval.HashOf(p.value); err != nil || ph != rec.PreviewSHA256 || p.policy != rec.PolicySHA256 {
		env := envelope.Failure[Out](tg.Name, envelope.Errorf(envelope.CodeApprovalInvalid,
			"the target or policy changed since approval; request a new approval by calling the tool without approval_id"))
		env.Approval = d.approvalObject(&rec, approval.StatusUsed)
		return env, outcomeInvalid, ap.ID
	}
	if s.precondition != nil {
		s.precondition(&in, p)
	}
	if s.tierFromPreview {
		// The approved operation runs at its own tier's ceiling (the fresh
		// preview hashed as approved, so its tier is the approved one).
		ctx = withCeiling(ctx, p.tier)
	}
	env := s.run(ctx, req, in)
	env.Approval = d.approvalObject(&rec, approval.StatusUsed)
	return env, outcomeUsed, ap.ID
}

// perTierCall runs a call of a tool whose gating follows the tier of the
// operation its preview resolves (shell_run_command, D-006). A re-call
// with approval_id goes through the approval flow. Otherwise the preview
// is computed first, at the tool's ceiling: an operation whose tier needs
// approval goes through the approval flow with that preview (and, when
// approved, runs at that tier's ceiling); one that does not runs at once
// at the highest tier that needs no approval, with the preview's
// precondition, so an operation whose tier rose after the preview (a
// policy edit) is refused by the gate instead of running unapproved.
func perTierCall[In, Out any](ctx context.Context, d *Deps, s spec[In, Out], req *mcp.CallToolRequest, in In, ap approvalInput) (envelope.Envelope[Out], approvalOutcome, string) {
	if ap.given {
		if d.method() == approval.MethodNone {
			return envelope.Failure[Out]("", d.unavailable(s.tier)), "", ap.ID
		}
		return approveCall(ctx, d, s, req, in, ap, nil)
	}
	tn := ""
	if t, ok := any(in).(targeted); ok {
		tn = t.targetName()
	}
	tg, e := d.resolve(tn)
	if e != nil {
		return envelope.Failure[Out](tn, e), "", ""
	}
	p, e := s.preview(ctx, in, tg.Name)
	if e != nil {
		return envelope.Failure[Out](tg.Name, e), "", ""
	}
	if !p.tier.valid() || p.tier > s.tier {
		return envelope.Failure[Out](tg.Name, envelope.Errorf("internal", "the preview named no tier within the tool's")), "", ""
	}
	if d.gated(p.tier) {
		if d.method() == approval.MethodNone || d.Approvals == nil {
			return envelope.Failure[Out](tg.Name, envelope.Errorf(envelope.CodeApprovalUnavailable,
				"this %s-tier operation needs a human approval and this server collects none (SHELL_MCP_APPROVAL_METHOD=none); nothing was run", p.tier)), "", ""
		}
		return approveCall(ctx, d, s, req, in, ap, p)
	}
	if s.precondition != nil {
		s.precondition(&in, p)
	}
	return s.run(withCeiling(ctx, d.ungatedCeiling(s.tier)), req, in), "", ""
}

// ungatedCeiling is the highest tier, up to max, whose operations need no
// approval under SHELL_MCP_APPROVAL_TIERS: operator by default, read when
// operator is listed.
func (d *Deps) ungatedCeiling(maxTier Tier) Tier {
	for t := maxTier; t > TierRead; t-- {
		if !d.gated(t) {
			return t
		}
	}
	return TierRead
}

// describeBytes is "N byte(s)".
func describeBytes(n int) string { return plural(n, "byte", "bytes") }

// timeoutDefault is a call's timeout_seconds with the server default
// applied, for the canonical arguments.
func (d *Deps) timeoutDefault(a timeoutArg) int {
	if a.TimeoutSeconds != nil {
		return *a.TimeoutSeconds
	}
	return int(d.budget() / time.Second)
}

func (d *Deps) outputDefault(a outputArg) int {
	if a.MaxOutputBytes != nil {
		return *a.MaxOutputBytes
	}
	return d.maxOutput()
}
