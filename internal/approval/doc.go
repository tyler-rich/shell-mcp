// Package approval implements human approval (D-006, S-12): approval records
// bound to principal, tool, target, the SHA-256 of the canonical arguments,
// of the preview and of the gate policy; the bounded in-memory store (at most
// MaxPendingPerPrincipal pending records per principal, MaxRecords in all,
// deduplication, expiry sweep); and the execution check a re-call goes
// through (docs/handoff/S4B-APPROVAL.md §6.1–§6.3).
//
// A record is approved or declined only through Decide: by the approval page
// (package page) after a verified TOTP code, or, under confirm-argument, by
// the model itself (ConfirmApprover). Nothing in this package logs a code, a
// seed, a CSRF token, a description, a preview or content: its audit lines
// carry ids, hashes and approver names only.
package approval
