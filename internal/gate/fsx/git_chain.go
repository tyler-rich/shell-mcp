//go:build linux

package fsx

// CheckGitRepo applies the closed-repository rule (POLICY §7, handoff
// N-20). Inert stub: the rule is not applied yet.
func (f *FS) CheckGitRepo(_ string) error { return nil }

// gitOpen says why an entry is open to another account. Inert stub.
func (f *FS) gitOpen(_ *ident) string { return "" }
