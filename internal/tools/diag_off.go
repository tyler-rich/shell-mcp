//go:build !shellmcp_diag

package tools

// DiagBuild reports whether this binary carries the elicitation diagnostic
// tool (build tag shellmcp_diag). Release builds and CI's image never do.
const DiagBuild = false

func registerDiag(*Registry, *Deps) error { return nil }
