//go:build linux

package sandbox

// capABI is the ABI the sandbox plans for, given the kernel's.
func capABI(v int) int { return v }
