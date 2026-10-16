// Package sshx is the SSH client (D-012, S-04): host keys pinned by type and
// SHA-256 fingerprint and verified on every new connection, HostKeyAlgorithms
// derived from the pinned types only (never SHA-1 ssh-rsa, DSA or
// certificates), an Ed25519 client key and nothing else (no agent, password
// or keyboard-interactive), no forwarding, PTY, environment, shell or
// subsystem, a connect timeout, keepalives, at most SHELL_MCP_SSH_MAX_SESSIONS
// sessions per target, and reconnects with a bounded exponential backoff.
package sshx
