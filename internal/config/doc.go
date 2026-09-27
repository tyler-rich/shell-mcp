// Package config reads the server configuration from environment variables,
// *_FILE secret files and an optional targets file, and validates it against
// the fail-closed startup rules in docs/SECURITY.md §6. Secrets are held in
// types that never render their value.
package config
