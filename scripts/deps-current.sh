#!/usr/bin/env bash
# deps-current (D-013): fail when a module we build from is behind its newest
# stable release, or when go.mod's go/toolchain line is older than the newest
# stable Go on go.dev. Needs go and curl. Run from any directory; checks the
# module containing this script unless DEPS_CURRENT_DIR names another.
#
# Scope: every go.mod requirement, plus every module that provides a package
# to `go list -deps -test ./...` (everything compiled into our binaries and
# tests). Modules that are in the module graph only because a dependency's
# own go.mod requires them are reported as info: `go mod tidy` removes any
# requirement we add for them, so they cannot be pinned from here.
set -euo pipefail

cd "${DEPS_CURRENT_DIR:-$(dirname "$0")/..}"

fail=0

# --- Modules ---------------------------------------------------------------
required="$(go mod edit -print | awk '
	/^require \(/ { inblock = 1; next }
	inblock && /^\)/ { inblock = 0; next }
	inblock && NF { print $1 }
	/^require [^(]/ { print $2 }')"
built="$(go list -deps -test -f '{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}' ./...)"
mapfile -t scope < <(printf '%s\n%s\n' "$required" "$built" | grep -v '^$' | sort -u)

if [[ ${#scope[@]} -eq 0 ]]; then
	echo "deps-current: no modules in scope (unexpected; refusing to pass vacuously)" >&2
	exit 1
fi

# `go list -m -u` never proposes a pre-release while a module is on a stable
# version, so any Update is a newer stable release.
tmpl='{{if .Update}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}'
behind="$(go list -m -u -f "$tmpl" "${scope[@]}" | grep -v '^$' || true)"
if [[ -n "$behind" ]]; then
	echo "deps-current: FAIL — modules we build from have a newer release:"
	sed 's/^/  /' <<<"$behind"
	fail=1
else
	echo "deps-current: ${#scope[@]} modules in scope, all current"
fi

graph_only="$(go list -m -u -f "$tmpl" all | grep -v '^$' |
	awk 'NR == FNR { inscope[$1] = 1; next } !($1 in inscope)' <(printf '%s\n' "${scope[@]}") - || true)"
if [[ -n "$graph_only" ]]; then
	echo "deps-current: info — graph-only modules (required by dependencies' go.mod, not built here):"
	sed 's/^/  /' <<<"$graph_only"
fi

# --- Go toolchain ------------------------------------------------------------
# ?mode=json lists stable releases only, newest first.
latest="$(curl -fsS --max-time 30 'https://go.dev/dl/?mode=json' |
	grep -o '"version": *"go[0-9][0-9.]*"' | head -n1 | grep -o 'go[0-9][0-9.]*' || true)"
if [[ -z "$latest" ]]; then
	echo "deps-current: could not determine the newest Go release" >&2
	exit 1
fi
latest="${latest#go}"

go_line="$(awk '$1 == "go" { print $2 }' go.mod)"
toolchain_line="$(awk '$1 == "toolchain" { sub(/^go/, "", $2); print $2 }' go.mod)"
# The go command drops a toolchain line equal to the go line, so the
# effective toolchain is the newer of the two.
effective="$(printf '%s\n%s\n' "$go_line" "${toolchain_line:-$go_line}" | sort -V | tail -n1)"

older() { [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]; }

if older "$go_line" "$latest"; then
	echo "deps-current: FAIL — go.mod 'go $go_line' is older than the newest stable Go $latest"
	fail=1
elif older "$effective" "$latest"; then
	echo "deps-current: FAIL — go.mod toolchain $effective is older than the newest stable Go $latest"
	fail=1
else
	echo "deps-current: go.mod go $go_line (toolchain ${toolchain_line:-implied by go line}) matches newest stable Go $latest"
fi

exit "$fail"
