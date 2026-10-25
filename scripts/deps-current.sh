#!/usr/bin/env bash
# deps-current (D-013): enforce latest-everything instead of remembering it.
# Fails when
#   - a module we build from is behind its newest stable release;
#   - a direct requirement has a stable next major version (<path>/vN+1, or
#     <path>/v2 for a v0/v1 module) — pre-release-only next majors are info;
#   - the golangci-lint or govulncheck version pinned in ci.yml and
#     scripts/ci-local.sh differs between the two or is older than its newest
#     stable release;
#   - go.mod's go/toolchain line is not the newest stable Go on go.dev that
#     has a published official golang:<version>-trixie image (the newest
#     stable Go, unless its image is not published yet; deps-current-go.sh);
#   - scripts/ci-local.sh lints with a Go older than go.mod's go/toolchain
#     line, or with anything but golangci-lint built in the Go image.
# Needs go, git and curl. Run from any directory; checks the module containing
# this script unless DEPS_CURRENT_DIR names another.
#
# Module scope: every go.mod requirement, plus every module that provides a
# package to `go list -deps -test ./...` (everything compiled into our
# binaries and tests). Modules that are in the module graph only because a
# dependency's own go.mod requires them are reported as info: `go mod tidy`
# removes any requirement we add for them, so they cannot be pinned from here.
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
cd "${DEPS_CURRENT_DIR:-$script_dir/..}"

fail=0
stable_re='^v[0-9]+\.[0-9]+\.[0-9]+$'

# older A B: A is a strictly older version than B (sort -V order).
older() { [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]; }

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

# --- Next major versions -------------------------------------------------------
# `go list -m -u` never crosses a major version, so query the module proxy for
# the next major path of every direct requirement.
direct="$(go mod edit -print | awk '
	/^require \(/ { inblock = 1; next }
	inblock && /^\)/ { inblock = 0; next }
	inblock && NF && !/\/\/ indirect/ { print $1 }
	/^require [^(]/ && !/\/\/ indirect/ { print $2 }')"
if [[ -z "$direct" ]]; then
	echo "deps-current: no direct requirements (unexpected; refusing to pass vacuously)" >&2
	exit 1
fi
while read -r mod; do
	if [[ "$mod" =~ ^(gopkg\.in/.+)\.v([0-9]+)$ ]]; then
		next="${BASH_REMATCH[1]}.v$((BASH_REMATCH[2] + 1))"
	elif [[ "$mod" =~ ^(.+)/v([0-9]+)$ ]]; then
		next="${BASH_REMATCH[1]}/v$((BASH_REMATCH[2] + 1))"
	else
		next="$mod/v2"
	fi
	# A missing module is an error from the proxy: no next major.
	versions="$(go list -m -versions "$next" 2>/dev/null | awk '{ $1 = ""; print }' | tr ' ' '\n' | grep -v '^$' || true)"
	newest_stable="$(grep -E "$stable_re" <<<"$versions" | sort -V | tail -n1 || true)"
	newest_any="$(sort -V <<<"$versions" | tail -n1 || true)"
	if [[ -n "$newest_stable" ]]; then
		echo "deps-current: FAIL — $mod has a stable next major: $next $newest_stable"
		fail=1
	elif [[ -n "$newest_any" ]]; then
		echo "deps-current: info — next major has only pre-releases: $next $newest_any (required: $mod)"
	fi
done <<<"$direct"

# --- CI tool pins ----------------------------------------------------------------
ci_yml=".github/workflows/ci.yml"
ci_local="scripts/ci-local.sh"

# check_tool NAME CI_PIN LOCAL_PIN NEWEST
check_tool() {
	local name="$1" ci="$2" local_pin="$3" newest="$4"
	if [[ -z "$ci" || -z "$local_pin" ]]; then
		echo "deps-current: FAIL — cannot find the $name pin in $ci_yml (got '$ci') or $ci_local (got '$local_pin')"
		fail=1
		return
	fi
	if [[ -z "$newest" ]]; then
		echo "deps-current: FAIL — could not determine the newest stable $name release"
		fail=1
		return
	fi
	if [[ "$ci" != "$local_pin" ]]; then
		echo "deps-current: FAIL — $name is pinned differently: $ci_yml $ci, $ci_local $local_pin"
		fail=1
	fi
	local pin
	for pin in $(printf '%s\n%s\n' "$ci" "$local_pin" | sort -u); do
		if older "$pin" "$newest"; then
			echo "deps-current: FAIL — $name $pin is older than the newest stable $newest"
			fail=1
		fi
	done
	if [[ "$ci" == "$local_pin" ]] && ! older "$ci" "$newest"; then
		echo "deps-current: $name $ci is the newest stable release"
	fi
}

lint_ci="$(awk '$1 == "GOLANGCI_LINT_VERSION:" { print $2 }' "$ci_yml" 2>/dev/null || true)"
lint_local="$(sed -n 's/^golangci_lint_version="\(v[0-9.]*\)"$/\1/p' "$ci_local" 2>/dev/null || true)"
lint_newest="$(git ls-remote --tags --refs https://github.com/golangci/golangci-lint |
	awk '{ sub("refs/tags/", "", $2); print $2 }' | grep -E "$stable_re" | sort -V | tail -n1 || true)"
check_tool golangci-lint "$lint_ci" "$lint_local" "$lint_newest"

vuln_ci="$(awk '$1 == "GOVULNCHECK_VERSION:" { print $2 }' "$ci_yml" 2>/dev/null || true)"
vuln_local="$(sed -n 's/^govulncheck_version="\(v[0-9.]*\)"$/\1/p' "$ci_local" 2>/dev/null || true)"
# @latest on the module proxy is the newest release, never a pre-release.
vuln_newest="$(go list -m -f '{{.Version}}' golang.org/x/vuln@latest 2>/dev/null || true)"
check_tool govulncheck "$vuln_ci" "$vuln_local" "$vuln_newest"

# --- Go toolchain ------------------------------------------------------------
# go.mod must be on the newest stable Go that has a published official
# golang:<version>-trixie image; see deps-current-go.sh.
if ! DEPS_CURRENT_DIR="$PWD" bash "$script_dir/deps-current-go.sh"; then
	fail=1
fi

go_line="$(awk '$1 == "go" { print $2 }' go.mod)"
toolchain_line="$(awk '$1 == "toolchain" { sub(/^go/, "", $2); print $2 }' go.mod)"
# The go command drops a toolchain line equal to the go line, so the
# effective toolchain is the newer of the two.
effective="$(printf '%s\n%s\n' "$go_line" "${toolchain_line:-$go_line}" | sort -V | tail -n1)"

# --- golangci-lint toolchain (ci-local) ----------------------------------------
# ci-local.sh runs with GOTOOLCHAIN=local, so the Go that builds golangci-lint
# must be able to load this module. It must build golangci-lint with `go run`
# in the Go image (the Dockerfile's golang builder stage), never use a
# prebuilt image that bundles its own Go, and that Go must not be older than
# go.mod's go/toolchain line.
lint_go_ok=1
lint_run='in_lint() { in_go go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$golangci_lint_version" "$@"; }'
if ! grep -q -x -F -- "$lint_run" "$ci_local" ||
	! grep -q -x -F -- 'in_go() { docker run "${common[@]}" "$go_image" "$@"; }' "$ci_local" ||
	! grep -q '^go_image="$(awk .* Dockerfile)"$' "$ci_local"; then
	echo "deps-current: FAIL — golangci-lint in $ci_local does not run with the Go image's go (expected: $lint_run, with in_go on the Dockerfile's golang image)"
	fail=1
	lint_go_ok=0
fi
lint_steps="$(grep -c '^step "golangci-lint' "$ci_local" || true)"
lint_steps_in_go="$(grep -c '^step "golangci-lint[^"]*" "" in_lint run ' "$ci_local" || true)"
if [[ "$lint_steps" -eq 0 || "$lint_steps" != "$lint_steps_in_go" ]]; then
	echo "deps-current: FAIL — golangci-lint in $ci_local does not run with the Go image's go ($lint_steps_in_go of $lint_steps lint steps use in_lint)"
	fail=1
	lint_go_ok=0
fi
go_image="$(awk 'toupper($1) == "FROM" { for (i = 2; i <= NF; i++) if ($i ~ /^golang:/) { print $i; exit } }' Dockerfile 2>/dev/null || true)"
lint_go="$(sed -n 's/^golang:\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)[-@].*/\1/p' <<<"$go_image")"
if [[ -z "$lint_go" ]]; then
	echo "deps-current: FAIL — cannot read the Go version from the Dockerfile's golang image (got '$go_image')"
	fail=1
elif older "$lint_go" "$effective"; then
	echo "deps-current: FAIL — golangci-lint in $ci_local runs on Go $lint_go, older than go.mod's go $effective"
	fail=1
elif [[ "$lint_go_ok" -eq 1 ]]; then
	echo "deps-current: golangci-lint in $ci_local is built with Go $lint_go (go.mod: $effective)"
fi

exit "$fail"
