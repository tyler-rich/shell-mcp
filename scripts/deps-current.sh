#!/usr/bin/env bash
# deps-current (D-013): enforce latest-everything instead of remembering it.
# Fails when
#   - a module we build from is behind its newest stable release;
#   - a direct requirement has a stable next major version (<path>/vN+1, or
#     <path>/v2 for a v0/v1 module) — pre-release-only next majors are info;
#   - the golangci-lint or govulncheck version pinned in ci.yml and
#     scripts/ci-local.sh differs between the two or is older than its newest
#     stable release;
#   - go.mod's go/toolchain line is older than the newest stable Go on go.dev.
# Needs go, git and curl. Run from any directory; checks the module containing
# this script unless DEPS_CURRENT_DIR names another.
#
# Module scope: every go.mod requirement, plus every module that provides a
# package to `go list -deps -test ./...` (everything compiled into our
# binaries and tests). Modules that are in the module graph only because a
# dependency's own go.mod requires them are reported as info: `go mod tidy`
# removes any requirement we add for them, so they cannot be pinned from here.
set -euo pipefail

cd "${DEPS_CURRENT_DIR:-$(dirname "$0")/..}"

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
lint_local="$(sed -n 's#.*golangci/golangci-lint:\(v[0-9.]*\)@.*#\1#p' "$ci_local" 2>/dev/null | head -n1 || true)"
lint_newest="$(git ls-remote --tags --refs https://github.com/golangci/golangci-lint |
	awk '{ sub("refs/tags/", "", $2); print $2 }' | grep -E "$stable_re" | sort -V | tail -n1 || true)"
check_tool golangci-lint "$lint_ci" "$lint_local" "$lint_newest"

vuln_ci="$(awk '$1 == "GOVULNCHECK_VERSION:" { print $2 }' "$ci_yml" 2>/dev/null || true)"
vuln_local="$(sed -n 's/^govulncheck_version="\(v[0-9.]*\)"$/\1/p' "$ci_local" 2>/dev/null || true)"
# @latest on the module proxy is the newest release, never a pre-release.
vuln_newest="$(go list -m -f '{{.Version}}' golang.org/x/vuln@latest 2>/dev/null || true)"
check_tool govulncheck "$vuln_ci" "$vuln_local" "$vuln_newest"

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
