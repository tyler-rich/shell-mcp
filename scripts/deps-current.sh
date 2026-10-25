#!/usr/bin/env bash
# deps-current (D-013): enforce latest-everything instead of remembering it.
# Fails when
#   - a module we build from is behind its newest stable release;
#   - a direct requirement has a stable next major version (<path>/vN+1, or
#     <path>/v2 for a v0/v1 module) — pre-release-only next majors are info;
#   - a tool pinned in the workflows or scripts/ci-local.sh is older than its
#     newest stable release, or the files that pin it disagree, or a pin is
#     missing: golangci-lint and govulncheck (ci.yml, ci-local.sh and, for
#     govulncheck, release-build.yml), Trivy and Grype (ci.yml and
#     release-build.yml), gitleaks (ci.yml), cosign and syft
#     (release-build.yml);
#   - the release workflow's loopback registry image
#     (scripts/release/Dockerfile.registry) is not pinned by digest, or is
#     older than the newest stable distribution release whose official
#     registry image is published;
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
release_yml=".github/workflows/release-build.yml"
ci_local="scripts/ci-local.sh"

# check_pins NAME NEWEST FILE=PIN...: every file pins NAME, all to the same
# version, none older than NEWEST. A pin may omit the leading v (gitleaks).
check_pins() {
	local name="$1" newest="$2" spec file val first="" listed="" ok=1
	shift 2
	local -a vals=()
	for spec in "$@"; do
		file="${spec%%=*}" val="${spec#*=}"
		if [[ -z "$val" ]]; then
			echo "deps-current: FAIL — cannot find the $name pin in $file"
			fail=1 ok=0
			continue
		fi
		val="v${val#v}"
		vals+=("$val")
		listed+="${listed:+, }$file $val"
		[[ -z "$first" ]] && first="$val"
		[[ "$val" != "$first" ]] && ok=2
	done
	if [[ -z "$newest" ]]; then
		echo "deps-current: FAIL — could not determine the newest stable $name release"
		fail=1
		return
	fi
	if [[ $ok -eq 2 ]]; then
		echo "deps-current: FAIL — $name is pinned differently: $listed"
		fail=1
	fi
	local pin
	for pin in $(printf '%s\n' "${vals[@]}" | sort -u); do
		if older "$pin" "$newest"; then
			echo "deps-current: FAIL — $name $pin is older than the newest stable $newest"
			fail=1 ok=0
		fi
	done
	if [[ $ok -eq 1 ]]; then
		echo "deps-current: $name $first is the newest stable release"
	fi
}

# pin_of FILE VAR: the value of "VAR: value" (a workflow env entry).
pin_of() { awk -v k="$2:" '$1 == k { print $2; exit }' "$1" 2>/dev/null || true; }
# newest_tag OWNER/REPO: the newest vX.Y.Z tag of a GitHub repository.
newest_tag() {
	git ls-remote --tags --refs "https://github.com/$1" |
		awk '{ sub("refs/tags/", "", $2); print $2 }' | grep -E "$stable_re" | sort -V | tail -n1 || true
}

check_pins golangci-lint "$(newest_tag golangci/golangci-lint)" \
	"$ci_yml=$(pin_of "$ci_yml" GOLANGCI_LINT_VERSION)" \
	"$ci_local=$(sed -n 's/^golangci_lint_version="\(v[0-9.]*\)"$/\1/p' "$ci_local" 2>/dev/null || true)"

# @latest on the module proxy is the newest release, never a pre-release.
check_pins govulncheck "$(go list -m -f '{{.Version}}' golang.org/x/vuln@latest 2>/dev/null || true)" \
	"$ci_yml=$(pin_of "$ci_yml" GOVULNCHECK_VERSION)" \
	"$ci_local=$(sed -n 's/^govulncheck_version="\(v[0-9.]*\)"$/\1/p' "$ci_local" 2>/dev/null || true)" \
	"$release_yml=$(pin_of "$release_yml" GOVULNCHECK_VERSION)"

check_pins Trivy "$(newest_tag aquasecurity/trivy)" \
	"$ci_yml=$(pin_of "$ci_yml" TRIVY_VERSION)" "$release_yml=$(pin_of "$release_yml" TRIVY_VERSION)"
check_pins Grype "$(newest_tag anchore/grype)" \
	"$ci_yml=$(pin_of "$ci_yml" GRYPE_VERSION)" "$release_yml=$(pin_of "$release_yml" GRYPE_VERSION)"
check_pins gitleaks "$(newest_tag gitleaks/gitleaks)" "$ci_yml=$(pin_of "$ci_yml" GITLEAKS_VERSION)"
check_pins cosign "$(newest_tag sigstore/cosign)" "$release_yml=$(pin_of "$release_yml" COSIGN_VERSION)"
check_pins syft "$(newest_tag anchore/syft)" "$release_yml=$(pin_of "$release_yml" SYFT_VERSION)"

# --- Loopback registry image -----------------------------------------------------
# The official registry image (Docker Hub library/registry) is tagged with
# distribution's release versions, published some time after the release.
# The pin must equal the newest stable distribution release whose image is
# published, walking back from the newest at most five releases; a release
# without its image yet is info. Docker Hub is queried anonymously with a
# HEAD request; anything but 200 or 404 fails closed.
registry_file="scripts/release/Dockerfile.registry"
registry_image="$(awk 'toupper($1) == "FROM" { print $2; exit }' "$registry_file" 2>/dev/null || true)"
registry_tag="$(sed -n 's/^registry:\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)@sha256:[0-9a-f]\{64\}$/\1/p' <<<"$registry_image")"
registry_status() { # registry_status <tag>: 200, 404 or another status
	local token
	token="$(curl -fsS --max-time 30 \
		'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/registry:pull' |
		grep -o '"token": *"[^"]*"' | head -n1 | sed 's/^"token": *"\(.*\)"$/\1/')" || return 1
	[[ -n "$token" ]] || return 1
	printf 'Authorization: Bearer %s\n' "$token" |
		curl -sS --max-time 30 -I -o /dev/null -w '%{http_code}' -H @- \
			-H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json' \
			"https://registry-1.docker.io/v2/library/registry/manifests/$1"
}
if [[ -z "$registry_tag" ]]; then
	echo "deps-current: FAIL — $registry_file must pin registry:X.Y.Z@sha256:<digest> (got '$registry_image')"
	fail=1
else
	registry_newest=""
	registry_failed=0
	while read -r tag; do
		[[ -n "$tag" ]] || continue
		status="$(registry_status "${tag#v}")" || status="error"
		case "$status" in
		200) registry_newest="${tag#v}"; break ;;
		404) echo "deps-current: info — distribution $tag is released but registry:${tag#v} is not published yet" ;;
		*)
			echo "deps-current: FAIL — cannot query Docker Hub for registry:${tag#v} ($status)"
			fail=1 registry_failed=1
			break
			;;
		esac
	done < <(git ls-remote --tags --refs https://github.com/distribution/distribution |
		awk '{ sub("refs/tags/", "", $2); print $2 }' | grep -E "$stable_re" | sort -V | tail -n5 | sort -rV)
	if [[ $registry_failed -eq 0 ]]; then
		if [[ -z "$registry_newest" ]]; then
			echo "deps-current: FAIL — none of the 5 newest distribution releases has a published registry image"
			fail=1
		elif older "$registry_tag" "$registry_newest"; then
			echo "deps-current: FAIL — the loopback registry image registry:$registry_tag is older than registry:$registry_newest"
			fail=1
		else
			echo "deps-current: the loopback registry image registry:$registry_tag is the newest published"
		fi
	fi
fi

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
