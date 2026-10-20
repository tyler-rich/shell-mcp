#!/usr/bin/env bash
# deps-current-go (D-013): go.mod's go/toolchain line must be the newest
# stable Go that has a published official golang:<version>-trixie image, the
# image we build and run CI in. Called by deps-current.sh; run on its own it
# checks the module in DEPS_CURRENT_DIR (default: this repository).
#
# The newest stable Go comes from go.dev. When its image exists, go.mod must
# not be older than it. When it does not exist yet, the check walks back to
# the newest stable Go whose image does exist, requires go.mod to equal it,
# and prints an INFO line naming the Go version awaiting its image. Once that
# image is published, the check fails again until go.mod moves.
#
# Fails closed: if go.dev or the registry cannot be queried, or the registry
# answers anything but 200 or 404, the check fails. The registry is queried
# anonymously (Docker Hub's public pull token, no credentials) with a HEAD
# request per tag, which Docker Hub does not count against its pull limit.
# Needs curl.
set -euo pipefail

cd "${DEPS_CURRENT_DIR:-$(dirname "$0")/..}"

# Tag variant of the Dockerfile's golang builder image.
image_variant="trixie"
# How many of the newest stable Go releases to try before failing.
max_walk=5

older() { [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]; }

# image_status <tag>: prints 200 (exists), 404 (not published) or another
# status; returns non-zero if the registry cannot be reached.
image_status() {
	local tag="$1" token
	token="$(curl -fsS --max-time 30 \
		'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/golang:pull' |
		grep -o '"token": *"[^"]*"' | head -n1 | sed 's/^"token": *"\(.*\)"$/\1/')" || return 1
	[[ -n "$token" ]] || return 1
	# The token goes to curl on stdin, not argv.
	printf 'Authorization: Bearer %s\n' "$token" |
		curl -sS --max-time 30 -I -o /dev/null -w '%{http_code}' -H @- \
			-H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
			"https://registry-1.docker.io/v2/library/golang/manifests/$tag"
}

# ?mode=json&include=all lists every release with its "stable" flag.
releases="$(curl -fsS --max-time 60 'https://go.dev/dl/?mode=json&include=all' || true)"
mapfile -t stable < <(tr -d ' \t\r\n' <<<"$releases" |
	grep -o '"version":"go[0-9]*\.[0-9]*\.[0-9]*","stable":true' |
	sed 's/^"version":"go\([^"]*\)".*/\1/' | sort -u -V -r || true)
if [[ ${#stable[@]} -eq 0 ]]; then
	echo "deps-current: could not determine the newest Go release" >&2
	exit 1
fi
latest="${stable[0]}"

go_line="$(awk '$1 == "go" { print $2 }' go.mod)"
toolchain_line="$(awk '$1 == "toolchain" { sub(/^go/, "", $2); print $2 }' go.mod)"
# The go command drops a toolchain line equal to the go line, so the
# effective toolchain is the newer of the two.
effective="$(printf '%s\n%s\n' "$go_line" "${toolchain_line:-$go_line}" | sort -V | tail -n1)"

target=""
awaiting=()
for v in "${stable[@]:0:max_walk}"; do
	tag="$v-$image_variant"
	status="$(image_status "$tag")" || status=""
	case "$status" in
	200)
		target="$v"
		break
		;;
	404) awaiting+=("$v") ;;
	"")
		echo "deps-current: FAIL — cannot query the registry for golang:$tag (refusing to pass without it)"
		exit 1
		;;
	*)
		echo "deps-current: FAIL — cannot query the registry for golang:$tag (HTTP $status)"
		exit 1
		;;
	esac
done
if [[ -z "$target" ]]; then
	echo "deps-current: FAIL — none of the ${#awaiting[@]} newest stable Go releases (${awaiting[0]} … ${awaiting[-1]}) has a published golang:<version>-$image_variant image"
	exit 1
fi

if [[ "$target" == "$latest" ]]; then
	if older "$go_line" "$latest"; then
		echo "deps-current: FAIL — go.mod 'go $go_line' is older than the newest stable Go $latest"
		exit 1
	elif older "$effective" "$latest"; then
		echo "deps-current: FAIL — go.mod toolchain $effective is older than the newest stable Go $latest"
		exit 1
	fi
	echo "deps-current: go.mod go $go_line (toolchain ${toolchain_line:-implied by go line}) matches newest stable Go $latest"
	exit 0
fi

for v in "${awaiting[@]}"; do
	echo "deps-current: INFO — Go $v is released but golang:$v-$image_variant is not published yet; go.mod stays on Go $target until it is"
done
about="Go $target, the newest stable Go with a published golang:$target-$image_variant image"
if older "$go_line" "$target"; then
	echo "deps-current: FAIL — go.mod 'go $go_line' is older than $about"
	exit 1
elif older "$effective" "$target"; then
	echo "deps-current: FAIL — go.mod toolchain $effective is older than $about"
	exit 1
elif older "$target" "$effective"; then
	echo "deps-current: FAIL — go.mod go $effective is newer than $about"
	exit 1
fi
echo "deps-current: go.mod go $go_line (toolchain ${toolchain_line:-implied by go line}) matches $about"
