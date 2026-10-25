#!/usr/bin/env bash
# release/registry.sh: the release workflow's image plumbing.
#   start LABEL        run the loopback registry (scripts/release/Dockerfile.registry's
#                      image, 127.0.0.1:5000 only, no volume) labelled LABEL
#   stop LABEL         remove the containers labelled LABEL (only those)
#   digest REF         print the digest REF (repo:tag or repo@digest) resolves to
#   load DIR REF WANT  push the OCI layout in DIR (from `cosign save`) to REF
#                      with `cosign load`, which writes the index and its
#                      images unchanged, and fail unless REF now resolves to
#                      the digest WANT
# Runs only in the release workflow (GitHub-hosted runners). Needs docker,
# curl, jq and, for load, cosign.
set -euo pipefail

registry="localhost:5000"
index_types='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

digest_of() {
	local ref="$1" repo tag
	if [[ "$ref" == "$registry/"* ]]; then
		repo="${ref#"$registry"/}"
		if [[ "$repo" == *@* ]]; then
			tag="${repo#*@}" repo="${repo%%@*}"
		else
			tag="${repo##*:}" repo="${repo%:*}"
		fi
		curl -fsSI -H "Accept: $index_types" "http://$registry/v2/$repo/manifests/$tag" |
			tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" { print $2 }'
	else
		docker buildx imagetools inspect "$ref" --format '{{json .Manifest.Digest}}' | tr -d '"'
	fi
}

case "${1:-}" in
start)
	label="$2"
	image="$(awk 'toupper($1) == "FROM" { print $2; exit }' "$(dirname "$0")/Dockerfile.registry")"
	if [[ "$image" != *@sha256:* ]]; then
		echo "release registry: $image is not pinned by digest" >&2
		exit 1
	fi
	docker run -d --label "$label" -p 127.0.0.1:5000:5000 "$image" >/dev/null
	for _ in $(seq 1 60); do
		if curl -fsS "http://$registry/v2/" >/dev/null 2>&1; then
			echo "release registry: up at $registry ($image)"
			exit 0
		fi
		sleep 0.5
	done
	echo "release registry: not answering on $registry" >&2
	exit 1
	;;
stop)
	ids="$(docker ps -aq --filter "label=$2")"
	if [[ -n "$ids" ]]; then
		# shellcheck disable=SC2086 # one container id per word
		docker rm -f $ids >/dev/null
	fi
	;;
digest)
	digest_of "$2"
	;;
load)
	dir="$2" ref="$3" want="$4"
	cosign load --dir "$dir" "$ref"
	got="$(digest_of "$ref")"
	if [[ "$got" != "$want" ]]; then
		echo "release registry: $ref resolves to '$got', want $want" >&2
		exit 1
	fi
	echo "release registry: $ref is $want"
	;;
*)
	echo "usage: $0 start LABEL | stop LABEL | digest REF | load DIR REF DIGEST" >&2
	exit 2
	;;
esac
