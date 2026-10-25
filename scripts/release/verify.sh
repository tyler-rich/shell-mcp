#!/usr/bin/env bash
# release/verify.sh: verify a signed release the way a user would, and that
# the signatures are bound to the run that made them. Run by the release
# workflow after signing, in the dry run and in a real release alike.
#   - SHA256SUMS lists every release file and each one matches;
#   - every binary, the examples archive and SHA256SUMS has a cosign bundle
#     that verifies with the certificate identity of this run's workflow
#     (release-build.yml at REF) and GitHub's OIDC issuer;
#   - the image index and each platform image verify with cosign the same way;
#   - every release file has a SLSA provenance attestation, and every binary
#     and platform image a CycloneDX SBOM attestation, signed by
#     release-build.yml at REF in this repository (gh attestation verify);
#   - and none of that verifies for another ref: the identity a user pins
#     (a release tag) is what separates a release from a dry run.
#
#   bash scripts/release/verify.sh DIR VERSION IMAGE REPOSITORY REF
# DIR holds the release files, SHA256SUMS and the *.sigstore.json bundles;
# IMAGE is <registry>/<repository>@sha256:<index digest>; REF is the run's
# git ref (refs/tags/vX.Y.Z for a release). Needs cosign, gh (GH_TOKEN), jq.
set -euo pipefail

if [[ $# -ne 5 ]]; then
	echo "usage: $0 DIR VERSION IMAGE OWNER/REPO REF" >&2
	exit 2
fi
dir="$1" version="$2" image="$3" repo="$4" ref="$5"
workflow=".github/workflows/release-build.yml"
issuer="https://token.actions.githubusercontent.com"
identity="https://github.com/$repo/$workflow@$ref"
other="https://github.com/$repo/$workflow@refs/heads/never-a-release-ref"
cd "$dir"

fail=0
check() { # check <what> <command…>: must succeed
	local what="$1"
	shift
	if "$@" >/tmp/release-verify.out 2>&1; then
		echo "ok   $what"
	else
		echo "FAIL $what"
		sed 's/^/     /' /tmp/release-verify.out
		fail=1
	fi
}
refuse() { # refuse <what> <command…>: must fail
	local what="$1"
	shift
	if "$@" >/tmp/release-verify.out 2>&1; then
		echo "FAIL $what (it verified)"
		fail=1
	else
		echo "ok   $what (refused)"
	fi
}

# --- Checksums ---------------------------------------------------------------
listed="$(awk '{ print $2 }' SHA256SUMS | sed 's/^\*//' | LC_ALL=C sort)"
present="$(ls -1 | grep -v -e '^SHA256SUMS' -e '\.sigstore\.json$' | LC_ALL=C sort)"
check "SHA256SUMS lists exactly the release files" test "$listed" = "$present"
check "SHA256SUMS matches every file" sha256sum --strict -c SHA256SUMS

binaries=()
for arch in amd64 arm64; do
	for c in shell-mcp shell-mcp-gate shell-mcp-privd; do
		binaries+=("${c}_${version}_linux_${arch}")
	done
done
signed=("${binaries[@]}" "shell-mcp_${version}_examples.tar.gz" SHA256SUMS)

# --- cosign: files ------------------------------------------------------------
for f in "${signed[@]}"; do
	check "cosign bundle: $f" cosign verify-blob --bundle "$f.sigstore.json" \
		--certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$f"
done
refuse "cosign bundle of SHA256SUMS for another ref" cosign verify-blob --bundle SHA256SUMS.sigstore.json \
	--certificate-identity "$other" --certificate-oidc-issuer "$issuer" SHA256SUMS

# --- cosign: image -------------------------------------------------------------
check "cosign: image index $image" cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$image"
# --insecure lets docker read the loopback registry of a dry run over HTTP.
platforms="$(docker manifest inspect --insecure "$image")"
mapfile -t platform_digests < <(jq -r '.manifests[] | select(.platform.os == "linux") | .digest' <<<"$platforms")
check "image index has two linux images" test "${#platform_digests[@]}" -eq 2
for d in "${platform_digests[@]}"; do
	check "cosign: platform image $d" cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "${image%@*}@$d"
done
refuse "cosign: image index for another ref" cosign verify --certificate-identity "$other" --certificate-oidc-issuer "$issuer" "$image"

# --- GitHub artifact attestations -----------------------------------------------
att=(--repo "$repo" --signer-workflow "$repo/$workflow" --source-ref "$ref")
for f in $listed; do
	check "provenance: $f" gh attestation verify "$f" "${att[@]}"
done
for f in "${binaries[@]}"; do
	check "SBOM attestation: $f" gh attestation verify "$f" "${att[@]}" --predicate-type https://cyclonedx.org/bom
done
check "provenance: image index" gh attestation verify "oci://$image" "${att[@]}"
for d in "${platform_digests[@]}"; do
	check "SBOM attestation: platform image $d" gh attestation verify "oci://${image%@*}@$d" "${att[@]}" --predicate-type https://cyclonedx.org/bom
done
refuse "provenance of SHA256SUMS for another ref" gh attestation verify SHA256SUMS --repo "$repo" \
	--signer-workflow "$repo/$workflow" --source-ref refs/heads/never-a-release-ref

if [[ $fail -ne 0 ]]; then
	echo "release verify: FAILED" >&2
	exit 1
fi
echo "release verify: every check passed for $identity"
