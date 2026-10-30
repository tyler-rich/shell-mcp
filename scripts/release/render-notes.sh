#!/usr/bin/env bash
# release/render-notes.sh: the release notes: the CHANGELOG section (none for
# a pull request's dry run, NOTES_VERSION "-"), then how to verify what was
# published, with the image digest and the identity to pin.
#
#   bash scripts/release/render-notes.sh VERSION NOTES_VERSION IMAGE_REPO INDEX_DIGEST OWNER/REPO REF
set -euo pipefail

if [[ $# -ne 6 ]]; then
	echo "usage: $0 VERSION NOTES_VERSION IMAGE_REPO INDEX_DIGEST OWNER/REPO REF" >&2
	exit 2
fi
version="$1" notes_version="$2" image_repo="$3" digest="$4" repo="$5" ref="$6"
here="$(dirname "$0")"
if [[ "$notes_version" != "-" ]]; then
	bash "$here/notes.sh" "$notes_version"
	echo
fi
workflow=".github/workflows/release-build.yml"
cat <<EOF
## Verify

Image: \`${image_repo}:${version}@${digest}\` (linux/amd64, linux/arm64). Pin the digest.

\`SHA256SUMS\` lists every release file except itself and the Sigstore bundles. The binaries, the examples archive and \`SHA256SUMS\` are signed with Sigstore keyless signing (\`<file>.sigstore.json\`). Every file \`SHA256SUMS\` lists, and the image index, carry SLSA build provenance; \`SHA256SUMS\` itself has no attestation (\`gh attestation verify SHA256SUMS\` finds nothing), and its cosign signature covers it. The binaries and the platform images also carry CycloneDX SBOM attestations. Only the identity below is a release of this version; anything signed by another ref is not.

Run the \`cosign verify-blob\` command for each binary you use, the examples archive and \`SHA256SUMS\`, and the \`gh attestation verify\` command for each file you use that \`SHA256SUMS\` lists.

\`\`\`bash
cosign verify-blob --bundle shell-mcp-gate_${version}_linux_amd64.sigstore.json \\
  --certificate-identity https://github.com/${repo}/${workflow}@${ref} \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
  shell-mcp-gate_${version}_linux_amd64
\`\`\`

\`\`\`bash
sha256sum --ignore-missing -c SHA256SUMS
\`\`\`

\`\`\`bash
gh attestation verify shell-mcp-gate_${version}_linux_amd64 --repo ${repo} \\
  --signer-workflow ${repo}/${workflow} --source-ref ${ref}
\`\`\`

\`\`\`bash
cosign verify ${image_repo}@${digest} \\
  --certificate-identity https://github.com/${repo}/${workflow}@${ref} \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
\`\`\`

\`\`\`bash
gh attestation verify oci://${image_repo}@${digest} --repo ${repo} \\
  --signer-workflow ${repo}/${workflow} --source-ref ${ref}
\`\`\`
EOF
