## Summary

<!-- What changed and why. Public repository: no hostnames, IPs, domains,
usernames, unit/service/stack names or paths from any real deployment. -->

## Definition of done (plan.md §7)

- [ ] `gofmt`/`golangci-lint run` clean; `go vet ./...` clean; `go test -race ./...` green; `govulncheck ./...` clean
- [ ] New behaviour has tests that were **verified to fail** against the pre-change code (the PR body names the commit or shows the failing run)
- [ ] Gate and helper parsers and path handling covered by Go native fuzz tests where touched
- [ ] No new tool without: input/output schema, annotations, `title`, tier + profile registration, gate op (and helper op for `shell_priv_*`) + policy tier, approval classification, a `docs/TOOLS.md` row, a catalogue-snapshot update, and tests
- [ ] `docs/ARCHIVE.md` §14 entry, dated, with the decision, the reasoning and the dependency versions in use
- [ ] Public-repo hygiene: no hostnames, IPs, domains, usernames, unit/service/stack names or paths from any real deployment in the diff, fixtures, commit messages or PR body; the local pre-push hook passed and the session reviewed the diff itself
- [ ] PR opened against `dev`, not merged, link posted; attribution footer stripped from the PR body and the live body re-read to confirm

## Failing-test evidence

<!-- The commit whose tests fail against the pre-change code, and the failing
output (trimmed). -->

## Verification report

| Check | Command | Result | Notes |
|---|---|---|---|
| gofmt | | | |
| go vet | | | |
| golangci-lint | | | |
| go test -race | | | |
| govulncheck | | | |
| deps-current | | | |
| fuzz | | | |
| e2e | | | |
| privacy review | | | |
| attribution footer | | | |
