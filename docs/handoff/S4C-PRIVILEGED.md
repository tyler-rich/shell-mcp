# S4c handoff: the privileged tools

> Session S4c-scope, 2026-10-18. Documentation only: no code, test or other non-doc file changes in this PR.
> It answers plan §5 (S4c) and scopes the `shell_priv_*` tools into implementation sessions.
> **Status: proposed, awaiting the maintainer's answers to §6.** Two findings in merged code (§0, §2.1) were raised during the session; the maintainer's decisions on them are recorded in §2.1 and §5 (S4c-0).
> This PR changes no locked document. Wording changes to plan.md, PRIVILEGED, TOOLS, ARCHITECTURE and POLICY are listed in §7, for the sessions to apply after approval.

## 0. Summary

**What exists.** The helper (S1c, S1d) implements every operation in PRIVILEGED §6 apart from recursive chown and chmod. The gate forwards all of them, routes them to the core or broad socket, and tier-checks them at the request's ceiling. The server has only the generic plumbing: privileged registration (admin profile only), the forwarding status in `shell_get_policy`, and the S4b approval core. **No `shell_priv_*` tool exists**, and the catalogue has no privileged rows.

**Where the helper falls short of the gate (§2).** The helper was built before the bar was raised in S4a–S4b-2b, and it has not been raised since.
- **Nothing binds the privileged policy into an approval.** The gate replaces the helper's response block with its own (`internal/gate/ops/priv.go`, `forward`). So the server only ever sees the *gate* policy's hash, and an edit to the privileged policy between approval and execution changes nothing it checks.
- **`priv_delete` still uses S1's `fsx.Delete`.** That code re-reads directories while it removes them, so it can delete an entry that appeared after the preview. S4b-2a already recorded this as required for S4c. It has no preview op and no `expected_preview_sha256`.
- **`priv_exec` has no preview op, and nothing binds the approved argv to the run.** The server also has no way to learn a command's unit (PRIVILEGED §6 leaves this to S4c).
- **Package operations simulate but do not bind.** The simulation has no hash, and nothing ensures the approved transaction is the one that runs. If the index or dpkg state changes between approval and run, a different transaction runs.
- **`priv_restore_backup` binds nothing.** It restores over whatever is at the path now, and a tree restore writes files without create-only commits.
- **The approval core knows nothing about privileged tools.** `Deps.gated` (`internal/tools/approval.go`) decides by tier alone, but D-006 says privileged operations of tier operator or above are *always* gated, whatever `SHELL_MCP_APPROVAL_TIERS` says.
- **TOOLS.md promises inputs the helper does not have:** `recursive` on chown and chmod, and `stdin` on `shell_priv_run_command` (§7).

**Two problems found in merged code** (reported mid-session; the maintainer's decisions are in §2.1):
1. **`priv_copy` ignores `modes.max`** (low). A new copy keeps the source's mode minus `7002`, even when the mask forbids those bits.
2. **`priv_chown` and `priv_chmod` act on the inode behind a hard link** (medium, maintainer's rating). That inode can also have a name outside the write roots, so root can change the mode or owner of a file the write roots do not cover.

Both are fixed in **S4c-0**, a standalone `fix(privd)` PR that comes before any feature work.

**Proposed split (§5).** Ten sessions:
- S4c-0: the fix above.
- S4c-1: privileged binding, approval plumbing and the read tools.
- S4c-2: write, mkdir, copy and move.
- S4c-3: chown and chmod, including recursive.
- S4c-4: delete.
- S4c-5: restore.
- S4c-6: exec.
- S4c-7: packages.
- S4c-8: power.
- S4c-9 (optional): a policy summary.

Each is one PR, Opus 5.5 at High (D-022).

**Protocol changes needed (§4):** a `helper` block on forwarded responses; seven new read-tier preview ops; `expected_preview_sha256` on nine ops (optional on `priv_exec`); `recursive` on chown and chmod; a hash on the package previews; an `applied` list on package results; and the gate forwarding the clamped `timeout_ms`. Each needs the maintainer's approval.

## 1. Inventory

### 1.1 Operations, tools and what exists today

"Gate" means the op is in `privTiers` (`internal/gate/ops/dispatch.go`) and is routed by `route` (`internal/gate/ops/priv.go`). Every op below has both. "Server" means a tool exists in `internal/tools`; **none does**.

| Op (PRIVILEGED §6) | Tool (TOOLS.md) | Tier · approval (D-006) | Unit | Helper implementation | Tests today (unit · e2e-host) |
|---|---|---|---|---|---|
| `priv_read_file` | `shell_priv_read_file` | read · no | core | `internal/privd/ops/files.go` `readFile` → `fsx.ReadFile` (deny list, private-key refusal, built-in redaction) | `TestReads`, `TestHelperDenyRefusalNamesTheRule` · `TestHelperOperations`, `TestCoreCannotReadProcessEnvironment` |
| `priv_list_dir` | `shell_priv_list_directory` | read · no | core | `files.go` `listDir` → `fsx.ListDir` | `TestReads` · `TestHelperOperations` |
| `priv_stat` | `shell_priv_stat_path` | read · no | core | `files.go` `stat` → `fsx.Stat` | `TestReads` · `TestHelperOperations` and the self-check cases |
| `priv_write_file` | `shell_priv_write_file` | operator · always | core | `files.go` `writeFile` → `fsx.WriteFile`/`writeAtomic` (`write.go`): owner from `owners`, mode within `modes.max`, `expected_sha256` or `expect_absent` (link commit), backup hook, read-back | `TestWriteFile`, `TestWriteReadBackFailure`, `TestPrivWriteExpectAbsent`, `TestPrivCreateOnlyCommitWindow`, `TestDefaultModesWithinMask`, `TestBackupFormat`, `TestBackupFailureChangesNothing` · `TestHelperWriteBackupRestore`, `TestHelperCreateOnly`, `TestGateCeilingPrivileged`, `TestAuditJournal` |
| `priv_mkdir` | `shell_priv_make_directory` | operator · always | core | `files.go` `mkdir` → `fsx.MkdirAs` (owner, mode, `parents`) | `TestMkdirChownChmod`, `TestDefaultModesWithinMask` · `TestHelperOperations`, `TestHelperCreateOnly` |
| `priv_chown` | `shell_priv_change_owner` | operator · always | core | `files.go` `chown` → `fsx.Chown` (`helper.go`; fchown on the opened file; no `recursive`) | `TestMkdirChownChmod` · `TestHelperOperations` |
| `priv_chmod` | `shell_priv_set_permissions` | operator · always | core | `files.go` `chmod` → `fsx.Chmod` (`write.go`; fchmod; no `recursive`) | `TestMkdirChownChmod` · `TestHelperOperations` |
| `priv_copy` | `shell_priv_copy_path` | operator · always | core | `files.go` `copy` → `fsx.Copy` (source in any root, link commit without `overwrite`, backup of a replaced destination) | `TestCopyMoveDelete`, `TestPrivNoReplaceUnsupported`, `TestPrivCreateOnlyCommitWindow` · `TestHelperOperations`, `TestHelperCreateOnly` |
| `priv_move` | `shell_priv_move_path` | operator · always | core | `files.go` `move` → `fsx.Move` (`renameat2` `RENAME_NOREPLACE` without `overwrite`, backup of a replaced destination) | as copy |
| `priv_list_backups` | `shell_priv_list_backups` | read · no | core | `backups.go` `listBackups` (metadata, newest first, `path` and `limit`) | `TestBackupRetention`, `TestBackupsDisabled` · `TestHelperOperations` |
| `priv_restore_backup` | `shell_priv_restore_backup` | operator · always | core | `backups.go` `restoreBackup`, `restoreTree`, `readData` (data SHA-256 checked; file restored with its recorded owner and mode, current version backed up first; tree only where nothing exists) | `TestRestoreFile`, `TestRestoreTree`, `TestRestoreRefusals` · `TestHelperWriteBackupRestore`, `TestHelperOperations` |
| `priv_delete` | `shell_priv_delete_path` | destructive · always | core | `files.go` `delete` → **`fsx.Delete`** (`delete.go`, S1: `deleteOp`, `backupTree`, `removeTree`) | `TestCopyMoveDelete`, `TestBackupFailureChangesNothing` · `TestHelperOperations` |
| `priv_exec` | `shell_priv_run_command` | per command · always for operator+ | the command's | `exec.go` `exec`: unit check, then tier, then `template.Match` with the privileged resolver, then `cwd`, then `execx.Run` (trampoline); no stdin; `max_output_bytes` | `TestExec`, `TestCeilingBoundsExec`, `TestTierDenied`, `TestWrongUnitRefusedBy*` · `TestHelperExecTrampoline`, `TestCommandDiesWithGateOrHelper`, `TestHelperStopKillsUserSwitchedCommand`, `TestHelperNoNetwork`, `TestHelperLandlock`, `TestHelperCapabilityBoundingSet`, `TestMisroutedRequestsRefused`, `TestGateCeilingPrivileged` |
| `priv_pkg_update_index` | `shell_priv_update_package_index` | operator · always | broad | `pkg.go` `pkgOp(OpUpdate)` → `internal/privd/pkg` `Args`, `Runner.Run` (lock retry) | `TestPkgPolicySwitches`, `TestPkgLock` · `TestPackages`, `TestPackageLock` |
| `priv_pkg_install` | `shell_priv_install_packages` | operator · always | broad | `pkgOp(OpInstall)`: names from `packages.install`, `--no-install-recommends` | `TestPkgInstall`, `TestPkgAllowList`, `TestPkgOutput` · `TestPackages`, `TestPackageUpgrade`, `TestPackageLock` |
| `priv_pkg_upgrade` | `shell_priv_upgrade_packages` | operator · always | broad | `pkgOp(OpUpgrade)`: `allow_upgrade` | `TestPkgPolicySwitches` · `TestPackageUpgrade`, `TestPackages` |
| `priv_pkg_remove` | `shell_priv_remove_packages` | destructive · always | broad | `pkgOp(OpRemove)`: names from `packages.remove`, never a purge | `TestPkgRemoveNeverPurges` · `TestPackages` |
| `priv_pkg_*_preview` (3) | (none: used by the package tools' approvals) | read · no | broad | `pkgOp(…, simulate)`: `apt-get -s`, `pkg.ParseSimulation`, `complete` | `TestPkgPreviews`, `FuzzParseSimulation` · `TestPackages`, `TestPackageUpgrade` |
| `priv_power` | `shell_priv_reboot_host` | destructive · always | broad | `power.go` `power` → `internal/privd/dbus` `StartUnit(<action>.target, replace-irreversibly)` | `TestPower`, `TestPowerRefusals`, `TestPowerSystemdRefusals` · `TestPowerReachesSystemd`, `TestMisroutedRequestsRefused` |

**Cross-cutting helper code.**
- `ops/serve.go` `Serve`, `authenticate`, `checks`, `sandbox`, `run`: the §7 order, and the `fsx.Config` built from the privileged policy, with a second `restoreFS` whose write bound is the 64 MiB backup limit.
- `ops/dispatch.go` `dispatch`, `within`: unit first, then tier against min(`max_tier`, `ceiling`).
- `ops/audit.go` `auditRequest`, `auditRefusal`, `sanitizeArgs`.
- `ops/sandbox.go` `Rules`, `ApplyLandlock`: Landlock in the core unit.
- `ops/backups.go` `store.save`, `prune`, `metas`, `readMeta`.
- `internal/privd/units`: the core and broad unit generator.
- `internal/privd/selfcheck`, `internal/privd/peercred`.

Tests for these: `TestSelfCheckFailuresAnswered`, `TestPreAuthRefusalsAreSilent`, `TestPeerCheckComesFirst`, `TestNoRequestByteReadBeforeChecksPass`, `TestCeilingRequired`, `TestCeilingBoundsOps`, `TestAuditLineCarriesCeiling`, `TestAuditNeverContent`, `TestUnitEnvironment`, `TestBroadCapabilitySet*`; e2e `TestUnitsVerify`, `TestSecurityExposure` (core unit 1.4), `TestSocketPermissions`, `TestHelperWrongPeerRefused`, `TestHelperOneInstancePerConnection`, `TestHelperPolicyHashMismatch`, `TestHelperPolicyInvalidAnswered`, `TestHelperUnitClientUID`, `TestHelperSystemdConfinesWithoutOwnChecks`, `TestCoreUnitHidesRunAndAbstractSockets`, `TestCoreProtectProc`, `TestBroadUnitNetwork`, `TestBroadProtectClock`.

### 1.2 What the server has

| Piece | Where | State |
|---|---|---|
| Privileged registration | `internal/tools/registry.go` `Register(tool, tier, privileged)`, `ProfilesOf`, `ToolsForProfile` | Works: `shell_priv_*` names are required for privileged tools and registered only in `admin`. Nothing is registered with it. |
| Effective tool list per target | `internal/tools/deps.go` `EffectiveTools` | Drops privileged tools when the gate's `privileged.enabled` is false. |
| Forwarding status | `internal/tools/policy.go` (`shell_get_policy`) | `privileged: {enabled, max_tier}` from the gate. Nothing about the privileged policy itself. |
| Approval core | `internal/tools/approval.go` `gated`, `approveCall`, `perTierCall`, `ungatedCeiling`; `preview` struct; `internal/approval` | Tier-only gating: `gated(t)` has no notion of privileged. `preview.policy` holds one hash, which for a forwarded op is the gate's. |
| Catalogue | `cmd/shell-mcp/testdata/catalogue*.json` | No privileged rows. |

## 2. Gap analysis

**Legend.**
- **MUST**: must be fixed before the tool is exposed.
- **DOC**: acceptable once it is documented (in PRIVILEGED, TOOLS or ARCHIVE, as named).
- **OK**: meets the current bar.
- **n/a**: does not apply.

**The bar** is what the gate has reached since S4a:
- **create-only commits are atomic:** `expect_absent`, `Root.Link`, `renameat2` with `RENAME_NOREPLACE`, and no check-then-rename fallback;
- **previews bind the operation:** a preview hash that the operation recomputes (`expected_preview_sha256`), or a content precondition;
- **set-aside deletion:** entries are set aside under `.shell-mcp-delete-<32 hex>`, and stranded entries are named, refused and recoverable;
- **approval:** bound to principal, tool, target, arguments, preview and policy, with a fresh preview on the re-call;
- **per-tier approval:** an unapproved operation is sent at the highest tier that needs no approval;
- **audit:** ids, paths and flags, never content or hashes;
- **read-back verification:** a mismatch is a failure, never a warning.

### 2.1 Findings in merged code (raised mid-session; maintainer decisions)

**F-1. `priv_copy` ignores `modes.max`.**
- **Severity:** low.
- **Code.** A new copy's mode is the source's mode minus setuid, setgid, sticky and world-write: `internal/gate/fsx/write.go:479-480`, `srcMode := os.FileMode(unixMode(fi)) &^ 0o7002`. The helper passes it through unchecked (`internal/privd/ops/files.go:272-282`).
- **What the docs require.** PRIVILEGED §4 says "no bits outside this mask", and §6 says "modes within the mask" for `priv_copy`.
- **Example.** Under `modes.max: "0700"`, copying a `0644` file from a read root gives a `0644` file in a write root.
- **Who can reach it.** Anything that can send `priv_copy` through the gate, which today means a compromised server or service account. That is exactly the threat the privileged policy defends against (PRIVILEGED §3).
- **Who is exposed.** Other local users, not only the caller: a `0644` file inside a restricted directory becomes readable once copied out.
- **Decision:** fix in S4c-0 by clamping, not refusing (§5).

**F-2. `priv_chown` and `priv_chmod` change an inode that can also have a name outside the write roots.**
- **Severity:** medium (maintainer's rating: it can escalate, not only leak).
- **Code.** `fsx.Chown` (`internal/gate/fsx/helper.go:142-182`) and `fsx.Chmod` (`write.go:600-626`) fchown or fchmod the opened file. They refuse symlinks, special files and setuid/setgid/sticky files, but they never look at the link count.
- **Example.** `example-app` can read and write `/etc/example-app/app.conf` (`root:example-app 0660`). `/etc` is outside the write roots and read-only under `ProtectSystem=strict`.
  - It hard-links the file into a write root on the same filesystem. `fs.protected_hardlinks` allows that, because it has read and write access to the file.
  - `priv_chmod 0644` on that name then makes the `/etc` file world-readable.
  - `priv_chown` can hand the file to an allow-listed owner.
- **Why no other layer stops it.** `ReadWritePaths=` limits paths, not inodes, and Landlock has no chmod or chown right.
- **Not affected:** `priv_write_file`, `priv_mkdir`, `priv_copy`, `priv_move` and `priv_restore_backup`. Each one commits a new inode by rename, or creates a new entry.
- **Decision:** fix in S4c-0. Refuse a non-directory whose link count is above 1, with the count read by fstat on the same descriptor that fchown or fchmod acts on (§5).

**F-3. Not a bug, but surfaced by the same audit.** `priv_restore_backup` restores the recorded owner and mode without checking either against `owners` or `modes.max`.
- PRIVILEGED §6 says it does exactly that ("with its recorded owner and mode"), so the code matches the document.
- S4c-0 audits it with the other ops and reports the result. What it should do is open question Q3.

### 2.2 Cross-cutting gaps

| # | Gap | Rating | Fix |
|---|---|---|---|
| X-1 | **The privileged policy is not bound into approvals.** The gate's `forward` returns the helper's `ok`, `data`, `error` and `warnings` under the gate's own block, so the helper's `policy_sha256` never reaches the server. `preview.policy` is the gate's hash, and an edit to the privileged policy between approval and re-call goes unnoticed. D-006 binds "the gate policy" only. | **MUST** | Protocol P-1: a `helper` block on forwarded responses. The server binds both hashes (D1). Dedicated preview ops also hash `policy_sha256` themselves (D2). |
| X-2 | **The approval core ignores "privileged".** `gated(t)` is tier-only, so with the default `SHELL_MCP_APPROVAL_TIERS=destructive` a privileged operator tool would run unapproved. That violates D-006. `ungatedCeiling` has the same blind spot. | **MUST** | D9: `gated(t, privileged)`. Privileged operator and destructive tools are always gated. For `shell_priv_run_command` the ungated ceiling is `read`. |
| X-3 | **No tools, no catalogue rows, no descriptions**, and `requiresUserInteraction` is not set on them. | **MUST** | Every session adds its tools (§5). Gated privileged tools carry the meta in every catalogue variant, as the destructive tools do. |
| X-4 | **Unclamped timeouts.** The gate clamps its own wait to its `limits.max_timeout_s` (≤ 600) plus 15 s, but forwards the request's `timeout_ms` unchanged. The helper clamps only to its own `max_timeout_s` (≤ 1800). So for a request whose timeout is above the gate's limit, the gate answers `timeout` while the helper's command or apt transaction carries on and may complete. The caller is told nothing ran to completion when it may have. | **MUST** for exec and packages | P-7: the gate forwards `timeout_ms` clamped to what it will wait for. The `timeout` message for privileged ops also says the operation may still complete on the host (S4c-6, S4c-7). |
| X-5 | **Redaction.** The helper redacts with the built-in rules only (`redact.New(nil)`; the privileged policy has no patterns). The server applies its own built-in rules and `SHELL_MCP_REDACT_PATTERNS` after that. | DOC | PRIVILEGED §8 or §6 says so. A privileged `redact` key would be a schema change, and is not proposed. |
| X-6 | **The gate's audit line for a privileged op** omits `owner`, `group`, the backup `id` and `packages`, because `loggedArgs` lacks them. The helper's line has them, and the two join on the request id. | DOC | ARCHITECTURE §2 notes the join. Adding them to `loggedArgs` is optional; not proposed. |
| X-7 | **The backup store has no global bound.** Each backup is ≤ 64 MiB and `backups.keep` applies per path, but the number of distinct paths is not bounded. Repeated writes across many paths can fill `/var/lib`. | DOC (Q10) | PRIVILEGED §6 says it, and advises monitoring. A quota would be a schema change. |
| X-8 | **Pruning runs before the operation commits.** `store.save` prunes as soon as the new backup exists. An operation that then fails (verify, a lost race) has still pruned an older version. A restore can also prune the very backup it is restoring, if that backup is the oldest kept (its data is already in memory, so the restore itself succeeds). | DOC → fix (Q12) | Prune after the operation succeeded, and never the backup being restored (S4c-2 and S4c-5). |
| X-9 | **Backups are not tied to approvals.** A backup's metadata records `op` and `request_id`, but not the preview it belongs to. | DOC → fix | The metadata records `preview_sha256` when the op carried one (a local file format, not the wire; D3). |
| X-10 | **Read-back of metadata.** Chown and chmod do not re-read what they set. Writes verify their content. | **MUST** (cheap) | fstat the same descriptor after fchown or fchmod; a mismatch is `verify_failed` (S4c-0 for the non-recursive ops, S4c-3 for recursive). |

### 2.3 Per operation

Columns: create-only · preview binding · set-aside/stranded · approval and re-call · tier/ceiling · audit · sandbox · backups · owners · modes · read-back.

**Read ops (`priv_read_file`, `priv_list_dir`, `priv_stat`, `priv_list_backups`).**
- **OK:** create-only, preview binding, set-aside and approval are n/a. The tier ceiling is `read`. The audit logs paths and bounds. They run in the core unit under Landlock, with read roots only. The deny list and the private-key refusal apply.
- **MUST:** the tools (S4c-1).
- **DOC:** redaction (X-5). `priv_list_backups` lists backups of paths that are no longer roots, or are now denied. Only metadata is shown, and a restore re-checks the current roots.

**`priv_write_file`.**
- **Create-only: OK.** `expect_absent` commits with a hard link (`writeAtomic`), and `TestPrivCreateOnlyCommitWindow` covers it.
- **Preview: MUST.**
  - The server composes it from `priv_stat` and `priv_read_file`, as the gate's write preview does.
  - It also shows the current owner, group and mode, the requested ones, the resulting ones, and whether a backup will be written.
  - The privileged policy is bound through P-1.
  - The re-call sends `expected_sha256` of the fresh preview's content, or `expect_absent` when it saw no file (OK, existing fields).
- **DOC: the existing file's mode and owner are not bound at commit.** A chmod of the existing file between the fresh preview and the commit is kept, because `writeAtomic` preserves the current mode and owner when none is given (Q17).
- **DOC: no content hash above 256 MiB.** `read_file` gives no SHA-256 above `maxHashBytes` (256 MiB). Such a file cannot be overwritten with backups on (64 MiB limit), so the preview refuses to request an approval without a content hash, rather than approve an unbound overwrite.
- **Backups: OK.** The hook runs through verified descriptors, and `unchangedSince` checks the file before the commit. Add an assertion that the backup's SHA-256 equals the previewed `current.sha256`; it holds by construction through `expected_sha256`, but the check is cheap (S4c-2). Pruning: X-8.
- **Owners: OK.** **Modes: OK.** An explicit mode is checked against `modes.max`, and new files get `0640 & modes.max`. An existing file keeps its mode, and `TestDefaultModesWithinMask` tests that.
- **Read-back: OK.** **Audit: OK.** It logs `path`, `owner`, `group`, `mode`, `create`, `expect_absent` and `backup_ids`, never content. **Sandbox: OK** (core).

**`priv_mkdir`.**
- **Create-only: OK.** `mkdirIn` relies on `mkdir`'s own `EEXIST`, and `MkdirAs` without `parents` refuses an existing directory.
- **Preview: MUST, server-side.** A `priv_stat` of the path. With `parents`, also of each missing ancestor up to the first that exists (bounded by the path's depth). The preview lists the directories that will be created and their owner and mode.
- **Owners: OK.** **Modes: OK**, including the default `0750 & modes.max`. **Backups: n/a.** **Read-back: OK.** The created directory is re-opened and verified (`openSubdir`).

**`priv_chown`, `priv_chmod`.**
- **F-2: MUST (S4c-0).** The hard-link refusal.
- **Recursive: MUST if TOOLS keeps it** (Q2). The helper has no `recursive`, and the protocol has no field for it (P-4).
- **Preview binding: MUST.** The gate's own chmod has a stat preview and no commit precondition. For root the bar is higher:
  - a dedicated preview op (`priv_chown_preview`, `priv_chmod_preview`; P-2) returns the identity, owner and mode of every entry, and `preview_sha256`;
  - the op recomputes it (`expected_preview_sha256`, P-3), and applies each change on a descriptor whose identity it checks (D4).
- **Set-aside: n/a.** Nothing is removed. A tree holding a `.shell-mcp-delete-*` name is refused, as the delete refuses it.
- **Owners: OK.** **Modes: OK.** setuid, setgid and sticky files are never changed.
- **Read-back: MUST** (X-10).
- **Backups: DOC.** Metadata is not backed up; the preview and the audit carry the old values (Q8).

**`priv_copy`.**
- **F-1: MUST (S4c-0).**
- **Create-only: OK.** A link commit without `overwrite`.
- **Preview: MUST, server-side.** Two `priv_stat`s. It must show the source's mode, owner and size, and the destination's mode and owner when the destination exists. With `overwrite`, the existing destination keeps *its* mode and owner (`writeAtomic`), so root-only content can land in a world-readable file. The approver must see that.
- **DOC: the source's content is not bound.** A change between the fresh preview and the commit, one round trip, is copied. The fresh preview catches anything earlier (Q15).
- **Backups: OK.** A replaced destination is backed up. **Read-back: OK.** **Private-key refusal: OK.**

**`priv_move`.**
- **Create-only: OK.** `renameat2` with `RENAME_NOREPLACE`.
- **Preview: MUST, server-side.** Two `priv_stat`s, as the gate's.
- **DOC: a directory move's contents are not previewed.** The move checks deny and protected rules at every new path (`walkTree`) and moves the inode, so the mode and owner are the inode's own.
- **Backups: OK.** A replaced destination file is backed up. **Owners and modes: n/a**, since the inode is unchanged.

**`priv_restore_backup`.**
- **Preview: MUST.** There is none.
  - A dedicated `priv_restore_preview` (P-2) returns the backup's metadata (id, kind, path, size, SHA-256, owner, group, mode, created, op) and the current state at the path.
  - For a file, the current state is absent, or the file with its size, mode, owner and SHA-256; a tree needs nothing there now.
  - It also returns the owner and mode the restore will set, whether the current version will be backed up, `policy_sha256` and `preview_sha256`.
- **Restoring over a changed file: MUST.**
  - The restore recomputes the preview (`expected_preview_sha256`).
  - It then writes with `expected_sha256` of the content it previewed, or with `expect_absent` when it previewed nothing.
  - So a file changed after the preview is refused with `exists`, and an approval to restore over "absent" never replaces a file that appeared (D3).
- **Create-only in tree restores: MUST.** `restoreTree` writes files with `Create: true` and no `expect_absent`, so a file planted inside a just-created directory is replaced (after being backed up). Use `expect_absent` for files; directories already rely on `mkdir`'s `EEXIST`.
- **Owners and modes: F-3 / Q3.** **Backups: OK** (the current version is backed up first). Pruning: X-8. **Read-back: OK** for files. For trees, each file is verified by `WriteFile`; add an entry-count check against the metadata.

**`priv_delete`.**
- **Preview binding and set-aside: MUST.** Port the gate's `PreviewDelete` and `DeleteExact` (`delete_exact.go`) into the helper's op, with:
  - `priv_delete_preview` (P-2) and a required `expected_preview_sha256` (P-3);
  - the walk's refusals: roots, mount points, devices, set-aside names;
  - the set-aside deletion, and the stranded-entry naming (`fsx.Error.SetAside`), carried into the helper's audit line as `set_aside`.
  - S4b-2a's follow-up already lists this as required.
- **Backups: MUST, design D10.** The tree backup must hold exactly what is deleted. Today `backupTree` walks separately from the deletion.
- **Approval: always (destructive).** **Ceiling: `destructive`.** **Sandbox: OK.** Write roots grant `MAKE_*`, `REMOVE_*` and `REFER`. `PrivateDevices=yes` drops `CAP_MKNOD`, so device nodes are refused in the walk, as the gate refuses them.
- **DOC: trees holding a symlink or special file are refused while backups are on.** The tar backup holds directories and regular files only.

**`priv_exec`.**
- **Preview binding: MUST.** There is no preview op.
  - A helper `priv_exec_preview` (P-2) resolves the request through the same function as `priv_exec`: unit, tier, `template.MatchIndex`, the privileged resolver, `cwd`.
  - `priv_exec` takes `expected_preview_sha256` (P-3) and refuses `exists` on a mismatch.
  - The gate's `exec_preview` cannot be reused: the gate cannot read the privileged policy, and the helper resolves path placeholders in its own unit's mount namespace (D6).
- **Routing: MUST** (D6). The server cannot know a command's unit.
- **Per-tier approval: MUST** (X-2). Read commands are never gated; operator and destructive commands always are. Unapproved calls are sent at ceiling `read`, so a command whose tier rose after the preview is refused by the helper's tier check (`tier_denied`).
- **Stdin: DOC.** It is fixed in TOOLS (§7, Q11).
- **Timeout: MUST** (X-4).
- **Audit: OK.** It logs `command_id`, `arg_count`, `cwd` and `unit`.
- **Sandbox: OK.** Core commands run under Landlock and the core unit. Broad commands get no Landlock, are root-equivalent, and are audited at WARN.

**Package ops.**
- **Preview binding: MUST** (D5).
  - The simulation has no hash, and the operation does not compare against one.
  - The index or dpkg state can change between approval and run. Also, `apt-get upgrade` at run time upgrades whatever is upgradable *then*.
  - Fix: a `preview_sha256` over the transaction and the policy hash, and a required `expected_preview_sha256` that the operation compares against by re-simulating with the same argv.
  - The run pins versions and adds `--no-remove` where apt allows it. A dpkg-status diff after the run is compared with the approved transaction; a mismatch is `verify_failed`.
  - An incomplete simulation (`complete: false`) is never approvable.
- **Update index: MUST** (a preview of some kind). There is nothing to simulate, so `priv_pkg_update_index_preview` (P-2) returns the argv and the policy hash, and the approval binds the action.
- **Lock: OK.** **Timeout: MUST** (X-4). **Audit: OK.** WARN, with package names. **Backups: DOC.** Package operations write no backups; dpkg's `--force-confold` keeps existing configuration files, and dpkg and apt keep their own logs (D8). **Sandbox: OK** (broad, root-equivalent by design).

**`priv_power`.**
- **Preview: MUST, small.** `priv_power_preview` (P-2) returns the action, the target unit, the job mode and the policy hash. It refuses an action that `power.allowed` does not list, so no approval is requested for it.
- **Binding:** `expected_preview_sha256`.
- **Approval: always.** **Ceiling: `destructive`.** **Audit: OK** (WARN). **Sandbox: OK** (broad; the bus is reachable only from there).

## 3. Design decisions

### D1. Binding the privileged policy

| Option | For | Against |
|---|---|---|
| **H1.** Only dedicated preview ops return `policy_sha256` in their data. | No response change. | Previews composed from `priv_stat` and `priv_read_file` (write, mkdir, copy, move) stay unbound. Every op would need its own preview op. |
| **H2.** The gate passes the helper's own block through as `helper` on every forwarded response (P-1). The server binds `gate.policy_sha256` and `helper.policy_sha256` together. | One change covers every privileged preview, including stat-based ones. The helper already fills that block (`respond` in `serve.go`). | A response field. |
| H3. A hello-style privileged op that returns the policy hash, called with every preview. | No response change. | An extra round trip, and a window between that call and the preview. |

**Recommendation: H2, plus the hash inside every dedicated preview op's own `preview_sha256`.**
- **On the server.** The record's `PolicySHA256` becomes the SHA-256 of `gate:<hash>\nhelper:<hash>`. This is internal, and the record struct does not change.
- **Why this one.** H2 is the only option that binds the composed previews without a new op per operation.
- **Why both.** Hashing the policy inside the dedicated preview ops also binds it *at the operation*, in the same request as the recompute, which closes the last round trip for the ops that destroy or replace.
- **Locked-decision change.** D-006's "of the gate policy" becomes "of the gate policy and, for privileged operations, of the privileged policy" (§7, Q1).

### D2. Which preview pattern each op uses

| Op | Preview | Commit precondition | Why |
|---|---|---|---|
| `priv_write_file` | composed: `priv_stat`, `priv_read_file` | `expected_sha256` or `expect_absent` (existing) | Same as the gate. The content hash binds what is replaced, and the link commit binds "create". |
| `priv_mkdir` | composed: `priv_stat` (and ancestors) | none (`mkdir` is exclusive) | Same as the gate. |
| `priv_copy`, `priv_move` | composed: two `priv_stat`s | none; without `overwrite`, the atomic no-replace commit | Same as the gate. A replaced destination is backed up. |
| `priv_chown`, `priv_chmod` | **`priv_chown_preview`, `priv_chmod_preview`** | **`expected_preview_sha256`** | Root changes metadata in place, and the inode at the path must be the one approved (D4). |
| `priv_restore_backup` | **`priv_restore_preview`** | **`expected_preview_sha256`**, then `expected_sha256` or `expect_absent` | Binds both the backup and what it replaces (D3). |
| `priv_delete` | **`priv_delete_preview`** | **`expected_preview_sha256`** (required) | The gate's S4b-2a design (D10). |
| `priv_exec` | **`priv_exec_preview`** | **`expected_preview_sha256`** (optional on the wire, always sent) | The gate's S4b-2b design (D6). |
| `priv_pkg_install`, `_upgrade`, `_remove` | existing `priv_pkg_*_preview`, **gaining `preview_sha256`** | **`expected_preview_sha256`** (required), plus pins and post-run verification | D5. |
| `priv_pkg_update_index` | **`priv_pkg_update_index_preview`** | **`expected_preview_sha256`** (required) | Binds the action and the policy. |
| `priv_power` | **`priv_power_preview`** | **`expected_preview_sha256`** (required) | Binds the action and the policy, and refuses a disallowed action before an approval is requested. |

**Rejected:**
- **A dedicated preview op for every op**, write and mkdir included. These would duplicate preconditions that already bind exactly what changes.
- **A generic `priv_preview {op, args}`.** One op whose answer depends on another op's name. It is harder to tier-check and route (its unit depends on the inner op), and harder to fuzz.

**Rule for all of them.** Each preview op runs in the same unit as its operation, and through the same resolution code: the ops never compute their own preview hash another way.
- The server takes `preview_sha256` from the helper's answer before redaction (as `shell_delete_path` does).
- A preview op refuses whatever the op would refuse (path, owner, mode, allow-list, tier). Then no approval is requested.

### D3. Backups: creation, binding, retention and restore

**Unchanged.**
- **Where:** `/var/lib/shell-mcp/backups`, `root:root 0700`. It is on list A, `ReadWritePaths=`, Landlock read-write, and the built-in deny list.
- **Names:** `<id>.data` or `<id>.tar` beside `<id>.meta.json`, with `<id>` = `YYYYMMDDTHHMMSSZ-<16 hex>`.
- **Atomic creation:** temporary names, fsync, rename data first then metadata, then a directory fsync. A backup exists exactly when its metadata does.
- **The 64 MiB bound,** and the `unchangedSince` check after the backup and before the commit.

**Changes.**
1. **The backup is bound to the preview.**
   - The metadata gains `preview_sha256` when the request carried an `expected_preview_sha256` or an `expected_sha256` (the latter for writes). This is a local file format: `meta.V` stays 1, with a strict decoder that accepts the new optional field.
   - For a file, the backup's SHA-256 must equal the previewed content hash, or the op fails with `backup_failed` and changes nothing.
   - For a tree, the tar is written from the same plan the deletion walks, entry for entry (D10).
   - Every preview says whether a backup will be written: kind and bytes, `backups.keep` 0 meaning none. A backup that would exceed 64 MiB makes the preview refuse with `backup_failed` before any approval is requested.
2. **Retention.** `prune` runs after the operation has succeeded, not inside `save`, and never removes the backup the current request restores from (X-8, Q12). `backups.keep` stays per path.
3. **Restore, safely.**
   - `priv_restore_preview {id}` reads the metadata and the data, and checks the data's SHA-256. It then states the current state at the path and what will be set.
   - `priv_restore_backup {id, expected_preview_sha256}` recomputes that preview, and refuses `exists` on a mismatch.
   - Then:
     - **A file:** `WriteFile` with `expected_sha256` = the previewed current content, or `expect_absent` when there was none. The current version is backed up first (existing). A file changed between the recompute and the commit is refused by the content check at the commit: `exists`, nothing changed.
     - **A tree:** only where nothing exists. The root and each directory are created with `mkdir` (exclusive), and each file with `expect_absent`. The entry count must equal the metadata's `entries`.
       - A tree restore that stops part-way leaves what it created.
       - The message says how many entries were restored. Preview again, or delete the partial tree, and restore again.
   - **Restoring over a changed file** is therefore never silent. If the file changed after the approver looked, the restore is refused. If it changed in the last round trip, the commit refuses it.
4. **Owner and mode on restore** follow Q3. Recommended: the recorded owner and group, even outside `owners`, because they are the file's own previous owner and are shown on the approval page; the recorded mode clamped to `modes.max`, as F-1's copy fix does.

### D4. Recursive chown and chmod: preview and binding

| Option | For | Against |
|---|---|---|
| **R1.** A walk like `PreviewDelete`: each directory opened from its parent's handle and re-checked; a hash over every entry's path, type, device, inode, mount id, birth time, uid, gid and mode; the op recomputes it, then applies each change on a descriptor opened by name, checking its identity before the change. | The same machinery as the delete, and exact. | Code. |
| R2. A non-recursive walk at the server, one `priv_stat` per entry. | No new op. | Unbounded round trips, and no binding at the commit. |
| R3. Drop `recursive` from v1 (TOOLS change). | No code. | A common root need, `chown -R` of an application directory, is missing. |

**Recommendation: R1 (Q2).** The rules, mirroring the delete's where they apply:
- **Refused, as in a delete:** roots, mount points, device nodes, FIFOs and sockets, and `.shell-mcp-delete-*` names.
- **Never followed:** symlinks inside the tree are reported, and neither followed nor changed (no `lchown`).
- **Refused for these ops:** setuid, setgid and sticky files, and non-directories with a link count above 1 (F-2; checked on the same descriptor, as S4c-0 does).
- **Size bound:** `limits.max_delete_entries`, which avoids a schema change (Q2).
- **At each entry, before the change:** device, inode, type, mount id and birth time.
- **At the recompute only:** uid, gid and mode, because the change itself moves the change time. The change time is never compared after a change.
- **When it stops:** a mismatch stops with `exists`, "N of M entries were changed and K were not". There is no rollback; the counts are reported, consistent with the delete and the discard (Q8).
- **Read-back:** fstat after each change on the same descriptor (X-10).

### D5. Package operations: preview, binding, index changes

**The problem.**
- `apt-get` takes the dpkg frontend lock itself, so the helper cannot hold the lock across a simulation and the real run.
- The real run resolves again against whatever index and status exist at that moment.
- `apt-get upgrade` upgrades everything upgradable at run time.

| Option | For | Against |
|---|---|---|
| P1. Re-simulate under the same argv just before the run, compare `preview_sha256`, and run. | Simple. | A window between the re-simulation and apt-get taking the lock (an index update by a timer or another admin). Nothing checks what actually ran. |
| **P2.** P1, plus pins, `--no-remove`, and a post-run dpkg-status diff compared with the approved transaction (`verify_failed` on a mismatch). | Bounds what can run, and reports honestly when the host moved under it. | apt semantics must be verified at the source (below). The status-file parser is new code to fuzz. |
| P3. Download the approved `.deb`s, verify their hashes, and install them with `dpkg -i`. | Exact bytes. | Bypasses apt's resolver, triggers and ordering. Root-equivalent maintainer scripts run either way. Much more code. |
| P4. Hold the lock and tell apt-get it is held. | No window. | apt-get has no such mode (dpkg's `DPKG_FRONTEND_LOCKED` is for dpkg under a frontend, not for apt-get). Unverified, and likely impossible. |

**Recommendation: P2 (Q4).**

1. **The preview.**
   - `preview_sha256` covers the op, the requested names, the sorted `install` (name, version), `upgrade` (name, from, to) and `remove` (name, version, purge) lists, the argv and `policy_sha256`.
   - It excludes stderr, durations and attempts.
   - `complete: false` or a non-zero exit is refused as `exec_failed` ("the simulation was incomplete; nothing was requested"), and no approval is requested.
2. **Index changes after approval.** The re-call's fresh preview re-simulates. A different transaction (a new candidate version, a new dependency, a removal) changes the hash, and the answer is `approval_invalid`. An index change that leaves the transaction identical lets it proceed: that is the approved transaction.
3. **At the operation,** in the broad instance, in order:
   - read and hash the dpkg status (bounded);
   - re-simulate and compare `expected_preview_sha256`, refusing with `exists` and changing nothing on a mismatch;
   - run with the pinned argv:
     - **install:** the requested names as `name=version` from the approved transaction, plus `--no-remove`;
     - **upgrade:** `install --only-upgrade --no-remove --no-install-recommends -- name=to …` over exactly the approved upgrade list, instead of `apt-get upgrade`;
     - **remove:** the names, without pins (there is no candidate to pin);
   - read the dpkg status again and diff it.
4. **Verification.**
   - The diff (installed, upgraded with from/to, removed) must equal the approved transaction. Otherwise `verify_failed`, "the transaction differed from the approved one: N packages …; preview again", with the dpkg log as evidence. It cannot be undone, and it is never a success with a warning.
   - On success the result gains `applied` (P-6).
   - **Index changes between the comparison and the lock** are what this step catches.
5. **To verify at the source before implementing** (S4c-7 STOP conditions):
   - apt 3.0.3 (Debian 13) and the 3.1.x in Ubuntu 26.04:
     - that `name=version` resolves to the same transaction as the unpinned request when the candidate is that version;
     - `--no-remove` ("immediately aborts" if anything would be removed);
     - `--only-upgrade` with explicit names: no new packages installed, and whether it marks auto-installed packages as manual. If it does, `apt-mark` must not be used to repair it; STOP;
     - whether `-s` output for the pinned argv is the same as for the unpinned one.
   - dpkg's status format: `Package`, `Architecture`, `Status`, `Version`; multi-arch qualifiers.

**Why not trust the simulation alone.** On a host with apt timers, unattended upgrades or another administrator, "what apt-get resolves at run time" is not the transaction the approver saw unless something pins it and checks it afterwards.

### D6. `priv_exec`: preview and unit routing

**Preview.** A helper `priv_exec_preview`, not the gate's `exec_preview`.
- The gate cannot read the privileged policy, so it cannot resolve the command, its unit, its tier or its templates.
- `{path:read}` and `{path:write}` resolve against the privileged roots in the helper unit's own mount namespace. The core unit has `ProtectSystem=strict`, `PrivateTmp`, and `/run` as an empty tmpfs, so a path resolved in the gate's namespace or the other unit's could differ.
- `priv_exec_preview` refactors `exec` into one resolver function (`resolveExec`, as the gate did in S4b-2b). It returns `command_id`, `tier`, `unit`, `description`, `root_equivalent`, `capabilities`, the matched `template`, the resolved `argv` and `cwd`, `policy_sha256` and `preview_sha256`.
- `priv_exec` with `expected_preview_sha256` resolves again and refuses `exists`, running nothing, on a mismatch.

**Routing: how the server learns the unit.**

| Option | For | Against |
|---|---|---|
| U1. The gate reads the privileged policy. | — | It cannot (`0600`, root), and the helper must stay authoritative (S1d). |
| U2. The core instance answers previews for broad commands too. | One round trip. | It would resolve broad commands' paths in the wrong namespace, and break "an op meant for the other unit is refused before anything else". |
| U3. A privileged policy summary op tells the server each command's unit. | Useful anyway (Q6). | Discloses privileged policy values on the wire, which S1d deliberately avoided. A policy edit between the summary and the preview races. |
| **U5.** The server sends `priv_exec_preview` to the core socket without a label. If the answer is `helper_wrong_unit`, it sends it again with `unit: broad`. | No disclosure, no new op, and the helper stays authoritative. Deterministic: there are exactly two units, and `exec` already checks "declared" and "unit" before the tier. | One extra round trip for broad commands. |

**Recommendation: U5 (Q5).**
- The preview's `unit` is in its hash. The re-call sends the fresh preview's `unit` label with `priv_exec`, and the gate routes by it (existing code).
- A policy edit that moves a command to the other unit changes the hash (`approval_invalid`). Between the fresh preview and the exec, the instance refuses the mislabelled request (`helper_wrong_unit`).

**Gating.** Per-tier, as `shell_run_command`, with D-006's privileged rule:
- read commands: never gated;
- operator and destructive commands: always gated;
- unapproved calls: ceiling `read`;
- approved calls: the command's tier.

### D7. Core unit or broad unit, per op

| Unit | Ops | Why |
|---|---|---|
| **Core** | all file ops, backups, `priv_delete`, `priv_restore_backup` and their previews, core commands' `priv_exec` and `priv_exec_preview`, `priv_policy` (if Q6) | Landlock, `ProtectSystem=strict` with write access only to declared paths, four capabilities, no network, no local IPC. Nothing here needs more. |
| **Broad** | `priv_pkg_*` and every package preview (including `priv_pkg_update_index_preview`), `priv_power` and `priv_power_preview`, broad commands' `priv_exec` and `priv_exec_preview` | apt needs the network and writes `/usr`; power needs the system bus, which the core unit must never reach (S1d). Previews run in the same unit as their op so they resolve and simulate in the same environment. |

The gate's `broadOps` and the helper's `broadOps` both gain `priv_pkg_update_index_preview` and `priv_power_preview`. `priv_exec_preview` is routed by its `unit` label, like `priv_exec`.

### D8. Audit and journal evidence, per op

| Op | Helper journal (`shell-mcp-privd`) | Gate syslog | Server JSON | Other evidence on the host |
|---|---|---|---|---|
| reads | info: id, ceiling, peer, op, `path`, bounds | id, principal, op, `path` | tool call | — |
| write, mkdir, copy, move | info/notice: `path` (`source`, `destination`), `owner`, `group`, `mode`, `create`, `parents`, `overwrite`, `expect_absent`, `backup_ids` | id, principal, op, paths and flags (`owner` and `group` only in the helper's line, X-6) | tool call with `approval_id`, `approval_outcome` | backups' metadata (`op`, `request_id`, `preview_sha256`) |
| chown, chmod | as above, plus `recursive` and the entries changed (new field `changed`) | paths, `recursive` | as above | — |
| delete | `path`, `recursive`, `backup_ids`, `set_aside` (new, as the gate's) | `path`, `recursive`, `set_aside` | as above | the tree backup |
| restore | `backup_id`, `backup_ids` (the current version's) | — (only the backup id, which the gate does not log) | as above | both backups' metadata |
| exec | `command_id`, `arg_count`, `cwd`, `unit` (WARN in broad) | `command_id`, `cwd`, `unit`, `arg_count` | as above, `args_count` | — |
| packages | WARN: `packages`, and on success the `applied` counts (new) | op | as above, `packages` | `/var/log/apt/history.log`, `/var/log/apt/term.log`, `/var/log/dpkg.log` |
| power | WARN: `action` | op, `action` | as above | systemd's own shutdown journal |

Never logged, anywhere: content, command arguments, output, and `expected_preview_sha256`. The preview hash *is* recorded in the backup metadata, which is root-only and part of the evidence, not a log.

### D9. Approval for privileged tools

- `gated(t Tier, privileged bool)`: `t == destructive`, or `t == operator && (privileged || operator ∈ SHELL_MCP_APPROVAL_TIERS)`.
- `ungatedCeiling` for a privileged tool is `read`.
- Every gateable privileged tool carries `approval_id` (and `confirm` under `confirm-argument`). It has `requiresUserInteraction` in every catalogue variant, because it is always gated.
- **Descriptions:**
  - "As root, write N bytes to `<path>` on `<target>`"; "As root, delete `<path>` …"; "As root, run command `<id>` with N arguments in the `<unit>` unit on `<target>`"; "Install N packages on `<target>`"; "Reboot `<target>`".
  - Every description says "as root".
  - A path that is not plain is "a path shown in the arguments", as today.
- **Registration.** Read tools at `read`. Operator ops at `operator`. `shell_priv_delete_path`, `shell_priv_remove_packages`, `shell_priv_reboot_host` and `shell_priv_run_command` at `destructive`; the last runs read, operator and destructive commands per tier. All `admin` only.
- **Annotations.** As TOOLS.md says: read tools as the read tier, everything else `destructiveHint: true`. `idempotentHint`:
  - **true:** write (same content), mkdir, chown, chmod, and copy without `overwrite`;
  - **false:** move, restore, delete, exec, every package op, and power.

### D10. `priv_delete` with backups

The order inside the op, extending the gate's `DeleteExact`:
1. **Walk the plan, and recompute and compare the hash.** On a mismatch: `exists`, nothing deleted, no backup.
2. **Back up from the plan,** when `backups.keep > 0`. The tar is written from the plan's entries, in walk order: each directory re-opened from its parent's handle with the identity the walk saw, and each regular file opened by name and checked for that identity, size and change time.
   - A symlink or special file in the plan refuses here: `backup_failed`, nothing deleted. That is today's rule.
   - The tar's entry list must equal the plan's.
   - The backup's metadata records `preview_sha256` and `entries`.
3. **The set-aside deletion,** exactly as the gate's. At step 1 of each entry, a regular file's size and change time must still be what the backup recorded. So any write after the backup read the file stops the delete, with that entry and everything after it kept, except the open-descriptor case (c) below.
4. **What remains.** The gate's three cases (POLICY §3), and one consequence of case (c) for backups: a write through a descriptor opened before the delete, made after the entry's last check, lands in an inode that is removed, and the backup holds the content as of its read. That is documented in PRIVILEGED §6.

## 4. Protocol changes (each needs the maintainer's approval)

Protocol v1 is amended in place before any release, as in PRs #18, #24, #25 and #26. An older peer refuses each new field or op as unknown (`bad_request`, `unknown_op`), and never ignores it.

| # | Field or op | Where | Type | Why |
|---|---|---|---|---|
| P-1 | `helper` | response (set by the gate on every response it forwarded from the helper) | object: `version`, `principal`, `policy_sha256`, `max_tier`, `unit` (`core` or `broad`), `duration_ms`; the helper's own block, which gains `unit` | D1, X-1: the server binds the privileged policy. The gate keeps its own `gate` block. |
| P-2a | `priv_delete_preview` | new op, read, core | args `{path, recursive}` → `{path, type, entries, bytes, first[≤50], truncated, backup{written, kind, bytes}, policy_sha256, preview_sha256}` | D10 |
| P-2b | `priv_chown_preview`, `priv_chmod_preview` | new ops, read, core | args `{path, owner?, group?, recursive}` / `{path, mode, recursive}` → `{path, type, entries, changes, first[≤50] (path, type, uid, gid, owner, group, mode, new values), truncated, policy_sha256, preview_sha256}` | D4 |
| P-2c | `priv_restore_preview` | new op, read, core | args `{id}` → `{id, kind, path, backup{size, sha256, entries, uid, gid, owner?, group?, mode, created, op}, current{state, …}, restore{uid, gid, mode}, current_backup, policy_sha256, preview_sha256}` | D3 |
| P-2d | `priv_exec_preview` | new op, read (the command's tier is checked as for `priv_exec`), the command's unit | args `{command_id, args, cwd, unit?}` → `{command_id, tier, unit, description, root_equivalent, capabilities, template, argv, cwd, policy_sha256, preview_sha256}` | D6 |
| P-2e | `priv_pkg_update_index_preview` | new op, read, broad | args `{}` → `{argv, policy_sha256, preview_sha256}` | D2 |
| P-2f | `priv_power_preview` | new op, read, broad | args `{action}` → `{action, target, job_mode, policy_sha256, preview_sha256}` | D2 |
| P-3 | `expected_preview_sha256` | args of `priv_delete`, `priv_chown`, `priv_chmod`, `priv_restore_backup`, `priv_pkg_update_index`, `priv_pkg_install`, `priv_pkg_upgrade`, `priv_pkg_remove`, `priv_power` (**required**); `priv_exec` (**optional**, always sent by the server) | 64 lowercase hex; missing or malformed is `bad_request`; another hash is `exists`, nothing changed | D2: the operation runs exactly what was previewed, or nothing. |
| P-4 | `recursive` | args of `priv_chown`, `priv_chmod` | bool, default false | D4, Q2 |
| P-5 | `preview_sha256`, `argv`, `policy_sha256` | results of `priv_pkg_install_preview`, `priv_pkg_upgrade_preview`, `priv_pkg_remove_preview` | strings, list | D5 |
| P-6 | `applied` | results of `priv_pkg_install`, `_upgrade`, `_remove` | `{install[], upgrade[], remove[]}` as in the previews | D5: what actually changed, from dpkg's status. |
| P-7 | `timeout_ms` forwarded clamped | gate → helper | the gate rewrites the forwarded `timeout_ms` to the timeout it will wait for (its `limits.max_timeout_s` bound), instead of forwarding it unchanged | X-4 |
| P-8 | `priv_policy` (only if Q6 is yes) | new op, read, core | `{policy_sha256, max_tier, limits, roots (read, write, persistence), owners, modes_max, backups_keep, commands[] (id, tier, unit, description, templates, root_equivalent, capabilities), packages (enabled, install, remove, allow_update_index, allow_upgrade), power.allowed}`; never `paths.deny` values (only their count) and never `acknowledge` text | discoverability for the model (Q6) |

**Not protocol:** the backup metadata's new `preview_sha256` (a local file format), and the server's combined policy hash.

**Unchanged:** the error-code set; the request shape apart from P-7's value; and `priv_write_file`, `priv_mkdir`, `priv_copy` and `priv_move`, whose preconditions are already enough (D2).

## 5. Implementation sessions

All of them:
- **Model:** Opus 5.5 at High (D-022). Every session is security-critical, root code.
- **Shape:** one PR into `dev`. The docs for the session's ops come first, in its first commit.
- **Tests:** failing first, with the failing commit named in the PR.
- **Fuzzing:** a 60 s fuzz run for every parser or path function it touches.
- **e2e-host:** cases in the unit the op runs in.
- **Common STOP conditions:**
  - a protocol change beyond those approved in §4;
  - any privileged-policy schema change;
  - a change to generated unit directives or Landlock rights;
  - a new dependency;
  - a rule that blocks something legitimate;
  - a security problem in merged code outside the session's scope (report it and stop).
- **Out of scope for all:** S-MC, S5 (release, deployment docs, CLIENTS.md), `deploy/`, S4d.

### S4c-0: `fix(privd)`: modes.max on copy, hard links on chown and chmod, the mode/owner audit

- **Includes.**
  - **F-1, by clamping, not refusing.** `priv_copy` has no mode input, so refusing would make such files uncopyable.
    - The new file's mode is the source's mode, with setuid, setgid, sticky and world-write removed *and* masked by `modes.max`. So no bit falls outside the mask.
    - The result reports the mode actually set.
    - An overwrite keeps the destination's existing mode, as writes do; the audit records which case applied.
  - **F-2.** `priv_chown` and `priv_chmod` refuse a non-directory whose link count is above 1.
    - The refusal is `path_denied`, with a message naming the path and the link count.
    - The link count is read with fstat on **the same descriptor** that fchown or fchmod then acts on, never by a separate path lookup.
    - A link created after that fstat is equivalent to one created after the change. The inode was the write root's only name when it was checked. This is documented.
  - **The audit.** Check every helper op that sets a mode or owner against `modes.max` and the owner and group allow-lists, and list the result per op in the PR: `priv_write_file`, `priv_mkdir`, `priv_chmod`, `priv_chown`, `priv_move`, `priv_copy`, `priv_restore_backup`.
    - Also check whether any other helper op changes an existing inode's metadata or content *in place*, rather than committing a new inode. Apply F-2's rule to each one found, and list the result per op.
    - For restore: report only, and apply Q3's answer if the maintainer has given it by then. Otherwise S4c-5 does.
  - **Metadata read-back (X-10)** for the non-recursive ops: fstat after the change on the same descriptor; a mismatch is `verify_failed`.
  - **Docs.** PRIVILEGED §6 (copy's mode rule, the link-count rule, read-back) and ARCHIVE.
- **Excludes.** Any tool; any protocol change; recursive chown and chmod (S4c-3).
- **Tests (failing first).**
  - Copy under `modes.max: "0700"` of a `0644` source gives `0600`, and the result reports it.
  - Chmod and chown through a hard link inside a write root to a file outside it, through the helper's request handling: refused, and the outside file's mode and owner unchanged.
  - The same in **e2e-host in the core unit** (the link to a file under a non-write directory on the same filesystem).
  - Read-back with an injected fault.
- **STOP.** If any op turns out to set an owner or mode outside the allow-lists by design, other than restore (F-3), or if clamping would change an existing documented result shape.

### S4c-1: privileged binding, approval plumbing, read tools

- **Includes.**
  - The first commit applies §7's wording, including the D-006 and D-021 text if approved.
  - **P-1.** The helper's block gains `unit`; the gate's `forward` passes it as `helper`; protocol types; the server's `gateclient` decodes it; the approval binds the combined policy hash (D1).
  - **P-7**, the clamped `timeout_ms`.
  - **D9:** `gated(t, privileged)`, the privileged `ungatedCeiling`, registration helpers for privileged tools, and descriptions saying "as root".
  - **Tools:** `shell_priv_read_file`, `shell_priv_list_directory`, `shell_priv_stat_path`, `shell_priv_list_backups` (read, admin only). `shell_get_policy`'s privileged section is unchanged unless Q6.
  - Catalogue rows.
- **Excludes.** Every write-class tool.
- **Tests (failing first).**
  - **Binding:** a privileged-policy edit between approval and re-call is `approval_invalid` (once S4c-2 has a gated tool). Here: the server sees `helper.policy_sha256`, and a forwarded response without `helper` makes a privileged preview refuse ("internal").
  - **Gating:** a privileged operator tool is gated under every `SHELL_MCP_APPROVAL_TIERS`, with a synthetic tool in the registry test.
  - **The clamp:** a privileged request whose timeout is above the gate's limit reaches the helper clamped.
  - **Registration:** the read tools are admin only, and absent when forwarding is disabled.
  - **e2e-host (core):** each read tool through the real server; the deny list and the private-key refusal; the helper's journal line joined to the gate's by id.
- **STOP.** If binding the helper's hash needs anything beyond P-1 (for example a field on the approval record that the page shows).

### S4c-2: write, mkdir, copy, move

- **Includes.**
  - `shell_priv_write_file`, `shell_priv_make_directory`, `shell_priv_copy_path`, `shell_priv_move_path`, with previews composed per D2 and the preconditions passed through.
  - The backup's SHA-256 asserted against the preview.
  - The metadata's `preview_sha256`.
  - Prune after commit (X-8, Q12; the restore part is in S4c-5).
- **Excludes.** Chown, chmod, delete, restore.
- **Tests (failing first).**
  - The approval web flow for each tool.
  - A file created after approval: `approval_invalid`. One created after the fresh preview: `exists`, via the existing commit-window hook through the server.
  - Copy-over shows the destination's mode on the page.
  - A privileged-policy edit after approval: `approval_invalid`.
  - Pruning after a failed write keeps the older version.
  - **e2e-host (core):** each tool approved and run once; a second re-call is `approval_invalid`; the helper's journal shows the backup ids, and the backup's SHA-256 equals the preview's.
- **STOP.** If `priv_read_file`'s bounds make a whole-file hash impossible for files the helper may overwrite (they should not: the 64 MiB backup bound is below `maxHashBytes`).

### S4c-3: chown and chmod, recursive

- **Includes.**
  - P-2b, P-3 (chown and chmod) and P-4.
  - The R1 walk (D4) in `fsx`, shared with the delete's walk where possible.
  - F-2's refusal for every entry, and read-back per entry.
  - `shell_priv_change_owner`, `shell_priv_set_permissions`.
- **Excludes.** Metadata backups (Q8).
- **Tests (failing first).**
  - Hash coverage: an entry added, removed, renamed, replaced, chmod-ed or chown-ed, changes it.
  - Refusals: mount point, device, set-aside name, setuid, a hard link (F-2), symlinks not followed.
  - A **window test** at every step (before the recompute, after it, between an entry's identity check and its change), 200 runs each.
  - A **concurrent racer**, 400 runs: replacing entries and adding hard links; nothing outside the plan changes.
  - Read-back.
  - **e2e-host (core):** a recursive chown of a tree with a hard link to a file outside the roots is refused and changes nothing; the approval flow.
- **Fuzz.** The entry encoding (as `FuzzPreviewEntryEncoding`).
- **STOP.** If a change-time rule cannot be made to hold on the runner's filesystems.

### S4c-4: delete

- **Includes.**
  - P-2a and P-3 (delete).
  - The helper's `delete` moves to `PreviewDelete`/`DeleteExact` with the backup from the plan (D10).
  - `set_aside` in the helper's audit line.
  - S1's `fsx.Delete`, `DeletePreview`, `deleteOp`, `backupTree` and `removeTree` are removed once nothing uses them.
  - `shell_priv_delete_path`; `shell_priv_preview_delete` if Q7.
  - POLICY §3's "until S4c" sentence.
- **Tests (failing first).**
  - The gate's window and racer tests, through the helper.
  - The backup holds exactly the deleted entries, and a file written after the backup read it stops the delete.
  - Stranded entries named and refused.
  - Backups disabled.
  - A backup over 64 MiB refused at the preview.
  - **e2e-host (core):** approval, a second re-call, a newcomer after approval, a device node, a mount point.
- **STOP.** If the backup cannot be written from the plan without a second walk.

### S4c-5: restore

- **Includes.**
  - P-2c and P-3 (restore).
  - Restore through `expected_sha256` or `expect_absent`.
  - Tree restore create-only, with an entry-count check.
  - Q3's owner and mode rule.
  - Prune never removes the backup being restored (Q12).
  - `shell_priv_restore_backup`.
- **Tests (failing first).**
  - Restore over a file changed after approval (`approval_invalid`), and after the fresh preview (`exists`, via the commit hook).
  - A file planted in a tree being restored: `exists`, the planted file intact.
  - A tampered data file: `backup_failed`.
  - The restored owner and mode per Q3.
  - The restored backup is kept.
  - **e2e-host (core):** write, then restore, then restore again (the restore's own backup).
- **STOP.** If Q3 is unanswered.

### S4c-6: exec

- **Includes.**
  - P-2d and P-3 (exec).
  - `resolveExec` in the helper, shared by `priv_exec` and `priv_exec_preview`.
  - U5 routing in the server.
  - `shell_priv_run_command` with per-tier gating (D9).
  - TOOLS loses `stdin` (Q11).
  - X-4's message for exec timeouts.
- **Tests (failing first).**
  - Preview equals exec resolution for every template and placeholder type (`FuzzExecPreviewMatchesExec` for the helper).
  - A policy edit (binary, template, tier, unit) between preview and exec: `exists` or `tier_denied`.
  - A path placeholder retargeted.
  - A read command runs unapproved at ceiling `read`; a command raised to operator after its preview is refused.
  - A broad command routed after `helper_wrong_unit`.
  - **e2e-host:** a core command and a broad command, each approved and run once, with their journal lines; a misroute is refused by both instances.
- **STOP.** If U5's retry can ever send a request to the broad socket that the core instance did not refuse as `helper_wrong_unit`.

### S4c-7: packages

- **Includes.**
  - P-2e, P-3 (packages), P-5 and P-6.
  - The re-simulation compare; the pinned argv; `--no-remove`; upgrade as `install --only-upgrade` over the approved list.
  - A bounded dpkg-status reader and diff, fuzzed.
  - `verify_failed` on a mismatch.
  - The four package tools; `shell_priv_preview_packages` if Q7.
  - X-4's message for package timeouts.
- **Tests (failing first).**
  - The hash covers each list and version.
  - An incomplete simulation requests no approval.
  - **e2e-host (broad)**, with the local apt repository:
    - a new version published and indexed after approval: `approval_invalid`;
    - published and indexed between the fresh preview and the run (via a hook in the test build): `exists` or `verify_failed`, never a silent different transaction;
    - upgrade installs exactly the approved list when more upgrades are available;
    - remove never purges;
    - a held lock.
- **STOP.** If any apt behaviour in D5 §5 differs from what the design assumes.

### S4c-8: power

- **Includes.**
  - P-2f and P-3 (power).
  - `shell_priv_reboot_host`.
- **Tests (failing first).**
  - A disallowed action refused at the preview, with no approval requested.
  - A policy edit after approval: `approval_invalid`.
  - **e2e-host (broad):** the masked-target technique of `TestPowerReachesSystemd`, through the approval flow.
- **STOP.** If a test would need an unmasked shutdown target.

### S4c-9 (optional, only if Q6 is yes): privileged policy summary

- **Includes.**
  - P-8.
  - `shell_get_policy` gains a `privileged.policy` section when the helper answers.
- **Tests.**
  - The deny values and acknowledge text never reach the wire (a canary in each).
  - The summary's hash equals `helper.policy_sha256`.

**Order and dependencies.**
- S4c-0 first, on its own.
- S4c-1 before every tool session.
- S4c-2 before S4c-5, which needs write-side backups bound to previews.
- S4c-4 before S4c-5, which restores trees backed up by delete.
- S4c-3, S4c-6, S4c-7 and S4c-8 depend only on S4c-1. They can be done in any order, but they touch `internal/privd/ops/dispatch.go` and the shared preview code, so one at a time.

## 6. Open questions (pick first)

1. **Bind the privileged policy (D1, P-1), and extend D-006's text** to "of the gate policy and, for privileged operations, of the privileged policy"? **Pick: yes.** Without it an approval does not notice a root-policy edit.
2. **Recursive chown and chmod in v1 (D4, P-4)?** **Pick: yes, R1, bounded by `max_delete_entries`.** Alternatives: drop `recursive` from TOOLS; or a separate limit (a schema change).
3. **Owner and mode on restore (F-3).** **Pick: restore the recorded owner and group even outside `owners`** (they are the file's own previous owner, shown on the page), **and clamp the recorded mode to `modes.max`** (as copy).
   - Alternative: refuse any recorded owner outside the allow-lists or any mode outside the mask.
   - Alternative: keep today's behaviour and document it.
4. **Package binding (D5).** **Pick: P2** (re-simulate and compare, pins, `--no-remove`, upgrade as `install --only-upgrade` over the approved list, dpkg-status verification, `verify_failed`). Alternative: P1 without verification.
5. **`priv_exec` routing (D6).** **Pick: U5** (core first, `helper_wrong_unit`, then broad).
6. **A privileged policy summary op (P-8, S4c-9)** so the model can discover command ids, package names and power actions? **Pick: yes, minimal**: no deny values, no acknowledge text, roots and command templates included. It relaxes S1d's "privileged policy values never reach the wire" for an authenticated gate. Alternative: no, and operators tell the model out of band.
7. **Read-tier preview tools `shell_priv_preview_delete` and `shell_priv_preview_packages`,** mirroring `shell_preview_delete`? **Pick: yes.**
8. **Metadata backups for chown and chmod** (previous owner and mode per entry in the store, restorable)? **Pick: no in v1.** The preview and the audit carry the old values.
9. **Show apt sources in the update-index preview?** **Pick: no.** The action and the policy hash only.
10. **A global backup-store quota?** **Pick: document only** (X-7). A quota is a schema change.
11. **`stdin` on `shell_priv_run_command`?** **Pick: remove it from TOOLS.** PRIVILEGED §6 has none; adding it needs a privileged stdin limit (a schema change).
12. **Prune after commit, and never the backup being restored (X-8)?** **Pick: yes.**
13. **Metadata read-back after chown and chmod (X-10),** with `verify_failed` on a mismatch? **Pick: yes.**
14. **`expected_preview_sha256` required on every privileged op that has a dedicated preview, except `priv_exec` (optional, always sent)?** **Pick: yes.** It is defence in depth against server bugs, not against a compromised server.
15. **Copy and move with `overwrite`:** no destination-identity precondition, since the destination is backed up and the fresh preview checks it? **Pick: yes, documented.**
16. **`priv_write_file`:** a mode or owner change to the existing file between the fresh preview and the commit is kept (not bound)? **Pick: yes, documented.** Binding it would need a precondition beyond `expected_sha256` (a protocol change).

## 7. Corrections to the documents and the prompt

**Pushback on the documents.**
- **TOOLS.md, `shell_priv_run_command`** lists `stdin?`. PRIVILEGED §6 and the code (`execArgs` has no stdin) say there is none in v1. TOOLS is wrong (Q11). It also omits `max_output_bytes`, which the helper accepts.
- **TOOLS.md, `shell_priv_change_owner` and `shell_priv_set_permissions`** list `recursive=false`. Neither the helper nor the protocol has it (Q2, P-4). `owner?` and `group?` need "at least one".
- **TOOLS.md, `shell_priv_restore_backup`,** "preview: diff against current". No content is ever shown. The preview is the backup's and the current file's size, mode, owner and SHA-256 (and line counts where the server reads both).
- **PRIVILEGED §6, "Every write-class op returns a preview first".** No op returns a preview. Previews are separate read ops, or composed by the server. Reword to "every write-class op has a preview, shown in the approval request: …".
- **PRIVILEGED §6, `priv_copy` and `priv_move` row.** "Modes within the mask" was not true for copy (F-1, fixed in S4c-0). The row should say the new file's mode is the source's, masked by `modes.max`, and that an overwrite keeps the destination's.
- **PRIVILEGED §6, `priv_exec`.** "How the server learns a command's unit is S4c's" → D6 (U5).
- **PRIVILEGED §8.** Add `set_aside`, the package `applied` counts, chown and chmod's `changed`, and the note on redaction (X-5).
- **D-006 (plan §2, locked).** It binds the gate policy only. For privileged operations that binds nothing about the root policy (X-1, Q1). This is a locked-decision change, for the maintainer.
- **D-021 (plan §2, locked).** "Overwritten and deleted files are backed up first" stays true. Consider adding "and every write-class operation runs only the previewed change", if the maintainer wants the binding in the locked text. **Pick: no**, D-006 carries it.
- **POLICY §3,** "`priv_delete` … keeps its own rules, with backups, until S4c." S4c-4 replaces this with "applies the same rules, with a backup from the plan (PRIVILEGED §6)".
- **ARCHITECTURE §3 step 4,** "forward the request unchanged". P-7 changes `timeout_ms` to the clamped value, and the response gains `helper` (P-1). §4.2 documents `helper`. §4.3's `priv_*` row lists the new preview ops.

**Pushback on the prompt.**
- "How priv_exec preview works (reuse exec_preview or a helper equivalent)." Reuse is not possible: the gate cannot read the privileged policy, and path placeholders must resolve in the helper unit's own namespace (D6).
- "Whether a backup is itself bound into the preview." A backup's id cannot be in a preview, because it is created by the operation. What can be bound is its content (equal to the previewed hash), its plan (equal to the deletion's), and a record of the preview in its metadata (D3).
- Nothing else in the prompt disagreed with the code or the documents. PR #26 is on `dev` (`6294ac1`), and this branch starts there.

## 8. What was read and checked

- **Documents:** CLAUDE.md; plan.md (§2, §4.2 S-12 and S-13, §5); PRIVILEGED in full; TOOLS (approval, privileged); POLICY (§2, §3, §4, §4a, §5); ARCHITECTURE (§2, §3, §4, §6); SECURITY; the S4b handoff; ARCHIVE §14 from S1 (2026-09-27) to S4b-2b (2026-10-18), in detail for S1c, S1d and its follow-ups, the tier ceiling, S4a, S4b-1b, atomic create-only, S4b-2a and S4b-2b.
- **Code:**
  - `cmd/shell-mcp-privd`;
  - `internal/privd/ops` (every file), `policy`, `pkg`, `dbus`, `units`, `selfcheck`, `peercred` (by API);
  - `internal/gate/fsx` `write.go`, `helper.go`, `read.go` and the delete files (by API);
  - `internal/gate/ops/priv.go` and `dispatch.go`'s `privTiers` and `priv`;
  - `internal/gate/audit`'s `loggedArgs`;
  - `internal/gate/sandbox`'s read-write rights;
  - `internal/tools/approval.go` and `registry.go`;
  - the e2e tests' use of each `priv_*` op.
- **Versions:** Go 1.27.2 is the newest stable per go.dev (`go.dev/dl/?mode=json`, read 2026-10-18), the same as `go.mod`.
- **Not verified here, and marked where used:** apt's `name=version`, `--no-remove` and `--only-upgrade` semantics and marking (D5 §5, S4c-7 STOP); the dpkg status format details. Each is verified at the source in its session.
