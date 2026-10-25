# S4c handoff: the privileged tools

> Session S4c-scope, 2026-10-18. Documentation only: no code, test or other non-doc file changes in this PR.
> It answers plan §5 (S4c) and scopes the `shell_priv_*` tools into implementation sessions.
> **Status: decided by the maintainer on 2026-10-18.** §6 records the answer to every open question; where an answer changed the recommendation, the sections that depend on it (§2–§5, §7) were updated to match, and every S4c session builds from them. The two findings in merged code (§0, §2.1) and their decisions are in §2.1 and §5 (S4c-0).
> This PR changes no locked document. The approved D-006 and S-12 text (§7.1) and the other wording changes (§7.2) are applied by S4c-1's first commit, as S4b-1 applied its handoff's.

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

**The split (§5).** Ten sessions:
- S4c-0: the fix above.
- S4c-1: privileged binding, approval plumbing and the read tools.
- S4c-2: write, mkdir, copy and move.
- S4c-3: chown and chmod, including recursive.
- S4c-4: delete.
- S4c-5: restore.
- S4c-6: exec.
- S4c-7: packages.
- S4c-8: power.
- S4c-9: a minimal privileged policy summary (Q6), with N-13 (done; every S4c session is done).

Each is one PR, Opus 5.5 at High (D-022).

**After S4c: S-MC (done, PR #53).** Multi-call binaries in gate and privileged command templates (plan.md §5), as the maintainer decided on 2026-10-24 (ARCHIVE §14). The uutils multi-call binary is judged by the utility it runs as; GNU coreutils as one binary, BusyBox and toybox are refused by content; GNU coreutils' programs are recognised under the `gnu` prefix and by their embedded names (F1); `runcon` is in group 4 (F2); coreutils options that run a program need an acknowledge in the privileged policy (F3); #! scripts are judged by their interpreter, with N-26 recorded.

**Protocol changes (§4):**
- a `helper` block on forwarded responses;
- seven new read-tier preview ops;
- `expected_preview_sha256` on nine ops, and on `priv_exec` whenever approval applies;
- `expected_destination_sha256` on copy and move with `overwrite`;
- `recursive` on chown and chmod;
- a hash on the package previews, and an `applied` list on package results;
- the gate forwarding the clamped `timeout_ms`;
- `priv_policy` (P-8, amended in S4c-9 with `ops`, `findings`, `deny_patterns` and `roots.persistence`; approved by the maintainer, 2026-10-22);
- the restored mode on restore's preview and result (P-10, pre-approved after S4c-0).
- `priv_backup_check` (P-11) and the owner in write results (P-12), approved during S4c-2.
- the power preview's and `priv_power`'s result amended, and `priv_power_cancel` (P-13), approved during S4c-8.
- `owner_rule` on `priv_backup_check` (P-14), approved with N-8 and N-9.
- `owner` and `group` on `priv_copy` (P-15), approved with N-19 (maintainer, 2026-10-24).

Plus one privileged-policy schema change: a total size cap on the backup store (`backups.max_store_bytes`, §4.1).

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
- **Status: fixed in S4c-0 (PR #28).** fsx masks every new inode's mode by `fsx.Config.ModesMax`, which the helper sets to `modes.max`; the result reports the mode set.

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
- **Status: fixed in S4c-0 (PR #28).** `fsx.Chmod` and `fsx.Chown` refuse it with `path_denied` naming the path and the count. `fsx.Chmod` is shared, so the gate's `chmod` (`shell_set_permissions`) refuses it too: the same class of bug as the service account, within its own ownership (ARCHIVE §14, S4c-0).

**F-3. Not a bug, but surfaced by the same audit.** `priv_restore_backup` restores the recorded owner and mode without checking either against `owners` or `modes.max`.
- PRIVILEGED §6 says it does exactly that ("with its recorded owner and mode"), so the code matches the document.
- **Decided (Q3):** the recorded owner and group are kept, even outside `owners`; the recorded mode is clamped to `modes.max`; and the backup's recorded content hash is verified before anything is restored (`verify_failed` on a mismatch). S4c-0 applies the mode clamp with the other ops; S4c-5 the rest.

**F-4. Writes over an existing file keep its mode, even outside `modes.max`.** Found while answering Q16, and of the same kind as F-1.
- **Code.** `writeAtomic` gives the new inode the existing file's mode when no mode is given (`write.go`, `newMode = os.FileMode(um)`). `TestDefaultModesWithinMask` asserts exactly that: an existing `0640` file stays `0640` under `modes.max: "0700"`.
- **Decided (Q16; F-4 accepted by the maintainer):** a write's new inode is clamped to `modes.max` like every other new inode (S4c-0). That changes the tested result above to `0600`, deliberately.
- **Visible effect, documented in PRIVILEGED.md by S4c-0:** a file whose mode is wider than `modes.max` is narrowed to the mask when the helper writes it, copies over it or restores it.
- **Status: fixed in S4c-0 (PR #28),** with F-1; PRIVILEGED §4 states the visible effect. F-3's mode clamp is applied too (files and every tree entry); the rest of F-3 is S4c-5's.

**Found in S4c-0 (PR #28), with the maintainer's decisions (2026-10-18).**

**N-1. Move in, change, move out.**
- **Severity:** must fix before `shell_priv_change_owner` or `shell_priv_set_permissions` is exposed (S4c-3).
- **What.** An account that can write a write root *and* the directory that holds a file elsewhere on the same filesystem can:
  - rename that file into the write root;
  - have `priv_chmod` or `priv_chown` change it;
  - rename it back.
  The link count is 1 throughout, so F-2's rule does not see it, and S4c-3's identity binding (D4) does not either: the inode at the path is the one approved.
- **Example.** A root-owned `0600` file in a directory the application account can write is moved in, made `0644`, and moved out. The same works for a directory, and for a write or copy over a moved-in file.
- **Narrower than F-2,** because it needs write access to the file's own directory, but just as unbounded by `ReadWritePaths=` and Landlock, which confine paths.
- **Recommended fix, to evaluate in S4c-3:**
  - Refuse an in-place metadata change (`priv_chmod`, `priv_chown`, and every entry of a recursive walk) unless every directory from `/` to the target is owned by root and is neither group- nor world-writable.
  - Check this by descriptor along the walk: each directory opened from its parent's handle and checked by `fstat`, with no separate path lookup.
  - Add a `check-policy` warning and a helper self-check warning for any privileged write root that fails it.
  - To evaluate with it: a write root whose directories the application account owns or can write would then refuse every chmod and chown.
- **Alternative:** refuse to change an inode whose current owner is not on the `owners` allow-list.
- **Decision:** S4c-3 decides between the two with the maintainer.
- **Status: done (S4c-3, PR #32).** The maintainer chose the recommended fix (2026-10-19). The alternative was rejected because `root` is on `owners.users` in practically every policy, so a root-owned file moved in would still be changed. `priv_chmod` and `priv_chown`, alone and for every entry of a walk, change an entry only when every directory from `/` to it is root's and neither group- nor world-writable. The directories up to the target's parent are checked by descriptor (`O_PATH|O_NOFOLLOW` from the previous one, ending at the parent the operation holds), and inside a tree, every directory that holds entries. The helper's `check-policy` prints `ok` or a WARN per privileged write root; the refusal's journal line is the serve-time record (no per-connection warning, the maintainer's choice). PRIVILEGED §6, "Chown and chmod".
- **Found while implementing it:** the same move-in works for overwrites; recorded as N-6 below.

**N-2. Chmod of setuid, setgid and sticky files.**
- `fsx.Chmod` (gate and helper) does not refuse them, unlike `fsx.Chown`.
- It can only clear those bits, never set them, so it does not escalate.
- §2.3's "setuid, setgid and sticky files are never changed" holds for chown only.
- **Decision:** decided in S4c-3.
- **Status: done (S4c-3, PR #32).** The maintainer chose to refuse them in the gate too (2026-10-19). `fsx.Chmod` (the gate's `shell_set_permissions`) refuses a file or directory with setuid, setgid or sticky bits with `policy_denied`, as chown always did, and the helper's walk refuses such entries for both ops. The cost: the gate can no longer chmod a setgid shared directory that the service account owns. POLICY §3.

**N-3. Root-owned new inodes.**
- A copy, a new file or a new directory without an explicit owner is the helper's (`root:root`), whether or not root is in `owners.users`.
- The allow-list governs what may be *set*, so this is as documented.
- **Decision:** documented in PRIVILEGED §6 by S4c-2.
- **Status: done (S4c-2, PR #30).** PRIVILEGED §6 says so, and the write tools' previews show the owner that will be set ("root (a new file without an owner is root's)").

**N-4. The gate's chmod has no metadata read-back.**
- **Decision:** a low-priority follow-up, in no S4c session. It changes a gate tool, so it is its own PR.
- **Status: done (PR #48).** The gate sets `fsx.Config.VerifyMetadata`: after `fchmod`, `chmod` re-reads the mode, owner and group through the same descriptor, and a mismatch is `verify_failed` (POLICY §3; TOOLS.md, `shell_set_permissions`). Tested through the gate with a read-back fault (`ops.Options.InjectMetadataReadBackFault`); no real filesystem in CI ignores a chmod, so e2e-host has no case of its own.

**N-5. Destination previews hash through `read_file` (recorded by PR #31).**
- The approval preview of an overwrite (`shell_copy_path`, `shell_move_path`, and their privileged twins through `priv_read_file`) hashes the destination through the read op, so it inherits that op's limits: a destination above 256 MiB gets no hash (`too_large`), and one whose first 64 KiB contain a private key is refused (`path_denied`). Either way the overwrite cannot be approved, though the operation itself would replace the file without reading it out.
- A hash-only read-tier op for destination previews (the SHA-256 of a regular file, no content, bounded by time rather than by a size cap) would remove both limits. It is a protocol change (a new op).
- **Decision:** a low-priority follow-up, in no S4c session (maintainer, 2026-10-19). It is its own PR.
- **Re-assessed before release (fix/final-findings, PR #50; phase 1).** Still exactly as recorded: S4c-6 to S4c-9 and #45 changed nothing here. `boundFilePreview` (internal/tools) still hashes a destination through `read_file` (gate) or `priv_read_file` (helper), so a destination above 256 MiB answers without a hash (`too_large`, nothing requested) and one whose first 64 KiB hold a private key is `path_denied`. In practice a copy's source is itself capped by `max_read_bytes` and refused when it holds a private key, and a write's content by `max_write_bytes`, so the cases left are a move (or a small copy or write) over a destination larger than 256 MiB, or over a file holding a private key. Workaround: delete the destination first (the delete's preview hashes metadata, not content), then copy or move create-only (two approvals, and the destination is absent in between). What the fix would change: two read-tier ops, `hash_file` (gate) and `priv_hash_file` (helper, core unit; routed by the gate at read tier), answering `{path, size, sha256}` and the stat identity for a regular file under the same resolution, deny list and (in the helper) moved-in read rule as a read, hashing to the end within the request's deadline instead of a size cap and returning no content (so no private-key sniff); the server's destination previews would use them (and lose the destination's line count above the read cap). Protocol: two op names added to the closed op set, the gate's tier table and the helper's dispatch; no envelope or error-code change. Recommendation: defer past release (the earlier decision stands; the cases are rare and fail closed, and the workaround is bounded).
- **Decision (maintainer, 2026-10-24): deferred past release.** Until then the workaround above is the documented way: delete the destination first (its own approval; the delete's preview binds metadata, not content), then copy or move create-only (a second approval), accepting that the destination is absent in between.

**N-6. Overwrites inherit a moved-in file's root ownership (found in S4c-3, PR #32).**
- **What.** `priv_write_file` and `priv_copy` with `overwrite`, and `priv_restore_backup`, over an existing file give the new inode that file's owner and group (and its mode masked by `modes.max`) unless one is given. N-1's move-in applies:
  - an account that can write a directory under a write root, and the directory of a root-owned file elsewhere on the same filesystem, moves that file in;
  - it has the file overwritten as root (the content is the approved one);
  - it moves the result out again.
  It ends up with a root-owned file whose content it chose, at a place of its choosing on that filesystem.
- **Narrower than N-1:** the content is what the approver approved, and the account needs write access to both directories. But nothing ties the inherited owner to an owner the policy allows.
- **Proposed fix (maintainer, 2026-10-19), to decide in S4c-5 for all three operations.** When the target's path fails N-1's chain rule (a directory on it is not root's, or is group- or world-writable), a write, copy or restore over an existing file does not inherit that file's owner and group: it requires an explicit owner and group from `owners`, or it is refused.
- **Status: decided (maintainer, 2026-10-19, S4c-5) together with N-7, and done in S4c-5 (PR #34).** One test for both, "could another account have moved this file in?": the chain from the privileged root the path is resolved under (inclusive) down to the file's parent, by descriptor. Not the parent alone (a rename within one parent needs write access to that parent only, so an open directory higher in the root can swap a closed sibling into the path), and not the full chain from `/` (directories above a root are `check-policy`'s WARN, not checked per request; chmod and chown keep their full chain). A file is *owner-matched* when every directory in that chain is closed, or is owned by the file's owner and is neither group- nor world-writable. A write or copy over a file keeps its owner and group only when it is owner-matched; otherwise a write needs both an owner and a group from `owners`, a copy is refused (it has no owner inputs), and a restore applies the test to its recorded owner (for every file and tree entry it creates) and is refused otherwise. Pushback recorded: a restore never inherited the current file's owner (it sets the recorded one), so for restore the question was where the recorded owner lands. PRIVILEGED §6, "Files another account could have moved in".

**N-7. Moved-in files are readable as root (found in S4c-4, PR #33).**
- **What.** The chain rule (N-1) applies to chmod and chown only. An account that can write a directory under a privileged root and the directory of a root-only file elsewhere on the same filesystem can move that file in, have `priv_read_file` (read tier, never approval-gated) return its content as root, and move it back; the private-key refusal stops PEM keys only. The same move-in puts the file's SHA-256 into a delete's backup metadata, which `priv_list_backups` shows.
- **Decision (maintainer, 2026-10-19):** decided together with N-6 in S4c-5. No separate session.
- **Status: decided (maintainer, 2026-10-19, S4c-5) and done in S4c-5 (PR #34).** `priv_read_file` (the content, and a binary file's SHA-256) and `priv_copy`'s read of its source return a file only when it is owner-matched (N-6's test) or world-readable; otherwise `path_denied` naming the first directory that fails. `priv_stat`, `priv_list_dir` and `priv_list_backups` are unchanged (metadata). Documented consequence: a group-writable read root such as a `root:syslog 0775` `/var/log` refuses every file directly under it that is not world-readable; point read roots at closed subdirectories. The delete-backup hash is a documented residual. Because the composed write, copy and move previews hash an existing destination through `priv_read_file`, an overwrite of a file the read rule refuses is refused at its preview, even with an explicit owner.

**N-8. New files in an open directory are root's (found in S4c-5).**
- **What.** A file `priv_write_file` or `priv_copy` creates without an owner is `root:root` (N-3) in any directory. In a directory another account can write, that account can move it elsewhere on the filesystem with its approved content: N-6's gain, without a move-in. (`priv_mkdir` is not affected: a root-owned directory cannot be renamed into another parent without write access to it.)
- **Decision (maintainer, 2026-10-19):** not in S4c-5; a follow-up. Options recorded with the decision: an explicit owner and group required there (a copy, which has no owner inputs, refused), or a default to the directory's owner and group where it is not group- or world-writable.
- **Decision (maintainer, 2026-10-20):** decide together with N-9, before release, as one rule for files root creates in directories another account can write.
- **Found while deciding it (2026-10-23):** a new file also took a setgid parent's group (no `fchown` ran without an owner), while the approval page said "root", and the parent's default ACL, which the directory's owner can set; so under an application's own directory a file the approver saw as `root:root 0640` could be readable by that application.
- **Status: done (maintainer decision, 2026-10-23; PR #46).** **Rule R:** root leaves a regular file (written, copied, restored; new or over another) only when the owner it will have is owner-matched on the chain from the privileged root to its parent: the owner given, else the existing file's, else root's (a new file or copy without one), and for a restore the recorded one. So under a closed chain any owner; under directories one other account owns, only that account; under a group- or world-writable directory, none. Applied in `fsx`'s `writeAtomic` on the parent it holds, before anything is backed up or written (`ownerRule`, `OwnerVerdictOf`), refusals marked unchanged and naming the one owner that would pass when exactly one would. **N-6 tightened:** an explicit owner must itself pass, which closes the `owner: root` escape. `priv_mkdir` is exempt (a directory another account cannot write cannot be moved to another parent); `priv_move` is N-17 (done since, PR #47). **Every new inode gets both ids set** (`fsx.Config.ExplicitOwner`): the given, kept or recorded ones, else the helper's own (root's), so a setgid parent never chooses the group. **ACLs are not stripped:** under rule R a default ACL on the chain can only have been set by root or by the file's own owner; documented in PRIVILEGED §6. Also recorded: an overwrite gives the new inode the parent's default ACL (or none), not the replaced file's own ACL, which is lost. **P-14** (§4): `priv_backup_check` reports the verdict, and the write and copy previews refuse before approval.

**N-9. A restore applies the owner test to every restore (found in S4c-5, PR #34).**
- **What.** `priv_restore_backup` applies N-6's owner-matched test to the owner it sets on every restore: a file whether or not one exists at its path now, and every entry of a tree, whose restored directories extend the chain. So a root-owned file inside an application-owned directory (for example a `root:example-app 0640` `.env` in the application's own directory) cannot be restored, although that is where it was.
- **Why it is strict.** Restoring it gives the application account a root-owned file it could not have made itself, which it can move elsewhere on the filesystem (N-6's gain); a restore to an absent path is also a create (N-8).
- **Decision (maintainer, 2026-10-20):** keep the strict behaviour for now; decide N-8 and N-9 together before release, as one rule for files root creates in directories another account can write.
- **Found while deciding it (2026-10-23):** a delete has no chain rule (S4c-4), so it backs up, and removes, what a restore then refuses: a root-owned file under an application's own directory, or a tree holding one. The backup exists, but the tools can never restore it.
- **Status: done (maintainer decision, 2026-10-23; PR #46).** Restore stays strict (option N9-a): it is rule R (N-8) for the recorded owners, unchanged. The delete/restore trap is closed in the delete's preview: `priv_delete_preview` answers, through the existing `warnings`, "the tools won't be able to restore N entries of this backup: …" naming the first entry, its recorded owner and the directory, computed by the restore's own check (`restoreOwners`, shared with `planTreeRestore`) from the plan's owners and the modes the restore would give; the server shows it on the approval page as `backup.restore` (bound by the preview's hash), and `shell_priv_preview_delete` returns it as a warning. No protocol field.

**N-10. Path placeholders are confined as strings, then re-resolved by the command as root (found in S4c-6 review, PR #37).**
- **Severity:** must fix before S4c-7 (maintainer, 2026-10-21): `shell_priv_run_command` exposes it, and read commands run without approval.
- **What the code does.** `{path:read}` and `{path:write}` go through `fsx.ResolveRead` and `fsx.ResolveWrite` (`internal/privd/ops/exec.go`, `resolver`): `locate` walks from the privileged root with `os.Root`, the final component must not be a symlink, the real path must match and pass the deny list and the protected set, and then the descriptor is closed and only the **path string** is passed in the argv. No ownership check is made: neither N-1's chain rule (chown and chmod only) nor S4c-5's moved-in rule (`movedInRead` and `movedInOverwrite` are called from `ReadFile`, a copy's source, the restore's hash and overwrites only). The command then opens that string itself, as root, with the kernel's ordinary lookup, following symlinks.
- **The race.** Between the resolution (and the preview's hash, which covers the string) and the command's own open, an account that can write any directory on the path (the root, or any directory down to the parent) can rename a component and put a symlink, or another file, in its place. Root then reads or writes the symlink's target. Nothing in the hash or the recompute sees it: the string is unchanged.
- **What bounds it today.** In the core unit, systemd (`ProtectSystem=strict`, `ReadWritePaths=`, `InaccessiblePaths=`) and Landlock confine the command to the declared read and write roots and the backup store. A swapped link can still point at a root-only file under a read root (read as root: N-7's gain without moving the file), at a file under a write root that the account could not write, or into the backup store (which is read-write for the core unit). In the broad unit there is no Landlock and no `ProtectSystem=`, so the target can be anywhere on the host (`/etc/sudoers.d`, an `authorized_keys`): a local account that can write a directory on the path escalates to root. (The gate's own commands have the same race with the service account's rights, inside its Landlock domain; lower impact, and outside this item.)
- **Proposed fix.** At resolution, by descriptor, require every directory from the privileged root the path is resolved under (inclusive) down to the target's parent to be *closed*: root's, and neither group- nor world-writable. Use the moved-in rule's walk (`rootChain`, `O_PATH|O_NOFOLLOW`, `statx`, the last one being the parent held), with the strict test, not the owner-matched one: an owner-matched directory lets its owner swap in a link to a file it could not read. Refuse otherwise with `path_denied` naming the directory, in the preview and in `priv_exec` alike, through `resolveExec`, so no approval is requested. Then only root can change what the string names between resolution and use. `check-policy` already prints the chains of the roots. Consequence: a placeholder cannot point inside an application-owned tree; such trees are reached through fixed literal paths whose parents are closed (PRIVILEGED §6, "Managing an application-owned tree").
- **Rejected for the fix:** passing `/proc/self/fd/N` instead of the path (a command given a `{path:write}` that does not exist yet needs a name, not a descriptor, and many tools re-derive paths from what they are given); the owner-matched test (above); checking again just before the exec (the window stays, only shorter).
- **Status: done (N-10 fix, PR #40).** The proposal's chain started at the privileged root; the maintainer's correction (2026-10-21), confirmed from the code, starts it at `/`: `ResolveRead`, `ResolveWrite` and `ResolveDir` return the *real* path, which the command (and, for the `cwd`, the trampoline's `chdir`) resolves again from `/`, so a directory above the root that another account can write lets it rename the root, or a directory holding it, away within that directory and put a symlink in its place. The moved-in rule's reason for stopping at the root (its operations keep the descriptors they resolved) does not hold for a string. With `fsx.Config.GuardExecPaths` (the helper only), the three resolvers refuse with `path_denied` unless every directory from `/` to the target's parent is closed (root's, neither group- nor world-writable, and not sticky: a sticky directory counts as open, writable or not), checked by descriptor (`chainCheck`, `O_PATH|O_NOFOLLOW`, `statx`), ending at the parent fsx holds (for a root itself: its ancestors, ending at the root fsx opened). **A directory target is closed itself** (maintainer decision, 2026-10-21, after the first review of PR #40): the `cwd` always, and a `{path:read}` or `{path:write}` that resolves to a directory, checked by `statx` on the descriptor the resolution opened, in the same `execChain`; a file target keeps the chain alone (plus the existing final-symlink refusal). So the rule covers both placeholders and the `cwd`, in `priv_exec_preview` and `priv_exec` alike through `resolveExec`, in both units. No owner-matched exception. Passing descriptors instead was assessed again and not done (ARCHIVE §14, 2026-10-21). `check-policy`'s chain WARN for each read and write root now says root commands get no path under (or at) it. The gate's own commands: N-11.

**N-11. The gate's own commands re-resolve their paths too (found in the N-10 fix, PR #40).**
- **What.** The gate's `exec` and `exec_preview` resolve `{path:read}`, `{path:write}` and the `cwd` through the same `ResolveRead`, `ResolveWrite` and `ResolveDir`, without `GuardExecPaths`, and pass the real path as a string; the command looks it up again itself. An account that can write a directory on the path can swap in a symlink in between, exactly as in N-10.
- **Impact, lower than N-10's.** The command runs as the service account, with `no_new_privs`, inside the gate's Landlock domain (POLICY §4a), so a swapped link reaches only what the service account may read or write under the gate's own roots (and the sandbox's fixed grants). The service account itself gains nothing (it could open the target directly); another local account that can write a directory on the path (an application account that owns a tree under a gate root, or shares a group-writable directory) gets the service account's access under the roots: a confused deputy, bounded by Landlock, never root.
- **Decision (maintainer, 2026-10-21): recorded, not fixed in PR #40.** Options for later: the same rule with the gate's trust (directories from `/` owned by root or the service account and neither group- nor world-writable), which would refuse placeholders inside application-owned trees that read-only gate policies commonly name (a compose file under an application's directory); or documenting it as the gate's bound.
- **Status: done (PR #48), the first option.** The gate resolves its commands' `{path:read}`, `{path:write}` and `cwd` through an FS of their own with `GuardExecPaths`, trusting root and the service account (its own uid): every directory from `/` to the parent, and a directory target itself, must be owned by one of them, neither group- nor world-writable and not sticky (as N-10, sticky counts as open, writable or not), checked by descriptor ending at the held parent, in `exec_preview` and `exec` alike (`resolveExec`). The service account's own trees are trusted as they are. **Owner-matched exception for `{path:read}` (maintainer decision, 2026-10-24, after the first review of PR #48):** a read placeholder is also given when every directory on its path that is not closed (and the target itself, if it is a directory) belongs to one and the same other account and is neither group- nor world-writable nor sticky (`fsx.Config.OwnerMatchedReads`, `readOpen`); two such accounts are refused, naming both; `{path:write}` and the `cwd` stay strict. Accepted residual, documented in POLICY §3 (the deny list) and §4: the owning account can swap a component for a symlink, redirecting the read to anything the service account can read within the gate's Landlock domain, a file on the deny list included, returned to the client; never to a file the service account cannot read (e2e `TestGateExecOwnerMatchedReadRace`). POLICY's `compose -f {path:read}` example works for a compose file in an application's own directory. The built-in git operations resolve their repository through the gate's other FS, unchanged: N-20. Not added then: a `check-policy` WARN for gate roots whose chain is open (the helper's check-policy has one for its roots). Done since (PR #50): `check-policy` checks every read and write root's path from `/` by descriptor, trusting root and the account it runs as, with a sticky directory counting as open (`fsx.CheckClosedChain`).

**N-12. No test removes one read-confinement layer at a time (found in the test-runtime chore, PR #41). Low priority.**
- **What.** `fsx`'s `TestSwapRace` swaps a directory on the path for a symlink to outside the root while reads and writes run, and requires that nothing outside is read or written. A read is confined by three layers, each of which alone refuses the swapped path: the parent is held as an `os.Root` descriptor and the target is opened from it (`locate`, `openTarget`); the opened file's real path must equal the target's (`openTarget`); and that real path must be inside the roots and not denied (`checkReal`). The test is not vacuous: with all three removed it failed 20 of 20 runs ("read content from outside the root"). With the first two removed it passed 20 of 20, because `checkReal` still refused. So losing any one layer, or two, goes unnoticed while one holds.
- **Proposed (not done):** one test per layer that disables only that layer (a test-only hook, or a build of `openTarget` without it) and shows the escape is still refused by the others, naming which layer refused; or, where a layer turns out to be the last line for some case (a write, a directory target), a test that shows it is. No production change is proposed.
- **Status: done (PR #50).** The `shellmcp_confine_hook` test build (never released: `scripts/release-binary-check.sh` refuses the tag and the hook's text in the gate and the helper) turns off one layer (`confineLayer`: descriptor, real path, checkReal) and runs code at named points of a lookup (`parent`, `target`, `open`); a release build's hooks are empty. `TestConfineLayersFileRead`, `TestConfineLayersDirectoryTarget` and `TestConfineLayersWrite` swap a path at a fixed point and require, for every layer turned off, the refusal of a named layer (or the read to go through, inside the root); `TestConfineLayersSwapRace` is TestSwapRace with each layer off. What they show: (1) the descriptor is the parent's own `os.Root`, so it refuses a final symlink that leaves the parent directory, inside the root or not, and follows one to a sibling (and, for a directory component, one that stays inside the root); (2) **checkReal is the last line** for a directory symlink that stays inside the root and leads to a denied or protected directory (without it a read returns the denied file and a write lands in the protected directory), and for a directory swapped out of the root before the parent is opened when the descriptor is gone; (3) the real-path check is never the last line for an escape, but it is the only layer that binds the object opened to the path located when a swap stays inside the root and off the deny list. Removing any one layer from the code fails these tests (every one of the four for the descriptor and checkReal; for the real-path check all but `TestConfineLayersWrite`, since a write never uses it), while TestSwapRace still passes (output in the PR). The lookups by path that stand in for the descriptor exist only in the tagged build (`rootByPath`, `fileByPath`), so release source has no such open (CodeQL `go/zipslip`, fixed in PR #50).

**N-13. Privileged command templates can call apt-get, apt or dpkg (found in S4c-7, PR #42).**
- **What.** Neither the privileged policy's never list nor POLICY §5's groups name `apt-get`, `apt` or `dpkg`, so a command declared with one of them as its path (any unit, any tier) runs as root through `priv_exec`, outside everything S4c-7 binds: no transaction in the approval, no recompute, no pinned simulation, no dpkg-status diff, and `priv_exec`'s kill on a hang-up instead of the package operations' stop points (a killed dpkg leaves the database half-configured). The allow-lists of `packages.install` and `packages.remove` do not apply to it either.
- **Proposed (not done here; maintainer, 2026-10-22):** S4c-9's policy check warns about, or refuses, a command whose binary (as written or resolved, and by identity, as POLICY §5's check) is apt-get, apt or dpkg, except the one fixed recovery template of N-14 if it is kept. A refusal is a privileged-policy schema change (a STOP for that session).
- **Status: done (S4c-9, PR #44).** Decided by the maintainer (2026-10-22) from three options (check-policy warns; policy load refuses unless acknowledged; refuses outright), by category; no new schema key (the existing `commands[].acknowledge`), the acknowledge list extended (approved). Every program is recognised by written name, resolved name and identity (the identity check now also scans the built-in operations' binaries, the D-Bus clients and, in the helper, the package tools and `find`):
  - **Package tools** (`apt-get`, `apt`, `aptitude`, `dpkg`, `unattended-upgrade`, `unattended-upgrades`): refused unless acknowledged. N-14's recovery template keeps working with an `acknowledge`.
  - **`find`** with `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`, `-fprint`, `-fprint0`, `-fprintf` or `-fls` as a whole token of any template: refused unless acknowledged.
  - **Program-running wrappers**: refused outright, as `env` and `xargs` are. Groups 1–10 already covered shells, interpreters, `env`, `xargs`, `sudo`, `su`, `nsenter`, `unshare` and `chroot`; S4c-9 added `systemd-run`, `systemd-cat`, `systemd-inhibit`, `systemd-socket-activate`, `run-parts`, `start-stop-daemon`, `taskset`, `chrt`, `prlimit`, `setarch` (with `linux32`, `linux64`, `i386`, `x86_64`), `numactl`, `time`, `logsave`, `dbus-run-session`, `dbus-launch`, `ssh-agent`, `chronic`, `rlwrap`, `unbuffer`, `xvfb-run`, `fakeroot`, `faketime`, `daemonize`, `cgexec` (group 4); `perf`, `catchsegv` (group 5); `run0`, `machinectl`, `systemd-nspawn`, `bwrap`, `firejail`, `schroot`, `proot`, `lxc-attach`, `lxc-execute` (group 7). POLICY §5 is shared, so gate policies refuse them too.
  - **D-Bus clients** (`busctl`, `dbus-send`, `gdbus`, `qdbus`, `loginctl`): refused outright, as `systemctl` is (gate and helper).
  - **Renamed copies of `systemctl`, `journalctl` and `git`**: refused by identity (before, a copy of `systemctl` matched only the power names that link to it, so it needed just an acknowledge, and a copy of `git` was not caught).
  - **Power binaries** (group 11): already acknowledged; now also reported.
  - Each acknowledged package tool, `find` with an action and power binary is a finding, in `check-policy` and in the policy summary.
  - **Residual until S-MC:** a root-owned wrapper script that calls any of these programs is judged by its own name and identity only (PRIVILEGED §4). **After S-MC (PR #53):** a #! script is judged by its interpreter, and multi-call binaries by the program they run as (POLICY §5); what a script or a compiled wrapper itself runs is still not looked at (N-26).

**N-14. The recovery path for an unfinished dpkg database (found in S4c-7, PR #42).**
- **What.** A package operation killed at its limit (or any other interrupted dpkg) leaves packages half-configured; every later apt run, unattended security upgrades included, and every package preview refuses until `dpkg --configure -a` runs. No package operation does that (it would be a new op).
- **Documented recovery (PRIVILEGED §6, "Package operations"):** a fixed broad-unit command template in the privileged policy, `path: /usr/bin/dpkg`, `unit: broad`, `tier: operator`, `templates: [["--configure", "-a"]]`, run through `shell_priv_run_command` (always approval-gated). It runs maintainer scripts as root and is subject to N-13's concern and to `priv_exec`'s kill on a hang-up, so it is the operator's deliberate, reviewed exception, not a default.
- **Status:** documented; no op proposed in S4c-7.

**N-15. An answer that cannot be delivered makes the instance exit 1 (found in S4c-7, PR #42; recorded in S4c-8).**
- **What.** `Serve` returns the result of writing the answer as the instance's exit status. A package operation that finished, whose answer (or early `outcome_unknown` answer) could not be written because the gate had gone, therefore exits 1, and systemd logs the instance as failed, while the helper's journal line for the request says `ok` (or the operation's own result). The same holds for every operation, since all of them answer through the same code.
- **Decision (maintainer, 2026-10-22):** keep exit 1: it records that the answer was not delivered. The helper's journal line is authoritative for the outcome; the instance's exit status says only whether the answer was delivered. Documented in PRIVILEGED §8.
- **Status:** documented; no code change.

**N-16. The privileged check-policy has no GTFOBins warnings (found in S4c-9).**
- **What.** The gate's `check-policy` prints a WARN, with the technique categories and a link, for every command whose binary has documented escape techniques (POLICY §6, `internal/gate/policy/gtfobins.go`). The helper's `check-policy` prints nothing of the kind, although a root command is the more dangerous place for such a binary (for example `tar` with a `{path:write}`, or `sed`).
- **Decision (maintainer, 2026-10-22):** recorded, not fixed in S4c-9. A follow-up would reuse the gate's list (`EscapeTechniques`) for privileged commands.
- **Status: done (PR #50).** One list and one wording (`gpolicy.EscapeWarning`), by the name written and the name resolved, as the gate's; the helper's warning adds that the command runs as root. Every name on the list that a privileged policy accepts gets the gate's categories (`TestGTFOBinsSharedList`).

**N-17. `priv_move` places files where rule R does not look (found while deciding N-8 and N-9, 2026-10-23). Must fix before release (maintainer, 2026-10-23).**
- **What.** A move keeps its inode, owner and mode, and no chain rule applies to either end.
  - **Into an open directory:** moving a root-owned file from a closed directory into one another account owns or can write gives that account N-8's gain from an existing file: a root-owned file it can move elsewhere on the filesystem.
  - **Out of an open directory:** an account that can write a directory under a write root can move a root-owned file in from elsewhere on the same filesystem (or plant a tree there holding one), and an approved move of "its" path into a closed directory has root place that file where root-ownership is trusted (a configuration directory, for example). The move's preview shows the source's stat, not its content, and binds no source identity at the operation.
- **Proposed rule (walk-level):** a move is allowed only when, for every non-directory it moves (the source itself, or every entry of a moved tree, from the walk `MoveExpecting` already makes over a directory, by descriptor), the entry's owner is owner-matched both on the source's chain (it could not have been planted: the moved-in rule's test, as for reads and copy sources) and on the destination's chain extended by the moved tree's own directories (rule R: nobody could move it on). A moved directory itself is exempt at the destination (another account cannot move it to another parent without write access to it) but its entries are not. Refused with `path_denied` before the rename, naming the directory and the owner that would pass, in the helper and, through `priv_backup_check`'s verdict for the destination and a source-chain check, in the composed preview.
- **Status: done (maintainer decision, 2026-10-23; PR #47).** As proposed, with three corrections from the phase-1 analysis, all approved: (1) the source test is owner-matched only, with no world-readable exception (what moves is the inode, with root's ownership, not its content); (2) the walk is not enough by itself, because `rename(2)` acts on a name: the commit is staged under `.shell-mcp-move-<32 hex>` in the destination's directory, checked to be the entry that was checked, and only then committed, and anything else is put back; (3) with `overwrite`, the verified replace used to park the replaced destination under the source's name in the source's directory until it was removed, where another account could take it; the exchange now happens in the destination's directory. Also decided: the rule applies to every non-directory (symlinks included), and every directory of a moved tree must have a mode `priv_mkdir` could create (within `modes.max`, neither group- nor world-writable, no setuid, setgid or sticky bit); a file move's preview refuses from `priv_backup_check`'s `owner_rule` for both paths (no protocol change), a directory's contents are checked when it runs and its preview says so (option A; no new op); a staging entry a stopped helper leaves is refused in every operation, blocks moves into and out of its directory and deletes or recursive chown and chmod of a tree holding it, and is named in the refusal and the journal line (`set_aside`). PRIVILEGED §6, "Moves".

**N-18. The gate's verified replace parks the replaced file in the source's directory (found in the N-17 analysis, 2026-10-23). Fixed in PR #48.**
- **What.** The gate's `move` with `overwrite` and `expected_destination_sha256` (and any gate move whose replace is verified) exchanges the source and the destination (`exchangeVerified`), so for a few system calls, until it is removed, the replaced destination file is under the source's name in the source's directory. An account that can write the source's directory can rename it away then and keep the service account's replaced file. The gate's copy and write stage their new file in the destination's directory, so for them the replaced file never leaves it; the gate's move is the case.
- **Impact.** The service account's own files, inside the gate's Landlock domain: a confused deputy for another local account that can write a directory under a gate write root, never root. The helper's move has its own staged commit (N-17).
- **Status: done (PR #48).** Confirmed from the code first: only the gate's move parked a replaced file (its verified replace exchanged the source and the destination across their directories); its copy and write already stage their temp file in the destination's directory and exchange there, so the replaced file never leaves it, and nothing changed for them. Every gate move is now staged as the helper's are (N-17's `commitStaged`): the source is renamed under `.shell-mcp-move-<32 hex>` in the destination's directory, checked to be the entry that was checked, and committed there (`RENAME_NOREPLACE` without `overwrite`, the verified exchange with `expected_destination_sha256`, `rename(2)` for the unconditional replace); anything else staged is put back, under a staging name in the source's directory when its name was taken again (the refusal and the audit line's `set_aside`). A path through such a name is refused in every gate operation, and so is a move into or out of a directory holding one and a delete or move of a tree holding one (POLICY §3, "Moves are staged"). The move rule itself stays the helper's. Side effect: an unconditional overwrite move now needs `RENAME_NOREPLACE` too, so a filesystem without it (NFS) refuses every gate move; `check-policy`'s WARN says "delete and move".

**N-19. A copy into a setgid directory is always root:root (recorded with N-17, 2026-10-23). Done in PR #52.**
- **What.** Since N-8 the helper sets both ids on every inode it creates, so a new file, copy or directory in a setgid directory gets group root unless a group is given, also in a closed directory an operator made setgid on purpose. `priv_write_file` and `priv_mkdir` take `group`, which restores that layout; `priv_copy` has no group input, so a copy there is always `root:root`.
- **Workarounds** (PRIVILEGED §6): write the file with `group` instead of copying it; or change the copy's group afterwards with `priv_chown`, where its chain from `/` is closed (N-1's rule; under a directory another account controls, chown is refused).
- **Status: done (PR #52).** P-15 as proposed below: `priv_copy` and `shell_priv_copy_path` take `owner?` and `group?`, validated and resolved as `priv_write_file`'s; `fsx.CopyAs` carries the owner into `writeAtomic`, whose rule R treats a copy's explicit owner as a write's and whose both-ids `fchown` sets it on the new inode; the copy preview's `set` shows the owner and group given, `checkOwnerRule` checks a copy as a write, and the canonical arguments bind both. The workarounds above are no longer needed (PRIVILEGED §6 now names the inputs).
- **Phase 1 (fix/final-findings, PR #50).** Proposal: optional `owner` and `group` on `priv_copy` and `shell_priv_copy_path`, exactly as `priv_write_file` takes them (names on `owners.users` and `owners.groups`, resolved by the helper's `owner()`; the result already carries the ids and names, P-12). Under rule R the owner the copy will have is the one given, else the destination's current one, else root's; a copy over a destination whose current owner fails rule R needs both an owner and a group that pass, as a write does. Protocol (P-15): `priv_copy` gains `owner?` and `group?` (its own argument struct; `priv_move` keeps `srcDstArgs`); an older helper refuses the unknown keys (strict decoding), and the server sends them only when given. Preview: the copy's `set` shows the given owner and group as a write's does (`willSet`), so they are bound by the preview hash; `checkOwnerRule` treats a copy with an owner like a write. Catalogue: `shell_priv_copy_path`'s input schema and canonical arguments gain both fields. Beyond the setgid case, it is the only way to place a binary or large file into an application's own directory as root: today a new copy is root's, which rule R refuses there, `priv_write_file` takes text up to `max_write_bytes`, and moving a root-owned copy in is refused by the move rule. Recommendation: worth doing before release, as its own small PR (fsx `CopyExpecting` gains an owner, reusing the explicit-owner path writes already use; unit, server and e2e tests including a closed setgid directory and an application-owned directory).
- **Decision (maintainer, 2026-10-24): approved, before release, as its own PR after PR #50,** as proposed above (P-15). Not implemented in PR #50.

**N-20. The gate's built-in git operations pass their repository as a string (found in the N-11 fix, PR #48). Must fix before release (maintainer, 2026-10-24). Fixed in PR #49.**
- **What.** `gitRepo` resolves the repository and its `.git` by descriptor (`ResolveDir`, `ResolveWrite`), then git gets the real path as strings (`-C <repo>`, `GIT_DIR=<repo>/.git`, `GIT_WORK_TREE=<repo>`) and looks them up again itself, first for the repository-local configuration check (`git config --local --list`) and then for the operation. An account that can change the entries of a directory on that path could swap in a symlink to another repository between the check and the operation; an account that owns the repository, its `.git` or `.git/config` could rewrite the configuration in that window without any swap. Either way git could run with configuration the allowlist refuses (filters, `core.*` programs), so possibly commands as the service account, inside the gate's Landlock domain. Not verified with a working exploit: whether git skips its own ownership check (`safe.directory`) when `GIT_DIR` is set needs checking against the git of the e2e image.
- **Why not fixed in PR #48.** Outside N-11 as recorded (its `exec` and `exec_preview`), and a behaviour change for listed repositories: the same chain rule on the repository and its `.git` (and a check of who owns the configuration file) would refuse a repository in a directory another account owns or can write. N-11's fix keeps git on the gate's other FS, so nothing about git changed.
- **Open question, to settle first:** does git skip its own ownership check (`safe.directory`, "dubious ownership") when `GIT_DIR` is set explicitly, as the gate sets it? If it does, a repository another account owns runs under that account's configuration with nothing in git to stop it; if it does not, git refuses such a repository already (the gate passes `safe.directory=<repo>` for the listed path, which a swapped-in repository at that same path would match). To check against the git of the e2e image, from its source or with a test, not from memory.
- **Open question, settled (2026-10-24, git 2.55's `setup.c`):** git skips its ownership check for a repository `GIT_DIR` names (an explicit `GIT_DIR` returns before discovery, and only discovery calls `ensure_valid_ownership`), so the gate's `safe.directory=<repo>` did nothing for the repository and POLICY §7's statement that it was honoured was wrong for the gate.
- **Status: done (maintainer's option c, 2026-10-24; PR #49).** (1) **The closed repository rule** (`fsx.CheckGitRepo`, by descriptor, in `gitRepo`, before any git process of every git operation, preview and discard sharing it): every directory from `/` to the repository, the repository, `.git` and `.git/config` owned by root or the service account and neither group- nor world-writable nor sticky (`path_denied` naming the entry, its owner and its mode); `.git` a real directory; no `.git/commondir` and no `.git/config.worktree` (`policy_denied`, as the commondir refusal was). No owner-matched exception. (2) **Configuration isolation as a second layer:** `-c` overrides for every program-running key with a fixed name (`core.editor`, `sequence.editor`, `core.askPass`, `core.alternateRefsCommand`, `diff.external`, `gpg.program`, `gpg.openpgp.program`, `gpg.x509.program`, `gpg.ssh.program`, `gpg.ssh.defaultKeyCommand`, all `/bin/false`), `hook.<event>.enabled=false` for all 28 events (git 2.55 runs hooks defined in configuration whatever `core.hooksPath` says), and the program-naming variables set (`GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`, `GIT_EXTERNAL_DIFF`, `GIT_SSH`, `GIT_SSH_COMMAND` to `/bin/false`, `GIT_PAGER=cat`, `GIT_PROXY_COMMAND` empty); `checkConfig` and the allowlist are kept. (3) POLICY §7 corrected and the cost documented: the gate cannot run git in a repository another account owns or can write; the operator gives it to the service account (or root), or uses a fixed root command template. Tests: the shellmcp_gitconfig_hook test build (never released) changes the configuration between the check and the git run. The program keys and hook events come from one table (`gitx.ProgramKeys`, `gitx.HookEvents`), which `TestGitProgramKeysCovered` checks against the installed git's own `git help --config` and githooks(5), so a git that adds a hook event or a program-running key fails CI until the table covers it (maintainer, 2026-10-24). **Follow-ups done (PR #50):** `-c safe.directory=<repo>` dropped from the argv (it did nothing: verified in git 2.55's `setup.c` and `run-command.c`, for the repository and for the processes git starts in a submodule, which also get an explicit `GIT_DIR`); `check-policy` applies the closed repository rule to every `git.repos` entry and WARNs naming the entry, its owner and mode. Found on the way: N-23 (a submodule's own configuration).

**N-21. A delete's set-aside entries move with their tree (found in PR #48). Low.**
- **What.** A delete that could not put an entry back leaves it under `.shell-mcp-delete-<32 hex>`, and the refusal names where; delete and delete preview refuse a tree holding one (POLICY §3). A move of a tree holding one (gate or helper) is not refused, so the entry can move elsewhere and the path the refusal named no longer holds it. Nothing is lost or exposed (the recovery is `find <write root> -name '.shell-mcp-delete-*'`), but the message's path is then stale.
- **Status: done (PR #50).** The move walk (`guardEntry`, both programs) refuses a tree holding a `.shell-mcp-delete-` or `.shell-mcp-move-` entry at any depth, `path_denied` naming the entry, nothing moved (`leftEntry`; the staging entry's refusal now names it too).

**N-22. Passing a `{path:read}` as the gate's open descriptor (recorded with the owner-matched exception, PR #48, 2026-10-24). Not implemented.**
- **What.** An opt-in, per-template setting under which the gate passes a `{path:read}` to the command as the descriptor it already opened and checked (`/dev/fd/N`, inherited by the command) instead of the path string. The command would then read the very file the gate resolved, so the owner-matched exception's redirect (an account that owns a directory on the path swaps in a symlink between the resolution and the command's lookup; POLICY §3, §4) would be closed for commands that accept a descriptor.
- **Limits found in N-10** (ARCHIVE §14, 2026-10-21, point 5), which is why it can only be opt-in per template:
  - commands that re-derive or canonicalise the path (`realpath` and the like) turn the link back into a string, and the race returns;
  - commands that use the name or its directory behave differently: `docker compose -f` resolves relative paths in the file (build contexts, `env_file`, other compose files) from the compose file's own directory, which for `/dev/fd/N` is `/dev/fd`; a file's extension, or a temporary file written next to it, change the same way;
  - anything the command starts after closing its descriptors loses it;
  - only an existing file has a descriptor (a `{path:write}` that does not exist yet has none), and a directory given this way is a directory the command can walk but not name;
  - `execx`'s trampoline marks every descriptor from 3 up close-on-exec before the exec (`CloseRange(..., CLOSE_RANGE_CLOEXEC)`), so passing one changes the shared exec engine;
  - the approval would show a path while the argv carries `/dev/fd/N`, so the preview would have to show both.
- **Status:** recorded at the maintainer's request (2026-10-24); not implemented. A template that sets it would be a gate-policy schema change.

**N-23. A submodule's own configuration runs in the gate's git operations (found in fix/final-findings, PR #50, 2026-10-24). Must fix before release (maintainer, 2026-10-24); its own PR, next session. Fixed in PR #51.**
- **What.** `git status` and `git diff` (the gate's `git_status`, `git_diff`, a pull's status check, and the discard's status with `--ignore-submodules=none`) check every populated submodule for changes by starting `git status --porcelain=2` in it (`is_submodule_modified`, `submodule.c`, git 2.55). That process gets `GIT_DIR=.git` relative to the gitlink's directory in the work tree (`prepare_submodule_repo_env` → `prepare_other_repo_env`, `run-command.c`) and reads that repository's own configuration: the allowlist (`checkConfig`) never sees it, and the closed repository rule does not cover directories inside the work tree. It inherits the gate's `-c` overrides (`GIT_CONFIG_PARAMETERS` is kept), so hooks and the fixed-name program keys stay off, but keys under names the repository chooses (`filter.<driver>.clean`, `include.path`, …) do not. A submodule needs no configuration in the superproject for this: a gitlink in the index and a directory holding a `.git` suffice.
- **Shown** (git 2.47.3, the gate's exact argv and environment, invented layout): a superproject whose configuration passes the allowlist and has a gitlink at `vendor/lib`; the directory filled with a repository whose configuration sets `filter.x.clean` and whose attributes apply it to a stat-dirty file; `status --porcelain=v2 --branch -z --untracked-files=no`, `diff --no-color --no-ext-diff --no-textconv` and the discard's status each ran the filter as the service account. Git 2.55's source has the same path.
- **Who can.** An account that can write the gitlink's directory (or one above it inside the work tree), for example an application account that owns a deployed checkout's subdirectory. The effect is a command of its choice as the service account, inside the gate's Landlock domain, through a read-tier tool.
- **Options (not decided):** (a) refuse a repository whose index holds a gitlink (one `ls-files -s` in the top-level repository, which starts no submodule process), `policy_denied`, as LFS is refused: submodules unsupported in v1; (b) pass `--ignore-submodules=all` to every status and diff and `-c diff.ignoreSubmodules=all`, and make the discard refuse any gitlink entry from the index instead of from status; (c) extend the closed repository rule to every gitlink's directory and its `.git` (and check its configuration with the allowlist), which needs a walk of the work tree's gitlinks. Recommended in PR #50: (a), the smallest and closed by construction, with (b) as a second layer.
- **Maintainer's preferred fix (2026-10-24):** git is told never to enter a submodule in any gate operation, rather than refusing repositories that contain gitlinks: `--ignore-submodules=all` on every status and diff, or the configuration equivalents (`diff.ignoreSubmodules=all`, `status.submoduleSummary=false`, `submodule.recurse=false`, `fetch.recurseSubmodules=false`), through the shared table in `internal/gate/gitx/programs.go`, so every git process gets them as `-c` overrides. To settle in that session: the discard's own status passes `--ignore-submodules=none` today to refuse a repository with submodule changes, so it needs another way to find gitlink entries (the index, `ls-files -s`, starts no submodule process); and which of the command-line flag and the keys wins where both apply, checked in git 2.55's source and with a two-sided test like this PR's probe (a filter in a gitlink directory's configuration must never run).

- **Status: done (PR #51, 2026-10-24; the maintainer's direction, option B for the discard and the refinement for status and diff).** No git process the gate starts enters a submodule. Checked in git 2.55.0's source first: the finding holds (`run_diff_files` → `match_stat_with_submodule` → `is_submodule_modified`, `diff-lib.c` and `submodule.c`, for any populated gitlink, with no `.gitmodules` needed). (1) **Flags:** every run that can read the work tree carries `--ignore-submodules=all` (status, the work-tree diff), `--ignore-submodules` (`update-index --refresh` in the discard) or `--no-recurse-submodules` (pull); `clean -n -d` and `checkout-index` take none and start no process in a submodule; runs comparing only the index with HEAD or two commits pass `=dirty` (`diff --cached`, and the new staged-gitlink check `diff --cached --raw -z --no-renames --no-abbrev`) or `=none` (the pull's changed-files count); `git_diff` adds `--submodule=short`. (2) **Configuration layer** (`gitx.SubmoduleKeys`, as `-c` on every process): `diff.ignoreSubmodules=all`, `diff.submodule=short`, `status.submoduleSummary=false`, `submodule.recurse=false`, `fetch.recurseSubmodules=false`. **Which wins** (settled in the source, tested two-sided): the command-line `--ignore-submodules` sets `override_submodule_config`, so neither `diff.ignoreSubmodules` nor `submodule.<name>.ignore` is consulted; `diff.ignoreSubmodules` alone loses to a `.gitmodules` `ignore = none`; `--recurse-submodules=no`, which pull passes to its fetch, beats `fetch.recurseSubmodules` and `submodule.<name>.fetchRecurseSubmodules`; pull's merge takes no flag and reads only `submodule.recurse`, so the `-c` value is its only layer. (3) **Behaviour** (maintainer, 2026-10-24): `git_status` keeps reporting staged gitlink changes (from the index-to-HEAD check) and drops a submodule's own work-tree state; `git_diff --cached` keeps its `Subproject commit` lines, the work-tree diff shows no submodule; `git_pull` refuses a staged gitlink change and ignores a submodule's own work tree, and its `changed_files` still counts gitlinks; the discard (option B) refuses a staged gitlink change (found without looking at the work tree) and otherwise discards only the superproject's entries, with `clean_after` ignoring a dirty submodule. (4) **Tests:** `TestGitNeverEntersSubmodule` (every operation, with and without a `.gitmodules` `ignore = none`), `TestGitSubmoduleFlagBeatsConfig`, `TestGitWithSubmodules`, `TestGitWorkTreeCommandsIgnoreSubmodules` with `TestGitWorkTreeGapsFound` (`gitx.GitCommands`), `TestGitSubmoduleKeysCovered` with `TestGitSubmoduleKeyGapsFound`, `TestGitEveryProcessIsolated` extended, and e2e `TestGateGitNeverEntersSubmodule`; all failing first on the tests-only head. Found on the way: N-25.

**N-24. The helper's check-policy does not treat a sticky directory on a root's path as open (found in fix/final-findings, PR #50). Low. Fixed in PR #50.**
- **What.** The helper's per-root WARN uses `fsx.CheckRootChain`, which counts a directory as open when another account owns it or it is group- or world-writable. Root commands' paths (N-10) also count a sticky directory as open, writable or not, so a root with a sticky (`1755`) directory on its path gets `ok` while every root command's path under it is refused. Nothing is allowed that should not be; the report is incomplete. The gate's new root check (`fsx.CheckClosedChain`) counts sticky as open.
- **Status: done (PR #50, maintainer's decision, 2026-10-24).** A root whose path passes the chain rule is checked again with `fsx.CheckClosedChain`, under which a sticky directory is open: a WARN names the sticky directory and that root commands are given no path at or under the root (chmod, chown and the moved-in checks ignore the sticky bit and are not named); the `ok` line says "nor sticky". `TestCheckPolicyStickyIsOpen`, failing first.

**N-25. A FIFO in a gitlink's directory stalls a git operation (found in PR #51, 2026-10-24). Low. Not fixed (maintainer, 2026-10-24).**
- **What.** With `--ignore-submodules=all`, git still compares a populated gitlink's checked-out commit with the recorded one before it applies the flag: `ie_match_stat` → `ce_match_stat_basic` → `ce_compare_gitlink` (`read-cache.c`, git 2.55) resolves the submodule's HEAD within git's own process (`repo_resolve_gitlink_ref` → `repo_get_submodule_ref_store` → `repo_submodule_init`, which reads its `.git` gitfile, repository format and refs). No process starts and nothing from the submodule's configuration runs; the result is discarded under `=all`. But an account that can write the gitlink's directory can make one of those files a FIFO, and git's read then blocks: `git_status`, `git_diff`, `git_pull` and the discard (all of which run status) stall until the request timeout (`timeout`), through a read-tier tool. `update-index --refresh --ignore-submodules` skips the read; status has no such option.
- **Status:** recorded at the maintainer's request; not fixed. A fix would have the gate open each gitlink directory's `.git` entries itself, by descriptor, before git does (refusing a non-regular file), or refuse a repository whose work tree has a gitlink directory another account can write.

**N-26. What a #! script runs is not looked at (recorded in S-MC, PR #53, 2026-10-24). Open.**
- **What S-MC does.** A command whose binary is a `#!` script is judged by its interpreter, as a command's binary is (POLICY §5): a never-listed interpreter refuses it, as do one that is not absolute or cannot be resolved and a first line the kernel would read differently. A list B or package-tool interpreter needs the acknowledge, and the line's argument counts with the template's tokens for `find`'s and coreutils' actions. Any other script gets a `check-policy` WARN naming its interpreter (maintainer decision, 2026-10-24).
- **What remains.** The script's own content is not looked at. A root-owned `#!/usr/bin/python3` script is refused (group 2), but a script run by an allowed interpreter (a compiled one, or `#!/usr/sbin/nft -f`, acknowledged) does whatever its file says. A compiled wrapper that calls another program is judged only by its own names, content and identity. The same holds for a script whose interpreter is allowed but that `exec`s another program through it. Both are N-13's residual, narrowed.
- **The broader question, for the maintainer:** should scripts be commands at all? Options:
  - (a) keep S-MC's rule (the interpreter judged, the script's own content not);
  - (b) refuse every `#!` script in the privileged policy, so root commands are binaries only, and keep the WARN in the gate, where a script runs as the service account inside the gate's sandbox;
  - (c) refuse scripts in both.

  (b) and (c) would break POLICY §4's `example-renew` shape whenever it is a script. A script's content cannot be judged in general (it is a program).
- **Status:** recorded; no decision yet.

**R-1. A restore's narrowed mode is not reported.**
- S4c-0 clamps the restored mode but does not report it: the result has no `mode` field, and adding one was a protocol change.
- **Decision:** S4c-5 reports the resulting mode in the preview and in the result, so a narrowing is never silent. Any protocol field for that is pre-approved (P-10, §4).
- **Status: done (S4c-5, PR #34).** The preview's `restore` carries `mode` beside `recorded_mode` (and `backup.mode`), `narrowed` (entries whose mode the mask changed), and for a tree `first` (≤ 50 entries with `recorded_mode` and `mode`) and `truncated`; the result carries the same.

### 2.2 Cross-cutting gaps

| # | Gap | Rating | Fix |
|---|---|---|---|
| X-1 | **The privileged policy is not bound into approvals.** The gate's `forward` returns the helper's `ok`, `data`, `error` and `warnings` under the gate's own block, so the helper's `policy_sha256` never reaches the server. `preview.policy` is the gate's hash, and an edit to the privileged policy between approval and re-call goes unnoticed. D-006 binds "the gate policy" only. | **MUST** | Protocol P-1: a `helper` block on forwarded responses. The server binds both hashes (D1). Dedicated preview ops also hash `policy_sha256` themselves (D2). |
| X-2 | **The approval core ignores "privileged".** `gated(t)` is tier-only, so with the default `SHELL_MCP_APPROVAL_TIERS=destructive` a privileged operator tool would run unapproved. That violates D-006. `ungatedCeiling` has the same blind spot. | **MUST** | D9: `gated(t, privileged)`. Privileged operator and destructive tools are always gated. For `shell_priv_run_command` the ungated ceiling is `read`. |
| X-3 | **No tools, no catalogue rows, no descriptions**, and `requiresUserInteraction` is not set on them. | **MUST** | Every session adds its tools (§5). Gated privileged tools carry the meta in every catalogue variant, as the destructive tools do. |
| X-4 | **Unclamped timeouts.** The gate clamps its own wait to its `limits.max_timeout_s` (≤ 600) plus 15 s, but forwards the request's `timeout_ms` unchanged. The helper clamps only to its own `max_timeout_s` (≤ 1800). So for a request whose timeout is above the gate's limit, the gate answers `timeout` while the helper's command or apt transaction carries on and may complete. The caller is told nothing ran to completion when it may have. | **MUST** for exec and packages | P-7: the gate forwards `timeout_ms` clamped to what it will wait for. The `timeout` message for privileged ops also says the operation may still complete on the host (S4c-6, S4c-7). |
| X-5 | **Redaction.** The helper redacts with the built-in rules only (`redact.New(nil)`; the privileged policy has no patterns). The server applies its own built-in rules and `SHELL_MCP_REDACT_PATTERNS` after that. | DOC | PRIVILEGED §8 or §6 says so. A privileged `redact` key would be a schema change, and is not proposed. |
| X-6 | **The gate's audit line for a privileged op** omits `owner`, `group`, the backup `id` and `packages`, because `loggedArgs` lacks them. The helper's line has them, and the two join on the request id. | DOC | ARCHITECTURE §2 notes the join. Adding them to `loggedArgs` is optional; not proposed. |
| X-7 | **The backup store has no global bound.** Each backup is ≤ 64 MiB and `backups.keep` applies per path, but the number of distinct paths is not bounded. Repeated writes across many paths can fill `/var/lib`. | **MUST** (Q10) | A total size cap, `backups.max_store_bytes` (§4.1), checked before every backup and by every preview that would write one; retention stays. An operation whose backup would exceed the cap is refused with `backup_failed`, saying the store is full, and changes nothing (S4c-2). |
| X-8 | **Pruning runs before the operation commits.** `store.save` prunes as soon as the new backup exists. An operation that then fails (verify, a lost race) has still pruned an older version. A restore can also prune the very backup it is restoring, if that backup is the oldest kept (its data is already in memory, so the restore itself succeeds). | **MUST** (Q12) | Prune after the operation succeeded, and never the backup being restored (S4c-2 and S4c-5). |
| X-9 | **Backups are not tied to approvals.** A backup's metadata records `op` and `request_id`, but not the preview it belongs to. | **MUST** (cheap) | The metadata records `preview_sha256` when the op carried one (a local file format, not the wire; D3). |
| X-10 | **Read-back of metadata.** Chown and chmod do not re-read what they set. Writes verify their content. | **MUST** (cheap) | fstat the same descriptor after fchown or fchmod; a mismatch is `verify_failed` (S4c-0 for the non-recursive ops, S4c-3 for recursive). |

**Status after S4c-7:** X-4 fixed for the package operations: the index update is stopped on a hang-up like a command; install, upgrade and remove follow must-fix (a)'s amended exception (an early `outcome_unknown` with the until-time, the graceful stop and the final kill), and every lost answer is `outcome_unknown`.

**Status after S4c-6:** X-4 fixed for exec: the helper stops a command whose gate hung up, the gate tells it before giving up and waits for its answer, and a timeout or lost answer on a privileged operation that can change the host is reported as an outcome unknown (must-fixes (a) and (b), §5). The package operations' share is S4c-7's.

**Status after S4c-5:** X-8 fixed for restore too: the backup being restored is never pruned by the restore's own retention, nor counted as freed by the store's cap (`store.protect`).

**Status after S4c-3:** X-10 fixed for recursive ops too (every entry read back on the descriptor it was changed on).

**Status after S4c-2:** X-7 fixed (the store cap, §4.1). X-8 fixed for every op but restore (S4c-5: never the backup being restored). X-9 fixed (`preview_sha256` in the metadata).

**Status after S4c-1:** X-1 fixed (P-1 and the combined hash; the dedicated preview ops' own hashes come with each op). X-2 fixed in the approval core (`gated(t, privileged)`, ceiling `read` for unapproved privileged operations); each tool session registers its tools. X-4: P-7 done; the `timeout` message for privileged ops is S4c-6's and S4c-7's. X-5 documented (PRIVILEGED §6). X-3 for the read tools.

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
- **DOC: the existing file's mode and owner are not bound at commit** (Q16). A chmod of the existing file between the fresh preview and the commit is carried over, because `writeAtomic` takes the current mode and owner when none is given; but the new inode's mode is always clamped to `modes.max` (F-4, S4c-0), so a widened mode never survives beyond the mask.
- **DOC: no content hash above 256 MiB.** `read_file` gives no SHA-256 above `maxHashBytes` (256 MiB). Such a file cannot be overwritten with backups on (64 MiB limit), so the preview refuses to request an approval without a content hash, rather than approve an unbound overwrite.
- **Backups: OK.** The hook runs through verified descriptors, and `unchangedSince` checks the file before the commit. Add an assertion that the backup's SHA-256 equals the previewed `current.sha256`; it holds by construction through `expected_sha256`, but the check is cheap (S4c-2). Pruning: X-8.
- **Owners: OK.** **Modes: MUST (F-4, S4c-0).** An explicit mode is checked against `modes.max`, and new files get `0640 & modes.max`, but a write over an existing file keeps that file's mode even outside the mask. After S4c-0 the new inode gets the existing mode `& modes.max`.
- **Read-back: OK.** **Audit: OK.** It logs `path`, `owner`, `group`, `mode`, `create`, `expect_absent` and `backup_ids`, never content. **Sandbox: OK** (core).

**`priv_mkdir`.**
- **Create-only: OK.** `mkdirIn` relies on `mkdir`'s own `EEXIST`, and `MkdirAs` without `parents` refuses an existing directory.
- **Preview: MUST, server-side.** A `priv_stat` of the path. With `parents`, also of each missing ancestor up to the first that exists (bounded by the path's depth). The preview lists the directories that will be created and their owner and mode.
- **Owners: OK.** **Modes: OK**, including the default `0750 & modes.max`. **Backups: n/a.** **Read-back: OK.** The created directory is re-opened and verified (`openSubdir`).

**`priv_chown`, `priv_chmod`.**
- **F-2: MUST (S4c-0).** The hard-link refusal.
- **Recursive: MUST** (Q2: in v1). The helper has no `recursive`, and the protocol has no field for it (P-4).
- **Preview binding: MUST.** The gate's own chmod has a stat preview and no commit precondition. For root the bar is higher:
  - a dedicated preview op (`priv_chown_preview`, `priv_chmod_preview`; P-2) returns the identity, owner and mode of every entry, and `preview_sha256`;
  - the op recomputes it (`expected_preview_sha256`, P-3), and applies each change on a descriptor whose identity it checks (D4).
- **Set-aside: n/a.** Nothing is removed. A tree holding a `.shell-mcp-delete-*` name is refused, as the delete refuses it.
- **Owners: OK.** **Modes: OK.** setuid, setgid and sticky files are never changed.
- **Read-back: MUST** (X-10).
- **Backups: DOC.** Metadata is not backed up (Q8).
- **Audit: MUST** (Q8). The helper's line records the old mode, owner and group of every entry it changed, bounded for recursive ops (D8).

**`priv_copy`.**
- **F-1: MUST (S4c-0).**
- **Create-only: OK.** A link commit without `overwrite`.
- **Preview: MUST, server-side.** Two `priv_stat`s, plus a `priv_read_file` of an existing destination for its content hash. It must show the source's mode, owner and size, and the destination's type, mode, owner and SHA-256 when the destination exists. With `overwrite`, the existing destination keeps *its* owner, and its mode clamped to `modes.max` (F-4), so root-only content can land in a readable file. The approver must see that.
- **Destination binding: MUST** (Q15). With `overwrite`:
  - when the fresh preview saw a regular file, the re-call sends `expected_destination_sha256` (P-9), and the helper refuses with `exists`, changing nothing, if the destination's content or type changed;
  - when it saw no destination, the re-call is sent with `overwrite: false`, so the commit is create-only (link, or `RENAME_NOREPLACE`) and never replaces a file that appeared;
  - a destination of another type (a directory, a symlink) is refused at the preview, and no approval is requested.
- **DOC: the source's content is not bound.** A change between the fresh preview and the commit, one round trip, is copied. The fresh preview catches anything earlier.
- **Backups: OK.** A replaced destination is backed up, and the backup's SHA-256 equals `expected_destination_sha256`. **Read-back: OK.** **Private-key refusal: OK.**

**`priv_move`.**
- **Create-only: OK.** `renameat2` with `RENAME_NOREPLACE`.
- **Preview: MUST, server-side.** Two `priv_stat`s as the gate's, plus the destination's content hash when it exists.
- **Destination binding: MUST** (Q15). As copy: `expected_destination_sha256` with `overwrite` when a destination file was previewed, `overwrite: false` when none was. Directories are never replaced (existing rule).
- **DOC: a directory move's contents are not previewed.** The move checks deny and protected rules at every new path (`walkTree`) and moves the inode, so the mode and owner are the inode's own.
- **Backups: OK.** A replaced destination file is backed up. **Owners and modes: n/a**, since the inode is unchanged. (Since N-17, PR #47: the move rule decides where an inode may go, and a moved tree's directories must have modes `priv_mkdir` could create.)

**`priv_restore_backup`.** (Status: done in S4c-5, PR #34; every MUST below, with the moved-in rule of N-6.)
- **Preview: MUST.** There is none.
  - A dedicated `priv_restore_preview` (P-2) returns the backup's metadata (id, kind, path, size, SHA-256, owner, group, mode, created, op) and the current state at the path.
  - For a file, the current state is absent, or the file with its size, mode, owner and SHA-256; a tree needs nothing there now.
  - It also returns the owner and mode the restore will set, whether the current version will be backed up, `policy_sha256` and `preview_sha256`.
- **Restoring over a changed file: MUST.**
  - The restore recomputes the preview (`expected_preview_sha256`).
  - It then writes with `expected_sha256` of the content it previewed, or with `expect_absent` when it previewed nothing.
  - So a file changed after the preview is refused with `exists`, and an approval to restore over "absent" never replaces a file that appeared (D3).
- **Create-only in tree restores: MUST.** `restoreTree` writes files with `Create: true` and no `expect_absent`, so a file planted inside a just-created directory is replaced (after being backed up). Use `expect_absent` for files; directories already rely on `mkdir`'s `EEXIST`.
- **The backup's own content: MUST** (Q3). `readData` already compares the data with the recorded SHA-256, but answers a mismatch with `backup_failed`. It becomes `verify_failed`, and nothing is restored. The preview checks it too, so a tampered or damaged backup never reaches an approval.
- **Owners and modes: MUST** (Q3). The recorded owner and group are kept, even outside `owners`; the recorded mode is clamped to `modes.max` (S4c-0), for files and for every entry of a tree. **Backups: OK** (the current version is backed up first, within the store cap, X-7). Pruning: X-8. **Read-back: OK** for files. For trees, each file is verified by `WriteFile`; add an entry-count check against the metadata.

**`priv_delete`.** (Status: done in S4c-4, PR #33.)
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
  - `priv_exec` takes `expected_preview_sha256` (P-3), required for an operator or destructive command (always approval-gated) and optional only for a read command (never gated), and refuses `exists` on a mismatch (Q14).
  - The gate's `exec_preview` cannot be reused: the gate cannot read the privileged policy (D6).
- **Routing: MUST** (D6, Q5). The server cannot know a command's unit. The preview reports it, the approval shows it and binds it, and the server sends `priv_exec` to that unit directly.
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
- **Approved as P2** (Q4): the steps above, in D5.
- **Lock: OK.** **Timeout: MUST** (X-4). **Audit: OK.** WARN, with package names. **Backups: DOC.** Package operations write no backups; dpkg's `--force-confold` keeps existing configuration files, and dpkg and apt keep their own logs (D8). **Sandbox: OK** (broad, root-equivalent by design).

**`priv_power`.** (Status: done in S4c-8; the design changed, see the S4c-8 entry.)
- **Preview: MUST, small.** `priv_power_preview` (P-2) returns the action, the target unit, the delay and the policy hash (amended in S4c-8: no job mode). It refuses an action that `power.allowed` does not list, and anything that blocks the action, so no approval is requested for it.
- **Binding:** `expected_preview_sha256`.
- **Approval: always.** **Ceiling: `destructive`.** **Audit: OK** (WARN). **Sandbox: OK** (broad; the bus is reachable only from there).
- **Found in S4c-8:** the op as built in S1d asked PID 1 directly for `StartUnit(<action>.target, replace-irreversibly)`. That never goes through logind, so it ignored every systemd inhibitor lock (block and delay), and the shutdown it started stopped the helper's own instance, whose answer then raced the shutdown. Replaced in S4c-8.

## 3. Design decisions

### D1. Binding the privileged policy

| Option | For | Against |
|---|---|---|
| **H1.** Only dedicated preview ops return `policy_sha256` in their data. | No response change. | Previews composed from `priv_stat` and `priv_read_file` (write, mkdir, copy, move) stay unbound. Every op would need its own preview op. |
| **H2.** The gate passes the helper's own block through as `helper` on every forwarded response (P-1). The server binds `gate.policy_sha256` and `helper.policy_sha256` together. | One change covers every privileged preview, including stat-based ones. The helper already fills that block (`respond` in `serve.go`). | A response field. |
| H3. A hello-style privileged op that returns the policy hash, called with every preview. | No response change. | An extra round trip, and a window between that call and the preview. |

**Decided (Q1): H2, plus the hash inside every dedicated preview op's own `preview_sha256`.**
- **On the server.** The record's `PolicySHA256` becomes the SHA-256 of `gate:<hash>\nhelper:<hash>`. This is internal, and the record struct does not change.
- **Why this one.** H2 is the only option that binds the composed previews without a new op per operation.
- **Why both.** Hashing the policy inside the dedicated preview ops also binds it *at the operation*, in the same request as the recompute, which closes the last round trip for the ops that destroy or replace.
- **Locked-decision change (approved).** D-006 extends its binding to the privileged policy's hash and, for a privileged command, its unit. The exact text is in §7.1.

### D2. Which preview pattern each op uses

| Op | Preview | Commit precondition | Why |
|---|---|---|---|
| `priv_write_file` | composed: `priv_stat`, `priv_read_file` | `expected_sha256` or `expect_absent` (existing) | Same as the gate. The content hash binds what is replaced, and the link commit binds "create". |
| `priv_mkdir` | composed: `priv_stat` (and ancestors) | none (`mkdir` is exclusive) | Same as the gate. |
| `priv_copy`, `priv_move` | composed: two `priv_stat`s, and the destination's content hash when it exists | without `overwrite`, the atomic no-replace commit; with `overwrite`, **`expected_destination_sha256`** (P-9) when a destination file was previewed, or the request sent with `overwrite: false` when none was | Q15: what an overwrite replaces is bound, as a write's is. A replaced destination is backed up. |
| `priv_chown`, `priv_chmod` | **`priv_chown_preview`, `priv_chmod_preview`** | **`expected_preview_sha256`** | Root changes metadata in place, and the inode at the path must be the one approved (D4). |
| `priv_restore_backup` | **`priv_restore_preview`** | **`expected_preview_sha256`**, then `expected_sha256` or `expect_absent` | Binds both the backup and what it replaces (D3). |
| `priv_delete` | **`priv_delete_preview`** | **`expected_preview_sha256`** (required) | The gate's S4b-2a design (D10). |
| `priv_exec` | **`priv_exec_preview`** (always the core unit; reports the command's unit) | **`expected_preview_sha256`**: required for operator and destructive commands, optional only for read commands; the server always sends it | The gate's S4b-2b design (D6, Q5, Q14). |
| `priv_pkg_install`, `_upgrade`, `_remove` | existing `priv_pkg_*_preview`, **gaining `preview_sha256`** | **`expected_preview_sha256`** (required), plus pins and post-run verification | D5. |
| `priv_pkg_update_index` | **`priv_pkg_update_index_preview`** | **`expected_preview_sha256`** (required) | Binds the action and the policy. |
| `priv_power` | **`priv_power_preview`** | **`expected_preview_sha256`** (required) | Binds the action, the delay and the policy, and refuses a disallowed or blocked action before an approval is requested. |

**Rejected:**
- **A dedicated preview op for every op**, write and mkdir included. These would duplicate preconditions that already bind exactly what changes.
- **A generic `priv_preview {op, args}`.** One op whose answer depends on another op's name. It is harder to tier-check and route (its unit depends on the inner op), and harder to fuzz.

**Rule for all of them.** Each preview op runs through the same resolution code as its operation: the ops never compute their own preview hash another way. Each runs in its operation's unit, except `priv_exec_preview`, which always runs in the core unit, because the unit is what it reports (D6); a broad command's `priv_exec` then recomputes the same hash in the broad unit, so any difference between the two is a refusal, never a different run.
- The server takes `preview_sha256` from the helper's answer before redaction (as `shell_delete_path` does).
- A preview op refuses whatever the op would refuse (path, owner, mode, allow-list, tier). Then no approval is requested.

### D3. Backups: creation, binding, retention and restore

**Unchanged.**
- **Where:** `/var/lib/shell-mcp/backups`, `root:root 0700`. It is on list A, `ReadWritePaths=`, Landlock read-write, and the built-in deny list.
- **Names:** `<id>.data` or `<id>.tar` beside `<id>.meta.json`, with `<id>` = `YYYYMMDDTHHMMSSZ-<16 hex>`.
- **Atomic creation:** temporary names, fsync, rename data first then metadata, then a directory fsync. A backup exists exactly when its metadata does.
- **The 64 MiB bound per backup,** and the `unchangedSince` check after the backup and before the commit.

**Changes.**
0. **A total size cap** (Q10, §4.1). `backups.max_store_bytes` bounds the bytes of every backup's data and metadata in the store together.
   - **Checked before each backup is written.** The check counts the store as it will be after this backup and after this backup's own retention pruning (versions of the same path beyond `backups.keep`, which X-8 removes once the operation succeeds). So a file rewritten again and again does not fill the store. Writing also stops at whatever room remains, through the existing counting writer.
   - **Refusal.** A backup that would exceed the cap is `backup_failed`: "the backup store is full (N of M bytes used); nothing was changed; remove old backups on the host or raise backups.max_store_bytes". Nothing changes. Every preview that would write a backup checks the same, so no approval is requested for an operation that would be refused.
   - **Fail closed.** A store whose total cannot be computed (more than `maxStoreEntries` names, unreadable metadata) refuses every backup the same way.
   - **Retention is unchanged:** `backups.keep` versions per path.
1. **The backup is bound to the preview.**
   - The metadata gains `preview_sha256` when the request carried an `expected_preview_sha256` or an `expected_sha256` (the latter for writes). This is a local file format: `meta.V` stays 1, with a strict decoder that accepts the new optional field.
   - For a file, the backup's SHA-256 must equal the previewed content hash, or the op fails with `backup_failed` and changes nothing.
   - For a tree, the tar is written from the same plan the deletion walks, entry for entry (D10).
   - Every preview says whether a backup will be written: kind and bytes, `backups.keep` 0 meaning none. A backup that would exceed 64 MiB makes the preview refuse with `backup_failed` before any approval is requested.
2. **Retention.** `prune` runs after the operation has succeeded, not inside `save`, and never removes the backup the current request restores from (X-8, Q12). `backups.keep` stays per path.
3. **Restore, safely.**
   - `priv_restore_preview {id}` reads the metadata and the data, and checks the data against its recorded SHA-256; a mismatch is `verify_failed`, and no approval is requested. It then states the current state at the path and what will be set.
   - The restore checks the data's SHA-256 again before it writes anything; a mismatch is `verify_failed` and nothing is restored (Q3; today `backup_failed`).
   - `priv_restore_backup {id, expected_preview_sha256}` recomputes that preview, and refuses `exists` on a mismatch.
   - Then:
     - **A file:** `WriteFile` with `expected_sha256` = the previewed current content, or `expect_absent` when there was none. The current version is backed up first (existing). A file changed between the recompute and the commit is refused by the content check at the commit: `exists`, nothing changed.
     - **A tree:** only where nothing exists. The root and each directory are created with `mkdir` (exclusive), and each file with `expect_absent`. The entry count must equal the metadata's `entries`.
       - A tree restore that stops part-way leaves what it created.
       - The message says how many entries were restored. Preview again, or delete the partial tree, and restore again.
   - **Restoring over a changed file** is therefore never silent. If the file changed after the approver looked, the restore is refused. If it changed in the last round trip, the commit refuses it.
4. **Owner and mode on restore (decided, Q3):** the recorded owner and group, even outside `owners`, because they are the file's own previous owner and are shown on the approval page; the recorded mode clamped to `modes.max`, as F-1's copy fix does.

### D4. Recursive chown and chmod: preview and binding

| Option | For | Against |
|---|---|---|
| **R1.** A walk like `PreviewDelete`: each directory opened from its parent's handle and re-checked; a hash over every entry's path, type, device, inode, mount id, birth time, uid, gid and mode (amended 2026-10-22: without the mount id, below); the op recomputes it, then applies each change on a descriptor opened by name, checking its identity before the change. | The same machinery as the delete, and exact. | Code. |
| R2. A non-recursive walk at the server, one `priv_stat` per entry. | No new op. | Unbounded round trips, and no binding at the commit. |
| R3. Drop `recursive` from v1 (TOOLS change). | No code. | A common root need, `chown -R` of an application directory, is missing. |

**Decided (Q2): R1, with S4c-0's link-count refusal on every entry of the walk.** The rules, mirroring the delete's where they apply:
- **Refused, as in a delete:** roots, mount points, device nodes, FIFOs and sockets, and `.shell-mcp-delete-*` names.
- **Never followed:** symlinks inside the tree are reported, and neither followed nor changed (no `lchown`).
- **Refused for these ops:** setuid, setgid and sticky files, and non-directories with a link count above 1 (F-2; checked on the same descriptor, as S4c-0 does).
- **Size bound:** `limits.max_delete_entries`, which avoids a schema change (Q2).
- **The hash** (amended by the maintainer, 2026-10-22, after a CI failure on PR #44): every entry's path, type, device, inode, birth time, uid, gid and mode, **without the mount id**. `stx_mnt_id` is local to a mount namespace, and every helper instance has its own, whose mounts get new ids (the lowest free ones); when another mount namespace came or went between two instances, an unchanged tree hashed differently and its approval or operation was refused (`approval_invalid`, `exists`). The mount id stays in the checks made within one instance: the walk's mount-crossing refusal (a mount placed into the tree after the preview is still refused) and the identity check before each change. The hash domain is v2. ARCHIVE §14, 2026-10-22, "The chown and chmod preview hash leaves out the mount id".
- **At each entry, before the change:** device, inode, type, mount id and birth time. (Within the operation's own instance.)
- **At the recompute only:** uid, gid and mode, because the change itself moves the change time. The change time is never compared after a change.
- **When it stops:** a mismatch stops with `exists`, "N of M entries were changed and K were not". There is no rollback; the counts are reported, consistent with the delete and the discard.
- **Read-back:** fstat after each change on the same descriptor (X-10).
- **No metadata backup** (Q8). Instead, the helper's audit line records, for every entry it changed, its path and its old mode, owner and group (`changed`). For a recursive op the list is bounded: at most 100 entries and 32 KiB of the line, whichever comes first, with `changed_total` and `changed_truncated: true` when it was cut. The line also carries the counts. Non-recursive ops record their one entry.

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

**Decided (Q4): P2.**

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
   - apt 3.0.3 (Debian 13) and the apt in Ubuntu 26.04 (3.2.0 when S4c-7 checked it; this said 3.1.x):
     - that `name=version` resolves to the same transaction as the unpinned request when the candidate is that version;
     - `--no-remove` ("immediately aborts" if anything would be removed);
     - `--only-upgrade` with explicit names: no new packages installed, and whether it marks auto-installed packages as manual. If it does, `apt-mark` must not be used to repair it; STOP;
     - whether `-s` output for the pinned argv is the same as for the unpinned one.
   - dpkg's status format: `Package`, `Architecture`, `Status`, `Version`; multi-arch qualifiers.

**Checked at the source in S4c-7 (apt 3.0.3 and dpkg 1.22.22 on Debian 13; apt 3.2.0 and dpkg 1.23.7 on Ubuntu 26.04, not the 3.1.x this section assumed), with invented packages in a local repository:**
- `name=version` gives a simulation identical to the unpinned request when that version is the candidate; it also installs a version that is *not* the candidate, so the pin alone would install the approved version after the candidate moved, and the recompute of the unpinned preview is what refuses that.
- `--no-remove` aborts with exit 100 ("Packages need to be removed but remove is disabled") and changes nothing.
- **Differs from the design:** `install --only-upgrade` with explicit names installs no package that is not installed *by name* ("Skipping …, it is not installed", exit 0), but **does install a new package that the pinned version depends on**, where `apt-get upgrade` keeps the package back. Decided (maintainer, 2026-10-21): the operation simulates the exact pinned argv it will run and requires its transaction to equal the approved one, in addition to recomputing the unpinned preview's hash, and keeps the dpkg-status diff after the run.
- `--only-upgrade` and a pinned install both leave automatically-installed packages marked as such; a downgrade is refused without `--allow-downgrades`; versions ending in `+` pin correctly.
- `-s` output for the pinned argv equals the unpinned one's when the candidates are the approved versions (upgrade: the pinned `install --only-upgrade` list equals `apt-get -s upgrade`).
- `apt-get -s` takes no lock; `apt-get update` takes the lists lock only.
- **Not assumed by the design:** after an interrupted dpkg, `apt-get -s` still succeeds, listing only pending `Conf` lines, while the real run refuses ("dpkg was interrupted"). Decided: the preview and the operation refuse up front on unfinished dpkg state or a non-empty `/var/lib/dpkg/updates/`, with the recovery command.
- apt exits 0 after a `SIGINT` stop, with only a warning; the result is therefore derived from dpkg's status, never from apt's exit code.
- dpkg status: `Package`, `Architecture`, `Status` (want, flag, state), `Version`; apt qualifies a name with `:arch` only when the architecture is neither `all` nor native (`pkgCache::PkgIterator::FullName(true)`), and dpkg's own entry carries the native architecture.

**Why not trust the simulation alone.** On a host with apt timers, unattended upgrades or another administrator, "what apt-get resolves at run time" is not the transaction the approver saw unless something pins it and checks it afterwards.

### D6. `priv_exec`: preview and unit routing

**Preview.** A helper `priv_exec_preview`, not the gate's `exec_preview`. The gate cannot read the privileged policy, so it cannot resolve the command, its unit, its tier or its templates.
- `priv_exec_preview` and `priv_exec` share one resolver function (`resolveExec`, as the gate did in S4b-2b): the command declared, its tier against min(`max_tier`, `ceiling`), `template.MatchIndex`, `{path:read}` and `{path:write}` against the privileged roots, and `cwd`.
- It returns `command_id`, `tier`, `unit`, `description`, `root_equivalent`, `capabilities`, the matched `template`, the resolved `argv` and `cwd`, `policy_sha256` and `preview_sha256`. The hash covers every one of them, the unit included.

**Routing (decided, Q5).** The helper's preview resolves the command against the privileged policy and reports its unit. The server never guesses, and never retries.
- **The preview is a core-unit op.** `priv_exec_preview` always goes to the core socket, with no `unit` label; the gate routes it like the other core ops. The core instance holds the whole privileged policy, so it resolves a command of either unit and reports which one it is declared for. This is the only preview that does not run in its operation's unit, because the unit is what it reports.
- **The approval shows the unit and binds it.** The unit is on the approval page and in the record's description ("in the broad unit"). It is in `preview_sha256`, and so bound by D-006's extended text (§7.1).
- **The server sends `priv_exec` to that unit directly.** The re-call's fresh preview reports the unit again. The server sends `priv_exec` with that `unit` label and the fresh preview's hash, and the gate routes by the label (existing code). An unapproved read command is sent the same way, after its preview.
- **`helper_wrong_unit` is an error, never a retry.** The instance behind the socket can refuse the request as meant for the other unit, for example after a policy edit between the preview and the exec moved the command. That answer passes through as the tool's error, and the server sends nothing to the other unit. Calling the tool again previews afresh, and a gated command then needs a new approval, because its preview hash changed.
- **Resolution in two namespaces.** A broad command is previewed in the core unit and run in the broad unit, which recomputes the hash in its own mount namespace before running anything.
  - The privileged roots are host paths that both units see under the same names: `ProtectSystem=strict` and `ProtectHome=read-only` make them read-only in the core unit, not invisible, and `/run` cannot be a root.
  - Anything that does resolve differently makes the hashes differ: a placeholder whose path exists in only one unit's view, for example, since each instance has its own `PrivateTmp`. The exec is then refused with `exists` (or `not_found`), never run with another argv.

**`expected_preview_sha256` on `priv_exec`** (decided, Q14). Required when approval is involved; optional only when it is not.
- Approval follows the command's tier: D-006 always gates privileged operator and destructive commands, and never read commands.
- So the helper enforces the field by the command's declared tier. A missing hash for an operator or destructive command is `bad_request`; for a read command it is accepted.
- The server sends it on every call either way.

**Rejected:**
- the gate reading the privileged policy: it cannot (`0600`, root), and the helper must stay authoritative (S1d);
- the server trying the core unit and then the broad one after `helper_wrong_unit`: the maintainer's decision is that a refusal is an error, never a retry in another unit;
- learning the unit from the policy summary (P-8): a policy edit between the summary and the preview would race, while the preview's own answer is bound by its hash.

**Gating.** Per-tier, as `shell_run_command`, with D-006's privileged rule:
- read commands: never gated;
- operator and destructive commands: always gated;
- unapproved calls: ceiling `read`;
- approved calls: the command's tier.

### D7. Core unit or broad unit, per op

| Unit | Ops | Why |
|---|---|---|
| **Core** | all file ops, backups, `priv_delete`, `priv_restore_backup` and their previews, `priv_exec_preview` for every command (D6), core commands' `priv_exec`, `priv_policy` | Landlock, `ProtectSystem=strict` with write access only to declared paths, four capabilities, no network, no local IPC. Nothing here needs more. |
| **Broad** | `priv_pkg_*` and every package preview (including `priv_pkg_update_index_preview`), `priv_power`, `priv_power_preview` and `priv_power_cancel`, broad commands' `priv_exec` | apt needs the network and writes `/usr`; power needs the system bus, which the core unit must never reach (S1d). These previews run in the same unit as their op, so they simulate in the same environment. |

The gate's `broadOps` and the helper's `broadOps` both gain `priv_pkg_update_index_preview` and `priv_power_preview`. `priv_exec_preview` is a core op at both (no label). `priv_exec` keeps its `unit` label.

### D8. Audit and journal evidence, per op

| Op | Helper journal (`shell-mcp-privd`) | Gate syslog | Server JSON | Other evidence on the host |
|---|---|---|---|---|
| reads | info: id, ceiling, peer, op, `path`, bounds | id, principal, op, `path` | tool call | — |
| write, mkdir, copy, move | info/notice: `path` (`source`, `destination`), `owner`, `group`, `mode`, `create`, `parents`, `overwrite`, `expect_absent`, `backup_ids` | id, principal, op, paths and flags (`owner` and `group` only in the helper's line, X-6) | tool call with `approval_id`, `approval_outcome` | backups' metadata (`op`, `request_id`, `preview_sha256`) |
| chown, chmod | as above, plus `recursive`, and `changed`: each changed entry's path with its old mode, owner and group (Q8). For recursive ops it is bounded at 100 entries or 32 KiB, with `changed_total` and `changed_truncated` | paths, `recursive` | as above | — |
| delete | `path`, `recursive`, `backup_ids`, `set_aside` (new, as the gate's) | `path`, `recursive`, `set_aside` | as above | the tree backup |
| restore | `backup_id`, `backup_ids` (the current version's) | — (only the backup id, which the gate does not log) | as above | both backups' metadata |
| exec | `command_id`, `arg_count`, `cwd`, `unit` (WARN in broad) | `command_id`, `cwd`, `unit`, `arg_count` | as above, `args_count` | — |
| packages | WARN: `packages`, and on success the `applied` counts (new) | op | as above, `packages` | `/var/log/apt/history.log`, `/var/log/apt/term.log`, `/var/log/dpkg.log` |
| power | WARN: `action`, and for `priv_power` `power` (what happened: requested, cancelled, refused, unconfirmed, not delivered), `scheduled_at`, `answered_early` and the logind error when it refused | op, `action` | as above | logind's and systemd's own shutdown journal |

Never logged, anywhere: content, command arguments, output, and `expected_preview_sha256`. The preview hash *is* recorded in the backup metadata, which is root-only and part of the evidence, not a log.

### D9. Approval for privileged tools

- `gated(t Tier, privileged bool)`: `t == destructive`, or `t == operator && (privileged || operator ∈ SHELL_MCP_APPROVAL_TIERS)`.
- `ungatedCeiling` for a privileged tool is `read`.
- Every gateable privileged tool carries `approval_id` (and `confirm` under `confirm-argument`). It has `requiresUserInteraction` in every catalogue variant, because it is always gated.
- **Descriptions:**
  - "As root, write N bytes to `<path>` on `<target>`"; "As root, delete `<path>` …"; "As root, run command `<id>` with N arguments in the `<unit>` unit on `<target>`"; "Install N packages on `<target>`"; "Reboot `<target>`".
  - Every description says "as root".
  - A path that is not plain is "a path shown in the arguments", as today.
- **Registration.** Read tools at `read`. Operator ops at `operator`. `shell_priv_delete_path`, `shell_priv_remove_packages`, `shell_priv_reboot_host` and `shell_priv_run_command` at `destructive`; the last runs read, operator and destructive commands per tier. `shell_priv_cancel_power` (S4c-8) at `read`, never gated, though it changes state: it can only stop a power action this helper scheduled. All `admin` only.
- **Annotations.** As TOOLS.md says: read tools as the read tier, everything else `destructiveHint: true`. `idempotentHint`:
  - **true:** write (same content), mkdir, chown, chmod, and copy without `overwrite`;
  - **false:** move, restore, delete, exec, every package op, and power.

### D10. `priv_delete` with backups

The order inside the op, extending the gate's `DeleteExact`:
1. **Walk the plan, and recompute and compare the hash.** On a mismatch: `exists`, nothing deleted, no backup.
2. **Back up from the plan,** when `backups.keep > 0`, within the store cap (D3, change 0; a delete whose backup would exceed it is refused before anything is removed). The tar is written from the plan's entries, in walk order: each directory re-opened from its parent's handle with the identity the walk saw, and each regular file opened by name and checked for that identity, size and change time.
   - A symlink or special file in the plan refuses here: `backup_failed`, nothing deleted. That is today's rule.
   - The tar's entry list must equal the plan's.
   - The backup's metadata records `preview_sha256` and `entries`.
3. **The set-aside deletion,** exactly as the gate's. At step 1 of each entry, a regular file's size and change time must still be what the backup recorded. So any write after the backup read the file stops the delete, with that entry and everything after it kept, except the open-descriptor case (c) below.
4. **What remains.** The gate's three cases (POLICY §3), and one consequence of case (c) for backups: a write through a descriptor opened before the delete, made after the entry's last check, lands in an inode that is removed, and the backup holds the content as of its read. That is documented in PRIVILEGED §6.

## 4. Protocol changes (approved with the answers in §6)

Protocol v1 is amended in place before any release, as in PRs #18, #24, #25 and #26. An older peer refuses each new field or op as unknown (`bad_request`, `unknown_op`), and never ignores it. A session that needs anything not in this table stops and asks.

| # | Field or op | Where | Type | Why |
|---|---|---|---|---|
| P-1 | `helper` | response (set by the gate on every response it forwarded from the helper) | object: `version`, `principal`, `policy_sha256`, `max_tier`, `unit` (`core` or `broad`), `duration_ms`; the helper's own block, which gains `unit` | D1, X-1: the server binds the privileged policy. The gate keeps its own `gate` block. |
| P-2a | `priv_delete_preview` | new op, read, core | args `{path, recursive}` → `{path, type, entries, bytes, first[≤50], truncated, backup{written, kind, bytes}, policy_sha256, preview_sha256}` | D10 |
| P-2b | `priv_chown_preview`, `priv_chmod_preview` | new ops, read, core | args `{path, owner?, group?, recursive}` / `{path, mode, recursive}` → `{path, type, entries, changes, first[≤50] (path, type, uid, gid, owner, group, mode, new values), truncated, policy_sha256, preview_sha256}` | D4 |
| P-2c | `priv_restore_preview` | new op, read, core | args `{id}` → `{id, kind, path, backup{size, sha256, entries, uid, gid, owner?, group?, mode, created, op}, current{state, …}, restore{uid, gid, mode}, current_backup, policy_sha256, preview_sha256}` | D3 |
| P-2d | `priv_exec_preview` | new op, read (the command's tier is checked as for `priv_exec`), **always the core unit**, for commands of either unit (D6) | args `{command_id, args, cwd}` (no `unit` label) → `{command_id, tier, unit, description, root_equivalent, capabilities, template, argv, cwd, policy_sha256, preview_sha256}` | D6 |
| P-2e | `priv_pkg_update_index_preview` | new op, read, broad | args `{}` → `{argv, policy_sha256, preview_sha256}` | D2 |
| P-2f | `priv_power_preview` | new op, read, broad | args `{action}` → `{action, target, delay_s, policy_sha256, preview_sha256}` (amended in S4c-8, approved by the maintainer 2026-10-22: `job_mode` dropped, `delay_s` added). **`priv_power`'s result** becomes `{action, target, scheduled_at, delay_s, cancel}` (same approval). | D2; S4c-8 |
| P-3 | `expected_preview_sha256` | args of `priv_delete`, `priv_chown`, `priv_chmod`, `priv_restore_backup`, `priv_pkg_update_index`, `priv_pkg_install`, `priv_pkg_upgrade`, `priv_pkg_remove`, `priv_power` (**required**); `priv_exec` (**required** for an operator or destructive command, which approval always covers; **optional** only for a read command; always sent by the server) | 64 lowercase hex; missing (where required) or malformed is `bad_request`; another hash is `exists`, nothing changed | D2, Q14: the operation runs exactly what was previewed, or nothing. |
| P-4 | `recursive` | args of `priv_chown`, `priv_chmod` | bool, default false | D4, Q2 |
| P-5 | `preview_sha256`, `argv`, `policy_sha256` | results of `priv_pkg_install_preview`, `priv_pkg_upgrade_preview`, `priv_pkg_remove_preview` | strings, list | D5 |
| P-6 | `applied` | results of `priv_pkg_install`, `_upgrade`, `_remove` | `{install[], upgrade[], remove[]}` as in the previews | D5: what actually changed, from dpkg's status. |
| P-7 | `timeout_ms` forwarded clamped | gate → helper | the gate rewrites the forwarded `timeout_ms` to the timeout it will wait for (its `limits.max_timeout_s` bound), instead of forwarding it unchanged | X-4 |
| P-8 | `priv_policy` (Q6: yes) | new op, read, core | `{policy_sha256, max_tier, limits, roots (read, write, persistence), owners, modes_max, backups_keep, backups_max_store_bytes, commands[] (id, tier, unit, description, templates, root_equivalent, capabilities), packages (enabled, install, remove, allow_update_index, allow_upgrade), power.allowed}`; never `paths.deny` values (only their count) and never `acknowledge` text. **Amended in S4c-9** (maintainer, 2026-10-22): `roots.persistence` as paths only, `deny_patterns` (the count), `power: {allowed}`, `ops[] (op, tier, unit)` (what the policy allows, by the operations' own checks; `priv_exec` with tier and unit `command`) and `findings[] (command_id, category, program, match)` (N-13) | discoverability for the model (Q6); N-13 findings visible to the client |
| P-9 | `expected_destination_sha256` | args of `priv_copy`, `priv_move`; valid only with `overwrite: true` (otherwise `bad_request`) | 64 lowercase hex. The destination must exist as a regular file with that content when the commit is prepared; otherwise `exists` (`not_found` when it is gone), and nothing changes. It is checked through the descriptor the backup reads, and `unchangedSince` holds it to the commit, as `expected_sha256` does for writes. | Q15 (approved): an approved overwrite replaces exactly the destination the approver saw. A preview that saw no destination sends `overwrite: false` instead; one that saw a directory or symlink requests no approval. |
| P-10 | the restored mode (pre-approved by the maintainer, 2026-10-18, R-1) | results of `priv_restore_backup`, and `priv_restore_preview` (P-2c) | S4c-5 designs the exact fields: the recorded and the resulting mode, for a file and for tree entries | A restore's narrowing to `modes.max` is never silent (S4c-0 clamps it but has no field to report it). |
| P-11 | `priv_backup_check` (approved by the maintainer during S4c-2, 2026-10-18) | new op, read, core | args `{path}` → `{written, bytes, fits, store_bytes, max_store_bytes}` | The composed previews of write, copy and move (D2) cannot otherwise learn `backups.keep`, the store cap or its use, so they could not refuse an operation whose backup would not fit (D3 change 0). The path must be one the write ops may change, so it is also the previews' write-root check. |
| P-12 | `uid`, `gid`, `owner?`, `group?` (approved by the maintainer during S4c-2, 2026-10-18) | results of `priv_write_file`, `priv_copy`, `priv_mkdir` | the new inode's owner and group as fsx read them from its descriptor; names when they are on `owners` | The tools report the owner and group actually set, as they report the mode. fsx keeps the ids `json:"-"`, so the gate's own `write_file`, `copy` and `mkdir` wire is unchanged. |
| P-13 | `priv_power_cancel` (approved by the maintainer during S4c-8, 2026-10-22) | new op, read tier (never approval-gated; admin profile only), broad | args `{}` → `{cancelled, request_id, action, scheduled_at}` | Stops a power action this helper scheduled, identified by the package operation record, never by anything the client sends. Read tier only so that no approval is needed (an approval takes longer than the delay); it is not in the read ops that change nothing, so a lost answer is `outcome_unknown`. |
| P-14 | `owner_rule` (approved by the maintainer, 2026-10-23, with N-8 and N-9) | result of `priv_backup_check` | `{verdict: any \| only \| none, uid?, name?, dir?, why?}`: rule R's verdict for a file at the path, from the same chain the operations check; `name` when `uid` is on `owners.users`; `dir` and `why` the first directory that is not closed. Only paths, uids and modes, the same in every helper instance (the #45 audit). | The composed write and copy previews refuse before an approval is requested what the helper would refuse under rule R (N-8); the move preview asks for both paths (N-17). |
| P-15 | `owner?`, `group?` (approved by the maintainer, 2026-10-24, with N-19) | args of `priv_copy` | names on `owners.users` and `owners.groups`, resolved and refused (`policy_denied`) exactly as `priv_write_file`'s; `priv_move` keeps its arguments. The server sends them only when given, so a copy without them reaches an older helper unchanged; an older helper refuses them as unknown (`bad_request`). | Under rule R the copy's owner is the one given, else the destination's, else root's, and an explicit owner must itself pass (N-6 tightened); both ids are set on the new inode. Without them a copy into an application's directory is refused (root's) and one into a setgid directory is always `root:root`, and a copy is the only way to place a binary or large file there as root. |

**Not protocol:** the backup metadata's new `preview_sha256` (a local file format), and the server's combined policy hash.

**Unchanged:** the error-code set (the store cap and a tampered backup reuse `backup_failed` and `verify_failed`); the request shape apart from P-7's value; and `priv_write_file` and `priv_mkdir`'s arguments, whose preconditions are already enough (D2; their results gain P-12's fields). `priv_copy`'s gain P-15's owner and group.

### 4.1 Privileged policy schema change (approved, Q10)

```yaml
backups:
  keep: 10                       # per file, unchanged
  max_store_bytes: 1073741824    # new: total bytes of every backup's data and metadata in the store
```

- **Default:** 1 GiB (1073741824).
- **Range:** 67108864 (64 MiB, one backup's maximum) to 1099511627776 (1 TiB). Outside it, the policy fails validation (`helper_policy_invalid`, field `backups.max_store_bytes`).
- **Ignored when `backups.keep` is 0**, since no backup is written then.
- **Reported by `check-policy`,** with the store's current use when it can read it.
- **Effect:** D3, change 0. A backup that would take the store over the cap is refused with `backup_failed`, saying the store is full and how much is used, and the operation changes nothing.
- **Documented** in PRIVILEGED §4 (schema and rules) and §6 (backups), and in the example privileged policy. The policy's SHA-256 changes, so the units are regenerated (existing rule).

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

### S4c-0: `fix(privd)`: every new inode within modes.max, hard links on chown and chmod, the mode/owner audit

- **Status: done (PR #28).** One exception: a restore's result has no `mode` field, and adding one is a protocol change, so the restored mode is not reported yet. The maintainer moved that to S4c-5 (R-1, §2.1). ARCHIVE §14, S4c-0, has the audit table. The findings N-1 to N-4 and their target sessions are in §2.1.
- **Includes.**
  - **One rule for every new inode the helper creates:** its mode lies within `modes.max`. The result reports the mode actually set.
  - **F-1: copy, by clamping, not refusing.** `priv_copy` has no mode input, so refusing would make such files uncopyable.
    - A new copy's mode is the source's mode, with setuid, setgid, sticky and world-write removed *and* masked by `modes.max`. So no bit falls outside the mask.
    - A copy over an existing destination takes the destination's existing mode, masked the same way (F-4).
  - **F-4: writes over an existing file** (Q16). The new inode gets the existing file's mode `& modes.max`, not the existing mode as it is. `TestDefaultModesWithinMask`'s "existing `0640` stays `0640` under `0700`" changes to `0600`, deliberately.
  - **Restore's mode** (Q3). A restored file, and every entry of a restored tree, gets the recorded mode `& modes.max`. The recorded owner and group are kept, even outside `owners`.
  - **F-2.** `priv_chown` and `priv_chmod` refuse a non-directory whose link count is above 1.
    - The refusal is `path_denied`, with a message naming the path and the link count.
    - The link count is read with fstat on **the same descriptor** that fchown or fchmod then acts on, never by a separate path lookup.
    - A link created after that fstat is equivalent to one created after the change. The inode was the write root's only name when it was checked. This is documented.
  - **The audit.** Check every helper op that sets a mode or owner against `modes.max` and the owner and group allow-lists, and list the result per op in the PR: `priv_write_file`, `priv_mkdir`, `priv_chmod`, `priv_chown`, `priv_move`, `priv_copy`, `priv_restore_backup`.
    - Also check whether any other helper op changes an existing inode's metadata or content *in place*, rather than committing a new inode. Apply F-2's rule to each one found, and list the result per op.
    - Restore is covered by the rule above; its other changes (preview binding, `verify_failed` on a damaged backup) are S4c-5's.
  - **Metadata read-back (X-10, Q13)** for the non-recursive ops: fstat after the change on the same descriptor; a mismatch is `verify_failed`.
  - **Old values in the audit (Q8)** for the non-recursive chown and chmod: the helper's line records the entry's old mode, owner and group (`changed`).
  - **Docs.** PRIVILEGED §4 and §6 (the new-inode mode rule, the link-count rule, read-back, restore's owner and mode) and ARCHIVE. PRIVILEGED.md must state the clamp's visible effect in so many words: a file wider than `modes.max` is narrowed to the mask when the helper writes it (and likewise when it copies over it or restores it).
- **Excludes.** Any tool; any protocol change; recursive chown and chmod (S4c-3).
- **Tests (failing first).**
  - Under `modes.max: "0700"`: a copy of a `0644` source gives `0600`, a copy over a `0644` destination gives `0600`, a write over an existing `0640` file gives `0600`, and a restore of a `0644` backup gives `0600`; each result reports the mode set.
  - Chmod and chown through a hard link inside a write root to a file outside it, through the helper's request handling: refused, and the outside file's mode and owner unchanged.
  - The same in **e2e-host in the core unit** (the link to a file under a non-write directory on the same filesystem).
  - Read-back with an injected fault.
  - The audit line carries the old mode, owner and group.
- **STOP.** If any op turns out to set an owner or mode outside the allow-lists by design, other than restore's recorded owner and group (F-3, decided); or if clamping would change a documented result shape other than F-4's.

### S4c-1: privileged binding, approval plumbing, read tools

- **Status: done (PR #29; ARCHIVE §14, S4c-1).** §7.1 applied verbatim in the first commit. P-1 (the helper's block names its `unit`; the gate passes it as `helper`), P-7 (the forwarded `timeout_ms` is the gate's clamped or default timeout), D1 (the combined policy hash in every privileged preview, through `previewFetch`), D9 (`gated(t, privileged)`, the privileged `ungatedCeiling`, the `privileged` flag on a tool's spec, "as root" in the descriptions), and the four read tools with their catalogue rows. §7.2 applied where this session's subject is concerned: ARCHITECTURE §3 step 4, §4.1, §4.2; PRIVILEGED §6's preview sentence; X-5's redaction note; §2.3's note on listing backups of former roots. The §7.2 items assigned to later sessions (TOOLS `stdin`, `recursive`, the restore preview; PRIVILEGED §6 `priv_exec` routing, §8's new audit fields) are left to them.
  - **Tested beyond the entry below:** a privileged-policy edit and a gate-policy edit after approval are each `approval_invalid`, with a synthetic privileged operator tool in the unit tests (no catalogue tool is gated yet); the forwarded timeout and the gate's answer coming after the helper's run, in the gate's unit tests and in e2e-host in both units with a command that ignores `SIGTERM`.
  - **Residual (X-4):** P-7 makes the helper's deadline the gate's, and the gate waits 15 s beyond it, so the gate's answer is the helper's, after the command has ended, unless an instance takes more than about 13 s to start or to end its command (the kill grace is 2 s). Closing that last window would need the helper to watch the connection and abort when the gate goes away, a behaviour this handoff does not specify; the `timeout` message for privileged ops (X-4, S4c-6 and S4c-7) stays the mitigation.
- **Includes.**
  - The first commit applies §7: the approved D-006 and S-12 text exactly as in §7.1 (D-021 is unchanged), and §7.2's wording for the documents this session touches.
  - **P-1.** The helper's block gains `unit`; the gate's `forward` passes it as `helper`; protocol types; the server's `gateclient` decodes it; the approval binds the combined policy hash (D1).
  - **P-7**, the clamped `timeout_ms`.
  - **D9:** `gated(t, privileged)`, the privileged `ungatedCeiling`, registration helpers for privileged tools, and descriptions saying "as root".
  - **Tools:** `shell_priv_read_file`, `shell_priv_list_directory`, `shell_priv_stat_path`, `shell_priv_list_backups` (read, admin only). `shell_get_policy`'s privileged section gains the summary in S4c-9.
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

- **Status: done (PR #30; ARCHIVE §14, S4c-2).** The four tools (admin, operator, always gated, `destructiveHint: true`); previews composed per D2 plus `priv_backup_check` (P-11, approved during the session: without it a composed preview cannot see the store cap); P-9; the store cap (§4.1) checked before every backup, retention-aware, under a store lock, fail-closed, and by every preview that would back up; the backup's hash asserted against the hash fsx computed and the precondition, recorded as `preview_sha256` (for copy and move, `expected_destination_sha256`); prune after commit, never the request's own backups (the restore part stays S4c-5's); the owner and group in results (P-12, approved during the session); `shell-mcp check` follows `privileged.max_tier`; N-3 in PRIVILEGED §6.
  - **Beyond the entry, found while testing:** with only `expected_destination_sha256` (or `expected_sha256`) and `unchangedSince`, a destination replaced in the moment after the last check is still replaced, and the window test of the handoff's own test list ("changed between the fresh preview and the commit (hook) is `exists`") failed on run 0. Every replace in the helper is now an exchange checked afterwards (`RENAME_EXCHANGE`, PRIVILEGED §6 "verified replaces"); an overwrite whose destination was absent commits create-only; and fsx itself requires the file backed up to be the version it hashed. Not a protocol change; a filesystem without `RENAME_EXCHANGE` (NFS) can no longer be overwritten as root. Accepted by the maintainer, with three additions in the same PR: the residual is documented (PRIVILEGED §6: the check compares inode, size and mtime, never the ctime, which the exchange itself changes, so an in-place edit that keeps the size and resets the mtime at that moment is overwritten); an operation that fails before committing anything deletes the backup it wrote; and the helper's `check-policy` probes `RENAME_EXCHANGE` and `RENAME_NOREPLACE` on each privileged write root.
  - **The gate has the same commit window.** The gate's own `write_file` with `expected_sha256`, and its `copy` and `move` with `overwrite`, check the destination a few system calls before `rename(2)`, so a file replaced there is replaced. **Fixed in PR #31** (ARCHIVE §14, 2026-10-19, the gate's verified replaces): a gate `write_file` with `expected_sha256`, and a `copy` or `move` with `overwrite` bound by the gate's new `expected_destination_sha256` (P-9 for the gate, approved by the maintainer; the server sends it on an approved re-call, or `overwrite: false` when the preview saw no destination), commit through the same verified replace; the gate's `check-policy` probes `RENAME_EXCHANGE` on each write root. Unapproved overwrites without a hash stay unconditional (POLICY §3).
- **Includes.**
  - `shell_priv_write_file`, `shell_priv_make_directory`, `shell_priv_copy_path`, `shell_priv_move_path`, with previews composed per D2 and the preconditions passed through.
  - **P-9** (Q15): `expected_destination_sha256` on copy and move with `overwrite`, and `overwrite: false` on the re-call when the preview saw no destination.
  - **The store cap** (Q10, §4.1): the `backups.max_store_bytes` key (parsing, range, `check-policy`, the example policy), the check before every backup (D3, change 0), and the previews refusing an operation whose backup would not fit.
  - The backup's SHA-256 asserted against the preview (for copy and move with `overwrite`, against `expected_destination_sha256`).
  - The metadata's `preview_sha256`.
  - Prune after commit (X-8, Q12; the restore part is in S4c-5).
  - **N-3 (§2.1):** PRIVILEGED §6 says that a file, copy or directory created without an explicit owner is the helper's (`root:root`), whether or not root is in `owners.users`, and the tools' descriptions or previews show the owner that will be set.
- **Excludes.** Chown, chmod, delete, restore.
- **Tests (failing first).**
  - The approval web flow for each tool.
  - A file created after approval: `approval_invalid`. One created after the fresh preview: `exists`, via the existing commit-window hook through the server.
  - Copy and move with `overwrite`: the destination changed after approval is `approval_invalid`; changed between the fresh preview and the commit (hook) is `exists`, with the destination intact; a destination that appeared where none was previewed is `exists` (create-only commit).
  - Copy-over shows the destination's type, mode and SHA-256 on the page.
  - A privileged-policy edit after approval: `approval_invalid`.
  - Pruning after a failed write keeps the older version.
  - The store cap: a backup that would exceed it refuses the operation with `backup_failed` and changes nothing; the preview refuses before an approval is requested; rewriting one file at `keep` versions never trips it; an over-full store (more names than can be counted) fails closed; the policy key's range.
  - **e2e-host (core):** each tool approved and run once; a second re-call is `approval_invalid`; the helper's journal shows the backup ids, and the backup's SHA-256 equals the preview's; a small cap refuses a write.
- **STOP.** If `priv_read_file`'s bounds make a whole-file hash impossible for files the helper may overwrite (they should not: the 64 MiB backup bound is below `maxHashBytes`).

### S4c-3: chown and chmod, recursive

- **Status: done (PR #32; ARCHIVE §14, S4c-3).** P-2b, P-3 and P-4 as listed (no other protocol change). The R1 walk is `fsx.PreviewMeta` and `fsx.ApplyMeta`, sharing the delete's walk primitives (`statxAt`, `inDir`, `readAll`, `crossesMount`). The hash is D4's list, nothing more. F-2 holds on every entry, at the walk and on the descriptor that is changed. Each change is read back on that descriptor. The bounded `changed` audit list has `changed_total` and `changed_truncated`. Both tools are in the catalogue. N-1 is fixed with the chain rule, and N-2 refuses special bits in the gate too (§2.1). Beyond the entry, decided or found:
  - The target being a configured root is refused too (D4's "roots", as in a delete; S4c-0's chmod allowed it).
  - An entry already as asked is skipped: no system call and no `changed` record. So `changes` in the preview counts only real changes, and a chown to the group a file already has records nothing.
  - Before each change, the descriptor's owner, group and mode must still be the walk's, not only its identity. Nothing the operation did can have changed them yet (children are changed before their directory).
  - On a filesystem that reports no birth time, an entry deleted and created again with the same inode number, owner and mode hashes the same (D4 has no change time). The chain rule leaves only root able to do that. Documented in PRIVILEGED §6.
  - The finding N-6 (§2.1): overwrites inherit a moved-in file's root ownership; to decide in S4c-5.
- **Includes.**
  - P-2b, P-3 (chown and chmod) and P-4.
  - The R1 walk (D4) in `fsx`, shared with the delete's walk where possible.
  - F-2's link-count refusal for every entry of the walk (Q2), read on the descriptor that is changed, and read-back per entry.
  - The audit's `changed` list with old values, bounded (100 entries or 32 KiB, `changed_total`, `changed_truncated`; Q8).
  - `shell_priv_change_owner`, `shell_priv_set_permissions`.
  - **N-1 (§2.1), must fix before these tools are exposed:** move in, change, move out.
    - Evaluate the recommended fix: refuse an in-place metadata change, non-recursive or any entry of a walk, unless every directory from `/` to the target is root-owned and neither group- nor world-writable. Check it by descriptor along the walk, with no separate path lookups. Add a `check-policy` and helper self-check warning for privileged write roots that fail it.
    - Evaluate the alternative: refuse an inode whose current owner is not on the `owners` allow-list.
    - **Decide which with the maintainer before implementing it** (a STOP below).
  - **N-2 (§2.1):** decide whether chmod refuses setuid, setgid and sticky files, as chown does. `fsx.Chmod` is shared with the gate, so a change there also changes `shell_set_permissions`.
- **Excludes.** Metadata backups (Q8: none).
- **Tests (failing first).**
  - Hash coverage: an entry added, removed, renamed, replaced, chmod-ed or chown-ed, changes it.
  - Refusals: mount point, device, set-aside name, setuid, a hard link (F-2), symlinks not followed.
  - A **window test** at every step (before the recompute, after it, between an entry's identity check and its change), 200 runs each.
  - A **concurrent racer**, 400 runs: replacing entries and adding hard links; nothing outside the plan changes.
  - Read-back.
  - The audit line: old values for every entry changed; a tree above the bound is truncated and flagged, with the right total.
  - **e2e-host (core):** a recursive chown of a tree with a hard link to a file outside the roots is refused and changes nothing; the approval flow; the journal line's `changed` list.
  - **N-1:** a file moved into a write root from a directory the attacking account can write cannot be chmod-ed or chown-ed, non-recursively or inside a walk, with whichever fix is chosen. Covered in the unit tests and in e2e-host (core).
- **Fuzz.** The entry encoding (as `FuzzPreviewEntryEncoding`).
- **STOP.** If a change-time rule cannot be made to hold on the runner's filesystems. Before implementing N-1's fix: the choice between the two options is the maintainer's.

### S4c-4: delete

- **Status: done (PR #33; ARCHIVE §14, S4c-4).** P-2a and P-3 as listed (no other protocol change; `priv_delete`'s result shape is unchanged). The gate's walk and set-aside deletion are shared, not copied: `fsx.PreviewDeleteBound` and `fsx.DeleteExactBound` call the gate's code with the privileged policy's hash in the preview hash (its own domain, so the gate's hash input is unchanged) and, with backups on, the backup written from the plan (D10) before anything is removed: files opened by name from their parent's handle and required to be the walk's objects with their size and change time (checked again after the read), directories re-opened with the walk's identity, the archive sized from the plan first (store cap and 64 MiB bound refused before anything is written) and holding exactly the plan's entries. S1's `Delete`, `DeletePreview`, `deleteOp`, `backupTree` and `removeTree` are removed. `set_aside` and a bounded `removed` list are in the helper's audit line. Both tools are in the catalogue. Decided or found beyond the entry:
  - **No chain rule for delete** (maintainer, 2026-10-19). Unlinking or renaming an entry needs write access to its directory, so an account that could move an entry in, or swap entries during the delete, could unlink it itself; the set-aside and identity checks make root remove only the approved inodes. PRIVILEGED §6, "Delete".
  - **No link-count refusal for delete** (maintainer, 2026-10-19), as in the gate: an unlink removes a name, never an inode. The prompt listed one as part of the S4b-2a machinery, which has none.
  - **The fail-safe backup rule for delete.** A commit is reported at each unlink and when an entry is left set aside. "Provably unchanged" is explicit accounting, not inferred from which paths ran (maintainer review, 2026-10-19): the deleter counts entries set aside, put back, stranded and unlinked, and only zero unlinks, zero stranded and put-backs equal to set-asides discard the backup; a stop after a set-aside with no put-back keeps it (`TestDeleteStopAfterSetAside`, `TestPrivDeleteStopAfterSetAsideKeepsBackup`).
  - **The preview reports the backup itself** (P-2a's `backup`), counted as the backup counts it: `priv_backup_check` (P-11) answers for an overwrite of a regular file only, so it cannot size a tree.
  - **An entry replaced or changed while it is backed up is `exists`**, nothing deleted (D10 named only `backup_failed` for symlinks and special files).
- **Includes.**
  - P-2a and P-3 (delete).
  - The helper's `delete` moves to `PreviewDelete`/`DeleteExact` with the backup from the plan (D10).
  - `set_aside` in the helper's audit line.
  - S1's `fsx.Delete`, `DeletePreview`, `deleteOp`, `backupTree` and `removeTree` are removed once nothing uses them.
  - `shell_priv_delete_path`, and the read tool `shell_priv_preview_delete` (Q7).
  - The store cap applies to the tree backup (§4.1).
  - POLICY §3's "until S4c" sentence.
- **Tests (failing first).**
  - The gate's window and racer tests, through the helper.
  - The backup holds exactly the deleted entries, and a file written after the backup read it stops the delete.
  - Stranded entries named and refused.
  - Backups disabled.
  - A backup over 64 MiB, or over the store cap, refused at the preview.
  - **e2e-host (core):** approval, a second re-call, a newcomer after approval, a device node, a mount point.
- **STOP.** If the backup cannot be written from the plan without a second walk.

### S4c-5: restore

- **Status: done (PR #34; ARCHIVE §14, S4c-5).** P-2c, P-3 and P-10 as listed (no other protocol change). `restorePlan` is shared by `priv_restore_preview` and `priv_restore_backup`: the data verified against its recorded size and SHA-256 at both (`verify_failed`), the path re-checked, the recorded owner checked by the moved-in rule, a file's current version hashed under the read rule and its backup counted against the cap, a tree's archive parsed (`parseTreeArchive`, fuzzed) with its entry count equal to the metadata's; a file is restored by a verified replace bound to the previewed content or create-only, a tree with exclusive mkdirs and create-only files; `store.protect` keeps the backup being restored (Q12). `shell_priv_restore_backup` (operator, admin, always gated); no read-tier preview tool (Q7 does not name one). N-6 and N-7 decided with the maintainer and done (§2.1); N-8 found. Beyond the entry: `check-policy` reports read roots' chains too; `-timeout 20m` on the CI and ci-local race runs (prompt). Go stayed at 1.27.2 until PR #35 bumped it to 1.27.3, which this branch merged (ARCHIVE's temporary note, resolved).
- **Must decide before S4c-5 ships: N-6 and N-7 (§2.1), together** (maintainer, 2026-10-19). For N-7: whether reads and backup listings follow the chain rule.
- **N-6 (§2.1)**, for `priv_write_file`, `priv_copy` with `overwrite` and `priv_restore_backup` together. Proposed: over an existing file whose path fails the chain rule, the owner and group are not inherited; an explicit allow-listed owner and group are required, or the operation is refused. Decide with the maintainer (a STOP), then implement it in this session for all three.
- **Includes.**
  - P-2c and P-3 (restore).
  - Restore through `expected_sha256` or `expect_absent`.
  - Tree restore create-only, with an entry-count check.
  - Q3: the backup's recorded content hash verified at the preview and again before anything is written, `verify_failed` on a mismatch (today `backup_failed`); the recorded owner and group kept; the mode clamp (S4c-0) carried into the preview's `restore` values.
  - **R-1 (§2.1):** the resulting mode is reported in the preview and in the result, so a narrowing is never silent: the recorded mode next to the mode set, for a file and for every entry of a tree (bounded as the preview's `first` list, with counts). The protocol field for it is pre-approved (P-10).
  - Prune never removes the backup being restored (Q12).
  - The current version's backup is within the store cap.
  - `shell_priv_restore_backup`.
- **Tests (failing first).**
  - Restore over a file changed after approval (`approval_invalid`), and after the fresh preview (`exists`, via the commit hook).
  - A file planted in a tree being restored: `exists`, the planted file intact.
  - A tampered data file: `verify_failed` at the preview (no approval requested), and `verify_failed` when it is tampered with after approval, with nothing restored.
  - The restored owner, group and mode per Q3.
  - R-1: a backup whose recorded mode is wider than `modes.max` shows both modes in the preview and the result, for a file and for a tree entry.
  - The restored backup is kept.
  - **e2e-host (core):** write, then restore, then restore again (the restore's own backup).
- **STOP.** If verifying the data before writing would need a second read of a file larger than the 64 MiB backup bound.

### Must fix before S4c-6 and S4c-7 ship (recorded by S4c-2, at the maintainer's request)

S4c-1 left one exception to "the gate never answers `timeout` while the helper's command still runs" (S4c-1 status, residual X-4): P-7 makes the helper's deadline the gate's, and the gate waits 15 s beyond it, so the gate's answer is the helper's unless an instance takes more than about 13 s to start or to end its command (the kill grace is 2 s). For a read that only costs an honest `timeout`; for a root command or an apt transaction it means the caller is told nothing finished while root work carries on and may complete. So, before `shell_priv_run_command` (S4c-6) or any package tool (S4c-7) is exposed:
- **(a) The helper kills its running command when the gate's connection drops.** It watches the connection while a command or apt-get runs, and on a hang-up or reset kills the process group (`SIGTERM`, then `SIGKILL` after the grace) before it exits, so the gate can never answer `timeout` while a root command keeps running. Tested in e2e-host in both units with a command that ignores `SIGTERM` and a gate killed mid-run.
- **(b) A timeout on any state-changing privileged op is reported as "outcome unknown".** The `timeout` message for a privileged operator or destructive op says the operation may have completed on the host and must be checked there (preview again, or read the journal and the backups) before retrying; the approval stays consumed, and a re-call needs a new approval. This is X-4's message, made a requirement.
- **Amended for package operations (maintainer decision, 2026-10-21, S4c-7): an explicit, documented exception.** For `priv_pkg_install`, `priv_pkg_upgrade` and `priv_pkg_remove` only, root work may continue after the answer: killing apt-get or dpkg part-way leaves dpkg's database half-configured, and every later apt run, unattended security upgrades included, refuses until an administrator runs `dpkg --configure -a` (verified in S4c-7 on Debian 13 and Ubuntu 26.04). On a hang-up or at the request's deadline the helper sends no signal and answers at once with `outcome_unknown`, naming the request id and the UTC time the operation may run until; at `limits.max_timeout_s` less the stop allowance (`min(60 s, max_timeout_s / 4)`) it sends `SIGINT` to apt-get alone (apt's own graceful stop at the next safe point); at `limits.max_timeout_s` it kills the process group and reaps, as (a) does, and the journal line names `dpkg --configure -a`. The operation is bounded by `limits.max_timeout_s`, always reported as `outcome_unknown` with the until-time, never `timeout` or a refusal, and its journal line is written whenever it ends. `priv_pkg_update_index` and every other privileged operation keep (a) unchanged. PRIVILEGED §6, "Timeouts, and a gate that goes away".
- **Amended for `priv_power` (maintainer decision, 2026-10-22, S4c-8): a second explicit, documented exception.** A reboot or power-off ends the connection that carries its own answer, so `priv_power` answers first and acts after a fixed delay (60 s). Until the helper has confirmed that the gate read the answer, a hang-up means nothing is scheduled. Once the answer is confirmed read, a hang-up of the gate does **not** cancel the scheduled action: only `priv_power_cancel`, or the instance ending for any reason (in which case nothing is requested from logind), does. The instance's life is bounded by the delay plus at most 20 s (the confirmation and the logind call), inside `RuntimeMaxSec=`. PRIVILEGED §6, "Power".
- Both belong to S4c-6's and S4c-7's scope; neither changes the protocol (a hang-up is already a closed connection, and the message is text).
- **Status: (a) done for `priv_exec`, (b) done for every privileged operation (S4c-6, PR #37; ARCHIVE §14, S4c-6).** (a): the helper watches its connection while a command runs and stops the command on a hang-up, kills and reaps what it started (child subreaper; fail closed: `outcome_unknown` when it cannot confirm none is left) before answering, and the gate shuts down its sending side 7 s before its deadline and waits for that answer. (b): for a request that can change the host (`protocol.PrivMayChange`), the gate, the helper (a command stopped by a hang-up) and the server (a failure after the session started) report the new closed-set code `outcome_unknown` (approved by the maintainer, 2026-10-21), with the approval used. **S4c-7 still owes (a) for apt-get:** the package operations must run through the same hang-up watch and reaping as `priv_exec` (`runCommand` in `internal/privd/ops/exec.go`); amended for install, upgrade and remove by the exception above (S4c-7).

### S4c-6: exec

- **Status: done (PR #37; ARCHIVE §14, S4c-6).** P-2d and P-3 as listed (no other protocol change). `resolveExec` is shared by `priv_exec_preview` (read, core, for commands of either unit; the broad instance refuses it) and `priv_exec`; the hash covers its domain, the policy's SHA-256, the command id, tier, unit, description, `root_equivalent`, capabilities, the matched template, the resolved argv and cwd. `priv_exec` requires `expected_preview_sha256` for operator and destructive commands and recomputes it in its own unit. `shell_priv_run_command` (admin, destructive, privileged; no stdin, Q11) previews first, runs a read command unapproved at ceiling `read` and an operator or destructive one only once approved, at its tier, sends `priv_exec` with the fresh preview's unit and hash, and never retries a `helper_wrong_unit`. The unit is on the approval page and in the description. Must-fixes (a) and (b), above. Beyond the entry, decided or found:
  - **The gate waits for the helper's confirmation.** The helper's kill alone would still let the gate answer `timeout` during the 2 s kill grace, so the gate shuts down its sending side before its deadline (not a protocol change: a half-closed connection is a hang-up) and reads on.
  - **Processes that leave the command's process group** (`setsid`) were outside the kill; the helper is now a child subreaper while it runs a command, and kills and reaps every child left before answering, within the units as they are (no unit or Landlock change).
  - **Lost answers, not only timeouts.** A helper that dies mid-run (OOM, `RuntimeMaxSec`) closes without a byte, which the gate reported as `helper_refused`, a refusal; for a request that can change the host it is now `outcome_unknown`.
  - **No STOP for the namespaces.** Both units see the roots under the same host paths; whatever resolves differently changes the argv and so the hash (tested with a link changed between the core preview and the broad run).
- **Includes.**
  - P-2d and P-3 (exec).
  - `resolveExec` in the helper, shared by `priv_exec` and `priv_exec_preview`.
  - `priv_exec_preview` as a core-unit op for commands of both units (gate and helper `broadOps` unchanged for it; the helper's unit check treats it as core).
  - Routing as decided (D6, Q5): the server sends `priv_exec` with the unit the fresh preview reported; `helper_wrong_unit` passes through as the error, never a retry.
  - The unit on the approval page and in the description, bound by the preview hash.
  - `expected_preview_sha256` required by the helper for operator and destructive commands, optional for read commands (Q14).
  - `shell_priv_run_command` with per-tier gating (D9).
  - TOOLS loses `stdin` (Q11).
  - X-4's message for exec timeouts.
- **Tests (failing first).**
  - Preview equals exec resolution for every template and placeholder type, in the core unit and for a broad command recomputed in the broad unit (`FuzzExecPreviewMatchesExec` for the helper).
  - A policy edit (binary, template, tier, unit) between preview and exec: `exists`, `tier_denied` or `helper_wrong_unit`, nothing run.
  - **No retry:** a command moved to the other unit after its preview gives `helper_wrong_unit` as the tool's result, and the other unit's socket receives nothing (the fake gate records every request).
  - A path placeholder retargeted.
  - A read command runs unapproved at ceiling `read`; a command raised to operator after its preview is refused.
  - `priv_exec` of an operator command without `expected_preview_sha256` is `bad_request`; a read command without it runs.
  - **e2e-host:** a core command and a broad command, each previewed in the core unit, approved, and run once in its own unit, with their journal lines; a misroute is refused by both instances.
- **STOP.** If a broad command's resolution in the core unit can differ from the broad unit's in a way the hash does not cover.

### S4c-7: packages

- **Status: done (PR #42; ARCHIVE §14, S4c-7).** P-2e, P-3 (packages), P-5 and P-6 as listed (no other protocol change; no error-code, envelope, unit, Landlock or schema change). The previews hash the transaction with the policy and refuse whatever the operation would refuse; an install, upgrade or remove recomputes the preview's hash, simulates the exact pinned argv and requires its transaction to equal the approved one, runs it, and decides its result from dpkg's status alone (`applied`, `verify_failed`, `exec_failed` when nothing changed). Decided with the maintainer (2026-10-21): the stop points and must-fix (a)'s exception for install, upgrade and remove (no signal at a hang-up or the deadline, an early `outcome_unknown` naming the request id and the until-time, `SIGINT` to apt-get alone at `max_timeout_s` less `min(60 s, max_timeout_s / 4)`, the process group killed at `max_timeout_s`; the index update keeps the kill); the second simulation with the pinned argv (D5 §5 differed: `--only-upgrade` installs new dependencies); the up-front refusal of unfinished dpkg state; the lock rule; the in-progress record (`flock` on `/run/shell-mcp-privd-pkg`). The five tools (`shell_priv_preview_packages` read; the update, install and upgrade tools operator; remove destructive). Findings: apt-get, apt and dpkg are not refused as privileged commands, which would bypass all of this (a schema change, not made); a recovery op for `dpkg --configure -a` is a possible follow-up.
- **Prerequisite: N-10 (§2.1)** is fixed before S4c-7 (maintainer, 2026-10-21; not in PR #37). **Done in PR #40.**
- **Includes.**
  - P-2e, P-3 (packages), P-5 and P-6.
  - The re-simulation compare; the pinned argv; `--no-remove`; upgrade as `install --only-upgrade` over the approved list.
  - A bounded dpkg-status reader and diff, fuzzed.
  - `verify_failed` on a mismatch.
  - The four package tools, and the read tool `shell_priv_preview_packages` (Q7).
  - The update-index preview shows the action and the policy hash only, no apt sources (Q9).
  - X-4's message for package timeouts (done generically by S4c-6: a lost answer of a package operation is already `outcome_unknown`; apt-get stopped by a hang-up must answer it too).
  - Must-fix (a) for apt-get: run it through the hang-up watch and child reaping S4c-6 built for `priv_exec` (`runCommand`), with the same tests in the broad unit.
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

- **Status: done (PR #43; ARCHIVE §14, S4c-8).** P-2f (amended), P-3 (power) and P-13 as approved (no other protocol change; no error-code, envelope, unit, Landlock or schema change). `shell_priv_reboot_host` (destructive, admin, always gated) and `shell_priv_cancel_power` (read, admin, never gated, not read-only). N-15 recorded (§2.1).
- **Decided with the maintainer (2026-10-22), beyond the entry below (design B2).** The S1d op called PID 1's `StartUnit(<action>.target, replace-irreversibly)` directly: no logind, so no inhibitor lock was ever consulted, and the shutdown it started stopped the helper's instance while its answer was being written. It is replaced:
  - **The preview** (P-2f, amended) reports the action, the target unit, the fixed delay (`delay_s`, 60 s) and the policy hash, and refuses, with no approval requested, whatever would block the action: an action `power.allowed` does not list, `limits.max_timeout_s` below 60 (the instance must outlive the delay), a package operation of this helper in progress or a power action already scheduled (the record), the dpkg frontend lock held by another process, packages dpkg left unfinished, a logind inhibitor lock on `shutdown` in mode `block` or `block-weak` (named by who and why), a shutdown logind has scheduled, or one already in progress. Blockers are refusals, not fields (the maintainer accepted this pushback): a preview refuses whatever its operation would refuse. The preview's hash cannot hold an absolute time (the re-call's fresh preview would differ), so it binds the delay; the result states the time. The gate policy's hash is bound by the server (D1), not by the helper, which cannot read it.
  - **The operation** takes the record (so no package operation of this helper, and no second power action, can start while it waits), recomputes the preview (`exists` on another hash, nothing scheduled), and answers `{action, target, scheduled_at, delay_s, cancel}` **before** anything is scheduled to happen. It then confirms that the gate read the answer: the socket's unread output (`SIOCOUTQ`) must reach 0 within 10 s, and the connection must not have been reset (a peer that closes with the answer unread sets `ECONNRESET` before the kernel drops the data). Otherwise nothing is scheduled, the journal says so, and the gate's side reports `outcome_unknown`. Once confirmed, it waits the delay, holding the record; a gate hang-up does not cancel it (must-fix (a)'s second exception). Immediately before the logind call it checks again that it still holds the record, that the dpkg lock is free and that dpkg left nothing unfinished, and calls nothing if any fails. Then it calls logind's `RebootWithFlags` or `PowerOffWithFlags` with `SD_LOGIND_ROOT_CHECK_INHIBITORS` only, never `SD_LOGIND_SKIP_INHIBITORS`: logind refuses if a block (or, for root with that flag, a block-weak) inhibitor holds at that moment, honours delay inhibitors, and starts the target itself, an orderly shutdown. The journal line records what happened.
  - **The cancel** (P-13) stops only an action this helper scheduled, identified by the record; the waiting instance and the cancel arbitrate through one exclusively created decision file, so a cancel either wins (nothing is requested) or is told it came too late.
  - **Not logind's `ScheduleShutdown`.** Verified at the source (systemd 257 and 259, `logind-dbus.c`): it checks inhibitors when the shutdown is scheduled (flags 0, so for root a `block-weak` inhibitor does not stop it) and, when it elapses, only delay inhibitors; and it creates `/run/nologin` five minutes before the elapse (`nologin_timeout_usec()`), immediately for a shorter delay, which refuses every non-root login, the gate's service account's SSH included, so the cancel could not reach the host during the delay.
  - **Found in the CI rounds (2026-10-22):** logind's `ScheduledShutdown` keeps `(action, 0)` after an immediate request it refused at the target, so a schedule needs a non-zero time; and a shutdown that does not go through logind (PID 1 holding a job for a shutdown-family target) is refused too, from `ListJobs`, at the preview and immediately before the request (maintainer's request).
  - **No policy schema change:** `power.allowed` already lists `reboot` and `poweroff` separately, and nothing is allowed when the section is omitted.
- **Includes.**
  - P-2f and P-3 (power).
  - `shell_priv_reboot_host`.
- **Tests (failing first).**
  - A disallowed action refused at the preview, with no approval requested.
  - A policy edit after approval: `approval_invalid`.
  - **e2e-host (broad):** the masked-target technique of `TestPowerReachesSystemd`, through the approval flow.
- **STOP.** If a test would need an unmasked shutdown target.

### S4c-9: privileged policy summary (Q6: yes, minimal)

- **Status: done (PR #44; ARCHIVE §14, S4c-9), with N-13.** P-8 as amended (above; no other protocol, error-code, envelope, unit, Landlock or schema change). `priv_policy` is a read-tier core op built from the policy the instance enforces: its `ops` come from the operations' own checks (`within`'s tier rule, the broad unit's existence, `pkgAllowed`, `powerAllowed`), its commands state what `priv_exec_preview` resolves. The broad instance refuses it. `shell_get_policy` reports it as `privileged.policy` in the admin profile only, when the gate forwards privileged operations, with `approval` per D-006; a failure is a warning, never the tool's error. PRIVILEGED §6, "The policy summary", records the relaxation. N-13 decided and done (§2.1). N-16 recorded.
- **Left for S4c-10 or S5:** nothing of S4c-9's scope. Recorded and open: N-8/N-9 (done since, PR #46: rule R), N-17 (done since, PR #47: the move rule), N-11, N-12, N-14's recovery op (if wanted), N-16, S-MC (multi-call binaries, and with it N-13's residual: wrapper scripts are judged by their own name and identity; done since, PR #53, with N-26 recorded), and the deployment docs (S5), which should show the policy summary as the way to review what a host's privileged policy allows.
- **Includes.**
  - P-8, including `backups.max_store_bytes`.
  - `shell_get_policy` gains a `privileged.policy` section when the helper answers.
  - PRIVILEGED §8 or §6 records the relaxation: an authenticated gate may read the summary; deny values and acknowledge text still never reach the wire.
- **Excludes.** Routing: the server never learns a command's unit from the summary (D6).
- **Tests (failing first).**
  - The deny values and acknowledge text never reach the wire (a canary in each).
  - The summary's hash equals `helper.policy_sha256`.
  - **e2e-host (core):** `shell_get_policy` shows the declared commands with their units.

**Order and dependencies.**
- S4c-0 first, on its own.
- S4c-1 before every tool session.
- S4c-2 before S4c-5, which needs write-side backups bound to previews.
- S4c-4 before S4c-5, which restores trees backed up by delete.
- S4c-3, S4c-6, S4c-7, S4c-8 and S4c-9 depend only on S4c-1. They can be done in any order, but they touch `internal/privd/ops/dispatch.go` and the shared preview code, so one at a time.

## 6. Decisions on the open questions (maintainer, 2026-10-18)

Every S4c session builds from this table. "As picked" means the maintainer accepted the recommendation unchanged.

| # | Question | Decision | Where it is applied |
|---|---|---|---|
| Q1 | Bind the privileged policy hash into approvals, and extend D-006 | **As picked.** H2 and the hash in every dedicated preview. D-006 is approved only as an extension of the binding to the privileged policy's hash and, for a privileged command, its unit (§7.1). | D1, P-1, §7.1; S4c-1 |
| Q2 | Recursive chown and chmod in v1 | **As picked**, R1 bounded by `max_delete_entries`, **with S4c-0's link-count refusal on every entry of the walk.** | D4, P-4; S4c-3 |
| Q3 | Owner and mode on restore | **Changed.** Keep the recorded owner and group; clamp the recorded mode to `modes.max`; **and verify the backup's recorded content hash before restoring, refusing with `verify_failed` on a mismatch.** | F-3, §2.3 restore, D3; S4c-0 (mode), S4c-5 |
| Q4 | Package binding | **As picked**, P2: re-simulate and compare, pins, `--no-remove`, upgrade as `install --only-upgrade` over the approved list, dpkg-status verification, `verify_failed`. | D5, P-5, P-6; S4c-7 |
| Q5 | `priv_exec` routing | **Changed.** No try-core-then-broad. The helper's preview resolves the command against the privileged policy and reports its unit; the unit is shown in the approval and bound into the preview hash; the server sends `priv_exec` to that unit directly. **A `helper_wrong_unit` answer is an error, never a retry in another unit.** | D6, D7, P-2d; S4c-6 |
| Q6 | A privileged policy summary op | **As picked**, minimal: no deny values, no acknowledge text. | P-8; S4c-9 |
| Q7 | Read-tier preview tools for delete and packages | **As picked.** `shell_priv_preview_delete`, `shell_priv_preview_packages`. | S4c-4, S4c-7 |
| Q8 | Metadata backups for chown and chmod | **Changed.** No metadata backups, **but the audit line records the old mode and owner/group for every entry changed** (bounded, truncated and flagged for recursive ops). | D4, D8; S4c-0, S4c-3 |
| Q9 | Apt sources in the update-index preview | **As picked: no.** | D2, P-2e; S4c-7 |
| Q10 | Backup store bound | **Changed.** **Enforce a total size cap** (and keep retention), refusing with a clear error any operation whose backup would exceed it. The setting and its default are documented. | X-7, D3 (change 0), §4.1 (`backups.max_store_bytes`, default 1 GiB); S4c-2 |
| Q11 | `stdin` on `shell_priv_run_command` | **As picked:** removed from TOOLS. | §7.2; S4c-6 |
| Q12 | Prune after commit, never the backup being restored | **As picked.** | X-8; S4c-2, S4c-5 |
| Q13 | Metadata read-back after chown and chmod | **As picked.** | X-10; S4c-0, S4c-3 |
| Q14 | Where `expected_preview_sha256` is required | **Changed.** Required on every op with its own preview, **and on `priv_exec` whenever approval is involved; optional on `priv_exec` only when no approval applies** (enforced by the command's tier, since privileged operator and destructive commands are always gated). | P-3, D6; S4c-6 |
| Q15 | Copy and move with `overwrite` | **Changed.** **Bind the destination's current content hash (and type) when `overwrite` is true; refuse if it changed.** The protocol field is approved (P-9). | §2.3 copy and move, D2, P-9; S4c-2 |
| Q16 | A write keeps a concurrent mode or owner change to the existing file | **As picked, provided a write's new inode mode is clamped to `modes.max`** (F-4). | F-4, §2.3 write; S4c-0 |

## 7. Changes to the documents, and corrections

### 7.1 Approved text: D-006, S-12 and the CLAUDE.md definition

Approved on the condition that it only extends the approval binding to the privileged policy's hash and, for a privileged command, its unit. Nothing else in these texts changes. S4c-1's first commit applies them verbatim; any other change to them is a STOP-and-ask.

**D-006 (plan §2), "The re-call" bullet.** Today:

> **The re-call.** The model re-calls the tool with the approval id. The server executes only if that exact approval was approved: principal, tool, target, SHA-256 of the canonical arguments, of the preview and of the gate policy, within `SHELL_MCP_APPROVAL_TTL`, and not yet used. A fresh preview must still match.

Becomes:

> **The re-call.** The model re-calls the tool with the approval id. The server executes only if that exact approval was approved: principal, tool, target, SHA-256 of the canonical arguments, of the preview and of the gate policy (for a privileged operation, also of the privileged policy, and for a privileged command, the unit it runs in, as its preview reports it), within `SHELL_MCP_APPROVAL_TTL`, and not yet used. A fresh preview must still match.

**S-12 (plan §4.2), "Record" and "Executing".** Today:

> **Record.** An approval record (128-bit random id) binds principal, tool, target, canonical-args SHA-256, preview SHA-256, gate-policy SHA-256 and expiry. …
>
> **Executing.** … It is marked used before execution, and a fresh preview's hash and the policy hash must still match. …

Become:

> **Record.** An approval record (128-bit random id) binds principal, tool, target, canonical-args SHA-256, preview SHA-256, gate-policy SHA-256 (for a privileged operation, also the privileged policy's SHA-256, and for a privileged command, the unit it runs in) and expiry. …
>
> **Executing.** … It is marked used before execution, and a fresh preview's hash and the policy hashes must still match. …

(The elided parts are unchanged.)

**CLAUDE.md, Definitions, "Approval"** (confirmed by the maintainer, 2026-10-18, with the same extension as D-006 and nothing more; applied verbatim in S4c-1's first commit with D-006 and S-12). "bound to principal, tool, target and the SHA-256 of the canonical arguments, the preview and the gate policy" becomes "bound to principal, tool, target and the SHA-256 of the canonical arguments, the preview and the gate policy (for a privileged operation, also the privileged policy, and for a privileged command, its unit)". The CLAUDE.md hard rule's list "(principal, tool, target, canonical arguments, preview, policy)" already covers both policies and is unchanged.

**D-021 (plan §2):** unchanged. "Overwritten and deleted files are backed up first" stays true with the store cap, which refuses an operation rather than skipping its backup; the binding lives in D-006.

### 7.2 Other wording changes and corrections

**Pushback on the documents.**
- **TOOLS.md, `shell_priv_run_command`** lists `stdin?`. PRIVILEGED §6 and the code (`execArgs` has no stdin) say there is none in v1. TOOLS is wrong (Q11). It also omits `max_output_bytes`, which the helper accepts.
- **TOOLS.md, `shell_priv_change_owner` and `shell_priv_set_permissions`** list `recursive=false`. Neither the helper nor the protocol has it (Q2, P-4). `owner?` and `group?` need "at least one".
- **TOOLS.md, `shell_priv_restore_backup`,** "preview: diff against current". No content is ever shown. The preview is the backup's and the current file's size, mode, owner and SHA-256 (and line counts where the server reads both).
- **PRIVILEGED §6, "Every write-class op returns a preview first".** No op returns a preview. Previews are separate read ops, or composed by the server. Reword to "every write-class op has a preview, shown in the approval request: …".
- **PRIVILEGED §6, `priv_copy` and `priv_move` row.** "Modes within the mask" was not true for copy (F-1, fixed in S4c-0). The row should say that every new inode's mode is masked by `modes.max` (a new copy takes the source's mode, a copy over a file the destination's), and that with `overwrite` the destination is bound by `expected_destination_sha256` (P-9).
- **PRIVILEGED §6, `priv_write_file` row.** "Owner and mode preserved unless given" becomes "owner preserved, and mode preserved within `modes.max`, unless given: a file wider than `modes.max` is narrowed to the mask when the helper writes it" (F-4, S4c-0).
- **PRIVILEGED §6, `priv_restore_backup` and Backups.** The restored mode is masked by `modes.max`; a backup whose data does not match its recorded SHA-256 is `verify_failed`, and nothing is restored (Q3). The store's total size cap (§4.1).
- **PRIVILEGED §4.** The `backups.max_store_bytes` key, its range and default (§4.1).
- **PRIVILEGED §6, `priv_exec`.** "How the server learns a command's unit is S4c's" → D6: the core-unit preview reports the unit, the server sends `priv_exec` there, and `helper_wrong_unit` is an error.
- **PRIVILEGED §8.** Add `set_aside`, the package `applied` counts, chown and chmod's `changed` with old values (bounded), and the note on redaction (X-5).
- **D-006 and S-12 (plan, locked) and CLAUDE.md:** §7.1.
- **POLICY §3,** "`priv_delete` … keeps its own rules, with backups, until S4c." S4c-4 replaces this with "applies the same rules, with a backup from the plan (PRIVILEGED §6)".
- **ARCHITECTURE §3 step 4,** "forward the request unchanged". P-7 changes `timeout_ms` to the clamped value, and the response gains `helper` (P-1). §4.2 documents `helper`. §4.3's `priv_*` row lists the new preview ops.

**Pushback on the prompt.**
- "How priv_exec preview works (reuse exec_preview or a helper equivalent)." Reuse is not possible: the gate cannot read the privileged policy, so it cannot resolve a root command (D6).
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
