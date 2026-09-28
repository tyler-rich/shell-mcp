# Tool catalogue (v1 contract)

Conventions: names are `shell_<verb>_<noun>`. Every tool takes `target: string` (optional when exactly one target exists or `SHELL_MCP_DEFAULT_TARGET` is set). **Gate op** is the operation in `docs/ARCHITECTURE.md` §4.3; the gate enforces the policy for it independently of this table.

Annotations: `read` → `readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true`. `operator` → `readOnlyHint: false, destructiveHint: false, openWorldHint: true` (`idempotentHint` per tool). `destructive` → `readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true`. Every tool sets `title` and an `outputSchema`.

Common optional inputs on tools that run a process: `timeout_seconds` (1..`SHELL_MCP_MAX_TIMEOUT`, default `SHELL_MCP_DEFAULT_TIMEOUT`), `max_output_bytes` (1..`SHELL_MCP_MAX_OUTPUT_BYTES`).

**Profiles.** `read-only` registers the read tier; `operator` adds the operator tier; `admin` adds the destructive and privileged tiers — `admin` is the profile for a fully capable deployment. Each host's gate and privileged policies still decide what actually runs.

**Approval (D-006).** Destructive tools, privileged tools of tier operator or above, and any tier listed in `SHELL_MCP_APPROVAL_TIERS` run in two round trips: the first call returns `input_required` with an elicitation that shows the computed preview and asks the user to approve; the client retries with the user's answer and the bound `requestState`. Declined → `approval_declined`; stale, altered or replayed → `approval_invalid`; client without elicitation → `approval_unavailable` unless the operator set `SHELL_MCP_APPROVAL_FALLBACK=confirm-argument`, in which case (and only then) the tools expose a `confirm` argument.

## Read tier (profile ≥ `read-only`)

| Tool | Gate op | Inputs | Notes | Session |
|---|---|---|---|---|
| `shell_list_targets` | — (server) | — | Name, host, port and user as configured. Reachability is not probed here; `shell_get_policy` does that. | S2 |
| `shell_get_policy` | `hello` + `policy` | `target` | Gate version, principal, `max_tier`, roots, limits, service/journal patterns, repos, command ids with templates and tiers. Call this first; it is the source of truth for what a target allows. | S2 |
| `shell_get_system_info` | `sysinfo` | `target` | OS release, kernel, uptime, load, memory, CPU count. | S3 |
| `shell_get_disk_usage` | `disk` | `target`, `include_pseudo=false` | Per mount: fs type, size, used, avail, inodes. | S3 |
| `shell_list_processes` | `processes` | `target`, `user?`, `name_contains?`, `sort_by=rss\|cpu\|pid`, `limit=100 (1..1000)` | Command lines redacted (values after secret-looking flags, URL userinfo, redaction patterns) and truncated to 512 chars. The walk is bounded by the policy's `max_processes`; a `hidepid` mount is reported. | S3 |
| `shell_get_service_status` | `service_status` | `target`, `unit` | Active/sub state, load state, main PID, since, memory, restarts, unit file state. | S3 |
| `shell_list_services` | `service_list` | `target`, `failed_only=false`, `name_contains?`, `limit=200 (1..5000)` | Only units matching the policy's `services.status`. | S3 |
| `shell_get_journal` | `journal` | `target`, `unit`, `lines=200 (1..max_lines)`, `since?`, `until?` (RFC 3339 with a zone, or relative `-N` + `s\|m\|h\|d\|w`, at most ten years), `priority?` (`emerg`…`debug`) | Output redacted; truncation flagged. The unit is an exact name, never a glob. | S3 |
| `shell_list_directory` | `list_dir` | `target`, `path`, `include_hidden=false`, `limit=500 (1..5000)` | Name, type, size, mode, owner, group, mtime; symlink targets reported, not followed. | S3 |
| `shell_stat_path` | `stat` | `target`, `path` | | S3 |
| `shell_read_file` | `read_file` | `target`, `path`, `offset=0`, `max_bytes=65536 (1..max_read_bytes)`, `tail_lines?` (1..5000; mutually exclusive with `offset`) | UTF-8 text returned as text; binary returned as `binary: true` with size and SHA-256 only. | S3 |
| `shell_find_files` | `find` | `target`, `root`, `name_glob?`, `type?` (`file\|dir\|symlink`), `max_depth=4`, `limit=200`, `modified_within?` | Native bounded walk; never the `find` binary. | S3 |
| `shell_inspect_certificate` | `cert_inspect` | `target`, `path` | Every certificate in the file (PEM or DER): subject, issuer, SANs, not-before/after, days remaining, key type/size, SHA-256. A file containing a private key is refused and nothing of it is returned. | S3 |
| `shell_get_git_status` | `git_status` | `target`, `repo` | Branch, upstream, ahead/behind, porcelain v2 summary. Every git tool refuses a repository whose `.git/config` holds anything beyond the inert keys `git clone` writes (POLICY §7). | S3 |
| `shell_get_git_log` | `git_log` | `target`, `repo`, `limit=20 (1..200)` | Hash, author name, date, subject (no bodies). | S3 |
| `shell_get_git_diff` | `git_diff` | `target`, `repo`, `staged=false`, `max_output_bytes` | Working-tree diff; redacted; capped. | S3 |
| `shell_run_read_command` | `exec` | `target`, `command_id`, `args: list[str] (≤ 64)`, `cwd?`, `timeout_seconds?` | Only commands whose policy tier is `read`. No `stdin`. | S3 |
| `shell_preview_delete` | `delete_preview` | `target`, `path`, `recursive=false` | Type, entry count, total bytes, first 50 entries. Same as the dry-run of `shell_delete_path`. | S4b |
| `shell_preview_git_discard` | `git_discard_preview` | `target`, `repo` | Files that would be reset or removed. | S4b |

## Operator tier (profile ≥ `operator`, policy `max_tier` ≥ `operator`)

| Tool | Gate op | Inputs | Notes | Session |
|---|---|---|---|---|
| `shell_control_service` | `service_control` | `target`, `unit`, `action: start\|stop\|restart\|reload` | polkit-authorized; returns the post-action status (re-read). `idempotentHint: false`. | S4a |
| `shell_write_file` | `write_file` | `target`, `path`, `content` (UTF-8, ≤ `max_write_bytes`), `mode?` (octal string), `create=true`, `expected_sha256?` | Atomic. **Read-back verified** — `verified: false` is a failure. `expected_sha256` = optimistic concurrency against the current content (refuses if the file changed since the caller read it). Returns old/new SHA-256 and a line-count diff summary (never content). | S4a |
| `shell_make_directory` | `mkdir` | `target`, `path`, `mode?`, `parents=false` | | S4a |
| `shell_copy_path` | `copy` | `target`, `source`, `destination`, `overwrite=false` | Files only in v1; destination under a write root. | S4a |
| `shell_move_path` | `move` | `target`, `source`, `destination`, `overwrite=false` | Both ends under write roots; same filesystem only (rename). | S4a |
| `shell_set_permissions` | `chmod` | `target`, `path`, `mode` | Refuses setuid/setgid/world-writable. | S4a |
| `shell_git_pull` | `git_pull` | `target`, `repo` | Fast-forward only; refuses dirty trees and foreign remotes. Returns old/new HEAD and changed-file count. | S4a |
| `shell_run_command` | `exec` | `target`, `command_id`, `args`, `cwd?`, `stdin?` (≤ `max_stdin_bytes`), `timeout_seconds?` | Commands of tier `read` or `operator`, run unprivileged in the sandbox. In the `admin` profile this tool also accepts `destructive` commands (approval required) and is registered with `destructiveHint: true`. | S4a / S4b |

## Destructive tier (profile = `admin`, policy `max_tier: destructive`, human approval)

| Tool | Gate op | Inputs | Preview shown in the approval request | Session |
|---|---|---|---|---|
| `shell_delete_path` | `delete` | `target`, `path`, `recursive=false` | `delete_preview`; with `recursive`, refuses above `max_delete_entries`. | S4b |
| `shell_discard_git_changes` | `git_discard` | `target`, `repo` | `git_discard_preview`. | S4b |
| `shell_run_command` (admin registration) | `exec` | as above | For `destructive` commands: the matched template and the resolved argv. | S4b |

## Privileged tier (profile = `admin`; gate policy `privileged.enabled`; helper installed) — S4c

All run as root through the helper (`docs/PRIVILEGED.md`); paths, owners, modes, commands and packages are limited by the host's privileged policy. Annotations: read tools as the read tier; everything else `destructiveHint: true` because it changes root-owned state.

| Tool | Helper op | Inputs | Approval | Notes |
|---|---|---|---|---|
| `shell_priv_read_file` | `priv_read_file` | `target`, `path`, `offset`, `max_bytes`, `tail_lines?` | no | Root-only files within privileged read roots. |
| `shell_priv_list_directory` | `priv_list_dir` | `target`, `path`, `include_hidden`, `limit` | no | |
| `shell_priv_stat_path` | `priv_stat` | `target`, `path` | no | |
| `shell_priv_write_file` | `priv_write_file` | `target`, `path`, `content`, `owner?`, `group?`, `mode?`, `create=true`, `expected_sha256?` | **yes** — preview: line-count diff, old/new SHA-256, owner/mode | Backup first; read-back verified. |
| `shell_priv_make_directory` | `priv_mkdir` | `target`, `path`, `owner?`, `group?`, `mode?`, `parents=false` | **yes** | |
| `shell_priv_change_owner` | `priv_chown` | `target`, `path`, `owner?`, `group?`, `recursive=false` | **yes** — preview: entries affected | Owners from the allow-list only. |
| `shell_priv_set_permissions` | `priv_chmod` | `target`, `path`, `mode`, `recursive=false` | **yes** | Within the mode mask; never setuid/setgid/sticky. |
| `shell_priv_copy_path` / `shell_priv_move_path` | `priv_copy` / `priv_move` | `target`, `source`, `destination`, `overwrite=false` | **yes** | Overwritten destinations are backed up. |
| `shell_priv_list_backups` | `priv_list_backups` | `target`, `path?` | no | |
| `shell_priv_restore_backup` | `priv_restore_backup` | `target`, `backup_id` | **yes** — preview: diff against current | The current version is backed up first. |
| `shell_priv_delete_path` | `priv_delete` | `target`, `path`, `recursive=false` | **yes** — preview: entries and bytes | Destructive; backed up within `max_delete_entries`. |
| `shell_priv_run_command` | `priv_exec` | `target`, `command_id`, `args`, `cwd?`, `stdin?`, `timeout_seconds?` | **yes** for operator/destructive commands — preview: resolved argv, unit (core/broad) | Runs as root. |
| `shell_priv_update_package_index` | `priv_pkg_update_index` | `target` | **yes** | Broad unit. |
| `shell_priv_install_packages` | `priv_pkg_install` | `target`, `packages: list[str] (1..20)` | **yes** — preview: simulated transaction | Allow-listed names only. |
| `shell_priv_upgrade_packages` | `priv_pkg_upgrade` | `target` | **yes** — preview: simulated transaction | Only if the policy allows upgrades. |
| `shell_priv_remove_packages` | `priv_pkg_remove` | `target`, `packages` | **yes** — preview: simulated transaction | Destructive; allow-listed names only. |

## Not in v1

Package managers other than apt, streaming/follow modes, file upload/download of binaries, archive extraction, container tools (use a container-manager MCP), anything in `docs/SECURITY.md` §4.

## Error contract

Every tool returns the envelope from `docs/ARCHITECTURE.md` §6. A non-zero process exit from `shell_run_*` is `ok: true` with `exec.exit_code` set; structured tools (`shell_git_pull`, `shell_control_service`) map a failed underlying command to `ok: false` with the gate's code and the exit status in `error.message`.
