# Setting up a target host

This guide sets up one Linux host ("target") so that a shell-mcp server can reach it: the gate (`shell-mcp-gate`) as an SSH forced command, and optionally the privileged helper (`shell-mcp-privd`) for root actions. It turns `docs/SECURITY.md` §5 into steps. The normative rules are in `docs/POLICY.md` (gate policy) and `docs/PRIVILEGED.md` (helper); where this guide and they disagree, they win.

Every name below is a placeholder: the service account `svc-shell` (uid/gid 60123), the helper's socket group `svc-shell-priv` (gid 60124), the second service account `svc-shell-std` (uid/gid 60125) for the keys without root actions on a host that has the helper (step 4), the application account `example-app`, the paths `/srv/app` and `/etc/example-app`, the unit `example-app.service`, the server's network `192.0.2.0/24`. Use your own.

**How each step was checked.** Every command marked *(container)* was run as written, as root, in throwaway containers of `debian:trixie` (Debian 13), `ubuntu:24.04` and `ubuntu:26.04`, against the binaries of the commit this guide was released with. Commands marked *(real host)* need something a container does not have: a running systemd and polkit, journald, a kernel with the Landlock ABI the gate needs, or the published release. The end-to-end tests (`e2e-host` in CI) run the gate and the helper on a real Ubuntu 26.04 machine.

**The quick start and this reference.** The README's quick start sets up a target and the server in eleven steps with the commands below; this guide is their reference. It keeps every step by hand, with its checks and per-OS notes, as the manual path and as what the commands write. Each step says which command does it.

**The install commands.** Steps 4, 7 and 8 are done by `shell-mcp-gate install`, and steps 9.2 to 9.4 by `shell-mcp-privd install` (§12). Step 2 is `verify-release.sh` (§12.7) and step 10 `shell-mcp doctor` (§12.6). They write exactly the files those steps write, byte for byte, with the same owners and modes, and refuse the mistakes the steps warn about: a key line without `restrict`, a `from=` wider than /24, an account in a privileged group, a uid that already owns files, units left on an old policy hash. Each step below says which command does it; the hand steps stay as the reference and as the manual path. The two policies (steps 5 and 9.1) can be generated from one answers file by `shell-mcp-gate policy new` and `shell-mcp-privd policy new` (POLICY §9); the gate's comes before `install`, the privileged one after it, because `install` creates the socket group the privileged policy names.

## 0. Requirements

- **Linux with systemd, amd64 or arm64** (D-018). Tested distributions: Debian 13, Ubuntu 24.04 LTS, Ubuntu 26.04 LTS.
- **Landlock ABI 4 or newer** (Linux 6.7 or later, with `landlock` among the enabled LSMs). The gate refuses to serve under the default `sandbox.landlock: required` without it (`sandbox_unavailable`); `best-effort` exists, but you must choose it explicitly and it is reported everywhere (POLICY §4a). Debian 13 and Ubuntu 24.04 and 26.04 kernels qualify.
- **OpenSSH server.** Checked with OpenSSH 9.6 (Ubuntu 24.04), 10.0 (Debian 13) and 10.2 (Ubuntu 26.04).
- **polkit** (`polkitd`), only if the gate may start, stop, restart or reload units.
- **Local accounts and groups.** The gate is a static binary and reads `/etc/passwd` and `/etc/group` only: a supplementary group that exists only in LDAP/SSSD has no name it can check, and it refuses to serve (`install_insecure`). Create the service account locally too (step 4).
- Root access on the host. Nothing here uses `sudo`, and nothing installs a sudoers entry: there is none in this design (D-017).

The helper's generated units were verified against systemd 257 and 259 (PRIVILEGED §5) and are exercised end to end on Ubuntu 26.04. On Ubuntu 24.04 (systemd 255) they pass `systemd-analyze verify`, but no end-to-end run covers that version; check them there with step 9.4 before relying on them.

## 1. Check the host *(real host)*

```bash
cat /sys/kernel/security/lsm
```

The list must contain `landlock`. Step 5's `check-policy` reports the kernel's Landlock ABI exactly (`kernel Landlock ABI N`), which is the check that counts. *`shell-mcp-gate install` (§12.1) checks Landlock against the policy's mode before it writes anything, and `shell-mcp doctor` (§12.6) reports each target's ABI as its gate applies it.*

```bash
systemctl --version
```

```bash
/usr/sbin/sshd -V
```

## 2. Download and verify the release *(real host: needs the published release)*

*Done by `verify-release.sh` (§12.7) from every release after 0.2.0: the checks below, for every file in a directory, with cosign or gh.*

Do this on a workstation, not on the target: it needs gh (logged in with `gh auth login`), cosign and, for `verify-release.sh`, git, and none of it needs root. Then copy the verified files to the target over SSH and confirm the copy there with `sha256sum --ignore-missing -c SHA256SUMS` (the README's quick start, step 3, also says how to run `verify-release.sh --sums` on the target itself).

Each release on GitHub carries, per architecture, `shell-mcp_X.Y.Z_linux_<arch>` (the server), `shell-mcp-gate_X.Y.Z_linux_<arch>` and `shell-mcp-privd_X.Y.Z_linux_<arch>`, plus `shell-mcp_X.Y.Z_examples.tar.gz` (the example policies and `deploy/`), `SHA256SUMS`, a Sigstore bundle `<file>.sigstore.json` for every binary, the archive and `SHA256SUMS`, and a CycloneDX SBOM per binary. The examples below use 0.2.0 on amd64.

```bash
gh release download v0.2.0 --repo tyler-rich/shell-mcp \
  --pattern 'shell-mcp-gate_0.2.0_linux_amd64*' --pattern 'shell-mcp-privd_0.2.0_linux_amd64*' \
  --pattern 'shell-mcp_0.2.0_examples.tar.gz*' --pattern 'SHA256SUMS*'
```

Verify the checksums, then the signature of each file you install. The certificate identity pins the release workflow at the release's own tag: anything signed by another ref (a dry run, a branch) is not a release and fails this check.

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

```bash
verified=yes
for f in SHA256SUMS shell-mcp-gate_0.2.0_linux_amd64 shell-mcp-privd_0.2.0_linux_amd64 shell-mcp_0.2.0_examples.tar.gz; do
  cosign verify-blob --bundle "$f.sigstore.json" \
    --certificate-identity https://github.com/tyler-rich/shell-mcp/.github/workflows/release-build.yml@refs/tags/v0.2.0 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$f" || { echo "FAILED: $f" >&2; verified=no; break; }
done
[ "$verified" = yes ] && echo "all verified"
```

The loop stops at the first file that fails, and the last line then fails without printing `all verified`: install nothing until it has. On arm64, use `linux_arm64` in the file names.

The build provenance (SLSA) can be checked with the GitHub CLI as well:

```bash
gh attestation verify shell-mcp-gate_0.2.0_linux_amd64 --repo tyler-rich/shell-mcp \
  --signer-workflow tyler-rich/shell-mcp/.github/workflows/release-build.yml --source-ref refs/tags/v0.2.0
```

These are the commands the release workflow's own `scripts/release/verify.sh` runs after signing, including the refusal of another ref; they cannot be run before the release exists. The release notes repeat them with the image digest.

## 3. Install the binaries *(container)*

*A hand step in every setup (the README's quick start, step 4): no command installs the binaries.*

```bash
install -o root -g root -m 0755 shell-mcp-gate_0.2.0_linux_amd64 /usr/local/bin/shell-mcp-gate
install -o root -g root -m 0755 -d /usr/local/libexec
install -o root -g root -m 0755 shell-mcp-privd_0.2.0_linux_amd64 /usr/local/libexec/shell-mcp-privd
shell-mcp-gate version
```

Install the helper only if you want root actions (step 9). Keep these paths: the generated units run `/usr/local/libexec/shell-mcp-privd`, both binaries re-execute themselves to start commands and so must sit under a read+execute directory of their sandbox (`/usr/local/bin`, `/usr/local/libexec`), and the gate refuses to serve unless its binary and every directory above it are root's and not group- or world-writable.

To unpack the example policies:

```bash
tar -xzf shell-mcp_0.2.0_examples.tar.gz
```

They are under `shell-mcp_0.2.0/examples/policies/` (`read-only.yaml`, `operator.yaml`, `admin.yaml`) and `shell-mcp_0.2.0/examples/privileged/privileged.yaml`; the steps below use those paths.

## 4. Create the service account *(container)*

*Done by `shell-mcp-gate install` (§12.1): the free-id checks, the groups, the account, the lock and the slice drop-in, for each account (a second account too, below).*

**One account per privilege level.** Keys with different privilege levels need different accounts. The account in the helper's socket group (step 9) serves only keys whose gate policy has `privileged.enabled: true`. Every other key (read-only, operator, destructive without root actions) runs as an account outside that group. Reason: below Landlock ABI 9 only the socket's permissions and the helper's peer-UID check govern a connect to the helper's socket. For the account the helper serves, both pass. Any command a key runs as that account could therefore ask the helper for root actions directly, and no approval covers that (approval is the server's, PRIVILEGED §3; SECURITY §2). The gate refuses to serve a policy without `privileged.enabled` as an account in the group of the helper's sockets (`install_insecure`, naming the fix), and `check-policy` reports it as a FAIL. `install` refuses to create the layout (§12.1). On a host without the helper, one account serves every key.

Choose an explicit uid and gid (D-020); never let `useradd` pick one, and check that nothing on the host already uses them, including files that container volumes or backups own:

```bash
getent passwd 60123; getent group 60123; getent group 60124
```

```bash
find / -xdev \( -uid 60123 -o -gid 60123 -o -gid 60124 \) -print
```

No output from either means the ids are free. `find -xdev` stays on one filesystem: run it on every filesystem that holds application or container data. Avoid systemd's dynamic-user range (61184–65519); `useradd` warns that 60123 is above its `UID_MAX` (60000), which is harmless for an explicitly chosen id.

```bash
groupadd --gid 60123 svc-shell
useradd --uid 60123 --gid svc-shell --home-dir /var/lib/svc-shell --create-home --shell /bin/sh svc-shell
usermod -L svc-shell
```

- **The shell must be a real shell** (`/bin/sh`): sshd runs the forced command through it, and `nologin` would refuse every connection. That is safe: the command is the root-owned forced command; what the client asks for never reaches the shell.
- **`usermod -L`** locks the password (after `useradd` the shadow field is already `!`, and it stays `!`; `passwd -S svc-shell` reports `L`). `passwd -l` does the same, but `/usr/bin/passwd` is a setuid binary, which the install commands never run. Key logins still work with the distributions' `UsePAM yes` (checked: the SSH tests below logged in to the locked account on all three images).
- **The home directory is protected:** the gate never writes there, and it may not be a write root.

Groups, only as needed, and nothing else (the gate refuses to serve as a member of `root`, `sudo`, `wheel`, `adm`, `docker`, `lxd`, `incus-admin`, `libvirt`, `kvm`, `disk` or `shadow`):

```bash
usermod -aG systemd-journal svc-shell       # only if the policy has a journal section
groupadd --gid 60124 svc-shell-priv         # only if you install the helper (step 9)
usermod -aG svc-shell-priv svc-shell        # only for the account whose keys' policies have privileged.enabled: true
id svc-shell
```

**A second service account** *(container)*, for the keys whose policy has no `privileged.enabled` on a host where `svc-shell` is in the socket group. `install` makes it exactly as it makes `svc-shell`, with its own unused uid and gid, and never puts it in the socket group. Run it for the first key the account serves, with the account's own `--user`, `--uid` and `--gid` (§12.1, "Several accounts"):

```bash
shell-mcp-gate install --policy /etc/shell-mcp/read-only.yaml --principal readonly \
  --from 192.0.2.10 --key ssh_key.pub --user svc-shell-std --uid 60125 --gid 60125
```

It runs the owner scan for the new ids, and writes the account's slice drop-in, its `Match` block (appended to the same sshd drop-in, step 7), its keys file with the key's line and, when the policy has `services.control`, its own polkit rule (step 8). Then it reloads sshd: until sshd reloads, it does not know the new account's block, and the account's keys are refused. Run `install` again for each further key the account serves. A key already on `svc-shell` moves with `shell-mcp-gate move-key` (step 7, "Moving a line"). The account's write roots and repositories must be its own (step 6).

**By hand** *(container)*, which is what `install` writes for the second account. Check the ids as above, then:

```bash
getent passwd 60125; getent group 60125
find / -xdev \( -uid 60125 -o -gid 60125 \) -print
groupadd --gid 60125 svc-shell-std
useradd --uid 60125 --gid svc-shell-std --home-dir /var/lib/svc-shell-std --create-home --shell /bin/sh svc-shell-std
usermod -L svc-shell-std
usermod -aG systemd-journal svc-shell-std   # only if its policies have a journal section (all of them, below)
mkdir -p /etc/systemd/system/user-60125.slice.d
printf '[Slice]\nMemoryMax=4G\nMemorySwapMax=0\n' >/etc/systemd/system/user-60125.slice.d/50-shell-mcp.conf
systemctl daemon-reload
id svc-shell-std
```

By hand, it also needs its own `Match` block and keys file (step 7) and, when one of its policies has `services.control`, its own polkit rule (step 8). These steps write exactly the files that `install` writes for an account (§12.1): the same account entries, slice drop-in, `Match` block, keys file and key lines. `install` for each key of either account then reports every item `unchanged`, and a host split this way is byte for byte the host `install` alone makes (both checked by `scripts/setup-check/` on all three images).

**An account's keys agree on the journal.** `install` allows `systemd-journal` only for a key whose policy has a journal section, and refuses a key whose policy has none on an account in `systemd-journal` (`supplementary_group`); `move-key` refuses to move a key there, or a journal key to an account outside it. Keys whose policy reads the journal and keys whose policy does not therefore go to different accounts.

**The first account's groups after a split** *(container)*. `svc-shell` keeps every supplementary group it had. When it was in `systemd-journal` only for keys that moved (a policy with a journal section), `install` for its remaining keys refuses that membership (`supplementary_group`: its only groups may be the socket group, and `systemd-journal` only for a policy with a journal section). Remove it, then run `install` again:

```bash
usermod -r -G systemd-journal svc-shell
```

**Bound the account's memory as a whole** (recommended). The gate gives each process it starts its own memory limit (`limits.max_memory_mb`, POLICY §4a), but several requests, or a command that starts several processes, each get one. A `MemoryMax=` on the account's slice bounds them all together, so the host's OOM killer never has to choose a victim outside it. sshd places each login in `user-<uid>.slice` through `pam_systemd` (`UsePAM yes`, the distributions' default):

```bash
mkdir -p /etc/systemd/system/user-60123.slice.d
printf '[Slice]\nMemoryMax=4G\nMemorySwapMax=0\n' >/etc/systemd/system/user-60123.slice.d/50-shell-mcp.conf
systemctl daemon-reload
systemctl show -p MemoryMax -p MemorySwapMax user-60123.slice
```

Choose the value from the requests you expect at once times `limits.max_memory_mb` (4G fits three requests at the default 1024 MiB). Set `MemorySwapMax=0` with it: without it, on a host with swap, a runaway command is pushed into swap and slows the whole host until the request times out, instead of being killed at `MemoryMax=`. The helper's units carry their own `MemoryMax=` and `MemorySwapMax=0` (PRIVILEGED §5).

## 5. Write the gate policy *(container)*

One policy per SSH key, so each server instance gets its own ceiling. Write it for the worst case: what would you accept a fully compromised MCP server doing with this key? (POLICY §1.)

Each key runs as the account for its privilege level (step 4). A policy with `privileged.enabled: true` runs as the account in the helper's socket group (`svc-shell`). Every other policy runs as an account outside that group (`svc-shell-std` on a host with the helper). Check each policy as the account that will serve it.

**Generated** (`shell-mcp-gate policy new`, POLICY §9): write an answers file (`setup.yaml`: the preset, your roots, deny patterns, units, repositories and commands; `examples/policies/*.answers.yaml` show the format), look at the result, then write it. It renders the preset's example with its comments, loads it strictly before anything is written, writes it `root:root 0644` (creating `/etc/shell-mcp` `0755` when absent) and runs `check-policy` as root:

```bash
shell-mcp-gate policy new --answers setup.yaml --out -
shell-mcp-gate policy new --answers setup.yaml --out /etc/shell-mcp/read-only.yaml
```

**By hand:** start from the example closest to what you need (`read-only.yaml`, `operator.yaml`, `admin.yaml`) and edit every placeholder.

```bash
install -o root -g root -m 0755 -d /etc/shell-mcp
install -o root -g root -m 0644 shell-mcp_0.2.0/examples/policies/read-only.yaml /etc/shell-mcp/read-only.yaml
```

The policy and every directory above it must be root's and not group- or world-writable (`0640 root:svc-shell` also works). Then check it **as the service account**, so the uid, group and home-directory checks describe that account, and the chain checks trust root and that account, as the gate will:

```bash
runuser -u svc-shell -- shell-mcp-gate check-policy --policy /etc/shell-mcp/read-only.yaml
```

It prints `ok`, `WARN` and `FAIL` lines, then the effective policy, and exits non-zero when `serve` would refuse. Run as root it prints a `NOTE` that the identity checks describe root instead. A policy without `privileged.enabled`, checked as an account in the group of the helper's sockets, fails with `FAIL install: gate process belongs to group "svc-shell-priv" (gid 60124), which owns the privileged helper's socket /run/shell-mcp/privd.sock, and this policy has no privileged forwarding …`. Serve that key from the second account (step 4). Read every WARN; the common ones:

- `remote uses TCP port 443, which sandbox.tcp_connect_ports does not list` — `git_pull` cannot connect; add 443 for a key that may pull.
- `apt has documented escape techniques (GTFOBins …)` — every command whose binary has known escapes is listed; review its templates and never give such a binary a `{path:write}`.
- `paths.write …: is group- or world-writable` — see step 6.
- `could not probe RENAME_NOREPLACE … permission denied` — the service account cannot write that write root yet (step 6).
- `repo has no .git directory` — the repository does not exist yet, or the path is wrong.
- `sandbox: … kernel Landlock ABI 3 …, required needs 4` followed by `FAIL … upgrade the kernel first` — the kernel is too old (this is what a container on an older host kernel shows). Upgrade the kernel; `sandbox.landlock: best-effort` weakens the sandbox (POLICY §4a) and is only ever your explicit choice, never the fix.

Run `check-policy` again after every edit; the gate re-reads the policy on every request, so there is nothing to restart.

## 6. Write roots, repositories and commands' paths *(container)*

*A hand step in every setup: which directories the gate may change is the application's decision. `shell-mcp-gate install` prints the write roots that `check-policy` warned about.*

`paths.write` roots must be writable by the service account. How you grant that decides what else works under them, because the gate's rules for commands' paths and for git repositories count a directory as open when an account other than root and the service account owns it, or when it is group- or world-writable (and for an ACL, the group bits are the ACL mask) or sticky (POLICY §4, "Commands' paths"; POLICY §7, "The repository is closed").

- **Owned by the service account (recommended).** Everything works: file operations, `{path:write}` placeholders and `cwd` for commands, and git.

  ```bash
  install -o svc-shell -g svc-shell -m 0755 -d /srv/app/config
  ```

- **An ACL on a root-owned directory.** The file operations work, but the ACL mask makes the directory group-writable, so `check-policy` warns, commands get no path placeholder (`{path:read}` or `{path:write}`) and no `cwd` at or under it, and git runs in no repository under it. Use it only for a root where neither is needed (SECURITY §5 step 5).

  ```bash
  setfacl -m u:svc-shell:rwX /srv/app/config
  setfacl -d -m u:svc-shell:rwX /srv/app/config
  ```

- **Git repositories** (`git.repos`) must be *closed*: every directory from `/` to the repository, the repository, its `.git` and `.git/config` owned by root or the service account and neither group- nor world-writable nor sticky. An application account's own checkout, a group-writable shared checkout, or one under `/tmp` is refused. Give the checkout to the service account:

  ```bash
  chown -R svc-shell: /srv/app/deploy
  chmod -R g-w,o-w /srv/app/deploy
  ```

  `check-policy` prints `ok git.repos[i] …: closed`, or a WARN naming the entry that fails. Remotes must be `https://`. Git LFS repositories (filters) are not supported, a repository-local configuration key outside the data-only list is refused (POLICY §7), submodules are never entered, and repositories on case-folding filesystems are not supported.
- **`{path:read}` under an application's own tree.** A read placeholder may also lie under directories that one other account owns and only it can write (`/srv/app` owned by `example-app`, mode 0755). `{path:write}` and `cwd` get no such exception.
- **Setgid directories.** A file the gate creates in a setgid directory takes the directory's group, as the kernel decides. `shell_set_permissions` (gate `chmod`) refuses any file or directory with setuid, setgid or sticky bits. The helper sets both ids on every inode it creates, so its new files in a setgid directory get group root unless a group is given (step 9).
- **Filesystems.** Deletes and moves need `RENAME_NOREPLACE`, and verified replaces `RENAME_EXCHANGE`; NFS supports neither. `check-policy` probes each write root and warns.

Never make a write root of, or around, anything in the protected set (`/etc/shell-mcp`, `/etc/ssh`, `/etc/systemd`, `/usr`, cron, the service account's home, `.git`, …; POLICY §3): the policy fails to load.

## 7. SSH: the forced command *(container)*

*Done by `shell-mcp-gate install` (§12.1): the drop-in, the keys directory, the key line (written last), the `StrictModes` and ownership checks, `sshd -t` and `sshd -T -C`, the reload, and the host-key pin (`shell-mcp-gate host-key` prints the pin alone, §12.2).*

The service account's keys live in a root-owned file that it cannot edit, selected by a `Match` block:

```bash
install -o root -g root -m 0755 -d /etc/ssh/authorized_keys.d
```

Write `/etc/ssh/sshd_config.d/60-shell-mcp.conf` (`root:root 0644`):

```
Match User svc-shell
    AuthorizedKeysFile /etc/ssh/authorized_keys.d/%u
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitTTY no
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitUserRC no
    MaxSessions 8
```

**With a second account** (step 4), the same file holds one block per account: the first account's block, an empty line, then the second account's block, which is the same block with its name. Nothing else changes: `AuthorizedKeysFile` names `%u`, so each account reads its own keys file. `install` for the second account appends its block this way (a third account's block follows the second's the same way), checks every account's block with `sshd -T -C` and reloads sshd; it refuses a drop-in with anything else in it (§12.1). The file then holds:

```
Match User svc-shell
    AuthorizedKeysFile /etc/ssh/authorized_keys.d/%u
    …the eleven lines above, unchanged…
    MaxSessions 8

Match User svc-shell-std
    AuthorizedKeysFile /etc/ssh/authorized_keys.d/%u
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitTTY no
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitUserRC no
    MaxSessions 8
```

By hand, write it without an editor, so the bytes are exactly these. This appends the second block to a drop-in that holds only the first account's block:

```bash
f=/etc/ssh/sshd_config.d/60-shell-mcp.conf
test "$(head -n1 "$f")" = "Match User svc-shell" && test "$(grep -c '^Match ' "$f")" = 1 &&
  { cat "$f"; echo; sed '1s/^Match User svc-shell$/Match User svc-shell-std/' "$f"; } >/root/60-shell-mcp.conf &&
  install -o root -g root -m 0644 /root/60-shell-mcp.conf "$f" && rm /root/60-shell-mcp.conf
```

Then run the `sshd -t` and `sshd -T -C` checks below for each account, and apply the configuration with the reload below. Until sshd reloads, it does not know the second account's block, and its keys are refused.

Debian 13 and Ubuntu 24.04 and 26.04 include `/etc/ssh/sshd_config.d/*.conf` near the top of `sshd_config`. Check the syntax, then the effective settings for the service account and for anyone else (the block must not change other accounts):

```bash
/usr/sbin/sshd -t
/usr/sbin/sshd -T -C user=svc-shell,host=client.example.test,addr=192.0.2.20 | grep -Ei '^(authorizedkeysfile|authenticationmethods|permittty|allowtcpforwarding|x11forwarding|maxsessions) '
/usr/sbin/sshd -T -C user=someone-else,host=client.example.test,addr=192.0.2.20 | grep -Ei '^(authorizedkeysfile|permittty|x11forwarding) '
```

On all three images the first showed the values above and the second the distribution's defaults (`authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2`, `permittty yes`, `x11forwarding yes`).

**`sshd -t` needs `/run/sshd`**, sshd's privilege separation directory: without it `sshd -t` and `sshd -T` stop with "Missing privilege separation directory: /run/sshd". Debian 13 and Ubuntu 26.04 create it at boot from systemd's tmpfiles entry (`/usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf`, `d /run/sshd 0755`); if it is missing there, `systemd-tmpfiles --create /usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf` recreates it. Ubuntu 24.04 has no such entry: only `ssh.service` creates it (`RuntimeDirectory=sshd`), and with the default socket activation (`ssh.socket`) that happens at the first connection, so on a host nobody has logged in to over SSH since boot, run `systemctl start ssh.service` once first. `shell-mcp-gate install` checks for the directory before it writes anything, names the remedy for the host, and never creates it.

Add one line per server key to `/etc/ssh/authorized_keys.d/svc-shell` (`root:root 0644`), always with `restrict`, a `from=` limited to where the server connects from, and its own policy and principal label:

```
restrict,from="192.0.2.10",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/read-only.yaml --principal readonly" ssh-ed25519 AAAA… shell-mcp-readonly
```

Each line goes in the keys file of the account that serves its policy (step 4): `/etc/ssh/authorized_keys.d/svc-shell` for keys whose policy has `privileged.enabled: true`, `/etc/ssh/authorized_keys.d/svc-shell-std` (`root:root 0644`, like the first) for every other key on a host with the helper. A line is the same in either file.

**Moving a line** to another account *(container; the reload: real host)*. `shell-mcp-gate move-key` moves the line of the key whose forced command names `--principal`, byte for byte, to the end of the other account's keys file, and removes it from the old one, in one run. It moves the polkit rule with it (step 8), runs `check-policy` as the new account, checks both files and `sshd -T -C` for every account, reloads sshd, and restores every file it changed if anything fails (§12.1, "Moving a key between accounts"):

```bash
shell-mcp-gate move-key --principal readonly --from-user svc-shell --to-user svc-shell-std
```

Then set the server's target user for that key to `svc-shell-std` (`SHELL_MCP_TARGET_USER`, or `user` in the targets file): from the move on, the key no longer logs in as `svc-shell`. To keep the key working throughout, create the line in the new account first: `install` for the same key with the new account's flags (step 4) writes the same line there, so the key logs in as either account. Switch the server's target user, then run `move-key`, which finishes the move by removing the line from the old file. A key with privileged forwarding is never moved: it stays on the account in the helper's socket group.

By hand, the move copies the line byte for byte, without an editor. Here it is the `readonly` key's line, selected by its forced command's `--principal`: first into the new file, then the server's target user for that key changes to `svc-shell-std`, and only then is the line removed from the old file:

```bash
cd /etc/ssh/authorized_keys.d
grep -F -- '--principal readonly"' svc-shell >/root/moved.keys
cat /root/moved.keys
cat svc-shell-std /root/moved.keys 2>/dev/null >/root/svc-shell-std.keys
install -o root -g root -m 0644 /root/svc-shell-std.keys svc-shell-std
grep -vF -- '--principal readonly"' svc-shell >/root/svc-shell.keys
install -o root -g root -m 0644 /root/svc-shell.keys svc-shell
rm /root/moved.keys /root/svc-shell-std.keys /root/svc-shell.keys
```

`cat /root/moved.keys` must show exactly the lines to move, and nothing else. The second `cat` keeps the lines `svc-shell-std` already has. sshd reads the keys files at every login, so the move itself needs no reload (`move-key` reloads anyway, as `install` does after its sshd changes). Run the ownership check below on both files.

The key is the server's `ssh_key.pub` (`deploy/README.md`); it must be Ed25519. Make `from=` the server's own fixed address as a single address (`192.0.2.10`, or `/32`; `/128` for IPv6). When the server's container runs on the target itself, that is the container's fixed address on its network (`ipv4_address` in the reference compose), which is where its connections to the host come from (SECURITY §7). A prefix, where one is needed, must be `/24` or narrower (`/64` for IPv6): `shell-mcp-gate install` refuses anything wider, with no override, and warns about anything wider than one address.

**Confirm that the service account cannot change its own key options** *(container)*. Neither the gate nor the helper reads this file; sshd's `StrictModes` is what refuses a bad one, and the ownership is yours to check:

```bash
/usr/sbin/sshd -T | grep -i '^strictmodes'
stat -c '%U:%G %a %n' /etc/ssh /etc/ssh/authorized_keys.d /etc/ssh/authorized_keys.d/svc-shell
```

The first must print `strictmodes yes` (the default; never set `StrictModes no`). The second must show `root:root` and no group or world write bit on all three (`755`, `755`, `644`). Both checks matter: on all three images `StrictModes` refused every login when the keys file or its directory was group- or world-writable, or owned by another account ("Authentication refused: bad ownership or modes for file …" in sshd's log), but **accepted a file or directory owned by the service account itself**, which could then rewrite its own `command=` and `restrict`. Only root ownership prevents that.

Apply the configuration *(real host)*. The reload applies to every account, so keep your own session to the host open until a second SSH login of your own has worked:

```bash
/usr/sbin/sshd -t && systemctl reload ssh
```

The unit is `ssh` on Debian and Ubuntu. On Ubuntu, where sshd is socket-activated, `reload` fails if `ssh.service` is not running; the next connection then starts it with the new configuration.

What the containers showed with this setup (a test copy of the policy with `landlock: best-effort`, because the containers' kernel had Landlock ABI 3): a request piped to `ssh … svc-shell@<host> shell-mcp-gate/1` returned the gate's `hello` answer; a session without a command got the gate's `bad_request`, not a shell; `ssh -tt` got "PTY allocation request failed"; and `shell-mcp check` (step 10) verified the pinned host key and listed the tools, while a wrong pin was refused ("the target presented a host key that is not pinned for it").

Pin the host key on the server from the host's own file, read over a channel you trust:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

The server's pin is the key type and the fingerprint: `ssh-ed25519 SHA256:…` (`SHELL_MCP_TARGET_HOST_KEYS`, ARCHITECTURE §5).

## 8. Service control: the polkit rule

*Done by `shell-mcp-gate install` (§12.1) when the policy has `services.control`, for each account; `shell-mcp-gate move-key` moves it with a key (step 7).*

Only when a policy has `services.control` (`read-only.yaml` has none; `operator.yaml` and `admin.yaml` do, each installed and edited like step 5's, for its own key). Generate the rule from that policy *(container)* and review it: it lets the service account run exactly the listed verbs on exactly the listed units, and nothing else.

```bash
shell-mcp-gate polkit --policy /etc/shell-mcp/operator.yaml --user svc-shell > 60-shell-mcp.rules
install -o root -g root -m 0644 60-shell-mcp.rules /etc/polkit-1/rules.d/60-shell-mcp.rules
```

`polkitd` is the package on all three distributions; `/etc/polkit-1/rules.d` is `root:polkitd 0750` there. Regenerate the rule whenever `services.control` changes.

**Per account.** The rule names one account, and it is generated from the policy of one of that account's keys. The first account's rule (the account of the sshd drop-in's first block, step 7) is `60-shell-mcp.rules`. A second account (step 4) whose policy has `services.control` gets its own file, named after it, with exactly what `polkit` prints for that policy and account. `install` writes it so for each account; by hand:

```bash
shell-mcp-gate polkit --policy /etc/shell-mcp/operator.yaml --user svc-shell-std > 60-shell-mcp-svc-shell-std.rules
install -o root -g root -m 0644 60-shell-mcp-svc-shell-std.rules /etc/polkit-1/rules.d/60-shell-mcp-svc-shell-std.rules
```

**When a key moves** to another account, the new account needs the rule for the key's policy, and the old account's rule must not keep granting it the moved key's units. `move-key` writes the new account's rule when the moved key's policy has `services.control`. It removes the old account's rule when that rule is exactly the moved policy's and none of the old account's remaining keys needs it, keeps it when one does, and refuses the move when a remaining key's policy needs another rule. By hand: regenerate the old account's rule from the policy of a key it still serves that has `services.control`, and if none of its keys has `services.control` any more, remove `60-shell-mcp.rules`. Check that it works *(real host)*:

```bash
runuser -u svc-shell -- systemctl --no-ask-password restart example-app.service
```

It succeeds for an allowed unit and verb and fails with an authorization error for anything else (the gate reports that as `not_authorized`). polkit picks up new rule files by itself; `systemctl restart polkit` forces it.

## 9. The privileged helper (only for root actions)

The helper runs one root process per request, socket-activated, inside a generated systemd sandbox, and does only what its own policy declares. Read `docs/PRIVILEGED.md` §3 before writing that policy: human approval stops a misled model, not a compromised server.

### 9.1 Its policy *(container)*

**Generated** (`shell-mcp-privd policy new`, POLICY §9): from the same answers file as step 5, with a `root:` section (preset `admin`), after step 4 (or `shell-mcp-gate install`) has created the socket group, which the privileged loader requires. `client_uid`, `socket_group` and the deny list come from the same answers as the gate's policy, so they agree. It writes the policy `root:root 0600` and runs `check-policy`:

```bash
shell-mcp-privd policy new --answers setup.yaml --out -
shell-mcp-privd policy new --answers setup.yaml --out /etc/shell-mcp/privileged.yaml
```

**By hand:** start from `examples/privileged/privileged.yaml`. Set `client_uid` to the service account's uid (`id -u svc-shell`) and `socket_group` to the group from step 4.

```bash
install -o root -g root -m 0600 shell-mcp_0.2.0/examples/privileged/privileged.yaml /etc/shell-mcp/privileged.yaml
/usr/local/libexec/shell-mcp-privd check-policy --policy /etc/shell-mcp/privileged.yaml
```

Run it as root. Review every `REVIEW` line (persistence roots, root-equivalent commands, packages, power, programs that bypass a bound operation) and every `WARN`; `FAIL` means the helper would refuse to serve.

### 9.2 Its units *(container)*

*Steps 9.2 to 9.4 are done by `shell-mcp-privd install` (§12.3): the review bound to the policy's SHA-256, the units written and verified, the backup store, the sockets enabled (and restarted after an edit), the broad pair removed when the policy stops using it, and the sandbox score.*

```bash
/usr/local/libexec/shell-mcp-privd units --policy /etc/shell-mcp/privileged.yaml --out /etc/systemd/system
install -o root -g root -m 0700 -d /var/lib/shell-mcp /var/lib/shell-mcp/backups
systemd-analyze verify --man=no /etc/systemd/system/shell-mcp-privd.socket /etc/systemd/system/shell-mcp-privd@.service
```

`units` writes `shell-mcp-privd.socket` and `shell-mcp-privd@.service` (the core unit), and the broad pair `shell-mcp-privd-broad.socket` and `shell-mcp-privd-broad@.service` only when the policy uses packages, `unit: broad` commands or power; it prints the policy's SHA-256 and what to run next. Verify the broad pair the same way. The broad unit is root-equivalent by design (network, full root capabilities) and is reported as such.

The units embed the policy's SHA-256: **after every edit of the privileged policy, run `units` again and `systemctl daemon-reload`**, or the helper refuses every request with `helper_policy_mismatch`.

### 9.3 Enable the sockets *(real host)*

```bash
systemctl daemon-reload
systemctl enable --now shell-mcp-privd.socket
systemctl enable --now shell-mcp-privd-broad.socket   # only if the broad pair was generated
ls -l /run/shell-mcp/
```

The directory is `root:root 0711` and each socket `srw-rw---- root svc-shell-priv`.

### 9.4 Check the sandbox score *(real host)*

```bash
systemd-analyze security shell-mcp-privd@.service
```

CI rates the core unit of the example policy and every end-to-end policy offline on the systemd of Debian 13 (257), Ubuntu 24.04 (255) and Ubuntu 26.04 (259), and on Ubuntu 26.04 against the running systemd; the expected score is 1.3 (1.4 when a root, command or the policy file lies under `/home`, `/root` or `/run/user`, which keeps `ProtectHome=read-only`; 1.6 with a core command that declares `CAP_KILL`), and CI fails above the recorded value. The broad unit's score is high by design.

### 9.5 Let the gate forward to it *(container)*

A gate policy generated with a `root:` section (step 5, POLICY §9) has this section already, with `broad_socket` exactly when the privileged policy uses the broad unit. By hand: in the gate policy of each key that may use root actions (only an admin server's key, normally), enable forwarding and give the broad socket when the broad pair is installed. Those keys, and only those, run as the account in the socket group; every other key on this host runs as the second account (step 4):

```yaml
privileged:
  enabled: true
  socket: /run/shell-mcp/privd.sock
  broad_socket: /run/shell-mcp/privd-broad.sock
  max_tier: operator
```

Then run `check-policy` on that policy again, as in step 5.

### 9.6 What the helper's rules mean for your layout

- **Files under an application's own directory are written as that application** (rule R, PRIVILEGED §6): under directories that `example-app` owns, the helper leaves a file only with owner `example-app`, `owner: root` included, and under a group- or world-writable directory none. Give `owner` and `group` explicitly there.
- **Group-writable read roots refuse files that are not world-readable**: a `/var/log` that is `root:syslog 0775` (Ubuntu with rsyslog) refuses files directly under it. Point read roots at closed subdirectories (`/var/log/example-app`) and read system logs with the journal tool.
- **Setgid directories:** a new file, copy or directory gets group root unless `group` is given, even under a setgid parent; give the group to keep such a layout. Moves refuse setgid directories.
- **Re-owning inside an application-owned tree** is a fixed command template in the privileged policy, not `shell_priv_change_owner` (PRIVILEGED §6, "Managing an application-owned tree").
- **Multi-call binaries.** On Ubuntu 26.04 coreutils is the uutils multi-call binary: `/usr/bin/chown` resolves to `/usr/lib/cargo/bin/coreutils/chown`. Declare commands by their usual path; `check-policy` prints `… is the uutils multi-call binary; it runs as du` (gate) or `[uutils applet chown]` (helper). Programs that run other programs (`env`, `timeout`, `nice`, `chroot`, …) are refused under every name, including GNU coreutils' copies under the `gnu` prefix (`/usr/bin/gnuenv`). BusyBox, toybox and a single-binary GNU coreutils are refused under any name (POLICY §5). A `#!` script is judged by its interpreter; what the script itself runs is not looked at.

## 10. Confirm it works

*Done by `shell-mcp doctor` (§12.6), which runs `check` and then checks the helper's sockets, the secrets, the trusted proxies, the approval page and the MCP endpoint, naming the step that fixes each failure. `check` stays, for scripts.*

With the reference compose, inside the running server's container:

```bash
docker compose exec shell-mcp /shell-mcp doctor
```

From the server, with the target configured (`docs/CLIENTS.md`, `deploy/README.md`):

```bash
shell-mcp check
```

*(container)* It prints the configuration (the token only as its length, the key only as its fingerprint) and, per target, `host_key_verified`, the gate's version, protocol, principal, policy hash and `max_tier`, the sandbox as enforced, whether privileged forwarding is enabled, and the tools that target can serve. It exits non-zero if any target fails. With Landlock enforced, `sandbox.mode` is `required` and `applied` true.

On the target *(real host)*:

```bash
journalctl -t shell-mcp-gate -n 20
journalctl -t shell-mcp-privd -n 20
```

The gate writes one JSON line per request (authpriv), the helper one per connection; the two join on the request id. Neither ever logs content or output.

## 11. Updating and removing

- **A new release:** verify it (step 2) and `install` the new binaries over the old ones (step 3). The gate and the helper start per request, so nothing needs restarting. Read the release notes for policy changes and run both `check-policy` commands. When the release notes say the helper's units changed (0.2.0's did), regenerate them: `shell-mcp-privd install --accept <the policy's sha256>` (§12.3), or by hand `units` and `systemctl daemon-reload` (step 9.2). Upgrading from 0.1.0: the numbered steps in `CHANGELOG.md`, "Upgrading from 0.1.0"; from 0.2.0 to the setup commands: the README, "Upgrading from 0.2.0", whose step 3 (splitting the shared account, §4) is required on a host with the helper whose account also serves keys without `privileged.enabled`.
- **A gate policy edit:** `check-policy` (step 5); regenerate the polkit rule if `services.control` changed (step 8).
- **A privileged policy edit:** `check-policy`, `units`, `systemctl daemon-reload` (step 9.2), or `shell-mcp-privd install` again with the new hash (§12.3), which does all of it.
- **Revoking a server:** remove its line from `/etc/ssh/authorized_keys.d/svc-shell`. sshd reads the file on every login. Rotating the server's key, with an overlap: `deploy/README.md`, "Rotating secrets".

### 11.1 Removing everything from a target

As root, in this order: first nothing new can log in, then nothing runs, then the files go. The server side (its container, network, secrets and the clients' configuration) is `deploy/README.md`, "Removing the server".

1. **No new logins:** remove the key file, and the second account's if there is one (step 4). sshd reads them at every login.

   ```bash
   rm -f /etc/ssh/authorized_keys.d/svc-shell /etc/ssh/authorized_keys.d/svc-shell-std
   ```

2. **The helper:** stop and disable its sockets (the broad one exists only when its pair was generated), then remove its units. Each request's instance ends with its request.

   ```bash
   systemctl disable --now shell-mcp-privd.socket
   systemctl disable --now shell-mcp-privd-broad.socket
   rm -f /etc/systemd/system/shell-mcp-privd.socket /etc/systemd/system/shell-mcp-privd@.service \
     /etc/systemd/system/shell-mcp-privd-broad.socket /etc/systemd/system/shell-mcp-privd-broad@.service
   rm -rf /run/shell-mcp
   ```

   `/run/shell-mcp` holds the sockets' file nodes, which systemd leaves after a stop; it is gone at the next boot anyway.
3. **The slice drop-in**, then reload systemd:

   ```bash
   rm -f /etc/systemd/system/user-60123.slice.d/50-shell-mcp.conf
   rmdir /etc/systemd/system/user-60123.slice.d
   systemctl daemon-reload
   ```

4. **sshd:** remove the drop-in and the keys directory (`rmdir` leaves it when another file is in it), check, reload. The reload applies to every account: keep your own session to the host open until a second SSH login of your own has worked.

   ```bash
   rm -f /etc/ssh/sshd_config.d/60-shell-mcp.conf
   rmdir /etc/ssh/authorized_keys.d
   /usr/sbin/sshd -t && systemctl reload ssh
   ```

5. **The polkit rules**, if a policy had `services.control` (the second account's file only exists when it had one):

   ```bash
   rm -f /etc/polkit-1/rules.d/60-shell-mcp.rules /etc/polkit-1/rules.d/60-shell-mcp-svc-shell-std.rules
   ```

6. **The account, its home and its groups.** `userdel` refuses while the account still runs a process; a request in flight ends within its timeout, or `loginctl terminate-user svc-shell` ends it now. `--remove` deletes the home directory (`/var/lib/svc-shell`). The primary group goes with the account where `USERGROUPS_ENAB` is `yes` (the default on Debian and Ubuntu); the two `groupdel` lines are for a group that is left, and for the helper's socket group.

   ```bash
   userdel --remove svc-shell
   getent group svc-shell >/dev/null && groupdel svc-shell
   getent group svc-shell-priv >/dev/null && groupdel svc-shell-priv
   ```

   A second account (step 4) goes the same way, with its slice drop-in (step 3's commands with its uid, 60125):

   ```bash
   userdel --remove svc-shell-std
   getent group svc-shell-std >/dev/null && groupdel svc-shell-std
   ```

7. **The policies and the binaries:**

   ```bash
   rm -rf /etc/shell-mcp
   rm -f /usr/local/bin/shell-mcp-gate /usr/local/libexec/shell-mcp-privd
   ```

8. **The helper's backups**, last: `/var/lib/shell-mcp/backups` holds the previous versions of every file the helper changed or deleted. Keep it until you no longer need them, then `rm -rf /var/lib/shell-mcp`.
9. **The firewall rule**, when the server ran on this host (README, the quick start's "Server and target on the same host"): delete the rule that let its address reach port 22 (`ufw delete allow proto tcp from 172.30.80.10 to any port 22`, or the nftables rule from your ruleset).

The journal keeps the gate's and the helper's audit lines (`journalctl -t shell-mcp-gate`, `-t shell-mcp-privd`) under the host's own retention.

## 12. The install commands

`shell-mcp-gate install` does steps 4, 7 and 8 for each account, `shell-mcp-gate move-key` moves a key between accounts (step 7, §12.1), `shell-mcp-gate host-key` prints step 7's pin, and `shell-mcp-privd install` does steps 9.2 to 9.4. They write the same files as the hand steps, byte for byte, with the same owners and modes, so a host set up by hand shows every item `unchanged`. They change no security property: the gate and the helper check everything they checked before, whoever wrote the files. The policies come from `policy new` (§12.5). Two more commands frame the setup and install nothing: `shell-mcp doctor` checks a running deployment from the server's side (§12.6, step 10), and `verify-release.sh` verifies the downloaded release before anything is installed (§12.7, step 2).

### 12.1 `shell-mcp-gate install` *(container; the reload: real host)*

Run as root, on the target, after the binaries (step 3) and the gate policy (step 5) are in place:

```bash
shell-mcp-gate install --policy /etc/shell-mcp/read-only.yaml --principal readonly \
  --from 192.0.2.10 --key ssh_key.pub --user svc-shell --uid 60123 --gid 60123
```

| Flag | Meaning |
|---|---|
| `--policy <file>` | Required. The gate policy this key serves: an absolute, clean path of the characters `A-Z a-z 0-9 . _ / -` only (sshd runs the forced command through `/bin/sh`), root-owned, loading as `serve` loads it. |
| `--principal <label>` | Required. The key's label, `^[a-z][a-z0-9-]{0,31}$`; also the key line's comment `shell-mcp-<label>`. |
| `--from <addr>[,<addr>…]` | Required, at most 8 entries. IP addresses or canonical CIDR prefixes. Never wider than `/24` (IPv4) or `/64` (IPv6), IPv4-mapped IPv6 judged as IPv4; no host names, wildcards or negations. Anything wider than one address is a WARN. |
| `--key <file.pub>` | Required. The server's `ssh_key.pub`: one `ssh-ed25519` line. |
| `--user <name>` | The service account (default `svc-shell`); its primary group has the same name. One account per privilege level (§4): the account in the helper's socket group only for a policy with `privileged.enabled: true`. Several accounts on one host: run `install` once per key, each with its account's own `--user`, `--uid` and `--gid` ("Several accounts", below). |
| `--uid <n>`, `--gid <n>` | Required, never defaulted (D-020): 1000 or above, not 65534, not in systemd's dynamic range 61184–65519. |
| `--home <dir>` | The account's home (default `/var/lib/<user>`). |
| `--socket-group <name>`, `--socket-gid <n>` | Required exactly when the policy has `privileged.enabled: true`: the helper's socket group. |
| `--memory-max <size>` | The account slice's `MemoryMax=` (`<n>M` or `<n>G`; default 4 × the policy's `limits.max_memory_mb`, which is step 4's `4G` at the default 1024 MiB). `none` writes no slice drop-in (a WARN). A value above the host's memory is a WARN: the bound would never act. |
| `--owner-scan-paths <dir>[,<dir>…]` | Narrows the owner scan (below) to these directories (absolute, at most 32), with a WARN naming what is not scanned. |
| `--dry-run` | Print every check, file and command; write and change nothing (§12.4). |
| `--no-reload` | Write and check everything, but run neither `systemctl daemon-reload` (nor the slice check after it) nor the reload of sshd; print them instead, with a WARN (also in the audit line) that the slice's memory limit is not active until systemd is reloaded. For hosts where you reload sshd yourself, and for containers without systemd. |
| `--replace-key` | Rewrite the existing line of the same key when its options differ (otherwise refused). |

What it does, in this order; nothing sshd reads exists until everything before it has passed:

1. **Checks, before any write:** root, and not run as an SSH forced command; each program it runs (`/usr/sbin/groupadd`, `useradd`, `usermod`, `sshd`, `/usr/bin/systemctl`) and its own binary (`/usr/local/bin/shell-mcp-gate`) root-owned and not group- or world-writable, every directory above included; Landlock against the policy's mode; the policy, the key file and `--from`; `sshd -T` reports `strictmodes yes`; the existing account, groups and files; that sshd can be reloaded (unless `--no-reload`); and, when the account or a group is created in this run, the **owner scan**: every local filesystem in `/proc/self/mountinfo` is walked (pseudo and network filesystems are listed and skipped), and any file owned by one of the new ids refuses the run. It is step 4's `find`, and it cannot be skipped.
2. **Groups and account** (step 4): `groupadd --gid`, `useradd --uid --gid --home-dir --create-home --shell /bin/sh`, `usermod -L`, and `usermod -aG` for `systemd-journal` (only with a `journal` section) and the socket group (only with `privileged.enabled`). Those two are the only supplementary groups an account may have.
3. **The slice drop-in** (step 4), then `systemctl daemon-reload` and `systemctl show -p MemoryMax -p MemorySwapMax user-<uid>.slice`, which must show the values.
4. **`check-policy` as the service account** (step 5): the installed `shell-mcp-gate check-policy` is run with the account's uid, gid and groups. The gate's own process runner switches to them after its usual checks, as root, then verifies them and that no capability is left before the command starts; no `runuser`, `sudo` or setuid program is involved. Its output is printed; a FAIL stops the run.
5. **The polkit rule** (step 8), when the policy has `services.control`: exactly `shell-mcp-gate polkit`'s output, in `60-shell-mcp.rules` for the drop-in's first account and `60-shell-mcp-<user>.rules` for any other.
6. **The sshd drop-in, the keys directory, and the key line** (step 7), the key line last. The account's `Match` block is appended to the drop-in when it has none.
7. **`sshd -t`, then `sshd -T -C`** for every account of the drop-in (every value of each `Match` block must be in force) and for a name that is not an account (its effective configuration must be what it was before the drop-in was written: the blocks reach no one else). Any difference rolls back every file the run changed.
8. **The reload**, when the drop-in changed (a new account's block: until sshd reloads, that account's keys are refused): `systemctl reload ssh.service` when it is active; nothing when only `ssh.socket` is (the next connection starts sshd with the new configuration). When neither is active the run refuses before anything is written (run with `--no-reload` and reload sshd yourself). A new key line needs no reload: sshd reads the keys file at every login.
9. **The pin**: `SHELL_MCP_TARGET_HOST_KEYS=ssh-ed25519 SHA256:…` from `/etc/ssh/ssh_host_ed25519_key.pub`, read locally (never `ssh-keyscan`), the other host keys as extra pins, and the write roots `check-policy` warned about (step 6 stays yours). Its last note: keep your own session to the host open until a second SSH login of your own has worked, since the reload applies to every account.

| File | Owner, mode | Content |
|---|---|---|
| `/etc/systemd/system/user-<uid>.slice.d/50-shell-mcp.conf` | `root:root 0644` | `[Slice]`, `MemoryMax=<size>`, `MemorySwapMax=0` (step 4) |
| `/etc/polkit-1/rules.d/60-shell-mcp.rules` | `root:root 0644` | `shell-mcp-gate polkit --policy <file> --user <user>` (step 8) for the drop-in's first account; the directory must exist |
| `/etc/polkit-1/rules.d/60-shell-mcp-<user>.rules` | `root:root 0644` | the same, for any other account (step 8, "Per account") |
| `/etc/ssh/sshd_config.d/60-shell-mcp.conf` | `root:root 0644` | step 7's `Match User` block, one per account in the order `install` added them, with one empty line between two blocks |
| `/etc/ssh/authorized_keys.d/` | `root:root 0755` | |
| `/etc/ssh/authorized_keys.d/<user>` | `root:root 0644` | one line per key: `restrict,from="<list>",command="/usr/local/bin/shell-mcp-gate serve --policy <file> --principal <label>" ssh-ed25519 <key> shell-mcp-<label>` |

`/etc/passwd`, `/etc/group` and the shadow files are written only by `groupadd`, `useradd` and `usermod`, and the home directory by `useradd --create-home`.

**What it refuses**, naming the value or file and what to do:
- `--from`: empty, `*` or any wildcard or negation, a host name, a duplicate, more than 8 entries, an IPv4 prefix shorter than /24 or an IPv6 prefix shorter than /64 (no flag or variable lowers this).
- The key: not exactly one line, options before the key type, not `ssh-ed25519`, a private key (nothing of it is printed; give the `.pub` file), one of this host's own host keys.
- The keys file: a line for the same key with other options (unless `--replace-key`); any line that does not parse or does not pass these checks (`restrict`, `from=` within the rules, `command=` exactly the forced command with a safe policy path and label, an Ed25519 key), reported by line number. Comments and blank lines are kept.
- The account: uid or gid 0, 65534, below 1000 or in 61184–65519; a uid or gid used by another name; an existing account whose uid, primary gid, home or shell (`/bin/sh`) differ; a member of `root`, `sudo`, `wheel`, `adm`, `docker`, `lxd`, `incus-admin`, `libvirt`, `kvm`, `disk` or `shadow`, or of any supplementary group but the two above (install never removes a membership: remove it and run again); a file owned by a new id (the owner scan); `--owner-scan-paths` with nothing to scan (when nothing is created there is nothing to scan for, and the flag only gets a NOTE, so a second run with the same flags reports `unchanged`).
- The socket group: a gid used by another group, the group existing with another gid, given for a policy without `privileged.enabled` or missing for one with it.
- sshd: `/run/sshd` missing (`sshd -t` cannot run; the message names the tmpfiles entry or `systemctl start ssh.service`, see §7, and install never creates it); `strictmodes no`; `/etc/ssh`, the keys directory or the keys file not `root:root` or group- or world-writable; `sshd -t` failing; the effective configuration differing (step 7); a drop-in that holds a block `install` did not write (`dropin_other_account`: another `Match` criterion, several names, `Match all`), or any other content than `install`'s blocks, such as an edited block, a comment or another number of empty lines (`file_differs`, with a diff).
- Any existing file with other content (a unified diff of what is there and what would be written is printed; the file is never overwritten: remove it or revert the edit and run again); `--policy` or `--principal` outside their character sets; a policy that does not load; `check-policy` as the account reporting FAIL.

**Idempotency.** A second run with the same flags changes nothing and reports every item `unchanged`; a run with another `--key` and `--principal` appends one line. Accounts and groups created before a failure are not removed by the rollback; the next run finds them `unchanged`.

**Several accounts.** One host can have several service accounts (§4, one per privilege level): run `install` for each key with its account's own `--user`, `--uid` and `--gid`. Each account gets everything above for itself: its ids checked and owner-scanned, its groups by the same rules (the socket group only for a policy with `privileged.enabled: true`), its slice drop-in, keys file and polkit rule. The sshd drop-in is shared: an account's `Match` block is appended after the others, with one empty line between two blocks, and sshd is reloaded. Re-running `install` for any key of any account changes nothing. This writes byte for byte what the hand steps of §4, §7 and §8 write, so a host split by hand reports every item `unchanged` *(container)*.

**Moving a key between accounts: `shell-mcp-gate move-key`** *(container; the reload: real host)*. Run as root, on a host where `install` made both accounts:

```bash
shell-mcp-gate move-key --principal readonly --from-user svc-shell --to-user svc-shell-std
```

| Flag | Meaning |
|---|---|
| `--principal <label>` | Required. Selects the line: the one whose forced command names `--principal <label>`. |
| `--from-user <name>`, `--to-user <name>` | Required. The account whose keys file holds the line, and the account it moves to. |
| `--dry-run` | Print every check, file and command, with each file's diff; write and change nothing (§12.4). |
| `--no-reload` | Move and check everything, but do not reload sshd; print the reload instead. |

What it does, in this order, with everything checked before anything is written:

1. **Checks:** root, not a forced command, the binaries (as `install`); both accounts exist with `/bin/sh` and have their own block in the drop-in, which holds only `install`'s blocks; both keys files are `root:root 0644` and every line in them passes `install`'s line checks; exactly one line of the old account's file names `--principal`, and the new account's file does not hold its key. The moved line's policy is loaded as `serve` will load it for the new account. A policy with `privileged.enabled: true` is refused: such a key stays on the account in the helper's socket group (§4). The new account's supplementary groups follow `install`'s rules for that policy: `systemd-journal` only with a journal section and nothing else, so an account in the socket group is refused. A missing `systemd-journal` membership is refused too, because `move-key` adds or removes no membership (`install` for the key on that account adds it).
2. **Polkit** (step 8): the new account's rule when the policy has `services.control` (an existing file with other content is refused). The old account's rule is removed when it is exactly the moved policy's and none of the account's remaining keys needs it, and kept when one does. When a remaining key needs another rule, the move is refused.
3. **`check-policy` as the new account**, as `install`'s step 4. A FAIL stops the run before anything is written.
4. **The writes**, in this order: the new account's polkit rule, its keys file with the line appended byte for byte, the old account's keys file without the line (an empty file when it was the last line, as the hand steps' `grep -v` leaves it), the old account's rule removed.
5. **Verify:** both keys files are read back (the line once in the new one, its key nowhere in the old one), then `sshd -t` and `sshd -T -C` for every account of the drop-in and for a name that is not an account. Any failure restores every file the run changed.
6. **The reload**, as `install`'s step 8, when a keys file changed. Its last note says to switch the server's target user for that key to the new account.

**What it refuses**, each naming the file or value: no line of the old account names `--principal`, or several do (`key_ambiguous`); the new account's file holds the key with other bytes (`key_in_destination`); a policy with privileged forwarding (`forwarding`); the new account in a privileged group, in any group the policy does not allow, or missing `systemd-journal` for a journal section; an account without its block, or a drop-in with anything but `install`'s blocks; a keys file that is not `root:root 0644` or has a line `install` cannot check; a polkit rule with other content; `check-policy` as the new account reporting FAIL; and, unless `--no-reload`, systemd not running or neither `ssh.service` nor `ssh.socket` active.

**A move half done** is finished, not refused: when the new account's file already holds exactly the same line, byte for byte (`install` for the same key on the new account writes it so, step 7), `move-key` only removes it from the old file. **Idempotency:** once moved (the old file names `--principal` nowhere, the new one holds the line once), the same command reports every item `unchanged`.

### 12.2 `shell-mcp-gate host-key` *(container)*

Prints the pin lines of §12.1's item 9 alone (step 7's pin), as any user (the `.pub` files are world-readable), for pinning the host again without running `install`:

```bash
shell-mcp-gate host-key
```

The server's pin is the value after `=` in its first line. Carry it to the server host over a channel you trust, such as your own SSH session to this host, never from what the network shows. The `NOTE` line lists this host's other keys (ECDSA, RSA). The server offers only the pinned key types, so the Ed25519 pin alone is enough; add another type's pin only to rotate to that key (`deploy/README.md`, "Rotating secrets").

### 12.3 `shell-mcp-privd install` *(container with `--no-start`; real host)*

Run as root after the privileged policy (step 9.1) and the account with its socket group (step 4) are in place. The first run prints the review and stops; read it, then run again with the hash it printed:

```bash
/usr/local/libexec/shell-mcp-privd install --policy /etc/shell-mcp/privileged.yaml --gate-policy /etc/shell-mcp/admin.yaml
/usr/local/libexec/shell-mcp-privd install --policy /etc/shell-mcp/privileged.yaml --gate-policy /etc/shell-mcp/admin.yaml --accept <sha256>
```

| Flag | Meaning |
|---|---|
| `--policy <file>` | Required. The privileged policy, `root:root` with no group or other bits (`0600`). |
| `--accept <sha256>` | The policy's SHA-256 from the review. Required on every run that writes or activates anything, a re-run of an unchanged policy included, so every install binds your review to the bytes installed. Without it, or with another hash, the run prints the review and exits 3. |
| `--gate-policy <file>` | Repeatable. A gate policy that forwards to the helper; each must have `privileged.enabled: true`, `socket: /run/shell-mcp/privd.sock`, and `broad_socket: /run/shell-mcp/privd-broad.sock` exactly when the broad pair is generated. |
| `--dry-run` | Print the review and the plan; write and change nothing; no `--accept` needed (exit 3 when the real run would stop for review). |
| `--no-start` | Write and verify the units, but run no `daemon-reload`, `enable`, restart or disable (for images and containers without systemd). |

What it does, in order:
1. The full `check-policy`, the same function as `shell-mcp-privd check-policy`, with its output printed; any FAIL stops the run.
2. The review: every `REVIEW` line, the broad unit's root-equivalence and the policy's SHA-256, then the `--accept` check. The policy is read once, so the hash you accept, the units generated and the hash inside them are of the same bytes.
3. The cross-checks: the `client_uid` account exists locally and has the socket group as a supplementary group, and each `--gate-policy` agrees.
4. `/var/lib/shell-mcp` and `/var/lib/shell-mcp/backups`, created `root:root 0700` when absent.
5. The units, generated exactly as `units` generates them and written only where they differ, then `systemd-analyze verify --man=no` on each pair; a failure rolls back to the previous files.
6. Unless `--no-start`: `systemctl daemon-reload` when a unit changed, `systemctl enable --now` for each socket, and a restart of a socket whose own `.socket` file changed. A socket whose service template alone changed is not restarted, since new connections start from the reloaded template. When the policy no longer uses the broad unit, `systemctl disable --now shell-mcp-privd-broad.socket`, and the broad pair is removed. The socket's file node `/run/shell-mcp/privd-broad.sock` stays, as systemd leaves any stopped socket's node (`RemoveOnStop=` is off); nothing listens on it, and a connection to it is refused.
7. `/run/shell-mcp` and the sockets' owners and modes are checked, and `systemd-analyze security` is printed with the expected score (§9.4).

| File | Owner, mode |
|---|---|
| `/etc/systemd/system/shell-mcp-privd.socket`, `shell-mcp-privd@.service` | `root:root 0644`, generated |
| `/etc/systemd/system/shell-mcp-privd-broad.socket`, `shell-mcp-privd-broad@.service` | `root:root 0644`, generated, only when the policy uses the broad unit; removed when it stops |
| `/var/lib/shell-mcp/`, `/var/lib/shell-mcp/backups/` | `root:root 0700` |

A unit file is replaced only when it carries the `# Generated by shell-mcp-privd units` header; a hand-written one is refused.

**What it refuses:** not root; run as a forced command; a running binary other than `/usr/local/libexec/shell-mcp-privd`; the policy's owner or mode; any `check-policy` FAIL; `--accept` missing or not the policy's hash (exit 3); the `client_uid` account missing or not in the socket group; a `--gate-policy` that disagrees; a backup directory with another owner or mode; a hand-written unit; `systemd-analyze verify` failing; systemd not running (without `--no-start`); the sockets' owners or modes after activation.

**Idempotency.** The same policy again (with `--accept` of the same hash): nothing written, no reload, the sockets confirmed enabled and active, every item `unchanged`. An edited policy: only what changed is written and reloaded.

`shell-mcp-privd units` stays, for review and for generating units elsewhere; its printed next steps point at `install`.

### 12.4 What every install command does the same way

- **Root only, never a forced command.** They refuse unless the effective uid is 0, and when `SSH_ORIGINAL_COMMAND` is set. They run every program by its absolute path, with a fixed argv and an empty environment, through the gate's own process runner (rlimits, a timeout, capped output, stdin `/dev/null`), never through a shell.
- **`--dry-run`** prints, in order, every check, every file with its owner, mode and full content, every command with its argv, and what each would be now (`create`, `unchanged`, `replace`, `refuse`). It writes nothing and runs only commands that read (`sshd -T`, `systemctl show`, `systemctl is-active`), and says so. It exits 0 only if the real run would succeed as far as can be known without changing anything.
- **Writes** go to a temporary file in the target's own directory, named `.<target>.shell-mcp-<12 random lowercase letters and digits>` (for example `.60-shell-mcp.conf.shell-mcp-k3v9q2m7x4ab`). It is created `0600`, written, `fsync`ed, given its owner and mode, renamed over the target, and the target is then read back and compared by SHA-256. sshd, systemd and polkit ignore such names. A failed run removes its temporary files; one left by a killed run is reported and removed by the next run of the same command.
- **Rollback.** When a check after a write fails, every file the run changed is restored to its previous bytes (or removed if the run created it), and the run says so and exits 1.
- **Output and exit codes.** `ok`, `WARN`, `FAIL`, `REVIEW` and `NOTE` lines on stdout, then a one-line result. Exit 0 done or nothing to do, 1 refused or failed, 2 usage (a missing required flag, an unknown one), 3 stopped for review. `--help` (or `-h`) prints the usage on stdout and exits 0, as it does for every subcommand of the three binaries.
- **Audit.** One JSON line per change and per refusal on stderr and to syslog (`/dev/log`, facility authpriv, tag `shell-mcp-gate` or `shell-mcp-privd`, notice for a change, warning for a refusal; a dry run writes none, since it changes nothing): paths, names, ids, modes, SHA-256s and key fingerprints only, never a key, a policy's content or a file's content. `journalctl -t shell-mcp-gate` shows them.

### 12.5 `shell-mcp-gate policy new` and `shell-mcp-privd policy new` *(container)*

They write steps 5 and 9.1 (and 9.5's section) from one answers file and a preset (POLICY §9), with the rules of 12.4: root only and never a forced command (except `--out -`, which only prints), the same temp files, read-back, `--dry-run`, rollback when `check-policy` fails after the write, and audit lines (with the preset). The written file is an owned file: an existing one with other content is refused with a diff, never overwritten. Run the gate's before `shell-mcp-gate install` and the helper's after it.

### 12.6 `shell-mcp doctor` *(container)*

On the server host, inside the running server's container, so that it sees the server's own environment, secrets and networks:

```bash
docker compose exec shell-mcp /shell-mcp doctor --mcp-url https://mcp.example.test/mcp
```

The reference compose sets no `container_name`, so Compose names the container `<project>-shell-mcp-1`. A stack editor shows the name it gave. The image has no shell, so in the editor's console set the command to the binary itself, `/shell-mcp doctor --mcp-url https://mcp.example.test/mcp`; from the host, `docker exec <container> /shell-mcp doctor --mcp-url https://mcp.example.test/mcp` does the same. Never use `docker compose run`: the second container it starts asks for the server's fixed address, which Docker refuses while the server runs ("Address already in use").

| Flag | Meaning |
|---|---|
| `--json` | The result as one JSON object: `ok`, and `rows`, each with `status`, `component`, `detail` and `fix`. |
| `--mcp-url <url>` | The MCP endpoint as clients reach it, `https://<name>/mcp`: one `POST` without a token is sent there. Without it, the endpoint is not checked (a NOTE). |
| `--ca-file <file>` | A PEM file of the CA that signs the proxy's certificates, for a private CA. Default: the system's roots. |

It prints one `ok`, `WARN`, `FAIL` or `NOTE` line per check, each failure with a `fix:` line naming the command and the section that fixes it, then a one-line result. Exit 0 with no FAIL, 1 with one, 2 for usage. Every row comes from a probe; what it cannot see is a NOTE that says so. In order:

- **`configuration`.** The variables, loaded exactly as `serve` loads them. A refusal is a FAIL that names the variable, and nothing else runs. Each startup warning is a WARN.
- **`secret <variable>`.** Each file named by `SHELL_MCP_TOKEN_FILE`, `SHELL_MCP_SSH_KEY_FILE`, `SHELL_MCP_APPROVERS_FILE`, `SHELL_MCP_APPROVAL_TLS_KEY_FILE` or `SHELL_MCP_APPROVAL_NOTIFY_TOKEN_FILE`:
  - group or other access is a FAIL (the server only warns at start), and so is anything but a regular file;
  - an owner other than the container's own uid is a WARN.
- **`target <name>`.** What `check` does: the pin verified, SSH authentication, and the gate's `hello`. The row reports the gate's version, protocol, principal, policy hash, `max_tier`, the sandbox's mode and Landlock ABI, and the profile's tools it can serve.
  - A sandbox that is not applied, or `best-effort`, is a WARN.
  - The failures and their fixes:

    | Code | Fix |
    |---|---|
    | `host_key_mismatch` | the pin from `shell-mcp-gate host-key` (§12.2) |
    | `auth_failed_ssh` | the key line, `--from` (§12.1) |
    | `target_unreachable`, `timeout` | the network and sshd (§7) |
    | `gate_unavailable`, the gate not installed | §3 |
    | `install_insecure` | `check-policy` as the account (§5, §12.1) |
    | `sandbox_unavailable` | Landlock (§0) |
    | `protocol_mismatch` | upgrade (README, Upgrading) |
- **`helper <name> core`**, when the gate forwards privileged operations. `priv_policy` through the core socket, at the read ceiling. The row reports the helper's version, the privileged policy's hash and its unit.
  - `helper_unavailable` (the socket is not listening): `shell-mcp-privd install` (§12.3).
  - `helper_refused` (the peer check): `client_uid` and the socket group (§12.3, §12.1).
  - `helper_policy_mismatch`: `install --accept` with the new hash (§12.3).
  - `protocol_mismatch`: upgrade.
  - The helper's other self-check codes. Each is a check the helper ran on itself before it read the request, so nothing ran. Its journal line (`journalctl -t shell-mcp-privd`) names the check:

    | Code | What the helper found | What to do, as root on the target |
    |---|---|---|
    | `helper_install_insecure` | It is not running as root with `no_new_privs`, its binary or the privileged policy is not root's or is group- or world-writable, or its unit's environment is wrong | `stat` the binary and `/etc/shell-mcp/privileged.yaml` (`root:root`, no group or other write; the policy `0600`), then `shell-mcp-privd install --accept <sha256>` (§12.3) to rewrite the units |
    | `helper_policy_invalid` | The privileged policy does not parse or validate | `shell-mcp-privd check-policy --policy /etc/shell-mcp/privileged.yaml` names the line (§9.1) |
    | `helper_client_uid_mismatch` | The policy's `client_uid` is not the uid the units were generated for | `client_uid` must be the service account's uid (`id -u svc-shell`); fix it, then `install` again with the new hash |
    | `helper_capabilities_broad` | The instance holds more capabilities than its unit declares | a drop-in or edit has changed the unit: `systemctl cat shell-mcp-privd@.service`, remove what is not generated, then `install --accept` again |
    | `helper_sandbox_unavailable` | The core unit's Landlock sandbox cannot be applied | the kernel (§0); upgrade it. `sandbox.landlock: best-effort` in the privileged policy weakens the sandbox (POLICY §4a) and is only ever your explicit choice |
    | `helper_wrong_unit` | An operation reached the other unit's socket | the gate policy's `socket` and `broad_socket` (§9.5), then `install --gate-policy` to cross-check them |

    The order of the checks and what each logs: PRIVILEGED §7.
- **`helper <name> broad`**, through a read operation that changes nothing, chosen from the policy the core socket reported:
  - `priv_pkg_update_index_preview` when the policy allows the index update;
  - otherwise `priv_power_preview` for the first allowed power action.

  The broad unit logs every request it serves at WARN, and the row says so. A preview the broad helper itself refuses (a dpkg lock held, a blocker) still shows the socket works, and the row reports the refusal. A policy whose only broad use is `unit: broad` commands, or packages without the index update, gets a NOTE that the socket is not probed. Its state then shows on the first broad call, and on the target in `systemctl status shell-mcp-privd-broad.socket`.
- **`trusted proxy <entry>`**, for each entry of `SHELL_MCP_TRUSTED_PROXIES`, checked statically (CLIENTS §1):
  - an entry that is, or holds, a gateway of the container's own routes (`/proc/net/route`, `/proc/net/ipv6_route`) is a FAIL;
  - a prefix, or an address on no network the container is attached to, is a WARN.

  A NOTE says that whether the server sees each client's own address is the log-line check, run once through the proxy (`deploy/caddy/README.md`). An empty list is a NOTE: `X-Forwarded-For` is then never believed.
- **`approval page`**, under `SHELL_MCP_APPROVAL_METHOD=web`. A `GET` of `SHELL_MCP_APPROVAL_PUBLIC_URL`, with no proxy variables, no redirect followed, and the system's roots or `--ca-file`. The page is told from another service by its own headers: `Content-Security-Policy` with `frame-ancestors 'none'`, `X-Frame-Options: DENY` and `Cache-Control: no-store`.

  | Answer | Row |
  |---|---|
  | 200 from the page | ok, with the certificate's end date (a WARN within 14 days) |
  | 403 from the page | FAIL: it serves only the proxies in `SHELL_MCP_TRUSTED_PROXIES` |
  | 403 without the page's headers | WARN: a proxy limited to the LAN or VPN refused the container's address, so check from a LAN or VPN machine |
  | a redirect, another service, a certificate that does not verify, no answer | FAIL |

  A NOTE says that doctor cannot show the page is unreachable from outside the LAN or VPN.
- **`mcp endpoint`**, with `--mcp-url`. One `POST` without a token, which does not count toward the lockout (ARCHITECTURE §3).

  | Answer | Row |
  |---|---|
  | 401 with `WWW-Authenticate: Bearer realm="shell-mcp"` | ok |
  | 421 | FAIL: the name is missing from `SHELL_MCP_ALLOWED_HOSTS` |
  | 403 without the server's headers | WARN, as for the approval page |
  | 2xx | FAIL: the endpoint answered without a token |
  | another answer, or none | FAIL |

It writes nothing and never sends the token anywhere. The gate and the helper log its read requests on the target under the server key's principal, which is the evidence it ran there. `shell-mcp check` is unchanged: the target checks alone, as JSON for scripts.

**What to do about each `WARN`.** A WARN does not stop the server, but each is something to fix or to accept knowingly:

| Row | WARN | What to do |
|---|---|---|
| `configuration` | a startup warning (it names the variable) | change that variable in the compose file, then `docker compose up -d`; [`deploy/.env.example`](../deploy/.env.example) says what each one takes |
| `secret <variable>` | owned by another uid than the container's | as root on the server host: `chown 65532:65532 <the file>` (the secrets directory too, for the `bind` form) |
| `secret <variable>` | cannot be read | the file is missing or its directory is not readable by uid 65532: run `shell-mcp init` again with the same flags (it keeps what is valid and names what is not; `deploy/README.md`, "Secrets") |
| `target <name>` | the sandbox is `best-effort`, or not applied | on the target, `check-policy` (§5) shows the kernel's Landlock ABI: upgrade the kernel (§0), and return the policy to `sandbox.landlock: required`. `best-effort` weakens the sandbox (POLICY §4a) and is only ever your explicit choice |
| `trusted proxy <entry>` | a prefix, not a single address | set `SHELL_MCP_TRUSTED_PROXIES` to the proxy's one fixed address (`--proxy-addr` of `init compose`) |
| `trusted proxy <entry>` | not on a network this container is attached to | the entry is not your proxy's address on the server's network: give the proxy its fixed address there (`deploy/caddy/README.md`, property 1) and list exactly that |
| `trusted proxy <entry>` | this container's interfaces could not be read | nothing could be checked statically: run the log-line check of `deploy/caddy/README.md` once |
| `approval page`, `mcp endpoint` | 200 or 401 as expected, but the certificate ends within 14 days | renew the proxy's certificate |
| `approval page`, `mcp endpoint` | 403 without the server's headers | the proxy refused the container's own address, as a LAN/VPN-only proxy should: check the URL from a LAN or VPN machine instead (the `curl` of CLIENTS §1) |
| `mcp endpoint` | 429 | the container's address is rate-limited or locked out after wrong tokens: wait 5 minutes and run `doctor` again (CLIENTS §7) |

### 12.7 `verify-release.sh` *(real host: needs the published release)*

Step 2's checks, for every file in a directory, from every release after 0.2.0. It is `scripts/verify-release.sh` in the repository and `verify-release.sh` in the examples archive. Run it with `sh`, as any user, from a checkout at the release's tag:

```bash
sh scripts/verify-release.sh <version> [--dir <dir>] [--sums <verified SHA256SUMS>]
```

`<version>` is `X.Y.Z`. `--dir` (default: the current directory) holds the downloaded files and nothing else: every file in it but `SHA256SUMS` and the `*.sigstore.json` bundles must be a release file.

- **Always:** every file present must be listed in `SHA256SUMS` and match it, and every binary and the archive must be of `<version>`.
- **With cosign:** `SHA256SUMS`, each binary and the archive must verify against their bundles. The certificate identity is `https://github.com/tyler-rich/shell-mcp/.github/workflows/release-build.yml@refs/tags/v<version>`, and the issuer is `https://token.actions.githubusercontent.com`. These are `scripts/release/verify.sh`'s identity and issuer, and a self-test holds the two scripts equal.
- **With gh:** each listed file must have a provenance attestation from that workflow at `refs/tags/v<version>`.
- **With both installed,** both run.
- **With neither,** only `--sums <file>` is accepted: a `SHA256SUMS` verified with cosign on another machine and copied over. The files are checked against it, the script says that the signature was checked elsewhere, and a different `SHA256SUMS` in `--dir` is refused. Without cosign, gh or `--sums`, it refuses and says how to get one.

It downloads nothing itself (cosign and gh fetch what their own verification needs). It never compares a hash with what a server returns: that would show only that GitHub served the same bytes twice. It writes nothing and needs no root. Exit 0 only when every check passed, 1 when one failed or it refused, 2 for usage.

A dry run's version (`X.Y.Z-dryrun.<commit>`) only names the files: the checks run, then the script refuses, in every mode, `--sums` included. The release workflow runs the script after signing: a release's files must pass, and a changed binary, a changed `SHA256SUMS`, a missing bundle and another release's identity must each be refused.

Read the script once. The copy in the examples archive cannot vouch for the archive it is in, so step 2's commands stay the root of trust.
