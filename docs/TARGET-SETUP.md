# Setting up a target host

This guide sets up one Linux host ("target") so that a shell-mcp server can reach it: the gate (`shell-mcp-gate`) as an SSH forced command, and optionally the privileged helper (`shell-mcp-privd`) for root actions. It turns `docs/SECURITY.md` §5 into steps. The normative rules are in `docs/POLICY.md` (gate policy) and `docs/PRIVILEGED.md` (helper); where this guide and they disagree, they win.

Every name below is a placeholder: the service account `svc-shell` (uid/gid 60123), the helper's socket group `svc-shell-priv` (gid 60124), the application account `example-app`, the paths `/srv/app` and `/etc/example-app`, the unit `example-app.service`, the server's network `192.0.2.0/24`. Use your own.

**How each step was checked.** Every command marked *(container)* was run as written, as root, in throwaway containers of `debian:trixie` (Debian 13), `ubuntu:24.04` and `ubuntu:26.04`, against the binaries of the commit this guide was released with (ARCHIVE §14, 2026-10-25 S5b). Commands marked *(real host)* need something a container does not have: a running systemd and polkit, journald, a kernel with the Landlock ABI the gate needs, or the published release. The end-to-end tests (`e2e-host` in CI) run the gate and the helper on a real Ubuntu 26.04 machine.

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

The list must contain `landlock`. Step 5's `check-policy` reports the kernel's Landlock ABI exactly (`kernel Landlock ABI N`), which is the check that counts.

```bash
systemctl --version
```

```bash
/usr/sbin/sshd -V
```

## 2. Download and verify the release *(real host: needs the published release)*

Each release on GitHub carries, per architecture, `shell-mcp_X.Y.Z_linux_<arch>` (the server), `shell-mcp-gate_X.Y.Z_linux_<arch>` and `shell-mcp-privd_X.Y.Z_linux_<arch>`, plus `shell-mcp_X.Y.Z_examples.tar.gz` (the example policies and `deploy/`), `SHA256SUMS`, a Sigstore bundle `<file>.sigstore.json` for every binary, the archive and `SHA256SUMS`, and a CycloneDX SBOM per binary. The examples below use 0.1.0 on amd64.

```bash
gh release download v0.1.0 --repo tyler-rich/shell-mcp \
  --pattern 'shell-mcp-gate_0.1.0_linux_amd64*' --pattern 'shell-mcp-privd_0.1.0_linux_amd64*' \
  --pattern 'shell-mcp_0.1.0_examples.tar.gz*' --pattern 'SHA256SUMS*'
```

Verify the checksums, then the signature of each file you install. The certificate identity pins the release workflow at the release's own tag: anything signed by another ref (a dry run, a branch) is not a release and fails this check.

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

```bash
for f in SHA256SUMS shell-mcp-gate_0.1.0_linux_amd64 shell-mcp-privd_0.1.0_linux_amd64 shell-mcp_0.1.0_examples.tar.gz; do
  cosign verify-blob --bundle "$f.sigstore.json" \
    --certificate-identity https://github.com/tyler-rich/shell-mcp/.github/workflows/release-build.yml@refs/tags/v0.1.0 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$f" || echo "FAILED: $f"
done
```

The build provenance (SLSA) can be checked with the GitHub CLI as well:

```bash
gh attestation verify shell-mcp-gate_0.1.0_linux_amd64 --repo tyler-rich/shell-mcp \
  --signer-workflow tyler-rich/shell-mcp/.github/workflows/release-build.yml --source-ref refs/tags/v0.1.0
```

These are the commands the release workflow's own `scripts/release/verify.sh` runs after signing, including the refusal of another ref; they cannot be run before the release exists. The release notes repeat them with the image digest.

## 3. Install the binaries *(container)*

```bash
install -o root -g root -m 0755 shell-mcp-gate_0.1.0_linux_amd64 /usr/local/bin/shell-mcp-gate
install -o root -g root -m 0755 -d /usr/local/libexec
install -o root -g root -m 0755 shell-mcp-privd_0.1.0_linux_amd64 /usr/local/libexec/shell-mcp-privd
shell-mcp-gate version
```

Install the helper only if you want root actions (step 9). Keep these paths: the generated units run `/usr/local/libexec/shell-mcp-privd`, both binaries re-execute themselves to start commands and so must sit under a read+execute directory of their sandbox (`/usr/local/bin`, `/usr/local/libexec`), and the gate refuses to serve unless its binary and every directory above it are root's and not group- or world-writable.

To unpack the example policies:

```bash
tar -xzf shell-mcp_0.1.0_examples.tar.gz
```

They are under `shell-mcp_0.1.0/examples/policies/` (`read-only.yaml`, `operator.yaml`, `admin.yaml`) and `shell-mcp_0.1.0/examples/privileged/privileged.yaml`; the steps below use those paths.

## 4. Create the service account *(container)*

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
passwd -l svc-shell
```

- **The shell must be a real shell** (`/bin/sh`): sshd runs the forced command through it, and `nologin` would refuse every connection. That is safe: the command is the root-owned forced command; what the client asks for never reaches the shell.
- **`passwd -l`** locks the password. Key logins still work with the distributions' `UsePAM yes` (checked: the SSH tests below logged in to the locked account on all three images).
- **The home directory is protected:** the gate never writes there, and it may not be a write root.

Groups, only as needed, and nothing else (the gate refuses to serve as a member of `root`, `sudo`, `wheel`, `adm`, `docker`, `lxd`, `incus-admin`, `libvirt`, `kvm`, `disk` or `shadow`):

```bash
usermod -aG systemd-journal svc-shell       # only if the policy has a journal section
groupadd --gid 60124 svc-shell-priv         # only if you install the helper (step 9)
usermod -aG svc-shell-priv svc-shell
id svc-shell
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

One policy per SSH key, so each server instance gets its own ceiling. Start from the example closest to what you need (`read-only.yaml`, `operator.yaml`, `admin.yaml`), edit every placeholder, and write it for the worst case: what would you accept a fully compromised MCP server doing with this key? (POLICY §1.)

```bash
install -o root -g root -m 0755 -d /etc/shell-mcp
install -o root -g root -m 0644 shell-mcp_0.1.0/examples/policies/read-only.yaml /etc/shell-mcp/read-only.yaml
```

The policy and every directory above it must be root's and not group- or world-writable (`0640 root:svc-shell` also works). Then check it **as the service account**, so the uid, group and home-directory checks describe that account, and the chain checks trust root and that account, as the gate will:

```bash
runuser -u svc-shell -- shell-mcp-gate check-policy --policy /etc/shell-mcp/read-only.yaml
```

It prints `ok`, `WARN` and `FAIL` lines, then the effective policy, and exits non-zero when `serve` would refuse. Run as root it prints a `NOTE` that the identity checks describe root instead. Read every WARN; the common ones:

- `remote uses TCP port 443, which sandbox.tcp_connect_ports does not list` — `git_pull` cannot connect; add 443 for a key that may pull.
- `apt has documented escape techniques (GTFOBins …)` — every command whose binary has known escapes is listed; review its templates and never give such a binary a `{path:write}`.
- `paths.write …: is group- or world-writable` — see step 6.
- `could not probe RENAME_NOREPLACE … permission denied` — the service account cannot write that write root yet (step 6).
- `repo has no .git directory` — the repository does not exist yet, or the path is wrong.
- `sandbox: … kernel Landlock ABI 3 …, required needs 4` followed by `FAIL` — the kernel is too old (this is what a container on an older host kernel shows).

Run `check-policy` again after every edit; the gate re-reads the policy on every request, so there is nothing to restart.

## 6. Write roots, repositories and commands' paths *(container)*

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

Debian 13 and Ubuntu 24.04 and 26.04 include `/etc/ssh/sshd_config.d/*.conf` near the top of `sshd_config`. Check the syntax, then the effective settings for the service account and for anyone else (the block must not change other accounts):

```bash
/usr/sbin/sshd -t
/usr/sbin/sshd -T -C user=svc-shell,host=client.example.test,addr=192.0.2.20 | grep -Ei '^(authorizedkeysfile|authenticationmethods|permittty|allowtcpforwarding|x11forwarding|maxsessions) '
/usr/sbin/sshd -T -C user=someone-else,host=client.example.test,addr=192.0.2.20 | grep -Ei '^(authorizedkeysfile|permittty|x11forwarding) '
```

On all three images the first showed the values above and the second the distribution's defaults (`authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2`, `permittty yes`, `x11forwarding yes`).

Add one line per server key to `/etc/ssh/authorized_keys.d/svc-shell` (`root:root 0644`), always with `restrict`, a `from=` limited to where the server connects from, and its own policy and principal label:

```
restrict,from="192.0.2.0/24",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/read-only.yaml --principal readonly" ssh-ed25519 AAAA… shell-mcp-readonly
```

The key is the server's `ssh_key.pub` (`deploy/README.md`); it must be Ed25519. When the server's container runs on the target itself, `from=` names the Docker network's subnet (SECURITY §7).

**Confirm that the service account cannot change its own key options** *(container)*. Neither the gate nor the helper reads this file; sshd's `StrictModes` is what refuses a bad one, and the ownership is yours to check:

```bash
/usr/sbin/sshd -T | grep -i '^strictmodes'
stat -c '%U:%G %a %n' /etc/ssh /etc/ssh/authorized_keys.d /etc/ssh/authorized_keys.d/svc-shell
```

The first must print `strictmodes yes` (the default; never set `StrictModes no`). The second must show `root:root` and no group or world write bit on all three (`755`, `755`, `644`). Both checks matter: on all three images `StrictModes` refused every login when the keys file or its directory was group- or world-writable, or owned by another account ("Authentication refused: bad ownership or modes for file …" in sshd's log), but **accepted a file or directory owned by the service account itself**, which could then rewrite its own `command=` and `restrict`. Only root ownership prevents that.

Apply the configuration *(real host)*, keeping your current session open until a new login has worked:

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

Only when a policy has `services.control` (`read-only.yaml` has none; `operator.yaml` and `admin.yaml` do, each installed and edited like step 5's, for its own key). Generate the rule from that policy *(container)* and review it: it lets the service account run exactly the listed verbs on exactly the listed units, and nothing else.

```bash
shell-mcp-gate polkit --policy /etc/shell-mcp/operator.yaml --user svc-shell > 60-shell-mcp.rules
install -o root -g root -m 0644 60-shell-mcp.rules /etc/polkit-1/rules.d/60-shell-mcp.rules
```

`polkitd` is the package on all three distributions; `/etc/polkit-1/rules.d` is `root:polkitd 0750` there. Regenerate the rule whenever `services.control` changes. Check that it works *(real host)*:

```bash
runuser -u svc-shell -- systemctl --no-ask-password restart example-app.service
```

It succeeds for an allowed unit and verb and fails with an authorization error for anything else (the gate reports that as `not_authorized`). polkit picks up new rule files by itself; `systemctl restart polkit` forces it.

## 9. The privileged helper (only for root actions)

The helper runs one root process per request, socket-activated, inside a generated systemd sandbox, and does only what its own policy declares. Read `docs/PRIVILEGED.md` §3 before writing that policy: human approval stops a misled model, not a compromised server.

### 9.1 Its policy *(container)*

Start from `examples/privileged/privileged.yaml`. Set `client_uid` to the service account's uid (`id -u svc-shell`) and `socket_group` to the group from step 4.

```bash
install -o root -g root -m 0600 shell-mcp_0.1.0/examples/privileged/privileged.yaml /etc/shell-mcp/privileged.yaml
/usr/local/libexec/shell-mcp-privd check-policy --policy /etc/shell-mcp/privileged.yaml
```

Run it as root. Review every `REVIEW` line (persistence roots, root-equivalent commands, packages, power, programs that bypass a bound operation) and every `WARN`; `FAIL` means the helper would refuse to serve.

### 9.2 Its units *(container)*

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

CI measures the core unit at an exposure of 1.4 on Ubuntu 26.04 (systemd 259) and fails above that. The broad unit's score is high by design.

### 9.5 Let the gate forward to it *(container)*

In the gate policy of each key that may use root actions (only an admin server's key, normally), enable forwarding and give the broad socket when the broad pair is installed:

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

- **A new release:** verify it (step 2) and `install` the new binaries over the old ones (step 3). The gate and the helper start per request, so nothing needs restarting. Read the release notes for policy changes and run both `check-policy` commands.
- **A gate policy edit:** `check-policy` (step 5); regenerate the polkit rule if `services.control` changed (step 8).
- **A privileged policy edit:** `check-policy`, `units`, `systemctl daemon-reload` (step 9.2).
- **Revoking a server:** remove its line from `/etc/ssh/authorized_keys.d/svc-shell`. sshd reads the file on every login.
- **Removing everything:** `systemctl disable --now` both sockets, then remove the units, `/etc/polkit-1/rules.d/60-shell-mcp.rules`, `/etc/ssh/sshd_config.d/60-shell-mcp.conf`, `/etc/ssh/authorized_keys.d/svc-shell`, `/etc/shell-mcp`, the two binaries and the accounts. `/var/lib/shell-mcp/backups` holds previous versions of files the helper changed; keep it until you no longer need them.
