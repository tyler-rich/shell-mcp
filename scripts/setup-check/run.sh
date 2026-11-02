#!/usr/bin/env bash
# run.sh: the setup check (handoff §3.8, F-13). Builds the release binaries
# from this commit in the Go image, then on Debian 13, Ubuntu 24.04 and
# Ubuntu 26.04 (Dockerfile, the bases scripts/exposure pins) runs, as each
# container's own root:
#   - shell-mcp-gate install on a fresh image: a dry run first that leaves
#     the filesystem identical, the install, a second run that reports only
#     unchanged, and a dry run again;
#   - a host set up by hand (TARGET-SETUP §4, §7, §8, §9.2 as written): install
#     and privd install over it report every item unchanged (byte identity);
#   - the SSH round trip: sshd -D in the target, a second container on a
#     labelled network: the gate's hello, no shell without a command, no PTY,
#     shell-mcp check verifying the printed pin and refusing a wrong one;
#   - every refusal a container can build, each leaving no temp file;
#   - policy new (POLICY §9) from the admin example's answers: --out -, the
#     dry run, the write and a second run unchanged, the helper's refusal
#     before install creates the socket group, install, the helper's policy,
#     privd install with its --gate-policy cross-check, check-policy ok on
#     both, the read-only preset, and its refusals, each writing nothing;
#   - shell-mcp-privd install --no-start: the review stop (exit 3), the units
#     byte-identical to units --out, a second run unchanged, the dry run;
# and, as the Go image's root, execx's credential tests
# (SHELL_MCP_REQUIRE_ROOT_TESTS=1: they fail rather than skip); then, with the
# server image built from this commit's Dockerfile (handoff §4.C):
#   - shell-mcp init in the image as 65532 with no network, a read-only root,
#     no capabilities and no-new-privileges, after the documented host
#     command: a dry run that changes nothing, the run, a second run that
#     changes nothing, the owners and modes, no temp file, its refusals;
#   - the server started with docker compose from init compose's printed
#     file in both forms, and shell-mcp check passing against a target.
#
# The containers run as their own root (approved, handoff §7 Q2), and only
# these: unprivileged, Docker's default capabilities with none added,
# no-new-privileges, no host mount but the repository read-only, and never
# --privileged, --pid=host or --network=host. Every container and the
# network carry the run's label and are removed by it. Needs docker; used by
# scripts/ci-local.sh and CI.
set -euo pipefail
export MSYS_NO_PATHCONV=1

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && { pwd -W 2>/dev/null || pwd; })"
dir_native="$(cd "$here" && { pwd -W 2>/dev/null || pwd; })"
cd "$here/../.."
label="${SHELL_MCP_CI_LOCAL_LABEL:-shell-mcp.ci-local=setup-check-$$-$RANDOM}"
run_id="${label#*=}"
net="shell-mcp-setup-check-$run_id"

go_image="$(awk 'toupper($1) == "FROM" { for (i = 2; i <= NF; i++) if ($i ~ /^golang:/) { print $i; exit } }' Dockerfile)"
if [[ "$go_image" != *@sha256:* ]]; then
	echo "setup-check: the Dockerfile's golang builder image is not pinned by digest" >&2
	exit 1
fi
if [[ "$(uname -s)" == Linux ]] && [[ "$(id -u)" != 0 ]]; then
	run_as="$(id -u):$(id -g)"
else
	run_as="65532:65532"
fi

bins_tar="$(mktemp)"
cleanup() {
	local ids
	ids="$(docker ps -aq --filter "label=$label" 2>/dev/null || true)"
	if [[ -n "$ids" ]]; then
		# shellcheck disable=SC2086 # one container id per word
		docker rm -f $ids >/dev/null 2>&1 || true
	fi
	local n
	for n in $(docker network ls -q --filter "label=$label" 2>/dev/null || true); do
		docker network rm "$n" >/dev/null 2>&1 || true
	done
	for n in $(docker volume ls -q --filter "label=$label" 2>/dev/null || true); do
		docker volume rm "$n" >/dev/null 2>&1 || true
	done
	rm -f "$bins_tar"
	rm -rf "${compose_tmp:-}"
}
trap cleanup EXIT

pass=0
fail=0
ok() { echo "ok   $*"; pass=$((pass + 1)); }
bad() { echo "FAIL $*"; fail=$((fail + 1)); }

# --- Images and binaries -------------------------------------------------------
read -r -a images <<<"${SETUP_CHECK_IMAGES:-debian13 ubuntu2404 ubuntu2604}"
for i in "${images[@]}"; do
	docker build -q --label "$label" --target "$i" -t "shell-mcp-setup-check:$i" -f "$dir_native/Dockerfile" "$dir_native" >/dev/null
done
docker volume create shell-mcp-ci-cache >/dev/null
if [[ -z "${SHELL_MCP_CI_LOCAL_LABEL:-}" ]]; then
	docker run --rm --label "$label" -u 0:0 -v shell-mcp-ci-cache:/cache "$go_image" \
		sh -c "mkdir -p /cache/build /cache/mod && chown -R $run_as /cache/build /cache/mod && chown $run_as /cache" >/dev/null
fi
docker run --rm --label "$label" -u "$run_as" \
	-e HOME=/tmp -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod -e CGO_ENABLED=0 \
	--tmpfs "/work:exec,uid=${run_as%%:*},gid=${run_as##*:},mode=0700" \
	-v shell-mcp-ci-cache:/cache -v "$repo:/src:ro" -w /src "$go_image" \
	sh -c 'set -e; for c in shell-mcp shell-mcp-gate shell-mcp-privd; do go build -trimpath -ldflags "-X main.version=setup-check" -o /work/setup-check/$c ./cmd/$c >&2; done
		tar -C /work -cf - setup-check' >"$bins_tar"

# --- The credential option, as root ---------------------------------------------
# execx's switch tests need a root test process (handoff §4.A): the Go image's
# root, a private GOCACHE, the module cache read-only. They must run and pass;
# a skip is a failure.
cred_out="$(docker run --rm --label "$label" -u 0:0 --security-opt no-new-privileges:true \
	-e HOME=/root -e GOCACHE=/gocache -e GOMODCACHE=/cache/mod -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local -e GOPROXY=off \
	-e SHELL_MCP_REQUIRE_ROOT_TESTS=1 --tmpfs /gocache:exec --tmpfs /tmp:exec,mode=1777 \
	-v shell-mcp-ci-cache:/cache:ro -v "$repo:/src:ro" -w /src "$go_image" \
	go test -count=1 -v -run 'Credential|NilCredential' ./internal/gate/execx/ 2>&1)" || true
for t in TestCredentialSwitch TestCredentialNoGroups TestCredentialNPROC TestCredentialRefusedValuesAsRoot TestNilCredentialAsRoot TestCredentialCallSites; do
	if grep -q -- "^--- PASS: $t " <<<"$cred_out"; then
		ok "execx (root, $go_image): $t"
	else
		bad "execx (root): $t did not pass"
		grep -E -- "--- (FAIL|SKIP)|^\s+credential" <<<"$cred_out" | head -n 20 || true
	fi
done

docker network create --label "$label" "$net" >/dev/null

# --- Helpers ---------------------------------------------------------------------
# new <image> [<prepare>]: a fresh container, the binaries copied in and
# installed (prepare-bare: without the test policies).
new() {
	local c
	c="$(docker run -d --label "$label" --network "$net" --security-opt no-new-privileges:true \
		-v "$repo:/src:ro" "shell-mcp-setup-check:$1" sleep infinity)"
	docker cp - "$c:/opt" <"$bins_tar"
	docker exec "$c" bash /src/scripts/setup-check/target.sh "${2:-prepare}" >&2
	echo "$c"
}
new_bare() { new "$1" prepare-bare; }
# pn <container> <command…>: a policy new run; sets out (stdout) and code.
pn() {
	local c="$1"
	shift
	code=0
	out="$(docker exec "$c" "$@" 2>/dev/null)" || code=$?
}
ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
ex() { docker exec "$@"; }
# install <container> <args…>: shell-mcp-gate install; sets out and code.
install() {
	local c="$1"
	shift
	code=0
	out="$(docker exec "$c" /usr/local/bin/shell-mcp-gate install "$@" 2>/dev/null)" || code=$?
}
no_temps() { # no_temps <container> <what>
	local t
	t="$(ex "$1" bash /src/scripts/setup-check/target.sh temps)"
	if [[ -z "$t" ]]; then ok "$2: no temp file left"; else bad "$2: temp files left: $t"; fi
}

for i in "${images[@]}"; do
	echo "=== $i"
	t="$(new "$i")"
	c="$(new "$i")"
	cip="$(ip "$c")"
	tip="$(ip "$t")"
	ex "$c" ssh-keygen -q -t ed25519 -N '' -C shell-mcp -f /root/ssh_key
	docker cp "$c:/root/ssh_key.pub" - | docker cp - "$t:/root"
	args=(--policy /etc/shell-mcp/read-only.yaml --principal readonly --from "$cip" --key /root/ssh_key.pub --uid 60123 --gid 60123 --no-reload)

	# A dry run on the fresh image changes nothing.
	before="$(ex "$t" bash /src/scripts/setup-check/target.sh snapshot)"
	install "$t" "${args[@]}" --dry-run
	after="$(ex "$t" bash /src/scripts/setup-check/target.sh snapshot)"
	if [[ "$code" == 0 && "$before" == "$after" ]]; then ok "$i: dry run on a fresh image: exit 0, filesystem identical"; else bad "$i: dry run: exit $code, identical: $([[ "$before" == "$after" ]] && echo yes || echo no)"; echo "$out" | tail -n 5 || true; fi

	# The install.
	install "$t" "${args[@]}"
	if [[ "$code" == 0 ]] && grep -q '^SHELL_MCP_TARGET_HOST_KEYS=ssh-ed25519 SHA256:' <<<"$out"; then ok "$i: install on a fresh image"; else bad "$i: install exit $code"; echo "$out" | tail -n 30 || true; fi
	pin="$(sed -n 's/^SHELL_MCP_TARGET_HOST_KEYS=//p' <<<"$out")"
	grep -q 'check-policy as svc-shell: serve would accept' <<<"$out" && ok "$i: check-policy ran as the account (execx's credential option)" || bad "$i: check-policy as the account"
	no_temps "$t" "$i: install"
	install "$t" "${args[@]}"
	if [[ "$code" == 0 ]] && grep -q 'nothing to do: every item unchanged' <<<"$out" && ! grep -qE '^ok   [^ ]+: (create|replace)|^ok   ran ' <<<"$out"; then
		ok "$i: second run: only unchanged"
	else
		bad "$i: second run exit $code"
		echo "$out" | tail -n 20 || true
	fi
	before="$(ex "$t" bash /src/scripts/setup-check/target.sh snapshot)"
	install "$t" "${args[@]}" --dry-run
	after="$(ex "$t" bash /src/scripts/setup-check/target.sh snapshot)"
	[[ "$code" == 0 && "$before" == "$after" ]] && ok "$i: dry run after install: exit 0, filesystem identical" || bad "$i: dry run after install: exit $code"
	ex "$t" sh -c 'grep "^svc-shell:" /etc/shadow | cut -d: -f2 | grep -q "^!"' &&
		ok "$i: the account is locked" || bad "$i: the account is not locked"

	# The SSH round trip.
	ex -d "$t" /usr/sbin/sshd -D -e
	ex "$c" sh -c "echo '$tip $(ex "$t" cat /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f1,2)' >/root/known_hosts"
	sshc=(ssh -i /root/ssh_key -o UserKnownHostsFile=/root/known_hosts -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=10)
	for _ in $(seq 1 20); do ex "$c" bash -c "exec 3<>/dev/tcp/$tip/22" 2>/dev/null && break || sleep 0.5; done
	r="$(printf '%s\n' '{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"hello"}' | docker exec -i "$c" "${sshc[@]}" "svc-shell@$tip" shell-mcp-gate/1 2>&1 || true)"
	grep -q '"ok":true' <<<"$r" && ok "$i: the gate answers hello over SSH" || { bad "$i: hello over SSH"; echo "$r" | tail -n 5 || true; }
	r="$(docker exec -i "$c" "${sshc[@]}" "svc-shell@$tip" </dev/null 2>&1 || true)"
	grep -q 'bad_request' <<<"$r" && ok "$i: no shell without a command (the gate's bad_request)" || { bad "$i: a session without a command"; echo "$r" | tail -n 3 || true; }
	r="$(docker exec -i "$c" "${sshc[@]}" -tt "svc-shell@$tip" shell-mcp-gate/1 </dev/null 2>&1 || true)"
	grep -q 'PTY allocation request failed' <<<"$r" && ok "$i: no PTY" || { bad "$i: a PTY request"; echo "$r" | tail -n 3 || true; }
	tok="$(head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | head -c 48)"
	cenv=(-e SHELL_MCP_TOKEN="$tok" -e SHELL_MCP_TARGET_NAME=target-a -e SHELL_MCP_TARGET_HOST="$tip" -e SHELL_MCP_TARGET_USER=svc-shell -e SHELL_MCP_SSH_KEY_FILE=/root/ssh_key)
	r="$(docker exec "${cenv[@]}" -e SHELL_MCP_TARGET_HOST_KEYS="$pin" "$c" /usr/local/bin/shell-mcp check 2>&1)" && rc=0 || rc=$?
	[[ "$rc" == 0 ]] && grep "host_key_verified" <<<"$r" | grep -qF -- "$pin" && ok "$i: shell-mcp check verifies install's pin" || { bad "$i: shell-mcp check exit $rc"; echo "$r" | tail -n 10 || true; }
	r="$(docker exec "${cenv[@]}" -e SHELL_MCP_TARGET_HOST_KEYS="ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "$c" /usr/local/bin/shell-mcp check 2>&1)" && rc=0 || rc=$?
	[[ "$rc" != 0 ]] && grep -q 'not pinned' <<<"$r" && ok "$i: shell-mcp check refuses a wrong pin" || { bad "$i: a wrong pin, exit $rc"; echo "$r" | tail -n 5 || true; }

	# A host set up by hand: install over it reports every item unchanged.
	h="$(new "$i")"
	docker cp "$c:/root/ssh_key.pub" - | docker cp - "$h:/root"
	ex "$h" bash /src/scripts/setup-check/target.sh hand "$cip" /root/ssh_key.pub
	install "$h" --policy /etc/shell-mcp/operator.yaml --principal operator --from "$cip" --key /root/ssh_key.pub --uid 60123 --gid 60123 --no-reload
	if [[ "$code" == 0 ]] && grep -q 'nothing to do: every item unchanged' <<<"$out"; then
		ok "$i: TARGET-SETUP §4, §7, §8 by hand: install finds every file byte-identical"
	else
		bad "$i: install over the hand steps, exit $code"
		echo "$out" | grep -E 'FAIL|differ|^     \|' | head -n 30 || true
	fi

	# The refusals a container can build (TARGET-SETUP §12.1), each on a fresh
	# image, each leaving no temp file and refusing with exit 1.
	for case in "docker-group:member of docker, a privileged group" "uid-in-use:uid 60123 is already account example-app's" \
		"keys-world-writable:must be a regular root:root 0644 file" "strictmodes-no:StrictModes must stay yes" \
		"match-wins:the Match block is not in force" "line-without-restrict:the line has no restrict option" \
		"from-16:floor for IPv4" "policy-with-space:holds characters"; do
		name="${case%%:*}"
		want="${case#*:}"
		x="$(new "$i")"
		docker cp "$c:/root/ssh_key.pub" - | docker cp - "$x:/root"
		a=("${args[@]}")
		case "$name" in
		from-16) a=(--policy /etc/shell-mcp/read-only.yaml --principal readonly --from 10.0.0.0/16 --key /root/ssh_key.pub --uid 60123 --gid 60123 --no-reload) ;;
		policy-with-space) a=(--policy "/etc/shell-mcp/read only.yaml" --principal readonly --from "$cip" --key /root/ssh_key.pub --uid 60123 --gid 60123 --no-reload) ;;
		esac
		[[ "$name" == from-16 ]] || ex "$x" bash /src/scripts/setup-check/target.sh break "$name"
		install "$x" "${a[@]}"
		if [[ "$code" == 1 ]] && grep -qF -- "$want" <<<"$out"; then ok "$i: refused: $name"; else bad "$i: $name: exit $code"; echo "$out" | grep -E 'FAIL' | head -n 5 || true; fi
		no_temps "$x" "$i: $name"
		if [[ "$name" == match-wins ]]; then
			ex "$x" sh -c '! test -e /etc/ssh/sshd_config.d/60-shell-mcp.conf && ! test -e /etc/ssh/authorized_keys.d/svc-shell' &&
				ok "$i: match-wins: the drop-in and the key line were rolled back" || bad "$i: match-wins: files left after the rollback"
		fi
		docker rm -f "$x" >/dev/null
	done

	# No /run/sshd (sshd -t cannot run): refused before anything is written,
	# naming this image's remedy, and the directory is never created.
	remedy="systemd-tmpfiles --create /usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf"
	[[ "$i" == ubuntu2404 ]] && remedy="systemctl start ssh.service"
	x="$(new "$i")"
	docker cp "$c:/root/ssh_key.pub" - | docker cp - "$x:/root"
	ex "$x" bash /src/scripts/setup-check/target.sh break no-privsep-dir
	before="$(ex "$x" bash /src/scripts/setup-check/target.sh snapshot)"
	install "$x" "${args[@]}"
	after="$(ex "$x" bash /src/scripts/setup-check/target.sh snapshot)"
	if [[ "$code" == 1 && "$before" == "$after" ]] && grep -qF -- "$remedy" <<<"$out" && ex "$x" sh -c '! test -e /run/sshd'; then
		ok "$i: refused without /run/sshd, naming $remedy; nothing written"
	else
		bad "$i: no /run/sshd: exit $code"
		echo "$out" | grep -E 'FAIL' | head -n 5 || true
	fi
	docker rm -f "$x" >/dev/null

	# The helper: install --no-start.
	p="$(new "$i")"
	docker cp "$c:/root/ssh_key.pub" - | docker cp - "$p:/root"
	install "$p" --policy /etc/shell-mcp/admin.yaml --principal admin --from "$cip" --key /root/ssh_key.pub --uid 60123 --gid 60123 \
		--socket-group svc-shell-priv --socket-gid 60124 --no-reload
	[[ "$code" == 0 ]] && ok "$i: install with the socket group" || { bad "$i: install with the socket group, exit $code"; echo "$out" | grep FAIL | head || true; }
	pi=(docker exec "$p" /usr/local/libexec/shell-mcp-privd install --policy /etc/shell-mcp/privileged.yaml --gate-policy /etc/shell-mcp/admin.yaml --no-start)
	rc=0
	r="$("${pi[@]}" 2>/dev/null)" || rc=$?
	hash="$(sed -n 's/^REVIEW policy \/etc\/shell-mcp\/privileged.yaml: sha256 //p' <<<"$r")"
	[[ "$rc" == 3 && -n "$hash" ]] && ex "$p" sh -c '! test -e /etc/systemd/system/shell-mcp-privd.socket' && ok "$i: privd install stops for review (exit 3), nothing written" || bad "$i: privd review stop: exit $rc"
	before="$(ex "$p" bash /src/scripts/setup-check/target.sh snapshot)"
	rc=0
	"${pi[@]}" --accept "$hash" --dry-run >/dev/null 2>&1 || rc=$?
	after="$(ex "$p" bash /src/scripts/setup-check/target.sh snapshot)"
	[[ "$rc" == 0 && "$before" == "$after" ]] && ok "$i: privd dry run: exit 0, filesystem identical" || bad "$i: privd dry run: exit $rc"
	rc=0
	r="$("${pi[@]}" --accept "$hash" 2>/dev/null)" || rc=$?
	[[ "$rc" == 0 ]] && grep -q 'systemd-analyze verify: shell-mcp-privd.socket, shell-mcp-privd@.service' <<<"$r" && ok "$i: privd install --no-start: written and verified" || { bad "$i: privd install exit $rc"; echo "$r" | grep -E 'FAIL|verify' | head || true; }
	ex "$p" sh -c 'mkdir -p /tmp/u && /usr/local/libexec/shell-mcp-privd units --policy /etc/shell-mcp/privileged.yaml --out /tmp/u >/dev/null &&
		cmp /tmp/u/shell-mcp-privd.socket /etc/systemd/system/shell-mcp-privd.socket && cmp /tmp/u/shell-mcp-privd@.service /etc/systemd/system/shell-mcp-privd@.service &&
		test "$(stat -c "%U:%G %a" /var/lib/shell-mcp /var/lib/shell-mcp/backups /etc/systemd/system/shell-mcp-privd.socket | tr "\n" " ")" = "root:root 700 root:root 700 root:root 644 "' &&
		ok "$i: privd units byte-identical to units --out; store root:root 0700" || bad "$i: privd units differ from units --out"
	rc=0
	r="$("${pi[@]}" --accept "$hash" 2>/dev/null)" || rc=$?
	[[ "$rc" == 0 ]] && grep -q 'nothing to do: every item unchanged' <<<"$r" && ok "$i: privd second run: unchanged" || bad "$i: privd second run exit $rc"
	rc=0
	r="$("${pi[@]}" 2>/dev/null)" || rc=$?
	[[ "$rc" == 3 ]] && ok "$i: privd re-run without --accept stops for review" || bad "$i: privd re-run without --accept: exit $rc"
	no_temps "$p" "$i: privd install"
	# §9.2 by hand on another image: privd install over it is unchanged.
	q="$(new "$i")"
	docker cp "$c:/root/ssh_key.pub" - | docker cp - "$q:/root"
	install "$q" --policy /etc/shell-mcp/admin.yaml --principal admin --from "$cip" --key /root/ssh_key.pub --uid 60123 --gid 60123 \
		--socket-group svc-shell-priv --socket-gid 60124 --no-reload
	ex "$q" bash /src/scripts/setup-check/target.sh hand-units
	rc=0
	r="$(docker exec "$q" /usr/local/libexec/shell-mcp-privd install --policy /etc/shell-mcp/privileged.yaml --no-start --accept "$hash" 2>/dev/null)" || rc=$?
	[[ "$rc" == 0 ]] && grep -q 'nothing to do: every item unchanged' <<<"$r" && ok "$i: TARGET-SETUP §9.2 by hand: privd install finds every unit byte-identical" || { bad "$i: privd install over §9.2 by hand: exit $rc"; echo "$r" | grep -E 'FAIL|replace|create' | head || true; }
	x="$(new "$i")"
	ex "$x" bash /src/scripts/setup-check/target.sh break privileged-0644
	rc=0
	r="$(docker exec "$x" /usr/local/libexec/shell-mcp-privd install --policy /etc/shell-mcp/privileged.yaml --no-start --accept "$hash" 2>/dev/null)" || rc=$?
	[[ "$rc" == 1 ]] && grep -q 'it must be root:root with no group or other bits' <<<"$r" && ok "$i: privd refused: a policy file 0644" || bad "$i: privd policy 0644: exit $rc"

	# policy new (handoff §4.D, POLICY §9): the admin example's answers, the
	# gate's policy new, install, the helper's policy new (after install,
	# which creates the socket group its loader needs), privd install with
	# the --gate-policy cross-check, and both check-policy runs.
	d="$(new_bare "$i")"
	docker cp "$c:/root/ssh_key.pub" - | docker cp - "$d:/root"
	abi="$(ex "$d" /usr/local/bin/shell-mcp-gate check-policy --policy /nonexistent 2>/dev/null | sed -n 's/.*kernel Landlock ABI \([0-9]*\);.*/\1/p' || true)"
	landlock=required
	[[ "${abi:-0}" -ge 4 ]] || landlock=best-effort
	echo "     $i: kernel Landlock ABI ${abi:-unknown}: landlock $landlock"
	ex "$d" bash /src/scripts/setup-check/target.sh app
	for preset in admin read-only; do ex "$d" bash /src/scripts/setup-check/target.sh answers "$preset" "$landlock"; done
	gpn=(/usr/local/bin/shell-mcp-gate policy new --answers /root/admin.yaml)
	ppn=(/usr/local/libexec/shell-mcp-privd policy new --answers /root/admin.yaml)
	before="$(ex "$d" bash /src/scripts/setup-check/target.sh snapshot)"
	pn "$d" "${gpn[@]}" --out -
	after="$(ex "$d" bash /src/scripts/setup-check/target.sh snapshot)"
	if [[ "$code" == 0 && "$before" == "$after" ]] && grep -q '^max_tier: destructive$' <<<"$out"; then
		ok "$i: gate policy new --out -: prints, writes nothing"
	else
		bad "$i: gate policy new --out -: exit $code"
		docker exec "$d" "${gpn[@]}" --out - 2>&1 >/dev/null | tail -n 10 || true
	fi
	pn "$d" "${gpn[@]}" --out /etc/shell-mcp/admin.yaml --dry-run
	after="$(ex "$d" bash /src/scripts/setup-check/target.sh snapshot)"
	[[ "$code" == 0 && "$before" == "$after" ]] && ok "$i: gate policy new --dry-run: exit 0, filesystem identical" || bad "$i: gate policy new --dry-run: exit $code"
	pn "$d" "${gpn[@]}" --out /etc/shell-mcp/admin.yaml
	if [[ "$code" == 0 ]] && grep -q '^ok: serve would accept this install and policy' <<<"$out" &&
		ex "$d" sh -c 'test "$(stat -c "%U:%G %a" /etc/shell-mcp /etc/shell-mcp/admin.yaml | tr "\n" " ")" = "root:root 755 root:root 644 "'; then
		ok "$i: gate policy new: written root:root 0644 in a new root:root 0755 /etc/shell-mcp; check-policy ok"
	else
		bad "$i: gate policy new: exit $code"
		echo "$out" | grep -E 'FAIL|WARN' | head -n 10 || true
	fi
	pn "$d" "${gpn[@]}" --out /etc/shell-mcp/admin.yaml
	[[ "$code" == 0 ]] && grep -q 'nothing to do: /etc/shell-mcp/admin.yaml unchanged' <<<"$out" && ok "$i: gate policy new again: unchanged" || bad "$i: gate policy new again: exit $code"
	pn "$d" "${ppn[@]}" --out /etc/shell-mcp/privileged.yaml
	if [[ "$code" == 1 ]] && grep -q 'does not exist on this host yet; run shell-mcp-gate install' <<<"$out" && ex "$d" sh -c '! test -e /etc/shell-mcp/privileged.yaml'; then
		ok "$i: privd policy new before install: refused (no socket group yet), nothing written"
	else
		bad "$i: privd policy new before install: exit $code"
	fi
	install "$d" --policy /etc/shell-mcp/admin.yaml --principal admin --from "$cip" --key /root/ssh_key.pub --uid 60123 --gid 60123 \
		--socket-group svc-shell-priv --socket-gid 60124 --no-reload
	if [[ "$code" == 0 ]] && grep -q 'check-policy as svc-shell: serve would accept' <<<"$out"; then
		ok "$i: install on the generated gate policy; check-policy as the account ok"
	else
		bad "$i: install on the generated policy: exit $code"
		echo "$out" | grep -E 'FAIL' | head || true
	fi
	pn "$d" "${ppn[@]}" --out /etc/shell-mcp/privileged.yaml
	if [[ "$code" == 0 ]] && grep -q '^OK: the helper would serve this policy' <<<"$out" &&
		ex "$d" sh -c 'test "$(stat -c "%U:%G %a" /etc/shell-mcp/privileged.yaml)" = "root:root 600"'; then
		ok "$i: privd policy new: written root:root 0600; check-policy ok"
	else
		bad "$i: privd policy new: exit $code"
		echo "$out" | grep -E 'FAIL|WARN' | head -n 10 || true
	fi
	pn "$d" "${ppn[@]}" --out /etc/shell-mcp/privileged.yaml
	[[ "$code" == 0 ]] && grep -q 'nothing to do: /etc/shell-mcp/privileged.yaml unchanged' <<<"$out" && ok "$i: privd policy new again: unchanged" || bad "$i: privd policy new again: exit $code"
	pi=(docker exec "$d" /usr/local/libexec/shell-mcp-privd install --policy /etc/shell-mcp/privileged.yaml --gate-policy /etc/shell-mcp/admin.yaml --no-start)
	rc=0
	r="$("${pi[@]}" 2>/dev/null)" || rc=$?
	dhash="$(sed -n 's/^REVIEW policy \/etc\/shell-mcp\/privileged.yaml: sha256 //p' <<<"$r")"
	rc=0
	r="$("${pi[@]}" --accept "$dhash" 2>/dev/null)" || rc=$?
	if [[ "$rc" == 0 && -n "$dhash" ]] && grep -q '^ok   --gate-policy /etc/shell-mcp/admin.yaml forwards to /run/shell-mcp/privd.sock and /run/shell-mcp/privd-broad.sock' <<<"$r" &&
		grep -q '^ok   client_uid 60123 is svc-shell, a member of svc-shell-priv' <<<"$r"; then
		ok "$i: privd install on the generated policies: the --gate-policy cross-check passes"
	else
		bad "$i: privd install on the generated policies: exit $rc"
		echo "$r" | grep -E 'FAIL|gate-policy|client_uid' | head -n 10 || true
	fi
	rc=0
	ex "$d" /usr/local/bin/shell-mcp-gate check-policy --policy /etc/shell-mcp/admin.yaml >/dev/null 2>&1 || rc=$?
	rc2=0
	ex "$d" /usr/local/libexec/shell-mcp-privd check-policy --policy /etc/shell-mcp/privileged.yaml >/dev/null 2>&1 || rc2=$?
	[[ "$rc" == 0 && "$rc2" == 0 ]] && ok "$i: check-policy ok on both generated policies (landlock $landlock)" || bad "$i: check-policy on the generated policies: gate $rc, privd $rc2"
	pn "$d" /usr/local/bin/shell-mcp-gate policy new --answers /root/read-only.yaml --out /etc/shell-mcp/read-only.yaml
	if [[ "$code" == 0 ]] && grep -q '^ok: serve would accept this install and policy' <<<"$out"; then
		ok "$i: gate policy new, read-only preset: written; check-policy ok"
	else
		bad "$i: gate policy new, read-only: exit $code"
		echo "$out" | grep -E 'FAIL' | head || true
	fi
	# Refusals: nothing is written, nothing changes.
	for case in "gate-protected|/usr/local/bin/shell-mcp-gate|answers write[0]: /etc/ssh is, or is inside, a protected path" \
		"root-never|/usr/local/libexec/shell-mcp-privd|answers root.write[0]: /etc/ssh is, or is inside, a path on the never list (PRIVILEGED §5.3 list A)" \
		"root-no-acknowledge|/usr/local/libexec/shell-mcp-privd|answers root.power.acknowledge: is required"; do
		IFS='|' read -r name path want <<<"$case"
		ex "$d" bash /src/scripts/setup-check/target.sh bad-answers "$name"
		before="$(ex "$d" bash /src/scripts/setup-check/target.sh snapshot)"
		pn "$d" "$path" policy new --answers "/root/bad-$name.yaml" --out /etc/shell-mcp/refused.yaml
		after="$(ex "$d" bash /src/scripts/setup-check/target.sh snapshot)"
		if [[ "$code" == 1 && "$before" == "$after" ]] && grep -qF -- "$want" <<<"$out"; then
			ok "$i: policy new refused: $name; nothing written"
		else
			bad "$i: policy new $name: exit $code"
			echo "$out" | grep FAIL | head -n 5 || true
		fi
	done
	ex "$d" sh -c 'echo "# an edit by hand" >>/etc/shell-mcp/admin.yaml'
	before="$(ex "$d" bash /src/scripts/setup-check/target.sh snapshot)"
	pn "$d" "${gpn[@]}" --out /etc/shell-mcp/admin.yaml
	after="$(ex "$d" bash /src/scripts/setup-check/target.sh snapshot)"
	if [[ "$code" == 1 && "$before" == "$after" ]] && grep -q '^     | -# an edit by hand' <<<"$out"; then
		ok "$i: policy new refuses a policy edited by hand, with a diff"
	else
		bad "$i: policy new over an edited policy: exit $code"
	fi
	no_temps "$d" "$i: policy new"
	docker rm -f "$t" "$c" "$h" "$p" "$q" "$x" "$d" >/dev/null
done

# --- shell-mcp init and init compose (handoff §4.C) -------------------------------
# init runs in the server image into a labelled named volume, not a host
# directory: CLAUDE.md allows no host mount but the repository, and a Windows
# host directory cannot hold uid 65532 or mode 0600. The documented host
# command (install -d -o 65532 -g 65532 -m 0700) runs as root in a
# target-image container that stands in for the host. Each form is started
# with docker compose from init compose's printed file plus a test-only
# override that changes three things only: the image (the tag built here: a
# local build has no registry digest), the run's label, and the secrets'
# source (the volume; for the bind form on the same /run/secrets target,
# which Compose merges by target; for the secrets form `secrets: !reset []`).
# Compose itself validates each printed file (docker compose config). The
# bind form from a real host directory runs on e2e-host only
# (test/e2e/zz_init_test.go).
echo "=== init and init compose"
srv="shell-mcp-setup-check:server"
docker build -q --label "$label" -t "$srv" -f Dockerfile . >/dev/null
vol="shell-mcp-setup-check-init-$run_id"
docker volume create --label "$label" "$vol" >/dev/null
hostc=(docker run --rm -i --label "$label" --network none --security-opt no-new-privileges:true -u 0:0 -v "$vol:/secrets" "shell-mcp-setup-check:${images[0]}")
hardened=(--label "$label" --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true)
initc=(docker run --rm "${hardened[@]}" -v "$vol:/secrets" "$srv")
initt=(docker run --rm -t "${hardened[@]}" -v "$vol:/secrets" "$srv")
# snap: every entry's kind, mode, owner, size, mtime and content hash, kept in
# a variable and compared, never printed.
snap() { "${hostc[@]}" sh -c 'cd /secrets && find . -printf "%p %y %m %U:%G %s %T@\n" | sort && find . -type f -exec sha256sum {} + | sort'; }
"${hostc[@]}" install -d -o 65532 -g 65532 -m 0700 /secrets
before="$(snap)"
rc=0
out="$("${initc[@]}" init --dir /secrets --approver alice 2>&1)" || rc=$?
after="$(snap)"
if [[ "$rc" == 1 && "$before" == "$after" ]] && grep -q 'shell-mcp approver add' <<<"$out" && ! grep -q 'otpauth://' <<<"$out"; then
	ok "init --approver with stdout not a terminal: refused, naming approver add, nothing written or shown"
else
	bad "init --approver off a terminal: exit $rc"
	tail -n 5 <<<"$out" || true
fi
rc=0
out="$("${initt[@]}" init --dir /secrets --approver alice --dry-run 2>&1)" || rc=$?
after="$(snap)"
if [[ "$rc" == 0 && "$before" == "$after" ]] && grep -q '<43 random characters>' <<<"$out"; then
	ok "init --dry-run in the image (65532, no network, read-only, no capabilities): nothing written"
else
	bad "init --dry-run: exit $rc"
	tail -n 5 <<<"$out" || true
fi
rc=0
"${initt[@]}" init --dir /secrets --approver alice >/dev/null 2>&1 || rc=$?
modes="$("${hostc[@]}" stat -c '%n %a %u:%g' /secrets /secrets/mcp_token /secrets/ssh_key /secrets/ssh_key.pub /secrets/approvers 2>&1 | tr '\n' ' ')" || true
want="/secrets 700 65532:65532 /secrets/mcp_token 600 65532:65532 /secrets/ssh_key 600 65532:65532 /secrets/ssh_key.pub 644 65532:65532 /secrets/approvers 600 65532:65532 "
if [[ "$rc" == 0 && "$modes" == "$want" ]]; then
	ok "init in the image after the one host command: every file 65532:65532, 0600 (.pub 0644), the directory 0700"
else
	bad "init in the image: exit $rc, $modes"
fi
before="$(snap)"
rc=0
out="$("${initc[@]}" init --dir /secrets --approver alice 2>/dev/null)" || rc=$?
after="$(snap)"
if [[ "$rc" == 0 && "$before" == "$after" ]] && grep -q 'nothing to do: every file kept' <<<"$out" && ! grep -q 'otpauth://' <<<"$out"; then
	ok "init second run with the same flags (no terminal): every file kept, no byte, mode or mtime changed"
else
	bad "init second run: exit $rc"
	tail -n 5 <<<"$out" || true
fi
[[ -z "$("${hostc[@]}" find /secrets -name '.*.shell-mcp-*')" ]] && ok "init: no temp file left" || bad "init: temp files left"
rc=0
out="$(docker run --rm "${hardened[@]}" -u 1000:1000 -v "$vol:/secrets" "$srv" init --dir /secrets 2>/dev/null)" || rc=$?
[[ "$rc" == 1 ]] && grep -q 'effective uid 1000 is neither 0 nor --uid 65532' <<<"$out" &&
	ok "init refused: an effective uid neither 0 nor --uid" || bad "init as uid 1000: exit $rc"
vol2="shell-mcp-setup-check-init-root-$run_id"
docker volume create --label "$label" "$vol2" >/dev/null
docker run --rm --label "$label" --network none --security-opt no-new-privileges:true -u 0:0 -v "$vol2:/secrets" "shell-mcp-setup-check:${images[0]}" chmod 0700 /secrets
rc=0
out="$(docker run --rm "${hardened[@]}" -v "$vol2:/secrets" "$srv" init --dir /secrets 2>/dev/null)" || rc=$?
if [[ "$rc" == 1 ]] && grep -q 'is owned by 0, not --uid 65532' <<<"$out"; then
	ok "init refused in the image: a directory owned by root"
else
	bad "init over a root-owned directory: exit $rc"
	tail -n 3 <<<"$out" || true
fi

# A target with the gate installed for init's key, on the harness network; it
# joins each form's compose network at a fixed address.
sub="10.$((200 + RANDOM % 50)).$((RANDOM % 256))"
t="$(new "${images[0]}")"
"${hostc[@]}" cat /secrets/ssh_key.pub | docker exec -i "$t" sh -c 'cat >/root/ssh_key.pub' || true
install "$t" --policy /etc/shell-mcp/read-only.yaml --principal readonly --from "$sub.10" --key /root/ssh_key.pub --uid 60123 --gid 60123 --no-reload
pin="$(sed -n 's/^SHELL_MCP_TARGET_HOST_KEYS=//p' <<<"$out")"
if [[ "$code" == 0 && -n "$pin" ]]; then ok "the target installs init's ssh_key.pub"; else
	bad "install of init's key: exit $code"
	grep FAIL <<<"$out" | head || true
fi
ex -d "$t" /usr/sbin/sshd -D -e
compose_tmp="$(mktemp -d)"
lkey="${label%%=*}"
lval="${label#*=}"
for form in secrets bind; do
	d="$compose_tmp/$form"
	mkdir -p "$d"
	dn="$(cd "$d" && { pwd -W 2>/dev/null || pwd; })"
	proj="shell-mcp-setup-check-$run_id-$form"
	cargs=(init compose --image "ghcr.io/tyler-rich/shell-mcp:0.0.0-setup-check@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		--host-key "$pin" --target-name app-host --target-host "$sub.20" --mcp-host mcp.example.test --subnet "$sub.0/24"
		--server-addr "$sub.10" --proxy-addr "$sub.5" --profile operator --approve-host approve.example.test --form "$form")
	[[ "$form" == bind ]] && cargs+=(--dir /srv/shell-mcp/secrets)
	rc=0
	docker run --rm "${hardened[@]}" "$srv" "${cargs[@]}" >"$d/docker-compose.yml" 2>"$d/notes" || rc=$?
	{
		echo "services:"
		echo "  shell-mcp:"
		echo "    image: $srv"
		echo "    labels: { \"$lkey\": \"$lval\" }"
		[[ "$form" == secrets ]] && echo "    secrets: !reset []"
		echo "    volumes:"
		echo "      - { type: volume, source: init-secrets, target: /run/secrets, read_only: true }"
		echo "networks:"
		echo "  front:"
		echo "    labels: { \"$lkey\": \"$lval\" }"
		echo "volumes:"
		echo "  init-secrets: { external: true, name: $vol }"
	} >"$d/override.yml"
	dc=(docker compose -p "$proj" --project-directory "$dn" -f "$dn/docker-compose.yml" -f "$dn/override.yml")
	if [[ "$rc" == 0 ]] && docker compose -p "$proj" --project-directory "$dn" -f "$dn/docker-compose.yml" config -q; then
		ok "init compose --form $form: Compose accepts the printed file"
	else
		bad "init compose --form $form: exit $rc, or Compose refuses it"
		cat "$d/notes" || true
		continue
	fi
	merged="$("${dc[@]}" config 2>&1)" || true
	if grep -q 'source: init-secrets' <<<"$merged" && ! grep -q '/srv/shell-mcp/secrets' <<<"$merged" && ! grep -qE 'cap_add|privileged: true' <<<"$merged"; then
		ok "$form form: the override replaces only the image, the label and the secrets' source"
	else
		bad "$form form: the merged file is not what the override should give"
	fi
	rc=0
	"${dc[@]}" up -d --wait --wait-timeout 120 >/dev/null 2>&1 || rc=$?
	if [[ "$rc" == 0 ]]; then ok "$form form: the server starts from init's files and is healthy"; else
		bad "$form form: docker compose up exit $rc"
		"${dc[@]}" logs --no-color 2>&1 | tail -n 20 || true
	fi
	docker network connect --ip "$sub.20" "${proj}_front" "$t" || true
	rc=0
	r="$("${dc[@]}" exec -T shell-mcp /shell-mcp check 2>&1)" || rc=$?
	if [[ "$rc" == 0 ]] && grep "host_key_verified" <<<"$r" | grep -qF -- "$pin"; then
		ok "$form form: shell-mcp check in the running server verifies the target with init's key"
	else
		bad "$form form: check exit $rc"
		tail -n 15 <<<"$r" || true
	fi
	docker network disconnect "${proj}_front" "$t" >/dev/null 2>&1 || true
	"${dc[@]}" down >/dev/null 2>&1 || true
done
docker rm -f "$t" >/dev/null

echo
echo "setup-check: $pass passed, $fail failed"
[[ "$fail" == 0 ]]
