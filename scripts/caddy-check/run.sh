#!/usr/bin/env bash
# caddy-check/run.sh: deploy/caddy/Caddyfile checked against the reference
# compose and by Caddy itself (handoff §4.G):
#   - drift: each site's upstream is deploy/docker-compose.yml's server
#     address with SHELL_MCP_PORT (the MCP site) or SHELL_MCP_APPROVAL_PORT
#     (the approval site), their defaults 8080 and 8081 when the compose sets
#     none; deploy/caddy/README.md names the compose's trusted proxy and
#     server addresses;
#   - the shape decided for the example (S8-4): both sites have a LAN/VPN
#     remote_ip matcher, reverse_proxy inside handle @private and respond 403
#     in a separate handle {} fallback; no trusted_proxies anywhere, so Caddy
#     replaces a client's X-Forwarded-For with the address it saw (V-4);
#   - caddy validate in the test-only image built from this directory's
#     Dockerfile, with the Caddyfile copied in, not mounted: --network none,
#     a read-only root with tmpfs for Caddy's data and config, no
#     capabilities, no-new-privileges, uid 65532; and its negative control, a
#     Caddyfile with a syntax error, which must be refused.
# No container runs Caddy as a proxy. The image and every container carry the
# run's label and are removed by it. Needs docker; used by
# scripts/ci-local.sh and CI.
set -euo pipefail
export MSYS_NO_PATHCONV=1

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/../.."
label="${SHELL_MCP_CI_LOCAL_LABEL:-shell-mcp.ci-local=caddy-check-$$-$RANDOM}"
# Everything this script creates also carries part, and its cleanup removes
# only that: under ci-local the run label is shared with the steps of the
# other lanes, whose containers must keep running (ci-local removes every
# container of the run label when the run ends).
part="shell-mcp.ci-local.part=caddy-check-$$-$RANDOM"
run_id="${label#*=}"
tag="shell-mcp-caddy-check:$(tr -c 'a-zA-Z0-9_.-' '-' <<<"$run_id" | cut -c1-100 | sed 's/-*$//')"
caddyfile="deploy/caddy/Caddyfile"
readme="deploy/caddy/README.md"
compose="deploy/docker-compose.yml"
ctx="$(mktemp -d)"
cleanup() {
	local ids
	ids="$(docker ps -aq --filter "label=$part" 2>/dev/null || true)"
	if [[ -n "$ids" ]]; then
		# shellcheck disable=SC2086 # one container id per word
		docker rm -f $ids >/dev/null 2>&1 || true
	fi
	docker image rm -f "$tag" >/dev/null 2>&1 || true
	rm -rf "$ctx"
}
trap cleanup EXIT

pass=0
fail=0
ok() { echo "ok   $*"; pass=$((pass + 1)); }
bad() { echo "FAIL $*"; fail=$((fail + 1)); }

# --- Drift against the reference compose -------------------------------------------
server="$(sed -n 's/^ *ipv4_address: *\([0-9.]*\).*/\1/p' "$compose" | head -n1)"
proxy="$(sed -n 's/^ *SHELL_MCP_TRUSTED_PROXIES: *"\{0,1\}\([0-9.]*\).*/\1/p' "$compose" | head -n1)"
port="$(sed -n 's/^ *SHELL_MCP_PORT: *"\{0,1\}\([0-9]*\).*/\1/p' "$compose" | head -n1)"
aport="$(sed -n 's/^ *SHELL_MCP_APPROVAL_PORT: *"\{0,1\}\([0-9]*\).*/\1/p' "$compose" | head -n1)"
port="${port:-8080}" aport="${aport:-8081}"
if [[ -z "$server" || -z "$proxy" ]]; then
	bad "the server address or SHELL_MCP_TRUSTED_PROXIES not found in $compose"
fi

# site <name>: the lines of that site's block, comments removed.
site() { awk -v s="$1" '/^[[:space:]]*#/ { next } $1 == s && $2 == "{" { on = 1; next } on && /^}/ { exit } on { print }' "$caddyfile"; }
for s in "mcp.example.test $port" "approve.example.test $aport"; do
	name="${s% *}" p="${s#* }"
	block="$(site "$name")"
	if [[ -z "$block" ]]; then
		bad "$name: no site block in $caddyfile"
		continue
	fi
	ups="$(sed -n 's/^[[:space:]]*reverse_proxy[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' <<<"$block")"
	[[ "$ups" == "$server:$p" ]] && ok "$name: reverse_proxy $ups is the compose's server and port" ||
		bad "$name: reverse_proxy '${ups//$'\n'/ }', want $server:$p (the compose's server address and port)"
	shape="$(awk '
		/^[[:space:]]*@private[[:space:]]+remote_ip([[:space:]]+[0-9a-fA-F.:\/]+)+[[:space:]]*$/ { m = NR }
		/^[[:space:]]*handle[[:space:]]+@private[[:space:]]*\{[[:space:]]*$/ { hp = NR }
		/^[[:space:]]*reverse_proxy[[:space:]]/ { rp = NR }
		/^[[:space:]]*handle[[:space:]]*\{[[:space:]]*$/ { h = NR }
		/^[[:space:]]*respond[[:space:]]+403[[:space:]]*$/ { r = NR }
		END { print (m && hp && rp && h && r && m < hp && hp < rp && rp < h && h < r) ? "ok" : "bad" }' <<<"$block")"
	[[ "$shape" == ok ]] && ok "$name: remote_ip matcher, reverse_proxy in handle @private, respond 403 in handle {}" ||
		bad "$name: not the shape @private remote_ip …, handle @private { reverse_proxy … }, handle { respond 403 }"
done
if grep -v '^[[:space:]]*#' "$caddyfile" | grep -q 'trusted_proxies'; then
	bad "$caddyfile sets trusted_proxies: Caddy would keep a client's X-Forwarded-For"
else
	ok "no trusted_proxies: Caddy replaces a client's X-Forwarded-For with the address it saw"
fi
# --- The LAN/VPN ranges: explicit, and none that holds a Docker network -------------
# A tunnel's connector (Cloudflare Tunnel, ngrok, Tailscale Funnel, …) in a
# container connects from a Docker network's address, so a matcher that
# admits such a network (private_ranges, 172.16.0.0/12, the compose's own
# subnet) admits whatever the tunnel carries.
subnet="$(sed -n 's/^ *- subnet: *\([0-9.\/]*\).*/\1/p' "$compose" | head -n1)"
gateway="${subnet%.*/*}.1"
ip4() { # ip4 <a.b.c.d>: the address as a number
	local IFS=. a b c d
	read -r a b c d <<<"$1"
	echo $(((a << 24) | (b << 16) | (c << 8) | d))
}
holds() { # holds <cidr> <address>: the prefix holds the address
	local net="${1%/*}" len="${1#*/}" mask
	[[ "$1" == */* ]] || len=32
	mask=$(((0xffffffff << (32 - len)) & 0xffffffff))
	(($(($(ip4 "$net") & mask)) == $(($(ip4 "$2") & mask))))
}
ranges() { # ranges <Caddyfile>: "bad …" for each matcher range outside the rule
	local r b
	while read -r r; do
		if [[ ! "$r" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
			echo "bad remote_ip $r is not an explicit IPv4 range"
			continue
		fi
		for b in "$gateway" "$server" "$proxy" 172.17.0.1 172.18.0.1 10.0.0.1 192.168.0.1; do
			if holds "$r" "$b"; then
				echo "bad remote_ip $r holds $b (a Docker network or the compose's own subnet)"
				break
			fi
		done
	done < <(grep -v '^[[:space:]]*#' "$1" | sed -n 's/^[[:space:]]*@private[[:space:]]\{1,\}remote_ip[[:space:]]\{1,\}//p' | tr -s ' \t' '\n\n')
}
out="$(ranges "$caddyfile")"
[[ -z "$out" ]] && ok "the @private ranges are explicit and hold no Docker network" || bad "${out//$'\n'/; }"
for neg in "private_ranges" "172.16.0.0/12" "$subnet"; do
	f="$(mktemp)"
	sed "0,/@private remote_ip 192.0.2.0\/24/s//@private remote_ip ${neg//\//\\/}/" "$caddyfile" >"$f"
	[[ -n "$(ranges "$f")" ]] && ok "refused: remote_ip $neg" || bad "not refused: remote_ip $neg"
	rm -f "$f"
done
grep -B3 '^[[:space:]]*@private' "$caddyfile" | grep -q 'tunnel' && ok "$caddyfile comments on tunnels beside the matcher" ||
	bad "$caddyfile has no comment on tunnels beside the @private matcher"

for a in "$proxy" "$server"; do
	grep -qF -- "\`$a\`" "$readme" && ok "$readme names $a, as the compose does" || bad "$readme does not name $a (the compose's address)"
done
for want in "SHELL_MCP_TRUSTED_PROXIES" "gateway" "X-Forwarded-For" "restart" "authentication failed" "tunnel" "installed on the host" "nginx.conf"; do
	grep -qF -- "$want" "$readme" && ok "$readme covers $want" || bad "$readme does not cover $want"
done

# --- caddy validate ---------------------------------------------------------------------
validate() { # validate <Caddyfile>: build the test image with it, then validate
	cp "$here/Dockerfile" "$ctx/Dockerfile"
	cp "$1" "$ctx/Caddyfile"
	docker build -q --label "$label" --label "$part" -t "$tag" "$(cd "$ctx" && { pwd -W 2>/dev/null || pwd; })" >/dev/null || return 3
	docker run --rm --label "$label" --label "$part" --network none --read-only --tmpfs /data --tmpfs /config \
		--cap-drop ALL --security-opt no-new-privileges:true --user 65532:65532 \
		"$tag" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
}
out="$(validate "$caddyfile" 2>&1)" && rc=0 || rc=$?
if [[ "$rc" == 0 ]] && grep -q 'Valid configuration' <<<"$out"; then
	ok "caddy validate: valid (no network, read-only, no capabilities, uid 65532)"
else
	bad "caddy validate: exit $rc"
	tail -n 10 <<<"$out" || true
fi
broken="$(mktemp)"
{ cat "$caddyfile"; printf 'mcp.example.test {\n\treverse_proxy\n'; } >"$broken"
out="$(validate "$broken" 2>&1)" && rc=0 || rc=$?
rm -f "$broken"
[[ "$rc" != 0 && "$rc" != 3 ]] && ok "caddy validate refuses a Caddyfile with a syntax error (exit $rc)" || bad "caddy validate of a broken Caddyfile: exit $rc"

echo
echo "caddy-check: $pass passed, $fail failed"
[[ "$fail" == 0 ]]
