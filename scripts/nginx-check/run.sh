#!/usr/bin/env bash
# nginx-check/run.sh: deploy/caddy/nginx.conf checked against the reference
# compose and by nginx itself, as caddy-check checks the Caddyfile:
#   - drift: each server block's proxy_pass is deploy/docker-compose.yml's
#     server address with SHELL_MCP_PORT (the MCP site) or
#     SHELL_MCP_APPROVAL_PORT (the approval site), their defaults 8080 and
#     8081 when the compose sets none;
#   - the shape every proxy needs (deploy/caddy/README.md): both sites allow
#     explicit LAN/VPN ranges and end with deny all; no allowed range holds
#     the compose's subnet (its gateway, the server or the proxy), a Docker
#     default network or all of IPv4; Host $host and X-Forwarded-For
#     $remote_addr; proxy_http_version 1.1, proxy_buffering off,
#     proxy_read_timeout of at least the server's default
#     SHELL_MCP_MAX_TIMEOUT (300 s) on the MCP site, client_max_body_size of
#     at least 2m; its negative controls, configurations that break one rule
#     each, which must be refused;
#   - nginx -t in the test-only image built from this directory's Dockerfile,
#     with the configuration copied in, not mounted: --network none, a
#     read-only root with a tmpfs /tmp, no capabilities, no-new-privileges,
#     uid 65532; and its negative control, a syntax error, which must be
#     refused.
# No container runs nginx as a proxy. The image and every container carry the
# run's label and are removed by it. Needs docker; used by
# scripts/ci-local.sh and CI.
set -euo pipefail
export MSYS_NO_PATHCONV=1

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/../.."
label="${SHELL_MCP_CI_LOCAL_LABEL:-shell-mcp.ci-local=nginx-check-$$-$RANDOM}"
# Everything this script creates also carries part, and its cleanup removes
# only that (as in caddy-check: the run label is shared with other lanes).
part="shell-mcp.ci-local.part=nginx-check-$$-$RANDOM"
run_id="${label#*=}"
tag="shell-mcp-nginx-check:$(tr -c 'a-zA-Z0-9_.-' '-' <<<"$run_id" | cut -c1-100 | sed 's/-*$//')"
conf="deploy/caddy/nginx.conf"
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

# --- The reference compose --------------------------------------------------------
server="$(sed -n 's/^ *ipv4_address: *\([0-9.]*\).*/\1/p' "$compose" | head -n1)"
proxy="$(sed -n 's/^ *SHELL_MCP_TRUSTED_PROXIES: *"\{0,1\}\([0-9.]*\).*/\1/p' "$compose" | head -n1)"
subnet="$(sed -n 's/^ *- subnet: *\([0-9.\/]*\).*/\1/p' "$compose" | head -n1)"
port="$(sed -n 's/^ *SHELL_MCP_PORT: *"\{0,1\}\([0-9]*\).*/\1/p' "$compose" | head -n1)"
aport="$(sed -n 's/^ *SHELL_MCP_APPROVAL_PORT: *"\{0,1\}\([0-9]*\).*/\1/p' "$compose" | head -n1)"
port="${port:-8080}" aport="${aport:-8081}"
if [[ -z "$server" || -z "$proxy" || -z "$subnet" ]]; then
	bad "the server address, SHELL_MCP_TRUSTED_PROXIES or the subnet not found in $compose"
fi
gateway="${subnet%.*/*}.1"

# ip4 <a.b.c.d>: the address as a number.
ip4() {
	local IFS=. a b c d
	read -r a b c d <<<"$1"
	echo $(((a << 24) | (b << 16) | (c << 8) | d))
}
# holds <cidr> <address>: the prefix holds the address.
holds() {
	local net="${1%/*}" len="${1#*/}" mask
	[[ "$1" == */* ]] || len=32
	mask=$(((0xffffffff << (32 - len)) & 0xffffffff))
	(($(($(ip4 "$net") & mask)) == $(($(ip4 "$2") & mask))))
}

# site <file> <name>: the lines of that server block, comments removed.
site() {
	awk -v s="$2" '
		{ sub(/#.*/, "") }
		/^[[:space:]]*server[[:space:]]*\{/ { blk = ""; on = 1; depth = 0 }
		on { blk = blk $0 "\n"; n = gsub(/\{/, "{"); m = gsub(/\}/, "}"); depth += n - m
			if (depth == 0 && n + m > 0) { if (blk ~ ("server_name[[:space:]]+" s ";")) { printf "%s", blk; exit } on = 0 } }' "$1"
}
# directive <block> <name>: the arguments of each such directive, one per line.
directive() { sed -n "s/^[[:space:]]*$2[[:space:]]\{1,\}\(.*\);[[:space:]]*\$/\1/p" <<<"$1"; }

# rules <file>: every rule of the shape, as ok/bad lines on stdout.
rules() {
	local f="$1" name p block ups allows a seen t b
	for s in "mcp.example.test $port 300" "approve.example.test $aport 0"; do
		read -r name p t <<<"$s"
		block="$(site "$f" "$name")"
		if [[ -z "$block" ]]; then
			echo "bad $name: no server block"
			continue
		fi
		ups="$(directive "$block" proxy_pass)"
		[[ "$ups" == "http://$server:$p" ]] && echo "ok $name: proxy_pass $ups is the compose's server and port" ||
			echo "bad $name: proxy_pass '${ups//$'\n'/ }', want http://$server:$p"
		allows="$(directive "$block" allow)"
		seen=0
		while read -r a; do
			[[ -z "$a" ]] && continue
			seen=1
			if [[ "$a" == all || "$a" == *:* || ! "$a" =~ ^[0-9.]+(/[0-9]+)?$ ]]; then
				echo "bad $name: allow $a is not an explicit IPv4 range"
				continue
			fi
			for b in "$gateway" "$server" "$proxy" 172.17.0.1 172.18.0.1 10.0.0.1 192.168.0.1; do
				if holds "$a" "$b"; then
					echo "bad $name: allow $a holds $b (a Docker network or the compose's own subnet, where a tunnel's connector could sit)"
					continue 2
				fi
			done
		done <<<"$allows"
		((seen)) && echo "ok $name: explicit LAN/VPN ranges only" || echo "bad $name: no allow range"
		[[ "$(grep -c '^[[:space:]]*deny all;' <<<"$block")" == 1 ]] && echo "ok $name: deny all" || echo "bad $name: no deny all"
		grep -qE '^[[:space:]]*proxy_set_header[[:space:]]+Host[[:space:]]+\$host;' <<<"$block" &&
			echo "ok $name: Host \$host" || echo "bad $name: proxy_set_header Host \$host missing"
		grep -qE '^[[:space:]]*proxy_set_header[[:space:]]+X-Forwarded-For[[:space:]]+\$remote_addr;' <<<"$block" &&
			echo "ok $name: X-Forwarded-For \$remote_addr" || echo "bad $name: proxy_set_header X-Forwarded-For \$remote_addr missing"
		[[ "$(directive "$block" proxy_http_version)" == 1.1 ]] && echo "ok $name: proxy_http_version 1.1" || echo "bad $name: proxy_http_version is not 1.1"
		[[ "$(directive "$block" proxy_buffering)" == off ]] && echo "ok $name: proxy_buffering off" || echo "bad $name: proxy_buffering is not off"
		b="$(directive "$block" client_max_body_size)"
		[[ "$b" =~ ^([0-9]+)[mM]$ ]] && ((BASH_REMATCH[1] >= 2)) && echo "ok $name: client_max_body_size $b" || echo "bad $name: client_max_body_size '$b', want at least 2m"
		if ((t > 0)); then
			b="$(directive "$block" proxy_read_timeout)"
			[[ "$b" =~ ^([0-9]+)s$ ]] && ((BASH_REMATCH[1] >= t)) && echo "ok $name: proxy_read_timeout $b" ||
				echo "bad $name: proxy_read_timeout '$b', want at least ${t}s (SHELL_MCP_MAX_TIMEOUT's default)"
		fi
	done
}

# --- The example ----------------------------------------------------------------------
while read -r verdict msg; do
	[[ "$verdict" == ok ]] && ok "$msg" || bad "$msg"
done < <(rules "$conf")
for want in "tunnel" "on the host" "SHELL_MCP_TRUSTED_PROXIES"; do
	grep -qF -- "$want" "$conf" && ok "$conf comments on $want" || bad "$conf does not comment on $want"
done

# --- Negative controls: each breaks one rule and must be refused ------------------------
neg() { # neg <what> <sed expression>
	local f
	f="$(mktemp)"
	sed "$2" "$conf" >"$f"
	if grep -q "^bad " <<<"$(rules "$f")"; then ok "refused: $1"; else bad "not refused: $1"; fi
	rm -f "$f"
}
neg "a Docker range allowed" '0,/allow 192.0.2.0\/24;/s//allow 172.16.0.0\/12;/'
neg "the compose's subnet allowed" "0,/allow 198.51.100.0\/24;/s//allow ${subnet//\//\\/};/"
neg "allow all" '0,/allow 192.0.2.0\/24;/s//allow all;/'
neg "no deny all" '0,/deny all;/s///'
neg "a client's X-Forwarded-For kept" '0,/X-Forwarded-For \$remote_addr/s//X-Forwarded-For $proxy_add_x_forwarded_for/'
neg "Host not passed" '0,/proxy_set_header Host \$host;/s///'
neg "buffering on" '0,/proxy_buffering off;/s//proxy_buffering on;/'
neg "a short read timeout" 's/proxy_read_timeout 330s;/proxy_read_timeout 60s;/'
neg "a small body limit" '0,/client_max_body_size 2m;/s//client_max_body_size 1m;/'
neg "another upstream" "0,/proxy_pass http:\/\/$server:$port;/s//proxy_pass http:\/\/$gateway:$port;/"

# --- nginx -t ---------------------------------------------------------------------------
check() { # check <conf>: build the test image with it, then nginx -t
	cp "$here/Dockerfile" "$here/nginx-test.conf" "$ctx/"
	cp "$1" "$ctx/nginx.conf"
	docker build -q --label "$label" --label "$part" -t "$tag" "$(cd "$ctx" && { pwd -W 2>/dev/null || pwd; })" >/dev/null || return 3
	docker run --rm --label "$label" --label "$part" --network none --read-only --tmpfs /tmp \
		--cap-drop ALL --security-opt no-new-privileges:true --user 65532:65532 --entrypoint nginx \
		"$tag" -t -e stderr -c /etc/nginx/nginx-test.conf
}
out="$(check "$conf" 2>&1)" && rc=0 || rc=$?
if [[ "$rc" == 0 ]] && grep -q 'test is successful' <<<"$out"; then
	ok "nginx -t: successful (no network, read-only, no capabilities, uid 65532)"
else
	bad "nginx -t: exit $rc"
	tail -n 10 <<<"$out" || true
fi
broken="$(mktemp)"
sed '0,/client_max_body_size 2m;/s//client_max_body_size 2m/' "$conf" >"$broken"
out="$(check "$broken" 2>&1)" && rc=0 || rc=$?
rm -f "$broken"
[[ "$rc" != 0 && "$rc" != 3 ]] && ok "nginx -t refuses a configuration with a syntax error (exit $rc)" || bad "nginx -t of a broken configuration: exit $rc"

echo
echo "nginx-check: $pass passed, $fail failed"
[[ "$fail" == 0 ]]
