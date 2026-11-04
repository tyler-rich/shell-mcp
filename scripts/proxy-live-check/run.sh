#!/usr/bin/env bash
# proxy-live-check/run.sh: the example proxies run live in front of a running
# server (deploy/caddy/README.md, properties 1-4, and "Check it once").
#
# The server is the image built from this commit's Dockerfile, started with
# docker compose from init compose's printed file (the secrets form, profile
# operator with the approval page), with init's secrets in a labelled volume
# and a test-only override that changes the image, the labels, the secrets'
# source, and adds the test CA and the two names' addresses (for doctor).
# In front of it, once with deploy/caddy/Caddyfile and once with
# deploy/caddy/nginx.conf, each in the test-only image its static check
# builds (scripts/caddy-check/Dockerfile, scripts/nginx-check/Dockerfile),
# a proxy container joins the server's network at the fixed proxy address.
# The example files change only in their placeholders: the compose's
# addresses (172.30.80.0/24), the allowed ranges, the certificate paths (and,
# for Caddy, which has none, one tls line per site naming the test
# certificate); the script undoes exactly those and asserts the result is
# byte-identical to the example. The certificates come from a CA made here.
#
# The clients sit on a separate --internal network that reaches only the
# proxy. Asserted, for each proxy:
#   (a) a request with the token reaches the MCP endpoint; one without, 401;
#   (b) the server's authentication failed line names the client container's
#       own address, not the proxy's or the gateway's;
#   (c) a client's forged X-Forwarded-For does not change that address;
#   (d) the approval page answers through its own name; the server's
#       approval listener refuses another Host with 421 (asked from the
#       proxy's own network namespace, its only trusted peer);
#   (e) a client outside the allowed ranges gets 403 from the proxy, and the
#       server sees nothing of it;
#   (f) doctor --mcp-url in the server container, with the test CA: the
#       trusted proxy, approval page and MCP endpoint rows ok.
# Negative controls, each of which must be caught:
#   - a proxy that passes a client's X-Forwarded-For through: (c) fails;
#     a proxy that appends instead still passes, because the server reads
#     only the last entry, the one the proxy added (internal/transport);
#   - a gateway-sourced proxy (its upstream a port the server publishes, so
#     the server's peer is the network's gateway, as for a proxy installed
#     on the host): (b) fails;
#   - SHELL_MCP_TRUSTED_PROXIES set to the gateway: doctor's trusted proxy
#     row is a FAIL.
# A proxy on the host network is not run: CLAUDE.md allows no
# --network=host, and the gateway-sourced case is what such a proxy looks
# like to the server.
#
# Every container runs unprivileged with no-new-privileges, the proxies and
# clients as uid 65532 with no capabilities and a read-only root; no host
# mount at all. Every container, network, volume and image carries the run's
# label and is removed by it, on success and failure. Needs docker; used by
# scripts/ci-local.sh and CI.
set -euo pipefail
export MSYS_NO_PATHCONV=1

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/../.."
label="${SHELL_MCP_CI_LOCAL_LABEL:-shell-mcp.ci-local=proxy-live-check-$$-$RANDOM}"
# Everything this script creates also carries part, and its cleanup removes
# only that (as in setup-check: the run label is shared with other lanes).
part="shell-mcp.ci-local.part=proxy-live-check-$$-$RANDOM"
run_id="${label#*=}"
slug="$(tr -c 'a-zA-Z0-9_.-' '-' <<<"$run_id" | cut -c1-60 | sed 's/-*$//')"
srv="shell-mcp-proxy-live-check:server-$slug"
caddy_tag="shell-mcp-proxy-live-check:caddy-$slug"
nginx_tag="shell-mcp-proxy-live-check:nginx-$slug"
# The client and the certificate maker: nginx-check's pinned base image
# (curl and openssl are in it), read from its Dockerfile, so no new pin.
client_image="$(awk 'toupper($1) == "FROM" { print $2; exit }' scripts/nginx-check/Dockerfile)"
if [[ "$client_image" != nginx:*@sha256:* ]]; then
	echo "proxy-live-check: scripts/nginx-check/Dockerfile's base image is not pinned by digest" >&2
	exit 1
fi
tmp="$(mktemp -d)"
proj="shell-mcp-proxy-live-check-$slug"
dc=()
cleanup() {
	if [[ ${#dc[@]} -gt 0 ]]; then "${dc[@]}" down >/dev/null 2>&1 || true; fi
	local ids n
	ids="$(docker ps -aq --filter "label=$part" 2>/dev/null || true)"
	if [[ -n "$ids" ]]; then
		# shellcheck disable=SC2086 # one container id per word
		docker rm -f $ids >/dev/null 2>&1 || true
	fi
	for n in $(docker network ls -q --filter "label=$part" 2>/dev/null || true); do
		docker network rm "$n" >/dev/null 2>&1 || true
	done
	for n in $(docker volume ls -q --filter "label=$part" 2>/dev/null || true); do
		docker volume rm "$n" >/dev/null 2>&1 || true
	done
	docker image rm -f "$srv" "$caddy_tag" "$nginx_tag" >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT

pass=0
fail=0
ok() { echo "ok   $*"; pass=$((pass + 1)); }
bad() { echo "FAIL $*"; fail=$((fail + 1)); }
native() { (cd "$1" && { pwd -W 2>/dev/null || pwd; }); }
t_start=$SECONDS

# The server's network (S) and the clients' (C): random, outside the
# 10.200-249 range setup-check uses. A is a client inside the allowed range,
# B one outside it.
S="10.$((150 + RANDOM % 50)).$((RANDOM % 256))"
C="10.$((150 + RANDOM % 50)).$((RANDOM % 256))"
while [[ "$C" == "$S" ]]; do C="10.$((150 + RANDOM % 50)).$((RANDOM % 256))"; done
A="$C.20"
B="$C.40"
allowed="$C.16/28"
desktop=""
[[ "$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)" == "Docker Desktop" ]] && desktop=1

hard=(--label "$label" --label "$part" --read-only --cap-drop ALL --security-opt no-new-privileges:true)

# --- The server image, init's secrets, the test certificates --------------------------
docker build -q --label "$label" --label "$part" -t "$srv" -f Dockerfile . >/dev/null
vol="shell-mcp-proxy-live-check-secrets-$slug"
tls="shell-mcp-proxy-live-check-tls-$slug"
docker volume create --label "$label" --label "$part" "$vol" >/dev/null
docker volume create --label "$label" --label "$part" "$tls" >/dev/null
# The documented host command (install -d -o 65532 -g 65532 -m 0700), as root
# in a container standing in for the host, then init in the image.
docker run --rm --label "$label" --label "$part" --network none --security-opt no-new-privileges:true -u 0:0 -v "$vol:/secrets" \
	--entrypoint install "$client_image" -d -o 65532 -g 65532 -m 0700 /secrets
docker run --rm -t "${hard[@]}" --network none -v "$vol:/secrets" "$srv" init --dir /secrets --approver alice >/dev/null 2>&1 ||
	{ echo "proxy-live-check: init in the image failed" >&2; exit 1; }
# A test CA and a certificate for each name, made here, used for nothing else;
# the CA's key is removed before any proxy starts.
docker run --rm "${hard[@]}" --network none -u 0:0 -v "$tls:/tls" --entrypoint sh "$client_image" -c '
	set -eu
	cd /tls
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=proxy-live-check test CA" \
		-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -keyout ca.key -out ca.crt 2>/dev/null
	for n in mcp.example.test approve.example.test; do
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$n" -keyout "$n.key" -out "$n.csr" 2>/dev/null
		printf "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n" "$n" >"$n.ext"
		openssl x509 -req -in "$n.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -extfile "$n.ext" -out "$n.crt" 2>/dev/null
		rm -f "$n.csr" "$n.ext"
	done
	rm -f ca.key ca.srl
	chmod 0644 ./*'
[[ "$(docker run --rm "${hard[@]}" --network none -v "$tls:/tls:ro" --entrypoint ls "$client_image" /tls | tr '\n' ' ')" == \
	"approve.example.test.crt approve.example.test.key ca.crt mcp.example.test.crt mcp.example.test.key " ]] &&
	ok "test CA and certificates for mcp.example.test and approve.example.test made; the CA's key removed" ||
	bad "the test certificates were not made as expected"

# --- The server, from init compose's printed file ------------------------------------
pin="ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
d="$tmp/compose"
mkdir -p "$d"
dn="$(native "$d")"
rc=0
docker run --rm "${hard[@]}" --network none "$srv" init compose \
	--image "ghcr.io/tyler-rich/shell-mcp:0.0.0-proxy-live-check@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
	--host-key "$pin" --target-name app-host --target-host "$S.20" --mcp-host mcp.example.test --subnet "$S.0/24" \
	--server-addr "$S.10" --proxy-addr "$S.5" --profile operator --approve-host approve.example.test --form secrets \
	>"$d/docker-compose.yml" 2>"$d/notes" || rc=$?
lkey="${label%%=*}" lval="${label#*=}" pkey="${part%%=*}" pval="${part#*=}"
# The test-only override: the image built here, the labels, init's volume in
# place of the secrets entries (as setup-check), and, for doctor, the test CA
# and the two names at the proxy's address.
cat >"$d/override.yml" <<EOF
services:
  shell-mcp:
    image: $srv
    labels: { "$lkey": "$lval", "$pkey": "$pval" }
    secrets: !reset []
    volumes:
      - { type: volume, source: init-secrets, target: /run/secrets, read_only: true }
      - { type: volume, source: test-ca, target: /run/test-ca, read_only: true }
    extra_hosts: ["mcp.example.test:$S.5", "approve.example.test:$S.5"]
networks:
  front:
    labels: { "$lkey": "$lval", "$pkey": "$pval" }
volumes:
  init-secrets: { external: true, name: $vol }
  test-ca: { external: true, name: $tls }
EOF
dc=(docker compose -p "$proj" --project-directory "$dn" -f "$dn/docker-compose.yml" -f "$dn/override.yml")
if [[ "$rc" == 0 ]] && grep -q "SHELL_MCP_TRUSTED_PROXIES: $S.5" "$d/docker-compose.yml" && grep -q 'SHELL_MCP_APPROVAL_METHOD: web' "$d/docker-compose.yml"; then
	ok "init compose --form secrets --profile operator --approve-host: the server's file, trusting only $S.5"
else
	bad "init compose: exit $rc"
	cat "$d/notes" || true
fi
# up <extra override file|""> <what>: (re)create the server and wait for it.
up() {
	local extra=() rc=0
	[[ -n "$1" ]] && extra=(-f "$dn/$1")
	"${dc[@]}" "${extra[@]}" up -d --wait --wait-timeout 120 >/dev/null 2>&1 || rc=$?
	sid="$("${dc[@]}" "${extra[@]}" ps -q shell-mcp 2>/dev/null || true)"
	if [[ "$rc" == 0 && -n "$sid" ]]; then ok "$2: the server is up and healthy"; else
		bad "$2: docker compose up exit $rc"
		"${dc[@]}" logs --no-color 2>&1 | tail -n 20 || true
		return 1
	fi
}
up "" "init compose's file" || exit 1
front="${proj}_front"
cnet="shell-mcp-proxy-live-check-clients-$slug"
docker network create --internal --label "$label" --label "$part" --subnet "$C.0/24" "$cnet" >/dev/null

# --- The clients ---------------------------------------------------------------------
# A in the allowed range, with the token (init's volume, read as 65532); B
# outside it. Both reach the proxy only: the --internal network holds just
# them and the proxy's second address.
client() { # client <ip> [extra docker args…]
	local ip="$1"
	shift
	docker run -d "${hard[@]}" -u 65532:65532 --network "$cnet" --ip "$ip" -v "$tls:/ca:ro" "$@" --entrypoint sleep "$client_image" infinity
}
ca="$(client "$A" -v "$vol:/secrets:ro")"
cb="$(client "$B")"
# cl <container> <curl args…>: curl from a client to the proxy's address.
cl() {
	local c="$1"
	shift
	docker exec "$c" curl -s --max-time 10 --cacert /ca/ca.crt --resolve "mcp.example.test:443:$C.5" --resolve "approve.example.test:443:$C.5" "$@"
}

# --- The example files, with only their placeholders replaced -----------------------
# subst <in> <out> <kind> [<upstream>]: the compose's addresses, the allowed
# ranges and the certificate paths; for Caddy one tls line per site. With
# <upstream> (host:port), the MCP site's upstream is that instead (the
# gateway-sourced control).
subst() {
	local in="$1" out="$2" kind="$3" up="${4:-}" c s
	c="$(cat "$in")"
	for s in "$S." "$C." "$allowed" "/etc/proxy-tls/"; do
		if [[ "$c" == *"$s"* ]]; then
			echo "proxy-live-check: $in already holds $s; the substitution would not be reversible" >&2
			return 1
		fi
	done
	c="${c//198.51.100.0\/24/$S.10\/32}"
	c="${c//192.0.2.0\/24/$allowed}"
	c="${c//172.30.80./$S.}"
	if [[ "$kind" == nginx ]]; then
		c="${c//\/etc\/nginx\/tls\//\/etc\/proxy-tls\/}"
	fi
	printf '%s\n' "$c" >"$out"
	if [[ "$kind" == caddy ]]; then
		awk '{ print } /^(mcp|approve)\.example\.test \{$/ { n = $1; printf "\ttls /etc/proxy-tls/%s.crt /etc/proxy-tls/%s.key\n", n, n }' "$out" >"$out.t" && mv "$out.t" "$out"
	fi
	if [[ -n "$up" ]]; then
		if [[ "$kind" == caddy ]]; then
			sed -i "0,/reverse_proxy $S.10:8080/s//reverse_proxy $up/" "$out"
		else
			sed -i "0,/proxy_pass http:\/\/$S.10:8080;/s//proxy_pass http:\/\/$up;/" "$out"
		fi
	fi
}
# unsubst <file> <kind>: subst undone; must be byte-identical to the example.
unsubst() {
	local c
	c="$(grep -vxE $'\ttls /etc/proxy-tls/[a-z.]+\\.crt /etc/proxy-tls/[a-z.]+\\.key' "$1")"
	c="${c//$S.10\/32/198.51.100.0\/24}"
	c="${c//$allowed/192.0.2.0\/24}"
	c="${c//$S./172.30.80.}"
	[[ "$2" == nginx ]] && c="${c//\/etc\/proxy-tls\//\/etc\/nginx\/tls\/}"
	printf '%s\n' "$c"
}

# --- The proxy -----------------------------------------------------------------------
# proxy <kind> <config file> [extra docker run args…]: build the test image
# of its static check with that file and run it on the server's network at
# the proxy address, then on the clients' network; wait until it answers.
pxy=""
proxy() {
	local kind="$1" conf="$2" ctx="$tmp/ctx-$1" tag i
	shift 2
	[[ -n "$pxy" ]] && docker rm -f "$pxy" >/dev/null 2>&1
	pxy=""
	rm -rf "$ctx"
	mkdir -p "$ctx"
	if [[ "$kind" == caddy ]]; then
		tag="$caddy_tag"
		cp scripts/caddy-check/Dockerfile "$ctx/"
		cp "$conf" "$ctx/Caddyfile"
		docker build -q --label "$label" --label "$part" -t "$tag" "$(native "$ctx")" >/dev/null || return 1
		pxy="$(docker run -d "${hard[@]}" -u 65532:65532 --network "$front" --ip "$S.5" \
			--tmpfs /data:uid=65532,gid=65532 --tmpfs /config:uid=65532,gid=65532 -v "$tls:/etc/proxy-tls:ro" "$@" \
			"$tag" caddy run --config /etc/caddy/Caddyfile --adapter caddyfile)"
	else
		tag="$nginx_tag"
		cp scripts/nginx-check/Dockerfile scripts/nginx-check/nginx-test.conf "$ctx/"
		cp "$conf" "$ctx/nginx.conf"
		docker build -q --label "$label" --label "$part" -t "$tag" "$(native "$ctx")" >/dev/null || return 1
		pxy="$(docker run -d "${hard[@]}" -u 65532:65532 --network "$front" --ip "$S.5" \
			--tmpfs /tmp:uid=65532,gid=65532 -v "$tls:/etc/proxy-tls:ro" "$@" \
			--entrypoint nginx "$tag" -g 'daemon off;' -c /etc/nginx/nginx-test.conf)"
	fi
	docker network connect --ip "$C.5" "$cnet" "$pxy"
	for i in $(seq 1 40); do
		[[ "$(cl "$ca" -o /dev/null -w '%{http_code}' https://approve.example.test/ 2>/dev/null || true)" =~ ^[1-5][0-9][0-9]$ ]] && return 0
		sleep 0.5
	done
	echo "proxy-live-check: the $kind proxy did not answer" >&2
	docker logs "$pxy" 2>&1 | tail -n 15 >&2 || true
	return 1
}

# --- The assertions --------------------------------------------------------------------
# authlog <client container> [curl args…]: send one POST /mcp without a token
# and print the client field of the server's authentication failed line it
# caused (empty if none came).
authlog() {
	local c="$1" n0 n i
	shift
	n0="$(docker logs "$sid" 2>&1 | grep -c '"msg":"authentication failed"' || true)"
	cl "$c" -o /dev/null -X POST "$@" https://mcp.example.test/mcp || true
	for i in $(seq 1 20); do
		n="$(docker logs "$sid" 2>&1 | grep -c '"msg":"authentication failed"' || true)"
		((n > n0)) && break
		sleep 0.25
	done
	docker logs "$sid" 2>&1 | grep '"msg":"authentication failed"' | tail -n +"$((n0 + 1))" | head -n1 | sed -n 's/.*"client":"\([^"]*\)".*/\1/p'
}
# check_b <what>: (b) the server logs client A's own address.
check_b() {
	local got
	got="$(authlog "$ca")"
	if [[ "$got" == "$A/32" ]]; then ok "$1: (b) the server logged the client's own address $got, not the proxy's ($S.5) or the gateway's ($S.1)"; else
		bad "$1: (b) the server logged '$got', not the client's address $A/32"
		return 1
	fi
}
# check_c <what>: (c) a forged X-Forwarded-For changes nothing.
check_c() {
	local got
	got="$(authlog "$ca" -H 'X-Forwarded-For: 203.0.113.99')"
	if [[ "$got" == "$A/32" ]]; then ok "$1: (c) with a forged X-Forwarded-For: 203.0.113.99 the server still logged $got"; else
		bad "$1: (c) with a forged X-Forwarded-For the server logged '$got', not $A/32"
		return 1
	fi
}
# quiet <command…>: run a check whose ok/FAIL line and counters are not the
# run's own (a negative control's expected failure); its status is kept.
quiet() {
	local p="$pass" f="$fail" rc=0 out
	out="$("$@")" || rc=$?
	pass="$p" fail="$f"
	sed 's/^/     | /' <<<"$out"
	return "$rc"
}

live() { # live <kind>: (a)-(f) through that proxy
	local k="$1" r code hdr dout miss want
	# (a)
	code="$(cl "$ca" -o /dev/null -w '%{http_code}' -X POST https://mcp.example.test/mcp || true)"
	# The token is read inside the client container, from init's file; it is
	# never on this script's command lines or output.
	# shellcheck disable=SC2016 # expanded by the client's sh
	r="$(docker exec "$ca" sh -c 'curl -s --max-time 10 --cacert /ca/ca.crt --resolve "mcp.example.test:443:$1" -w "\n%{http_code}" \
		-X POST https://mcp.example.test/mcp -H "Authorization: Bearer $(cat /secrets/mcp_token)" -H "Content-Type: application/json" \
		-H "Accept: application/json, text/event-stream" -H "MCP-Protocol-Version: 2025-11-25" \
		-d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"' _ "$C.5" || true)"
	if [[ "$code" == 401 && "$(tail -n1 <<<"$r")" == 200 ]] && grep -q '"result"' <<<"$r" && grep -q '"shell_get_policy"' <<<"$r"; then
		ok "$k: (a) with the token, tools/list through the proxy answers 200 with the catalogue; without it, 401"
	else
		bad "$k: (a) without the token $code (want 401), with it $(tail -n1 <<<"$r") (want 200 and a tools/list result)"
	fi
	check_b "$k" || true
	check_c "$k" || true
	# (d)
	hdr="$(cl "$ca" -o /dev/null -D - https://approve.example.test/ | tr -d '\r' || true)"
	if grep -q '^HTTP/[0-9.]* 200' <<<"$hdr" && grep -qi "^content-security-policy:.*frame-ancestors 'none'" <<<"$hdr" && grep -qi '^x-frame-options: DENY' <<<"$hdr"; then
		ok "$k: (d) https://approve.example.test/ answers 200 from the approval page (its own headers)"
	else
		bad "$k: (d) https://approve.example.test/ did not answer 200 from the approval page"
		head -n 12 <<<"$hdr" || true
	fi
	local own other
	own="$(docker run --rm "${hard[@]}" -u 65532:65532 --network "container:$pxy" --entrypoint curl "$client_image" \
		-s --max-time 10 -o /dev/null -w '%{http_code}' -H 'Host: approve.example.test' "http://$S.10:8081/" || true)"
	other="$(docker run --rm "${hard[@]}" -u 65532:65532 --network "container:$pxy" --entrypoint curl "$client_image" \
		-s --max-time 10 -o /dev/null -w '%{http_code}' -H 'Host: mcp.example.test' "http://$S.10:8081/" || true)"
	[[ "$own" == 200 && "$other" == 421 ]] && ok "$k: (d) from the proxy's address the approval listener answers its own name 200 and refuses Host mcp.example.test with 421" ||
		bad "$k: (d) from the proxy's address: its own name $own (want 200), another Host $other (want 421)"
	# (e)
	local n0 n1 m a2
	n0="$(docker logs "$sid" 2>&1 | wc -l)"
	m="$(cl "$cb" -o /dev/null -D - -X POST https://mcp.example.test/mcp | tr -d '\r' || true)"
	a2="$(cl "$cb" -o /dev/null -D - https://approve.example.test/ | tr -d '\r' || true)"
	sleep 1
	n1="$(docker logs "$sid" 2>&1 | wc -l)"
	if grep -q '^HTTP/[0-9.]* 403' <<<"$m" && grep -q '^HTTP/[0-9.]* 403' <<<"$a2" && ! grep -qi '^www-authenticate:' <<<"$m" &&
		! grep -qi '^content-security-policy:' <<<"$a2" && ((n1 == n0)); then
		ok "$k: (e) a client outside the allowed ranges ($B) gets 403 from the proxy on both names; the server logged nothing"
	else
		bad "$k: (e) the client at $B: MCP '$(head -n1 <<<"$m")', approval '$(head -n1 <<<"$a2")', server log lines $n0 -> $n1"
	fi
	# (f)
	dout="$("${dc[@]}" exec -T shell-mcp /shell-mcp doctor --mcp-url https://mcp.example.test/mcp --ca-file /run/test-ca/ca.crt 2>&1 || true)"
	miss=""
	for want in "^ok   trusted proxy $S.5: a single address on a network this container is attached to, and not its gateway" \
		"^ok   approval page: GET https://approve.example.test/ answered 200 from the approval page; certificate valid for approve.example.test" \
		"^ok   mcp endpoint: POST https://mcp.example.test/mcp without a token answered 401 with the server's challenge; certificate valid for mcp.example.test"; do
		grep -qE -- "$want" <<<"$dout" || miss="$miss [$want]"
	done
	if [[ -z "$miss" ]]; then ok "$k: (f) doctor --mcp-url: the trusted proxy, approval page and MCP endpoint rows ok"; else
		bad "$k: (f) doctor rows missing:$miss"
		grep -E 'trusted prox|approval page|mcp endpoint|^doctor' <<<"$dout" || tail -n 20 <<<"$dout" || true
	fi
}

for kind in caddy nginx; do
	echo "=== $kind"
	t0=$SECONDS
	src=deploy/caddy/Caddyfile
	[[ "$kind" == nginx ]] && src=deploy/caddy/nginx.conf
	conf="$tmp/$kind.conf"
	subst "$src" "$conf" "$kind"
	if cmp -s <(unsubst "$conf" "$kind") "$src"; then
		ok "$kind: $src with only the placeholders replaced (undoing them gives the example byte for byte)"
	else
		bad "$kind: the test copy of $src differs from it beyond the placeholders"
		diff <(unsubst "$conf" "$kind") "$src" | head -n 20 || true
	fi
	if ! proxy "$kind" "$conf"; then
		bad "$kind: the proxy did not start"
		continue
	fi
	live "$kind"

	# Negative controls: a proxy that passes the client's X-Forwarded-For
	# through must be caught by (c); one that appends must not, since the
	# server reads only the last entry, the proxy's own.
	broken="$tmp/$kind-passthrough.conf"
	appended="$tmp/$kind-append.conf"
	if [[ "$kind" == caddy ]]; then
		sed "s|^\(\t*\)reverse_proxy \($S.10:[0-9]*\)$|\1reverse_proxy \2 {\n\1\theader_up X-Forwarded-For {http.request.header.X-Forwarded-For}\n\1}|" "$conf" >"$broken"
	else
		sed 's/X-Forwarded-For \$remote_addr;/X-Forwarded-For $http_x_forwarded_for;/' "$conf" >"$broken"
		sed 's/X-Forwarded-For \$remote_addr;/X-Forwarded-For $proxy_add_x_forwarded_for;/' "$conf" >"$appended"
	fi
	if cmp -s "$conf" "$broken"; then bad "$kind: the pass-through control changed nothing"; elif proxy "$kind" "$broken"; then
		if quiet check_c "$kind, X-Forwarded-For passed through"; then bad "$kind: a proxy that passes X-Forwarded-For through was not caught by (c)"; else
			ok "$kind: control: a proxy that passes the client's X-Forwarded-For through is caught by (c)"
		fi
	else bad "$kind: the pass-through proxy did not start"; fi
	if [[ -f "$appended" ]]; then
		if proxy "$kind" "$appended" && quiet check_c "$kind, X-Forwarded-For appended"; then
			ok "$kind: control: a proxy that appends to X-Forwarded-For still passes (c): the server reads only the last entry, the proxy's"
		else bad "$kind: a proxy that appends to X-Forwarded-For failed (c)"; fi
	fi
	echo "     $kind: $((SECONDS - t0)) s"
done

# --- A gateway-sourced proxy: (b) must fail -----------------------------------------
# The server publishes its MCP port and the proxy's upstream is that port, so
# the server's peer is the network's gateway, as for a proxy installed on the
# host (deploy/caddy/README.md, property 1). On Linux the port is published on
# the gateway's own address, reachable only from the host and its bridges;
# Docker Desktop cannot bind there, so it is published on loopback and reached
# as host.docker.internal (its path also arrives from the gateway, CLIENTS §1).
echo "=== a gateway-sourced proxy"
gp="$((20000 + RANDOM % 20000))"
if [[ -n "$desktop" ]]; then bind=127.0.0.1 uphost=host.docker.internal; else bind="$S.1" uphost="$S.1"; fi
printf 'services:\n  shell-mcp:\n    ports: ["%s:%s:8080"]\n' "$bind" "$gp" >"$d/gateway-port.yml"
if up gateway-port.yml "the MCP port published on $bind"; then
	for kind in caddy nginx; do
		src=deploy/caddy/Caddyfile
		[[ "$kind" == nginx ]] && src=deploy/caddy/nginx.conf
		subst "$src" "$tmp/$kind-gw.conf" "$kind" "$uphost:$gp"
		if proxy "$kind" "$tmp/$kind-gw.conf" --add-host host.docker.internal:host-gateway; then
			got="$(authlog "$ca")"
			if quiet check_b "$kind via the gateway"; then bad "$kind: a gateway-sourced proxy was not caught by (b)"; else
				ok "$kind: control: a gateway-sourced proxy is caught by (b) (the server logged '$got'$([[ "$got" == "$S.1/32" ]] && echo ', the gateway'))"
			fi
		else bad "$kind: the gateway-sourced proxy did not start"; fi
	done
fi

# --- The gateway in SHELL_MCP_TRUSTED_PROXIES: doctor must fail -----------------------
echo "=== the gateway trusted"
printf 'services:\n  shell-mcp:\n    environment:\n      SHELL_MCP_TRUSTED_PROXIES: "%s"\n' "$S.1" >"$d/gateway-trusted.yml"
if up gateway-trusted.yml "SHELL_MCP_TRUSTED_PROXIES=$S.1" && proxy nginx "$tmp/nginx.conf"; then
	rc=0
	dout="$("${dc[@]}" -f "$dn/gateway-trusted.yml" exec -T shell-mcp /shell-mcp doctor --mcp-url https://mcp.example.test/mcp --ca-file /run/test-ca/ca.crt 2>&1)" || rc=$?
	if [[ "$rc" == 1 ]] && grep -qF -- "FAIL trusted proxy $S.1: holds $S.1, a gateway of this container's network" <<<"$dout" &&
		! grep -q "^ok   trusted proxy" <<<"$dout"; then
		ok "control: SHELL_MCP_TRUSTED_PROXIES=$S.1 (the gateway) makes doctor FAIL on the trusted proxy row"
	else
		bad "doctor with the gateway trusted: exit $rc"
		grep -E 'trusted prox|^doctor' <<<"$dout" || tail -n 15 <<<"$dout" || true
	fi
fi

echo
echo "proxy-live-check: $pass passed, $fail failed ($((SECONDS - t_start)) s)"
[[ "$fail" == 0 ]]
