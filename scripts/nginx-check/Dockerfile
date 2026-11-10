# Test-only image for scripts/nginx-check/run.sh: `nginx -t` of
# deploy/caddy/nginx.conf, copied in at build time. Nothing in deploy/ or any
# document runs this image; it ships to no one. Pinned by digest to the
# newest stable nginx (D-013); Dependabot's docker ecosystem tracks this
# directory.
FROM nginx:1.30.6@sha256:42c68eab6f7e22611786a9fe1d1c019e275c50185bd54b8f75dc2b9184322703
# nginx -t opens every certificate the configuration names. These are
# throwaway self-signed certificates for the example's placeholder names,
# made here and never used for anything but this syntax check. The image's
# own default site is removed, so only the example is checked.
RUN set -eu; \
	mkdir -p /etc/nginx/tls; \
	for n in mcp.example.test approve.example.test; do \
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
			-subj "/CN=$n" -keyout "/etc/nginx/tls/$n.key" -out "/etc/nginx/tls/$n.crt" 2>/dev/null; \
	done; \
	chmod 0644 /etc/nginx/tls/*; \
	rm -f /etc/nginx/conf.d/default.conf
COPY nginx-test.conf /etc/nginx/nginx-test.conf
COPY nginx.conf /etc/nginx/conf.d/shell-mcp.conf
