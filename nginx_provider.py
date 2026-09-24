"""dekube-provider-nginx — Nginx reverse proxy provider."""

import os
import sys

from dekube import IngressProvider  # pylint: disable=import-error  # h2c resolves at runtime


class NginxProvider(IngressProvider):
    """Convert Ingress manifests to an Nginx service + nginx.conf."""
    name = "nginx"

    def build_service(self, entries, ctx):
        """Build the Nginx (+ optional certbot) compose service dict."""
        ext_cfg = ctx.extension_config
        if ext_cfg.get("disabled"):
            return {}

        config = ctx.config
        volume_root = config.get("volume_root", "./data")
        email = ext_cfg.get("email")
        tls_internal = bool(ext_cfg.get("tls_internal"))
        tls_cert_path = ext_cfg.get("tls_cert_path")

        # Determine TLS mode
        use_tls = bool(email or tls_internal or tls_cert_path)

        # Nginx config filename matches write_config
        conf_file = "nginx.conf"
        if config.get("disable_ingress"):
            project = config.get("name", "project")
            conf_file = f"nginx.conf-{project}"

        nginx_volumes = [f"./{conf_file}:/etc/nginx/nginx.conf:ro"]
        ports = ["80:80"]

        # nginx:alpine ships libssl but not the openssl CLI — verified with
        # `docker run --rm nginx:alpine which openssl` (not found). Both
        # self-signed-cert branches (tls_internal below, and the ACME
        # placeholder further down) need it; apk add it lazily (skip if
        # already there, e.g. a same-container restart) rather than baking a
        # custom image for one binary.
        openssl_bootstrap = "command -v openssl >/dev/null 2>&1 || apk add --no-cache openssl >/dev/null 2>&1"

        if use_tls:
            ports.append("443:443")
            if tls_internal:
                # Self-signed certs generated in nginx entrypoint
                nginx_volumes.append(f"{volume_root}/nginx-certs:/etc/nginx/certs")
                domains = sorted({e["host"] for e in entries if e})
                cert_cmds = " && ".join(
                    f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
                    f"-keyout /etc/nginx/certs/{d}.key "
                    f"-out /etc/nginx/certs/{d}.crt "
                    f"-subj '/CN={d}'"
                    for d in domains
                    if d
                )
                services = {"nginx": {
                    "image": "nginx:alpine", "restart": "always",
                    "ports": ports,
                    "volumes": nginx_volumes,
                    "entrypoint": ["/bin/sh", "-c",
                                   f"{openssl_bootstrap} && mkdir -p /etc/nginx/certs && {cert_cmds} "
                                   # exec so SIGTERM reaches nginx directly
                                   # instead of waiting out sh's default
                                   # signal handling (10s grace -> SIGKILL).
                                   f"&& exec nginx -g 'daemon off;'"],
                }}
            elif tls_cert_path:
                # User-provided certs
                nginx_volumes.append(f"{tls_cert_path}:/etc/nginx/certs:ro")
                services = {"nginx": {
                    "image": "nginx:alpine", "restart": "always",
                    "ports": ports,
                    "volumes": nginx_volumes,
                }}
            else:
                # ACME via certbot. nginx can't start with ssl_certificate
                # pointing at a file that doesn't exist yet, and the real
                # cert isn't there until certbot completes its first HTTP-01
                # round trip — so nginx bootstraps its own throwaway
                # self-signed placeholder per domain (same recipe as
                # tls_internal above) if none exists, then reloads
                # periodically so it picks up the real cert once certbot
                # swaps it in. Needs write access to the letsencrypt volume
                # (read-only in the tls_internal/tls_cert_path branches,
                # where nginx never writes to it).
                nginx_volumes.append(f"{volume_root}/letsencrypt:/etc/letsencrypt")
                nginx_volumes.append(f"{volume_root}/certbot-webroot:/var/www/certbot:ro")
                domains = sorted({e["host"] for e in entries if e and e.get("host")})
                domain_flags = " ".join(f"-d {d}" for d in domains)
                bootstrap_cmds = " && ".join(
                    f"(test -f /etc/letsencrypt/live/{d}/fullchain.pem || "
                    f"(mkdir -p /etc/letsencrypt/live/{d} && "
                    f"openssl req -x509 -nodes -days 1 -newkey rsa:2048 "
                    f"-keyout /etc/letsencrypt/live/{d}/privkey.pem "
                    f"-out /etc/letsencrypt/live/{d}/fullchain.pem "
                    f"-subj '/CN={d}'))"
                    for d in domains
                    if d
                ) or "true"
                services = {
                    "nginx": {
                        "image": "nginx:alpine", "restart": "always",
                        "ports": ports,
                        "volumes": nginx_volumes,
                        "entrypoint": [
                            "/bin/sh", "-c",
                            f"{openssl_bootstrap} && {bootstrap_cmds} && "
                            # CBA: nginx reloads itself on a timer instead of
                            # certbot signalling it directly — cross-container
                            # signalling needs a shared PID namespace or the
                            # docker socket, overkill for a single-node
                            # compose stack. Ceiling: up to 6h of stale cert
                            # after a renewal.
                            "(while :; do sleep 6h; nginx -s reload; done &) "
                            # exec so SIGTERM reaches nginx directly instead of
                            # waiting out sh's default signal handling (10s
                            # grace -> SIGKILL).
                            "&& exec nginx -g 'daemon off;'",
                        ],
                    },
                    "certbot": {
                        "image": "certbot/certbot", "restart": "always",
                        "volumes": [
                            f"{volume_root}/letsencrypt:/etc/letsencrypt",
                            f"{volume_root}/certbot-webroot:/var/www/certbot",
                        ],
                        "entrypoint": [
                            "/bin/sh", "-c",
                            _certbot_script(domains, email, domain_flags),
                        ],
                    },
                }
        else:
            # Plain HTTP
            services = {"nginx": {
                "image": "nginx:alpine", "restart": "always",
                "ports": ports,
                "volumes": nginx_volumes,
            }}

        return services

    def write_config(self, entries, output_dir, config):
        """Write the nginx.conf."""
        if not entries:
            return

        ext_cfg = (config.get("extensions") or {}).get(self.name) or {}
        tls = _resolve_tls(ext_cfg)

        filename = "nginx.conf"
        if config.get("disable_ingress"):
            project = config.get("name", "project")
            filename = f"nginx.conf-{project}"

        by_host = _group_by_host(entries, config.get("replacements") or [])
        upstreams = _collect_upstreams(by_host)

        path = os.path.join(output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Generated by dekube — do not edit manually\n\n")
            f.write("events {}\n\n")
            f.write("http {\n")
            _write_upstream_blocks(f, upstreams)
            for host, host_entries in by_host.items():
                _write_server_block(f, host, host_entries, tls)
            f.write("}\n")
        print(f"Wrote {path}", file=sys.stderr)


def _certbot_script(domains: list[str], email: str, domain_flags: str) -> str:
    """Build the certbot entrypoint: cleanup, retry-until-issued, then renew loop.

    - Deletes nginx's placeholder live/archive dir before the FIRST real
      issuance only: a renewal.conf means certbot already claimed the domain
      for real, so it's left alone on subsequent restarts (re-deleting a
      valid lineage every restart would force re-issuance and risk the
      Let's Encrypt rate limit).
    - `certonly` is retried with capped exponential backoff (5min -> 60min)
      instead of falling straight into the renew loop: `certbot renew` only
      touches domains that already have a lineage, so a first-run failure
      (DNS not propagated yet, a transient CA hiccup, rate limiting) would
      otherwise leave nginx stuck on the throwaway self-signed cert forever,
      with nothing retrying.

      Ramp tuned against Let's Encrypt's own limit (letsencrypt.org/docs/rate-limits/,
      "Authorization Failures per Hostname per Account"): up to 5 failures per
      identifier per account per hour, refilling at 1 per 12min. Schedule here
      (delay starts at 300s, doubles, clamped to 3600s): attempts at
      t = 0, 300, 900, 2100, 4500, 8100, 11700, ... (i.e. every 3600s once
      capped) — at most 4 attempts fall inside any rolling 60-minute window
      (e.g. t=0,300,900,2100), staying under LE's 5/hour budget with one
      attempt of headroom; the capped steady state (1/hour) is well under the
      1-per-12min refill rate too.
    """
    script = (
        f"for d in {' '.join(domains)}; do "
        "test -f /etc/letsencrypt/renewal/$d.conf || "
        "rm -rf /etc/letsencrypt/live/$d /etc/letsencrypt/archive/$d; "
        "done\n"
        "delay=300\n"
        f"until certbot certonly --webroot -w /var/www/certbot "
        f"--email {email} --agree-tos --no-eff-email "
        f"--non-interactive {domain_flags}; do\n"
        '  echo "certbot: initial issuance failed, retrying in ${delay}s" >&2\n'
        "  sleep $delay\n"
        "  delay=$((delay * 2))\n"
        "  [ $delay -gt 3600 ] && delay=3600\n"
        "done\n"
        "trap exit TERM\n"
        "while :; do\n"
        "  sleep 12h & wait $!\n"
        "  certbot renew --webroot -w /var/www/certbot --quiet\n"
        "done"
    )
    # Compose interpolates single-$ references in the YAML itself, so every
    # shell variable meant for the *container* has to be escaped as $$
    # (dekube-engine does this automatically for K8s-derived command/args via
    # _escape_shell_vars_for_compose, but a provider authoring its own raw
    # entrypoint string has to do it by hand).
    return script.replace("$", "$$")


def _resolve_tls(ext_cfg: dict) -> dict:
    """Resolve TLS mode from extension config."""
    email = ext_cfg.get("email")
    tls_internal = bool(ext_cfg.get("tls_internal"))
    tls_cert_path = ext_cfg.get("tls_cert_path")
    return {"enabled": bool(email or tls_internal or tls_cert_path),
            "email": email, "internal": tls_internal, "cert_path": tls_cert_path}


def _group_by_host(entries: list[dict], replacements: list) -> dict[str, list[dict]]:
    """Group entries by host, applying replacements to upstreams."""
    by_host: dict[str, list[dict]] = {}
    for e in entries:
        if not e:
            continue
        for r in replacements:
            if not r:
                continue
            e["upstream"] = e["upstream"].replace(r["old"], r["new"])
        by_host.setdefault(e["host"], []).append(e)
    return by_host


def _collect_upstreams(by_host: dict[str, list[dict]]) -> dict[str, str]:
    """Collect unique upstream name → address mappings."""
    upstreams: dict[str, str] = {}
    for host_entries in by_host.values():
        for entry in host_entries:
            if not entry:
                continue
            upstreams[_upstream_name(entry["upstream"])] = entry["upstream"]
    return upstreams


def _write_upstream_blocks(f, upstreams: dict[str, str]) -> None:
    """Write nginx upstream blocks."""
    for name, addr in sorted(upstreams.items()):
        f.write(f"\n\tupstream {name} {{\n")
        f.write(f"\t\tserver {addr};\n")
        f.write("\t}\n")


def _write_server_block(f, host: str, host_entries: list[dict], tls: dict) -> None:
    """Write a single nginx server block."""
    f.write("\n\tserver {\n")
    f.write("\t\tlisten 80;\n")
    f.write(f"\t\tserver_name {host};\n")

    if tls["enabled"]:
        f.write("\t\tlisten 443 ssl;\n")
        _write_ssl_cert_lines(f, host, tls)

    if tls["email"]:
        f.write("\n\t\tlocation /.well-known/acme-challenge/ {\n")
        f.write("\t\t\troot /var/www/certbot;\n")
        f.write("\t\t}\n")

    specific = [e for e in host_entries if e and e["path"] and e["path"] != "/"]
    catchall = [e for e in host_entries if e and (not e["path"] or e["path"] == "/")]
    for entry in specific + catchall:
        _write_nginx_location(f, entry)

    f.write("\t}\n")


def _write_ssl_cert_lines(f, host: str, tls: dict) -> None:
    """Write ssl_certificate / ssl_certificate_key lines."""
    if tls["internal"] or tls["cert_path"]:
        f.write(f"\t\tssl_certificate /etc/nginx/certs/{host}.crt;\n")
        f.write(f"\t\tssl_certificate_key /etc/nginx/certs/{host}.key;\n")
    else:
        f.write(f"\t\tssl_certificate /etc/letsencrypt/live/{host}/fullchain.pem;\n")
        f.write(f"\t\tssl_certificate_key /etc/letsencrypt/live/{host}/privkey.pem;\n")


def _upstream_name(upstream: str) -> str:
    """Generate a safe upstream block name from host:port."""
    return upstream.replace(".", "_").replace(":", "_").replace("-", "_")


def _write_nginx_location(f, entry: dict) -> None:
    """Write a single nginx location block."""
    path = entry.get("path", "/")
    upstream = entry["upstream"]
    upstream_name = _upstream_name(upstream)
    scheme = entry.get("scheme", "http")

    f.write(f"\n\t\tlocation {path} {{\n")

    # strip_prefix via rewrite
    if entry.get("strip_prefix"):
        prefix = entry["strip_prefix"]
        f.write(f"\t\t\trewrite ^{prefix}/(.*) /$1 break;\n")

    # Response headers (structured)
    for hdr_name, hdr_val in (entry.get("response_headers") or {}).items():
        f.write(f"\t\t\tadd_header {hdr_name} \"{hdr_val}\" always;\n")

    # Max body size (structured)
    if entry.get("max_body_size"):
        f.write(f"\t\t\tclient_max_body_size {entry['max_body_size']};\n")

    f.write(f"\t\t\tproxy_pass {scheme}://{upstream_name};\n")
    f.write("\t\t\tproxy_set_header Host $host;\n")
    f.write("\t\t\tproxy_set_header X-Real-IP $remote_addr;\n")
    f.write("\t\t\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
    f.write("\t\t\tproxy_set_header X-Forwarded-Proto $scheme;\n")
    f.write("\t\t}\n")
