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

        if use_tls:
            ports.append("443:443")
            if tls_internal:
                # Self-signed certs generated in nginx entrypoint
                nginx_volumes.append(f"{volume_root}/nginx-certs:/etc/nginx/certs")
                domains = sorted({e["host"] for e in entries})
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
                                   f"mkdir -p /etc/nginx/certs && {cert_cmds} "
                                   f"&& nginx -g 'daemon off;'"],
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
                # ACME via certbot
                nginx_volumes.append(f"{volume_root}/letsencrypt:/etc/letsencrypt:ro")
                nginx_volumes.append(f"{volume_root}/certbot-webroot:/var/www/certbot:ro")
                domains = sorted({e["host"] for e in entries if e.get("host")})
                domain_flags = " ".join(f"-d {d}" for d in domains)
                services = {
                    "nginx": {
                        "image": "nginx:alpine", "restart": "always",
                        "ports": ports,
                        "volumes": nginx_volumes,
                    },
                    "certbot": {
                        "image": "certbot/certbot", "restart": "no",
                        "volumes": [
                            f"{volume_root}/letsencrypt:/etc/letsencrypt",
                            f"{volume_root}/certbot-webroot:/var/www/certbot",
                        ],
                        "entrypoint": (
                            f"certbot certonly --webroot -w /var/www/certbot "
                            f"--email {email} --agree-tos --no-eff-email "
                            f"{domain_flags}"
                        ),
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

        ext_cfg = config.get("extensions", {}).get(self.name, {})
        email = ext_cfg.get("email")
        tls_internal = bool(ext_cfg.get("tls_internal"))
        tls_cert_path = ext_cfg.get("tls_cert_path")
        use_tls = bool(email or tls_internal or tls_cert_path)

        filename = "nginx.conf"
        if config.get("disable_ingress"):
            project = config.get("name", "project")
            filename = f"nginx.conf-{project}"

        replacements = config.get("replacements", [])
        by_host: dict[str, list[dict]] = {}
        for e in entries:
            if replacements:
                for r in replacements:
                    e["upstream"] = e["upstream"].replace(r["old"], r["new"])
            by_host.setdefault(e["host"], []).append(e)

        # Collect unique upstreams
        upstreams: dict[str, str] = {}
        for host_entries in by_host.values():
            for entry in host_entries:
                upstream = entry["upstream"]
                upstream_name = _upstream_name(upstream)
                upstreams[upstream_name] = upstream

        path = os.path.join(output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Generated by dekube — do not edit manually\n\n")
            f.write("events {}\n\n")
            f.write("http {\n")

            # Upstream blocks
            for name, addr in sorted(upstreams.items()):
                f.write(f"\n\tupstream {name} {{\n")
                f.write(f"\t\tserver {addr};\n")
                f.write("\t}\n")

            # Server blocks
            for host, host_entries in by_host.items():
                f.write(f"\n\tserver {{\n")
                f.write("\t\tlisten 80;\n")
                f.write(f"\t\tserver_name {host};\n")

                if use_tls:
                    f.write("\t\tlisten 443 ssl;\n")
                    if tls_internal:
                        f.write(f"\t\tssl_certificate /etc/nginx/certs/{host}.crt;\n")
                        f.write(f"\t\tssl_certificate_key /etc/nginx/certs/{host}.key;\n")
                    elif tls_cert_path:
                        f.write(f"\t\tssl_certificate /etc/nginx/certs/{host}.crt;\n")
                        f.write(f"\t\tssl_certificate_key /etc/nginx/certs/{host}.key;\n")
                    else:
                        f.write(f"\t\tssl_certificate /etc/letsencrypt/live/{host}/fullchain.pem;\n")
                        f.write(f"\t\tssl_certificate_key /etc/letsencrypt/live/{host}/privkey.pem;\n")

                if not use_tls or email:
                    # Certbot challenge location (ACME or plain HTTP)
                    if email:
                        f.write("\n\t\tlocation /.well-known/acme-challenge/ {\n")
                        f.write("\t\t\troot /var/www/certbot;\n")
                        f.write("\t\t}\n")

                # Sort: specific paths before catch-all
                specific = [e for e in host_entries if e["path"] and e["path"] != "/"]
                catchall = [e for e in host_entries if not e["path"] or e["path"] == "/"]

                for entry in specific:
                    _write_nginx_location(f, entry)
                for entry in catchall:
                    _write_nginx_location(f, entry)

                f.write("\t}\n")

            f.write("}\n")
        print(f"Wrote {path}", file=sys.stderr)


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
