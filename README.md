# dekube-provider-nginx

Nginx reverse proxy provider for [dekube](https://dekube.io). Produces an `nginx` compose service + `nginx.conf` instead of Caddy.

## When to use

- Corporate environments that require Nginx
- Existing Nginx expertise / config reuse
- Setups where Caddy's automatic TLS isn't wanted

## TLS modes

| Config | Behavior |
|--------|----------|
| No `email`, no `tls_*` | Plain HTTP only (port 80) |
| `extensions.nginx.email: admin@example.com` | ACME via certbot sidecar (ports 80 + 443) |
| `extensions.nginx.tls_internal: true` | Self-signed certs via openssl in entrypoint |
| `extensions.nginx.tls_cert_path: /path` | User-provided certs mounted read-only |

## Configuration

```yaml
# dekube.yaml
extensions:
  nginx:
    email: admin@example.com      # optional — enables certbot ACME
    tls_internal: true             # optional — self-signed certs
    tls_cert_path: ./certs         # optional — user-provided certs
```

## Installation

```bash
python3 dekube-manager.py nginx-provider
```

## Compatibility

Works with any ingress rewriter (nginx, haproxy, traefik). The rewriter translates annotations into structured entries; this provider consumes them to generate `nginx.conf`.

Not included in any distribution by default — both helmfile2compose and kubernetes2simple use Caddy. Install explicitly if needed.

## Handled kinds

- `Ingress` (via `IngressProvider` base class)

## Priority

900 (same as all ingress providers — only one should be active per distribution).
