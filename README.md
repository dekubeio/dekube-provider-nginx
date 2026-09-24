# dekube-provider-nginx

![vibe coded](https://img.shields.io/badge/vibe-coded-ff69b4)
![python 3](https://img.shields.io/badge/python-3-3776AB)
![stdlib only](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen)
![public domain](https://img.shields.io/badge/license-public%20domain-brightgreen)
![untested](https://img.shields.io/badge/status-untested-orange)

Nginx reverse proxy provider for [dekube](https://dekube.io) — converts Ingress manifests into an Nginx compose service and generates `nginx.conf`.

**Untested** — written but never run against a real project. The contract is sound, the config generation is plausible, but no one has pointed it at a helmfile yet. Use at your own risk — or better yet, test it and report back.

## Type

`IngressProvider` (priority 900)

## Kinds

- `Ingress` (inherited from IngressProvider)

## TLS modes

| Config | Behavior |
|--------|----------|
| No `email`, no `tls_*` | Plain HTTP only (port 80) |
| `extensions.nginx.email: admin@example.com` | ACME via certbot sidecar (ports 80 + 443) — nginx bootstraps a throwaway self-signed cert per domain so it can start before certbot has issued the real one, then reloads every 6h to pick it up; certbot retries a failed first issuance with capped exponential backoff (60s → 30min) before settling into a 12h renew loop |
| `extensions.nginx.tls_internal: true` | Self-signed certs via openssl in entrypoint (both this and ACME `apk add` the `openssl` CLI on demand — `nginx:alpine` doesn't ship it) |
| `extensions.nginx.tls_cert_path: /path` | User-provided certs mounted read-only |

## Configuration

Extension config in `dekube.yaml`:

```yaml
extensions:
  nginx:
    email: admin@example.com      # optional — enables certbot ACME
    tls_internal: true             # optional — self-signed certs
    tls_cert_path: ./certs         # optional — user-provided certs
```

## Install

Via [dekube-manager](https://github.com/dekubeio/dekube-manager):

```sh
python3 dekube-manager.py nginx-provider
```

Not included in any distribution by default — both helmfile2compose and kubernetes2simple use Caddy. Install explicitly if needed.

## Compatibility

Works with any ingress rewriter (nginx, haproxy, traefik). The rewriter translates annotations into structured entries (`response_headers`, `max_body_size`); this provider consumes them to generate `nginx.conf`.

## Code quality

*Last updated: 2026-03-07*

| Metric | Value |
|--------|-------|
| Pylint | 9.92/10 |
| Pyflakes | clean |
| Radon MI | 45.96 (A) |
| Radon avg CC | 5.3 (B) |

Worst CC: `NginxProvider.build_service` (14, C).

The `E0401: Unable to import 'dekube'` is expected — extensions import from dekube-engine at runtime, not at lint time.

## Dependencies

None (stdlib only).
