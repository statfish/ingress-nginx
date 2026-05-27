# Stainless ingress-nginx Fork

Fork of [kubernetes/ingress-nginx](https://github.com/kubernetes/ingress-nginx) maintained by Stainless to patch critical vulnerabilities after the upstream project was retired (March 2026).

## Why This Fork Exists

The Kubernetes ingress-nginx project announced retirement in November 2025 and formally wound down in March 2026. v1.15.1 is the last upstream release. No further security patches will be issued upstream.

On May 14, 2026, **CVE-2026-42945 ("NGINX Rift")** was disclosed — a critical (CVSS 9.2) heap buffer overflow in `ngx_http_rewrite_module` that has existed since NGINX 0.6.27 (2008). It allows unauthenticated remote code execution or denial of service when specific rewrite configurations are used. Active exploitation in the wild began May 16, 2026.

Our statfish-prod cluster runs ingress-nginx with the vulnerable pattern (`rewrite-target: /$2` with unnamed PCRE captures) across dozens of ingresses created dynamically by Kallisto.

## What Was Changed

### Patch: `35_nginx-1.27.1-CVE-2026-42945.patch`

**Location:** `images/nginx/rootfs/patches/`

A one-line fix backported from upstream NGINX commit [`2046b45aa0c6e712c216b9075886f3f26e9b4ca9`](https://github.com/nginx/nginx/commit/2046b45aa0c6e712c216b9075886f3f26e9b4ca9) by Roman Arutyunyan.

The fix adds `e->is_args = 0;` in `ngx_http_script_regex_end_code()` in `src/http/ngx_http_script.c`. This clears the `is_args` flag between rewrite directives so the escaping size calculation matches the actual write pass, preventing the heap buffer overrun.

### Test: `test/e2e/security/cve_2026_42945.go`

Two e2e test cases that exercise the exact CVE trigger pattern:
1. Sends requests with characters that expand during re-escaping (`+`, `&`) through a rewrite with unnamed captures and `?` in the replacement, followed by a `set` directive. Verifies the worker doesn't crash.
2. Mirrors the PoC configuration and sends multiple requests, then checks NGINX logs for SIGSEGV/SIGABRT signals.

## Branches

| Branch | Controller | NGINX | Patch | Purpose |
|--------|-----------|-------|-------|---------|
| `main` | v1.15.0 | 1.27.1 | `35_nginx-1.27.1-CVE-2026-42945.patch` | Latest EOL controller with patched NGINX |
| `patch/v1.11.5-cve-2026-42945` | v1.11.5 | 1.25.5 | `32_nginx-1.25.5-CVE-2026-42945.patch` | Minimal patch for current prod controller version |

## Vulnerability Details

**CVE-2026-42945** — Heap buffer overflow in `ngx_http_rewrite_module`

- **Trigger conditions** (all three required):
  1. Consecutive `rewrite`, `if`, or `set` directives
  2. Unnamed PCRE capture groups (`$1`, `$2`)
  3. A `?` in the replacement string of a `rewrite` directive
- **Root cause:** The `is_args` flag is set when a rewrite replacement contains `?` but never cleared. Subsequent `set`/`if` directives allocate a buffer without escaping but write with escaping, overflowing the heap.
- **Affected:** NGINX 0.6.27 through 1.30.0
- **Fixed in:** NGINX 1.30.1 and 1.31.0

## Other CVEs Covered

- **CVE-2025-1974, CVE-2025-1097, CVE-2025-1098, CVE-2025-24514 (IngressNightmare):** Fixed in ingress-nginx v1.11.5+. Both branches include this.
- **CVE-2025-23419 (TLS SNI session reuse):** Patched via `28_nginx-1.27.1-CVE-2025-23419.patch` on `main`.

## Build

```bash
# Build the patched NGINX base image (amd64)
cd images/nginx
docker buildx create --name ingress-nginx --bootstrap
docker buildx build --builder ingress-nginx --platform linux/amd64 --load rootfs --tag statfish/nginx:v2.2.9-cve-2026-42945

# Build the controller image
make build image ARCH=amd64 BASE_IMAGE=statfish/nginx:v2.2.9-cve-2026-42945
```

## Validation

- Patch applies cleanly to NGINX 1.27.1 (verified via `patch --dry-run`)
- NGINX compiles and starts successfully with the patch applied
- Controller unit tests pass (including rewrite annotation tests)
- e2e tests require `kind` + `go` to run the CVE-specific crash test

## Additional Mitigation (Application Level)

Independent of this image patch, the Kallisto codebase (`api_resources.py:270`) and config-space Helm templates use the vulnerable `/$2` unnamed capture pattern. These should also be migrated to named captures (`(?P<remaining>.*)` / `/$remaining`) as defense in depth.

## References

- [NGINX security advisory](https://nginx.org/en/security_advisories.html)
- [NVD CVE-2026-42945](https://nvd.nist.gov/vuln/detail/CVE-2026-42945)
- [HeroDevs writeup](https://www.herodevs.com/blog-posts/cve-2026-42945-nginx-rift-heap-buffer-overflow-hits-ingress-nginx)
- [Upstream fix commit](https://github.com/nginx/nginx/commit/2046b45aa0c6e712c216b9075886f3f26e9b4ca9)
