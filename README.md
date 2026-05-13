<p align="center">
  <img src="https://raw.githubusercontent.com/Sipioteo/MCPBouncer/main/docs/assets/banner.png" alt="MCPBouncer — OAuth 2.1 for any MCP server" width="100%">
</p>

# MCPBouncer

[![CI](https://github.com/Sipioteo/MCPBouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/Sipioteo/MCPBouncer/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Sipioteo/MCPBouncer/actions/workflows/codeql.yml/badge.svg)](https://github.com/Sipioteo/MCPBouncer/actions/workflows/codeql.yml)
[![govulncheck](https://github.com/Sipioteo/MCPBouncer/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/Sipioteo/MCPBouncer/actions/workflows/govulncheck.yml)
[![Trivy](https://github.com/Sipioteo/MCPBouncer/actions/workflows/trivy.yml/badge.svg)](https://github.com/Sipioteo/MCPBouncer/actions/workflows/trivy.yml)
[![Go Report (sidecar)](https://goreportcard.com/badge/github.com/Sipioteo/MCPBouncer/sidecar?v=2)](https://goreportcard.com/report/github.com/Sipioteo/MCPBouncer/sidecar)
[![Go Report (plugin)](https://goreportcard.com/badge/github.com/Sipioteo/traefik-mcpbouncer?v=2)](https://goreportcard.com/report/github.com/Sipioteo/traefik-mcpbouncer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Sidecar release](https://img.shields.io/github/v/release/Sipioteo/MCPBouncer?filter=sidecar-*&label=sidecar)](https://github.com/Sipioteo/MCPBouncer/releases)
[![Plugin release](https://img.shields.io/github/v/release/Sipioteo/MCPBouncer?filter=plugin-*&label=plugin)](https://github.com/Sipioteo/MCPBouncer/releases)
[![Docker Hub](https://img.shields.io/docker/v/sipioteo/mcpbouncer-sidecar?logo=docker&label=docker%20hub&sort=semver)](https://hub.docker.com/r/sipioteo/mcpbouncer-sidecar)
[![Docker pulls](https://img.shields.io/docker/pulls/sipioteo/mcpbouncer-sidecar.svg?logo=docker)](https://hub.docker.com/r/sipioteo/mcpbouncer-sidecar)
[![Docker image size](https://img.shields.io/docker/image-size/sipioteo/mcpbouncer-sidecar/latest?logo=docker)](https://hub.docker.com/r/sipioteo/mcpbouncer-sidecar)

Drop OAuth 2.1 onto any MCP server with a Traefik label.

## What it does

MCPBouncer adds full OAuth 2.1 and OIDC support (DCR, PKCE, JWKS, key rotation) to MCP servers that lack native authentication—without modifying the server image.

- **Transparent to the MCP image.** Configuration via Traefik labels only. The server behind the proxy sees authenticated requests with `X-Mcp-Sub` and `X-Mcp-Scopes` headers.
- **Multi-tenant per image.** A single sidecar instance serves multiple MCP servers with different OAuth providers (e.g., `/wiki` → Google, `/world` → Zitadel).
- **Tiny footprint.** Sidecar is ~10 MB, stdlib-only Yaegi plugin with no external dependencies beyond the Go standard library.
- **Standards-conformant.** Implements MCP Authorization spec (rev. 2025-06-18), RFC 8414 (Authorization Server metadata), RFC 7591 (Dynamic Client Registration), RFC 8707 (Resource Indicators).

## How it works

<p align="center">
  <img src="https://raw.githubusercontent.com/Sipioteo/MCPBouncer/main/docs/assets/architecture.svg" alt="MCPBouncer architecture: client → Traefik (with plugin) → sidecar / MCP image / upstream IdP" width="100%">
</p>

> Source for the diagram: [`docs/assets/architecture.mmd`](docs/assets/architecture.mmd) (Mermaid). Rendered to SVG so it works on Docker Hub and other Markdown viewers that don't support Mermaid natively.

**Plugin** (in Traefik):
- Intercepts requests under each MCP's PathPrefix.
- Routes OAuth endpoints (`.well-known/*`, `/oauth/*`) to the sidecar.
- Validates JWT locally with cached JWKS from the sidecar.
- Forwards authenticated requests to the MCP server with `X-Mcp-Sub` and `X-Mcp-Scopes`.
- Returns 401 with `WWW-Authenticate` header on missing/invalid token.

**Sidecar** (internal Docker network):
- Never exposed externally. Binds only to internal Docker network.
- Handles OAuth 2.1 flows: discovery, DCR, authorization, token exchange.
- Acts as a local Authorization Server, issuing JWT signed with its own Ed25519 keypair.
- Federates to upstream IdP (Google, Zitadel, etc.) for actual user authentication.
- Encrypts upstream refresh tokens at rest using AES-GCM.
- Rotates signing keys automatically with configurable overlap.

## Quick start

Clone and prepare:
```bash
git clone https://github.com/Sipioteo/MCPBouncer
cd MCPBouncer/deploy
cp docker-compose.example.yml docker-compose.yml
# Edit docker-compose.yml and traefik.example.yml with your IdP credentials
# (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, etc.)
```

Launch the stack:
```bash
docker compose up --build
```

Test discovery:
```bash
curl -i https://mcp.localhost/wiki/anything
```

Expected response:
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.localhost/wiki/.well-known/oauth-protected-resource"
Content-Type: application/json

{"error":"unauthorized"}
```

The client can now fetch `.well-known/oauth-protected-resource` to discover the OAuth server and begin DCR.

For local development with source plugin, use `traefik.local.yml` and bind-mount the plugin directory.

## Labels reference

Attach these labels to your MCP container in `docker-compose.yml`:

| Label | Type | Required | Description |
|-------|------|----------|-------------|
| `traefik.enable` | bool | Yes | Must be `true` |
| `traefik.http.routers.<name>.rule` | string | Yes | Path rule, e.g. `Host(...) && PathPrefix(/wiki)` |
| `traefik.http.routers.<name>.middlewares` | string | Yes | Reference to middleware, e.g. `mcpb-wiki@docker` |
| `traefik.http.middlewares.<name>.plugin.mcpbouncer.providerIssuer` | string | Yes | OIDC issuer URL (e.g., `https://accounts.google.com`) |
| `traefik.http.middlewares.<name>.plugin.mcpbouncer.clientID` | string | Yes | OAuth client ID from upstream IdP |
| `traefik.http.middlewares.<name>.plugin.mcpbouncer.clientSecret` | string | Yes | OAuth client secret from upstream IdP |
| `traefik.http.middlewares.<name>.plugin.mcpbouncer.resource` | string | Yes | Resource name (e.g., `wiki`). Used as JWT `aud` claim. |
| `traefik.http.middlewares.<name>.plugin.mcpbouncer.scopes` | string | No | Space-separated OAuth scopes (default: `openid`) |
| `traefik.http.middlewares.<name>.plugin.mcpbouncer.sidecarURL` | string | Yes | Internal sidecar URL (e.g., `http://bouncer:8080`) |
| `traefik.http.middlewares.<name>.plugin.mcpbouncer.audience` | string | No | JWT `aud` claim (default: same as `resource`) |
| `traefik.http.middlewares.<name>.plugin.mcpbouncer.jwksCacheTTLSeconds` | int | No | JWKS cache TTL in seconds (default: `300`) |
| `traefik.http.middlewares.<name>.plugin.mcpbouncer.requiredScopes` | string | No | Space-separated scopes required for access (checked before forwarding to MCP) |

See `docs/labels.md` for extended examples and notes.

## Sidecar environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BOUNCER_DB_PATH` | `/data/bouncer.db` | SQLite database path (must be writable) |
| `BOUNCER_LISTEN_ADDR` | `:8080` | Bind address (typically `:8080` for internal Docker network) |
| `BOUNCER_ENCRYPTION_KEY` | (required) | 32-byte base64-encoded key for AES-GCM encryption of sensitive fields |
| `BOUNCER_KEY_ROTATION_DAYS` | `30` | Days between signing key rotations |
| `BOUNCER_KEY_OVERLAP_HOURS` | `24` | Hours that old and new keys coexist during rotation |
| `BOUNCER_ACCESS_TOKEN_TTL` | `1` (hour) | Access token TTL in hours |
| `BOUNCER_REFRESH_TOKEN_TTL` | `30` (days) | Refresh token TTL in days |
| `BOUNCER_LOG_LEVEL` | `info` | Log level (`debug` or `info`) |

Generate a random 32-byte base64 key:
```bash
openssl rand -base64 32
```

## Security notes

**PKCE is mandatory.** All OAuth flows require PKCE with S256 challenge method. `code_challenge` cannot be omitted.

**Refresh tokens are encrypted at rest** with the key specified in `BOUNCER_ENCRYPTION_KEY` using AES-GCM. The upstream refresh token is never exposed to clients.

**Sidecar is never exposed externally.** It binds only to an internal Docker network (`bouncer_internal` in examples). There is no Traefik routing to the sidecar. Verify in your deployment that the sidecar port (`:8080`) is not accessible from outside the Docker network.

**JWT algorithm validation.** Only Ed25519 (EdDSA) and RS256 are accepted. `alg=none` is rejected outright.

**Audience claim is enforced.** Every JWT includes an `aud` claim matching the resource name. A token issued for `/wiki` will not validate for `/world`.

**Issuer is exact-match.** The `iss` claim in every JWT must exactly match the public base URL (derived from request Host and PathPrefix). No wildcard or domain-level acceptance.

## Status

Early stage. Targets the MCP Authorization spec rev. 2025-06-18.

## License

MIT
