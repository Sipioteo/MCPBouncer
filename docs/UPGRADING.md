# Upgrading MCPBouncer

This guide covers migrating between sidecar versions. Changes are listed in reverse chronological order (newest first).

## v0.0.14

Released: 2026-05-20

### Summary

Hardening release: client secrets are now enforced for confidential clients, `redirect_uri` schemes are validated, DCR can be gated with an optional initial-access token, upstream refresh failures can surface as errors, and JWT `aud` claims are emitted as single-element arrays (RFC 7519).

### Breaking Changes

#### Client Secret Enforcement (Commit 778a963)

**What changed:**
- Confidential clients (those registered with `client_type=confidential` or with a `ClientSecretHash` in the database) **must now send `client_secret` with every token request**.
- Missing or wrong secret → `401 invalid_client` with `WWW-Authenticate: Basic realm="oauth"`.

**Migration impact:**
- **If you have existing public clients (no secret):** no change. Public clients continue to work.
- **If you have existing confidential clients registered before v0.0.14:** they were accepted without a secret before. With v0.0.14, they will be rejected unless they provide the secret.

**What to do:**
- Clients that were previously accepted without a secret should now explicitly provide it.
- If you don't know the original secret, delete the client and re-register via DCR.
- To identify confidential vs. public clients: `SELECT id, client_id, client_secret_hash FROM clients`.

#### Redirect URI Scheme Validation (Commit 292cc01)

**What changed:**
- `POST /oauth/register` (DCR) now validates the scheme of each `redirect_uri`:
  - ✓ `https://` — always allowed.
  - ✓ `mcp://` — always allowed (for MCP client-server).
  - ✓ `http://localhost:*` or `http://127.0.0.1:*` — allowed for local development.
  - ✗ `javascript://`, `data:`, `file:`, `vbscript:`, `blob:`, `about:` — explicitly denied.
  - ✗ Other schemes — denied.
- Violations → `400 invalid_redirect_uri`.

**Migration impact:**
- Any client registered with a `javascript://`, `data:`, etc. redirect will no longer be able to register with that URI.
- Localhost `http://` redirects are still supported (unchanged).

**What to do:**
- If you have clients with non-standard schemes, update them to use `https://` or `mcp://` before upgrading.
- To list all registered redirect URIs: `SELECT id, redirect_uris_json FROM clients`.

#### JWT `aud` Claim Emitted as Array (Commit 32b391b)

**What changed:**
- Access tokens now emit the `aud` claim as a JSON array `["https://mcp.example.com/wiki/"]` instead of a bare string `"https://mcp.example.com/wiki/"`.
- The plugin's JWT verification continues to work (it type-switches on both string and array).

**Migration impact:**
- **Plugin (Traefik middleware):** backward compatible. No change required.
- **Third-party MCP servers that parse the JWT:** may break if they expect `aud` to always be a string.

**What to do:**
- Audit any downstream services that parse the JWT's `aud` claim (e.g., custom MCP servers).
- Update them to handle both `aud` as a string (old tokens) and as an array (new tokens).
- Test with old and new access tokens before rolling out.

### Non-Breaking Improvements

#### PKCE Method Validation at Token Endpoint (Commit 778a963)

**What changed:**
- The sidecar now explicitly rejects `code_challenge_method` values other than `S256` at the `/oauth/token` endpoint.

**Impact:** defensive hardening. No client should be sending other methods; `/oauth/authorize` already rejects them.

#### Optional DCR Initial-Access Token (Commit 292cc01)

**What changed:**
- New environment variable: `BOUNCER_DCR_INITIAL_TOKEN`.
- When set (non-empty), `/oauth/register` requires `Authorization: Bearer <token>` in the request header.
- Missing or wrong token → `401 invalid_token`.
- When empty (default), DCR is open; any client can register (backward compat).

**How to use:**
```bash
# Generate a random token
TOKEN=$(openssl rand -base64 32)

# Set in docker-compose.yml or Kubernetes
environment:
  BOUNCER_DCR_INITIAL_TOKEN: "$TOKEN"

# Clients must then include it in DCR
curl -X POST https://mcp.example.com/wiki/.well-known/oauth/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"..."}'
```

**Impact:** recommended for production. Prevents unrestricted client registration.

#### Upstream Refresh Validation (Commit 778a963)

**What changed:**
- New environment variable: `BOUNCER_STRICT_UPSTREAM_REFRESH`.
- When set to `true`, the sidecar validates refresh tokens against the upstream IdP at each refresh request.
- If the upstream IdP has revoked the session (user changed password, logged out, etc.), the refresh fails with `invalid_grant` instead of silently minting a new access token.
- When set to `false` (default), refresh tokens are valid until expiry, even if the upstream session was revoked.

**How to use:**
```bash
# In docker-compose.yml or Kubernetes
environment:
  BOUNCER_STRICT_UPSTREAM_REFRESH: "true"
```

**Compatibility:**
- ✓ Zitadel: supports refresh token validation.
- ✗ Google: refresh tokens do not validate against session revocation via the standard `/token` endpoint.
- Consult your IdP's documentation.

**Impact:** improves security at the cost of a network round-trip on every refresh. Backward compat is preserved (off by default).

#### Identity Claims Persistence (Commit 7f8045d)

**What changed:**
- Refresh tokens now store a JSON snapshot of identity claims (email, name, picture, etc.) from the original authorization.
- When a client refreshes their access token, these claims are restored to the new token.
- Previously, refresh would mint a new access token with empty extra claims, so email/name were lost mid-session.

**Impact:** zero-breaking; improves user experience for MCP servers that authorize on email/name claims.

### Database Migrations

Upgrading to v0.0.14 triggers automatic schema migrations:

1. **`refresh_tokens.claims_json` column** (nullable, from commit 7f8045d):
   - Added on first sidecar startup if missing.
   - Existing refresh tokens have `NULL` claims_json; new ones are populated.

2. **No key versioning changes:** the encryption key format and usage are unchanged.

### Environment Variable Summary

| Variable | Default | New in v0.0.14 | Notes |
|----------|---------|----------------|-------|
| `BOUNCER_ENCRYPTION_KEY` | (required) | No | 32-byte base64-encoded key for AES-GCM. |
| `BOUNCER_DB_PATH` | `/data/bouncer.db` | No | SQLite database file. |
| `BOUNCER_LISTEN_ADDR` | `:8080` | No | Bind address (internal Docker network). |
| `BOUNCER_KEY_ROTATION_DAYS` | `30` | No | Days between signing key rotations. |
| `BOUNCER_KEY_OVERLAP_HOURS` | `24` | No | Hours old and new keys coexist. |
| `BOUNCER_ACCESS_TOKEN_TTL` | `1` (hour) | No | Access token validity period. |
| `BOUNCER_REFRESH_TOKEN_TTL` | `30` (days) | No | Refresh token validity period. |
| `BOUNCER_LOG_LEVEL` | `info` | No | Log level (debug, info, trace). |
| `BOUNCER_DCR_INITIAL_TOKEN` | (empty) | Yes | Bearer token for DCR authorization. Set for gated registration. |
| `BOUNCER_STRICT_UPSTREAM_REFRESH` | `false` | Yes | Validate refresh tokens upstream on each use. |

### Rollback

If v0.0.14 causes issues:

1. Downgrade the sidecar container to the previous version.
2. The database will continue to work (schema migrations are backward-compatible; the new `claims_json` column will be unused but not harmful).
3. Clients without secrets will work again (confidential clients will behave as if public).

## Earlier Versions

Earlier minor releases are not covered in this guide. Refer to Git history for details on versions prior to v0.0.14.

## Future / Planned Breaking Changes

### Issue #8: Key Versioning

**What:** allow multiple encryption keys to coexist so that old refresh tokens remain decryptable across key rotations.

**Breaking change:** the database schema and encryption key table will be restructured. A one-time migration will be required.

**Timeline:** TBD.

### Issue #9: Aud Claim RFC Compliance (Emitted, Not Yet Validated in Third-Party Servers)

**What:** the sidecar now emits `aud` as a JSON array (as of v0.0.14). Some third-party MCP servers may expect `aud` as a string.

**Breaking change:** MCP servers that parse the JWT's `aud` claim must update to handle both string and array forms.

**Timeline:** this is already shipped in v0.0.14. MCP server updates are on-demand; no forced upgrade.

## Migration Checklist

- [ ] Review the redirect URIs of all registered clients. Update any non-`https://` or non-`mcp://` schemes before upgrading.
- [ ] If you use confidential clients, ensure they provide the `client_secret` with all token requests.
- [ ] Test the upgrade in a staging environment with both old and new access tokens.
- [ ] Consider enabling `BOUNCER_DCR_INITIAL_TOKEN` in production (generates a random token and gates DCR).
- [ ] Consider enabling `BOUNCER_STRICT_UPSTREAM_REFRESH` if your IdP supports it.
- [ ] Update any custom MCP servers that parse the JWT's `aud` claim to handle both string and array forms.
- [ ] Plan for `BOUNCER_ENCRYPTION_KEY` rotation (manual process; not yet automated).

## Getting Help

For issues with upgrading, check:
- The sidecar logs: `docker logs <sidecar-container> | grep -i error`
- The plugin logs in Traefik: `docker logs <traefik-container> | grep mcpbouncer`
- The database integrity: `sqlite3 /path/to/bouncer.db ".schema"` (verify tables exist).
