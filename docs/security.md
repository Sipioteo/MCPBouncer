# Security Considerations

## Threat model and mitigation

### What MCPBouncer protects against

**Unauthenticated access to MCP servers.** MCPBouncer adds OAuth 2.1 and OIDC to servers that lack native support, making them require authentication before serving any content.

**Token spoofing.** JWT signatures are cryptographically verified by the plugin using the sidecar's JWKS endpoint. Clients cannot forge tokens without the sidecar's private key.

**Cross-resource token reuse.** Every JWT includes an `aud` (audience) claim matching the resource name. A token issued for `/wiki` will not validate for `/world`, even if the issuer is the same.

**Issuer impersonation.** The `iss` (issuer) claim is validated exactly against the public base URL. A token claiming to be from a different host or path is rejected.

**Replay attacks.** The `exp` (expiration) and optional `nbf` (not before) claims are validated. The plugin tolerates a 60-second clock skew for backward compatibility with slightly out-of-sync clocks, but beyond that, expired or not-yet-valid tokens are rejected.

**Client credential compromise (upstream).** If the upstream IdP's client secret (stored in Docker labels) is compromised, an attacker could impersonate the bouncer to the upstream IdP. However, they cannot directly forge tokens (the sidecar's keypair is separate). Rotate credentials immediately.

**Stolen refresh tokens.** Upstream refresh tokens are encrypted with AES-GCM at rest in the SQLite database using `BOUNCER_ENCRYPTION_KEY`. An attacker with database access but not the encryption key cannot extract tokens.

### What MCPBouncer does NOT protect against

**Compromise of the Docker host.** If the host is compromised, an attacker has access to environment variables, mounted volumes, database files, and memory. MCPBouncer provides no defense.

**Compromise of the upstream IdP.** If the upstream IdP (Google, Zitadel, etc.) is compromised or issues tokens to an attacker, MCPBouncer will accept those tokens as valid. Trust the IdP.

**Network eavesdropping between bouncer and IdP.** If TLS is not enforced for `providerIssuer` (https), tokens in transit can be intercepted. Always use HTTPS for IdP communication.

**MCP server logic bugs.** The bouncer adds authentication but does not validate that the MCP server correctly uses the `X-Mcp-Sub` and `X-Mcp-Scopes` headers for authorization. If the MCP server ignores these headers or has authorization bugs, MCPBouncer cannot prevent misuse.

**Malicious TLS termination proxy.** If a proxy between the client and Traefik intercepts TLS, it can steal tokens. Use TLS verification and certificate pinning for high-security scenarios.

## Encryption at rest

Sensitive data is encrypted with AES-GCM using the key specified in `BOUNCER_ENCRYPTION_KEY` before being written to the SQLite database:

- **Upstream refresh tokens** (in `codes` and `refresh_tokens` tables).
- **Resource configuration** (client secrets, stored for audit and recovery).

The encryption key must be:
- 32 bytes (256 bits) when base64-decoded.
- Generated cryptographically (e.g., `openssl rand -base64 32`).
- Stored securely (environment variable in Docker, secret in Kubernetes).
- Rotated every 90–180 days (requires key derivation or rotation logic; currently not automated).

**Note:** Database encryption is application-level. The SQLite file itself is not encrypted. To protect against physical theft of the disk, use full-disk encryption at the host or container level.

## Key rotation

The sidecar automatically rotates signing keys on a configurable schedule:

1. **Rotation interval** (`BOUNCER_KEY_ROTATION_DAYS`, default 30): every 30 days, a new Ed25519 keypair is generated and marked `status="next"`.
2. **Overlap period** (`BOUNCER_KEY_OVERLAP_HOURS`, default 24): after 24 hours, the new key becomes `status="active"` and the old key becomes `status="retiring"`.
3. **Retirement**: the retiring key remains in the JWKS and database until all issued tokens expire. It is then deleted.

**JWKS endpoint behavior during rotation:**
- Old (retiring) keys are published in `/oauth/jwks.json` with `alg: "EdDSA"`.
- New (active) keys are published.
- Pending (next) keys are not published until they become active.

**Token validation during rotation:**
- A token signed with the retiring key is valid if not expired (audience, issuer, and expiry all validated).
- A token signed with the active key is always valid (audience, issuer, expiry validated).
- A token signed with a key not in JWKS is rejected.

**Zero disruption:** clients with old tokens can refresh before expiry, or wait until the old key is retired. New clients immediately get tokens signed with the active key.

### Key rotation example

```
Day 0:
  - Sidecar starts, generates KEY1 (status="active")
  - /oauth/jwks.json returns [KEY1]

Day 30:
  - Rotation check runs, KEY1 is old
  - KEY2 is generated (status="next")
  - /oauth/jwks.json returns [KEY1]

Day 31 (after 24h overlap):
  - KEY2 status changed to "active"
  - KEY1 status changed to "retiring"
  - /oauth/jwks.json returns [KEY1, KEY2]

Day 60:
  - Next rotation check runs
  - KEY1 is expired + max_token_ttl (1h default), deleted
  - KEY3 is generated (status="next")
  - /oauth/jwks.json returns [KEY2]

Day 91 (after 24h overlap):
  - KEY3 becomes "active"
  - KEY2 becomes "retiring"
  - /oauth/jwks.json returns [KEY2, KEY3]
```

## PKCE enforcement

**PKCE (Proof Key for Code Exchange, RFC 7636) is mandatory.** The sidecar rejects any `/oauth/authorize` request without a `code_challenge` parameter or with `code_challenge_method` other than `S256`.

- No `code_challenge` → `400 Bad Request`.
- `code_challenge_method != "S256"` → `400 Bad Request`.

This prevents code interception attacks and is required by OAuth 2.1.

## JWT algorithm validation

Only the following algorithms are accepted for token verification:

- **EdDSA** (Ed25519, sidecar's default).
- **RS256** (RSA-2048+, for upstream IdP compatibility).

The algorithm `alg=none` is **explicitly rejected** (CVE-2015-9235 and variants). No signature-less tokens are accepted regardless of claims.

The plugin decodes the JWT header to extract `alg` and `kid`, then looks up the public key from JWKS and validates the signature using the correct algorithm.

## X-MCPB-* header stripping

The plugin strips all incoming `X-MCPB-*` headers from client requests before processing:

```go
for key := range r.Header {
    if strings.HasPrefix(strings.ToUpper(key), "X-MCPB-") {
        r.Header.Del(key)
    }
}
```

This prevents a malicious client from injecting headers that might influence the plugin's behavior. Configuration flows from Docker labels only, not from client requests.

## Sidecar network isolation

**The sidecar is never exposed externally.** It binds to an internal Docker network (e.g., `bouncer_internal`) and has no Traefik routing.

- No `traefik.enable=true` label on the sidecar container.
- No external hostname or port mapping.
- Only the plugin (Traefik middleware, in-process) can reach the sidecar via internal Docker DNS.

**Verification:**
```bash
# From outside the Docker network, this should fail or timeout:
curl http://bouncer:8080/oauth/jwks.json

# From inside (e.g., from the Traefik container):
curl http://bouncer:8080/oauth/jwks.json  # OK
```

If the sidecar is accidentally exposed (misconfigured port mapping or network), anyone can:
- Register arbitrary clients (DCR).
- Request authorization codes.
- Exchange codes for tokens.
- Perform key operations.

**Always verify network isolation.**

## TLS and certificate validation

**Use HTTPS in production.** All OAuth redirects and token endpoints must be served over TLS with valid certificates.

- Traefik should terminate TLS from clients using Let's Encrypt or similar.
- Communication between Traefik and upstream IdP should use HTTPS (enforced by RFC 8414; sidecar validates this).
- Communication between Traefik plugin and sidecar is on internal Docker network (no TLS needed, but host compromise is still a risk).

### Certificate validation

The sidecar uses Go's default TLS verification when contacting the upstream IdP (during OIDC discovery and token exchange). Standard CA bundles are used. Custom CAs can be supplied via environment or host-level trust stores.

## Scope validation

**Scope claim presence but not enforcement.** The plugin checks `scope` claim if configured with `requiredScopes`, but does not validate scope syntax or semantics beyond string matching.

- `requiredScopes=admin write` requires both `admin` and `write` to be present as space-separated tokens in the JWT's `scope` claim.
- The sidecar preserves the scopes granted by the upstream IdP in the JWT. If the upstream IdP is misconfigured or grants wrong scopes, the bouncer passes them through.

**MCP responsibility.** The MCP server should validate scopes for its business logic. The bouncer adds `X-Mcp-Scopes` header for the MCP's use, but does not enforce it.

## Recommendations

1. **Rotate encryption key every 90 days.** The database contains encrypted refresh tokens; key rotation limits exposure if the key is leaked. (Automated rotation is not yet implemented; manual process required.)

2. **TLS termination with real certificates.** Use Let's Encrypt in production. `mcp.localhost` with self-signed certs is fine for local dev with `traefik.local.yml`.

3. **Network segmentation.** Place the bouncer sidecar on a separate Docker network from external-facing services. Never expose the sidecar port to untrusted networks.

4. **Secret management.** Store `BOUNCER_ENCRYPTION_KEY` and IdP credentials (`clientSecret`) in a secret manager (Vault, AWS Secrets Manager, Kubernetes Secrets). Do not commit them to version control.

5. **Audit logging.** Enable `BOUNCER_LOG_LEVEL=debug` in testing to log all OAuth flows. In production, aggregate logs to detect abuse (many failed DCR attempts, repeated authorization failures, etc.).

6. **IdP credential rotation.** Rotate `clientID` and `clientSecret` at the IdP every 180 days. Update Docker compose/Kubernetes manifests atomically with the IdP rotation.

7. **Monitor token issuance.** The sidecar logs token exchanges. High-volume token requests or unusual `sub` claims can indicate token theft. Set up alerts.

8. **Disable JWKS caching in high-security scenarios.** Lower `jwksCacheTTLSeconds` (e.g., 60) to 1 minute for tight key rotation. Default 300s is reasonable for most deployments.

9. **Validate client `redirect_uri`.** DCR enforces that redirects are in the allowlist. Clients must be registered with exact redirect URIs. If a client is compromised and updates its redirect_uri via RFC 7592, re-authenticate and revoke old clients.

10. **Separate databases per environment.** Use different encryption keys and databases for dev, staging, and production. Do not share `BOUNCER_DB_PATH` across deployments.

## Common attack vectors

**Authorization code interception:**
- Mitigated by PKCE. The code is useless without the verifier.
- Also mitigated by short TTL (10 minutes) and single-use validation.

**Token theft (if TLS is broken):**
- Mitigated by short TTL (1 hour default) and refresh token encryption at rest.
- If bearer token is stolen, attacker has time window to make requests before expiry.
- Client should validate the token came from the correct issuer.

**Redirect URI mismatch:**
- Mitigated by validating against DCR allowlist.
- Upstream IdP also validates redirect URI.

**Man-in-the-middle between plugin and sidecar:**
- Not mitigated (no TLS between plugin and sidecar). Requires host/network security.
- Attacker could intercept X-MCPB-* headers and see client secrets.
- Docker network isolation mitigates this for normal deployments.

**JWT reuse across resources:**
- Mitigated by audience claim and plugin's `aud` validation.
- Token for `/wiki` has `aud=wiki`; plugin rejects it for `/world` which expects `aud=world`.
