# Threat Model: MCPBouncer in a "Trusted Upstream IdP" Deployment

## What MCPBouncer Is

MCPBouncer is an OAuth 2.1 / OIDC reverse proxy that gates any MCP server behind an external identity provider. It consists of two components:

- **Traefik Plugin** (in-process middleware): intercepts requests, validates JWTs using cached JWKS, and forwards authenticated requests with user claims in `X-Mcp-Sub` and `X-Mcp-Scopes` headers.
- **Sidecar** (internal Docker service): handles the OAuth 2.1 authorization code flow, federates to an upstream IdP (Google, Zitadel, Keycloak, etc.), mints its own JWTs signed with an Ed25519 keypair, and stores encrypted refresh tokens in a local SQLite database.

MCPBouncer does not implement authorization logic; it only enforces authentication and passes through claims. Authorization decisions—who can access what—remain the responsibility of the MCP server and the upstream IdP.

## The "Trusted Upstream IdP with Gating" Deployment Pattern

This threat model assumes a specific, practical deployment:

1. **The upstream IdP enforces strict gating.** For example:
   - Google Workspace tenant restricted to `@company.com` domain (Google Workspace admin enforces domain-level sign-in).
   - Zitadel instance configured to allow sign-in only for a whitelist of users or organizations.
   - Keycloak realm with a custom authentication flow that blocks users outside an allowed group.

2. **All unknown users are rejected upstream.** The IdP does not issue tokens to users outside the allowed set, regardless of what the bouncer or client does.

3. **The bouncer itself is deployed on a trusted network.** The Docker host is managed by a trusted team; the sidecar is not exposed externally; communication between Traefik and sidecar uses an internal Docker network.

4. **TLS termination is in place.** External clients (e.g., Claude AI) reach Traefik over HTTPS with valid certificates (Let's Encrypt or similar). The IdP communication is also HTTPS.

In this deployment, MCPBouncer acts as a local authentication gateway that trusts the upstream IdP to have already performed the hard part of user vetting.

## What Becomes "Security Theater" (and Why It Still Matters)

### DCR (Dynamic Client Registration) Open Registration

**In a "gated IdP" deployment:** if the upstream IdP rejects all unknown users, an attacker cannot use DCR to register an arbitrary client and then authenticate as a compromised user. The attacker would still need valid credentials at the upstream IdP.

**However, open DCR still matters because:**

- An attacker with upstream credentials can register as many clients as desired, creating a stepping stone for lateral movement or reconnaissance.
- Logging DCR activity helps detect abuse (e.g., many failed client registrations, suspicious `redirect_uri` values).
- Credential compromise scenarios (e.g., a contractor's account is stolen) benefit from DCR hardening.

**Mitigation in MCPBouncer:** the `BOUNCER_DCR_INITIAL_TOKEN` environment variable allows operators to gate DCR with a static bearer token. In closed deployments, set this to a random secret; in development, leave it empty for open registration. This is optional but recommended for production.

### PKCE (Proof Key for Code Exchange)

**In a "gated IdP" deployment:** an attacker who intercepts an authorization code still cannot exchange it without the PKCE verifier (a strong random nonce). Even if the upstream IdP rejects the attacker, PKCE blocks code interception at the bouncer level.

**PKCE still matters because:**

- Defense in depth: if the upstream IdP is temporarily misconfigured or down (fallback behavior), PKCE protects against local code theft.
- PKCE is mandatory in OAuth 2.1; clients must implement it anyway.

**Mitigation in MCPBouncer:** PKCE with S256 is mandatory. The sidecar rejects `/oauth/authorize` without `code_challenge` or with `code_challenge_method` not equal to `S256`.

### Rate Limiting on Token Endpoint

**In a "gated IdP" deployment:** rate limiting on `POST /oauth/token` does not prevent credential stuffing (the upstream IdP already does that). However, it prevents resource exhaustion attacks (e.g., an attacker spamming `/token` to overwhelm the sidecar or database).

**Rate limiting still matters because:**

- Protects against denial-of-service (CPU, database contention).
- Slows down attackers probing for valid `client_id` values or testing stolen refresh tokens.

**Mitigation in MCPBouncer:** the sidecar does not implement request-level rate limiting; it relies on Traefik to do so. Operators should configure Traefik's rate limiter middleware on OAuth endpoints.

### Client Secret Enforcement

**In a "gated IdP" deployment:** a stolen `client_id` alone does not let an attacker authenticate because the upstream IdP rejects the attacker's credentials. However, client secrets protect against two scenarios:

- **Leaked `client_id` in logs or error messages:** a stolen `client_id` plus a default/guessed secret allows an attacker to exchange a code that they intercepted locally.
- **Compromise of the sidecar's database:** without the secret, someone with database access could register new clients or impersonate existing ones.

**Client secrets still matter because:**

- They are a standard OAuth 2.1 requirement for confidential clients (public clients, like browser apps, cannot have secrets).
- Hashing the secret in the database limits damage if the database is leaked.

**Mitigation in MCPBouncer:** confidential clients (those registered with `client_type=confidential`) are stored with a SHA256 hash of the secret. At token time, the sidecar enforces that the secret is provided via HTTP Basic auth and matches. Missing or wrong secret → `401 invalid_client`.

## What MCPBouncer Does NOT Do

1. **User-level authorization beyond claims propagation.** MCPBouncer does not implement RBAC, group checks, or resource-specific permissions. It extracts identity claims from the upstream IdP and passes them through as headers (`X-Mcp-Sub`, `X-Mcp-Scopes`) and JWT claims. The MCP server must decide whether to honor those claims.

2. **Replay protection for JWT access tokens.** JWTs are stateless; MCPBouncer does not track which tokens have been issued or revoked. A leaked access token is valid until expiry. Refresh token rotation (if enabled) mitigates this for long-lived sessions, but does not help if an AT is stolen mid-session.

3. **Rate limiting on upstream IdP calls.** The sidecar does not throttle requests to the upstream IdP. High-volume token exchanges will call the upstream's `/token` endpoint repeatedly. Operators should:
   - Rely on the upstream IdP's own rate limiting.
   - Monitor sidecar logs for abuse patterns (many failed token exchanges, unusual refresh rates).
   - Deploy Traefik's rate limiter for local protection.

4. **Key versioning or multi-version encryption.** When `BOUNCER_ENCRYPTION_KEY` is rotated, the old key's encrypted data (refresh tokens) becomes unreadable. MCPBouncer does not support key versioning. Planned for a future release (issue #8).

5. **Aud claim validation in third-party MCP servers.** The sidecar emits the `aud` claim as a JSON array (per RFC 7519). Some third-party MCP servers may expect `aud` as a string. These servers must be updated to handle both forms. The plugin validates `aud` correctly, but downstream services may not.

## Assumed Trust Boundaries

### Traefik Plugin ↔ Sidecar: Trusted Internal Socket

The plugin and sidecar communicate over an internal Docker network. This boundary assumes:

- The Docker daemon itself is not compromised.
- The network is not exposed to external clients.
- Requests in transit are visible to any process on the host (no TLS between plugin and sidecar).

**Implication:** an attacker with host access can intercept `X-MCPB-*` headers and inspect JWTs. This is acceptable because host compromise is out of scope. The plugin mitigates accidental leakage by stripping incoming `X-MCPB-*` headers.

### Sidecar ↔ Upstream IdP: HTTPS with Certificate Validation

The sidecar contacts the upstream IdP via HTTPS for discovery, token exchange, and userinfo requests. This boundary assumes:

- The upstream IdP's TLS certificate is valid and issued by a trusted CA.
- The sidecar's host CA bundle is current.
- The upstream IdP's hostname matches the `providerIssuer` URL.

**Implication:** an attacker who controls DNS (e.g., via BGP hijack or local hosts poisoning) could redirect the sidecar to a fake IdP. MCPBouncer does not support certificate pinning. For high-security deployments, operators can use a custom CA or host-level trust store.

### Sidecar ↔ SQLite: Local File System

The sidecar stores refresh tokens and key material in SQLite. This boundary assumes:

- The SQLite file has restrictive file permissions (readable only by the sidecar's user).
- The filesystem itself is not encrypted; full-disk encryption at the OS or container level is the operator's responsibility.

**Implication:** an attacker with filesystem access (via container escape or host compromise) can read the encrypted refresh tokens. If they also have the `BOUNCER_ENCRYPTION_KEY`, they can decrypt tokens and use them against the upstream IdP. If they lack the key, the tokens are still readable as binary blobs but useless without decryption.

## Threats MCPBouncer DOES Mitigate

### Code Injection via PKCE

**Threat:** an attacker intercepts the authorization code in transit (e.g., via DNS hijack, BGP hijack, or compromised network device) and attempts to exchange it for a token without the PKCE verifier.

**Mitigation:** the sidecar validates that the `code_verifier` provided at token time matches the SHA256 hash of the `code_challenge` from the authorize step. Without the verifier, the code is useless.

**Residual risk:** if the verifier is also stolen (or never was random), the code is compromisable. MCPBouncer assumes clients generate cryptographically random verifiers (64+ characters of base64url).

### Refresh Token Theft via Rotation and Hashing

**Threat:** a stale refresh token (from an old AT's storage or a failed token request) leaks and is used to mint new tokens indefinitely.

**Mitigation:** 
- Refresh tokens are encrypted at rest with AES-GCM.
- At issue time, a refresh token is valid for a configurable TTL (default 30 days).
- When a refresh token is used, MCPBouncer can be configured (via `BOUNCER_STRICT_UPSTREAM_REFRESH=true`) to validate the token against the upstream IdP's session. If the upstream IdP has revoked the session (e.g., the user changed their password), the refresh fails and a new authentication is required.
- Future releases will add a "rotation" mode where each refresh issues a new token and invalidates the old one.

**Residual risk:** if `BOUNCER_STRICT_UPSTREAM_REFRESH` is off (default for backward compat), a leaked refresh token remains valid until its TTL expires. If the upstream IdP does not support session validation, MCPBouncer cannot detect revocation.

### Redirect URI Spoofing via Allowlist Scheme Check

**Threat:** an attacker registers a malicious `redirect_uri` (e.g., `javascript://steal-code`) and tricks the upstream IdP into redirecting the user's code to attacker-controlled code.

**Mitigation:**
- All `redirect_uri` values are validated at DCR time (and at authorize time).
- Allowed schemes: `https`, `mcp`, and `http` (only for `localhost` / `127.0.0.1`).
- Explicitly forbidden: `javascript:`, `data:`, `file:`, `vbscript:`, `blob:`, `about:`.
- If validation fails, DCR returns `400 invalid_redirect_uri`.

**Residual risk:** an attacker can still register `https://attacker.com/callback` and hope to intercept the code if the client is careless. This is mitigated by PKCE; see above.

### JWT Alg Confusion via Explicit EdDSA-or-RS256 Only

**Threat:** an attacker crafts a JWT with `alg=none` (no signature) or `alg=HS256` (HMAC, which requires the shared secret) and bypasses verification.

**Mitigation:**
- The plugin explicitly checks the JWT header for `alg`.
- Only `EdDSA` (the sidecar's default) or `RS256` (for upstream IdP tokens) are accepted.
- `alg=none` is rejected outright.
- If the algorithm is not recognized or the signature does not validate, the JWT is rejected.

**Residual risk:** if a future PR adds a new algorithm without updating the validation logic, the risk reappears. This is a code review concern, not a runtime mitigation.

## Recommended Hardening Checklist for Operations

### Before Deployment

- [ ] Generate `BOUNCER_ENCRYPTION_KEY` with `openssl rand -base64 32`. Store in a secret manager (Vault, AWS Secrets Manager, K8s Secret).
- [ ] In production, set `BOUNCER_DCR_INITIAL_TOKEN` to a random secret. Example: `openssl rand -base64 32 | xargs echo`. Share only with authorized clients.
- [ ] Enable `BOUNCER_STRICT_UPSTREAM_REFRESH=true` if your IdP supports session validation (Zitadel does; Google doesn't via refresh tokens alone).
- [ ] Configure Traefik's rate limiter on `/oauth/token` (e.g., 10 requests per minute per client IP).
- [ ] Verify the sidecar is not accessible from outside the Docker network: `curl http://bouncer:8080/oauth/jwks.json` should fail from the host.

### During Operation

- [ ] Rotate `BOUNCER_ENCRYPTION_KEY` every 90 days. This requires a one-time key-derivation pass (not yet automated). Record the old key in case rollback is needed.
- [ ] Monitor sidecar logs for 401 spikes (sign of credential theft or upstream IdP misconfiguration).
- [ ] Monitor sidecar logs for repeated `invalid_redirect_uri` rejections (sign of DCR abuse).
- [ ] Enable `BOUNCER_LOG_LEVEL=debug` in development; use `BOUNCER_LOG_LEVEL=info` in production.
- [ ] Aggregate and alert on error logs from the sidecar.
- [ ] Periodically review the list of registered clients (`SELECT * FROM clients` in the database) for orphaned or suspicious entries.

### After Incidents

- [ ] If a client secret is leaked, reissue a new secret and delete the old client.
- [ ] If `BOUNCER_ENCRYPTION_KEY` is leaked, rotate it immediately and re-encrypt the database (manual process; not automated).
- [ ] If a user's upstream IdP session is compromised, the upstream IdP should revoke it. With `BOUNCER_STRICT_UPSTREAM_REFRESH=true`, the next refresh will fail. Without it, in-flight tokens remain valid until expiry.

## Conclusion

MCPBouncer is a pragmatic OAuth 2.1 / OIDC gateway designed for deployments where the upstream IdP is trusted to vet users. It does not implement fine-grained authorization, replay protection, or long-term key versioning. Within its scope, it provides:

- **Authentication enforcement** via OAuth 2.1 (PKCE, refresh token rotation, JWT validation).
- **Token isolation** via audience claims (a token for one resource cannot be used for another).
- **Encryption at rest** for sensitive data (refresh tokens).
- **Defense in depth** via client secrets and redirect URI validation.

Security posture depends on correct deployment (network isolation, TLS, secret management) and ongoing operations (key rotation, log monitoring). Operators must understand the threat model and configure the system accordingly.
