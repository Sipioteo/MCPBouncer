# OAuth 2.1 / OIDC Flow

Complete end-to-end sequence of an MCP client authenticating with MCPBouncer and making authenticated calls to an MCP server.

In this example, the client targets `https://mcp.example.com/wiki`.

## Sequence diagram

```
Client                Traefik/Plugin          Sidecar             Upstream IdP
  │                         │                   │                     │
  ├─ GET /wiki/data ──────> │                   │                     │
  │  (no auth)              │ (intercept)       │                     │
  │                         │ return 401        │                     │
  │ <────── 401 ────────────┤                   │                     │
  │ WWW-Authenticate:...    │                   │                     │
  │                         │                   │                     │
  ├─ GET /wiki/.well-known/oauth-protected-resource                   │
  │  ─────────────────────> │                   │                     │
  │                         │ route to sidecar  │                     │
  │                         ├─ (with headers) ─>                      │
  │                         │                   │ return metadata     │
  │                         │ <─ return ────────┤                     │
  │ <─────── metadata ──────┤                   │                     │
  │ (resource=https://...)  │                   │                     │
  │                         │                   │                     │
  ├─ GET /wiki/.well-known/oauth-authorization-server                │
  │  ─────────────────────> │                   │                     │
  │                         │ route to sidecar  │                     │
  │                         ├─ (with headers) ─>                      │
  │                         │                   │ return endpoints    │
  │                         │ <─ return ────────┤                     │
  │ <─────── endpoints ─────┤                   │                     │
  │ (authorize, token, ...) │                   │                     │
  │                         │                   │                     │
  ├─ POST /wiki/oauth/register ──────────────> │                     │
  │  (client_name, redirect_uris)              │                     │
  │                         │ route to sidecar  │                     │
  │                         ├─ (with headers) ─>                      │
  │                         │                   │ DCR store           │
  │                         │ <─ client_id ─────┤                     │
  │ <──── client_id/secret──┤                   │                     │
  │                         │                   │                     │
  ├─ GET /wiki/oauth/authorize ────────────────┐                     │
  │   (client_id, redirect_uri, code_challenge,│ route to sidecar    │
  │    code_challenge_method=S256, state)      ├─────────────────> │
  │                         │                   │ validate PKCE       │
  │                         │                   │ generate state      │
  │                         │                   │ create session      │
  │                         │                   │ 302 to upstream... -─┼───> │
  │ <────────────────────── (302 + Location) ──┤                     │      login page
  │ (redirect_uri: upstream/authorize +        │                     │
  │  redirect_uri_sidecar: /wiki/oauth/callback)                     │
  │                         │                   │                     │
  ├─ User logs in to upstream IdP ───────────────────────────────────┤
  │                         │                   │                     │ auth
  │                         │                   │                     │ decision
  │ <──────────────────────────────────────────────────── 302 ────────┤
  │ (code + state back to /wiki/oauth/callback)                      │
  │                         │                   │                     │
  ├─ GET /wiki/oauth/callback?code=...&state=...                     │
  │  ──────────────────────> │                   │                     │
  │                         │ route to sidecar  │                     │
  │                         ├─ (with headers) ─>                      │
  │                         │                   │ validate state      │
  │                         │                   │ exchange code ──────> │
  │                         │                   │ for access+refresh    │
  │                         │                   │ <────── tokens ──────┤
  │                         │                   │ store refresh_enc    │
  │                         │                   │ generate local code  │
  │                         │ <─ 302 to client──┤                     │
  │ <────── 302 ────────────┤ (original         │                     │
  │ Location: redirect_uri?  │  redirect_uri +  │                     │
  │ code=<local_code>&state  │  local code)     │                     │
  │                         │                   │                     │
  ├─ POST /wiki/oauth/token ──────────────────>│                     │
  │  (code=<local_code>, code_verifier=...)    │ route to sidecar    │
  │                         ├─ (with headers) ─>                      │
  │                         │                   │ validate PKCE       │
  │                         │                   │ lookup code         │
  │                         │                   │ issue JWT           │
  │                         │ <─ JWT ───────────┤                     │
  │ <─────── JWT ───────────┤                   │                     │
  │ (access_token, ...)     │                   │                     │
  │                         │                   │                     │
  ├─ GET /wiki/data ──────> │                   │                     │
  │  Authorization: Bearer  │ (intercept)       │                     │
  │  <jwt>                  │ validate JWT      │                     │
  │                         │ check JWKS cache  │                     │
  │                         │ (miss → fetch from│ <─ JWKS ────────────┤
  │                         │  sidecar)         │ (if needed)         │
  │                         │ verify signature  │                     │
  │                         │ check aud/iss/exp │                     │
  │                         │ pass to upstream  │                     │
  │                         ├────────────────────> MCP server         │
  │                         │  (with X-Mcp-Sub, │                     │
  │                         │   X-Mcp-Scopes)   │                     │
  │                         │                   │                     │
  │ <─────── 200 OK ────────┤                   │                     │
  │ (data from MCP)         │  <── response ────┤                     │
```

## Key steps explained

### 1. Discovery (401 + WWW-Authenticate)

Client requests any path under `/wiki` without an `Authorization` header.

```
GET /wiki/data
```

Plugin intercepts, finds no bearer token, returns:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/wiki/.well-known/oauth-protected-resource"
Content-Type: application/json

{"error":"unauthorized"}
```

The `WWW-Authenticate` header tells the client where to fetch resource metadata (RFC 9728).

### 2. Resource metadata and provider discovery

Client fetches the resource metadata endpoint:

```
GET /wiki/.well-known/oauth-protected-resource
```

Plugin routes this to sidecar (path matches OAuth suffix). Plugin injects `X-MCPB-*` headers:

```
X-MCPB-Resource: wiki
X-MCPB-Public-Base: https://mcp.example.com/wiki
X-MCPB-Provider-Issuer: https://accounts.google.com
X-MCPB-Client-ID: (from label)
X-MCPB-Client-Secret: (from label)
X-MCPB-Scopes: openid email profile
X-MCPB-Audience: wiki
```

Sidecar returns (RFC 9728 format):

```json
{
  "resource": "https://mcp.example.com/wiki",
  "authorization_servers": ["https://mcp.example.com/wiki"],
  "bearer_methods_supported": ["header"],
  "resource_documentation": null
}
```

Client also fetches authorization server metadata:

```
GET /wiki/.well-known/oauth-authorization-server
```

Sidecar returns (RFC 8414 format):

```json
{
  "issuer": "https://mcp.example.com/wiki",
  "authorization_endpoint": "https://mcp.example.com/wiki/oauth/authorize",
  "token_endpoint": "https://mcp.example.com/wiki/oauth/token",
  "registration_endpoint": "https://mcp.example.com/wiki/oauth/register",
  "jwks_uri": "https://mcp.example.com/wiki/oauth/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  ...
}
```

### 3. Dynamic Client Registration (DCR)

Client registers with the sidecar:

```
POST /wiki/oauth/register
Content-Type: application/json

{
  "client_name": "MCP Client v1.0",
  "redirect_uris": ["mcp://localhost:5000/callback"],
  "response_types": ["code"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

Plugin routes to sidecar with headers.

Sidecar stores client in SQLite, returns:

```json
{
  "client_id": "d1234567890abcdef",
  "client_secret": "s9876543210fedcba",
  "redirect_uris": ["mcp://localhost:5000/callback"],
  "registration_access_token": "rat_..."
}
```

### 4. Authorization request with PKCE

Client initiates OAuth flow:

```
GET /wiki/oauth/authorize?
  response_type=code&
  client_id=d1234567890abcdef&
  redirect_uri=mcp://localhost:5000/callback&
  code_challenge=E9Mrozoa2owUednN87-7ZK50C3q0GmWTmes2rsQevKg&
  code_challenge_method=S256&
  scope=openid%20email&
  state=abcd1234
```

Plugin routes to sidecar with `X-MCPB-*` headers.

Sidecar:
1. Validates client_id and redirect_uri against DCR.
2. Validates PKCE code_challenge is present and S256 is the method (PKCE is mandatory).
3. Generates a server-side state and PKCE challenge for the upstream IdP.
4. Saves auth_session in SQLite with TTL 10 minutes.
5. Redirects client to Google:

```
HTTP/1.1 302 Found
Location: https://accounts.google.com/oauth/authorize?
  client_id=(google_client_id)&
  redirect_uri=https://mcp.example.com/wiki/oauth/callback&
  response_type=code&
  scope=openid%20email&
  code_challenge=(server_challenge)&
  code_challenge_method=S256&
  state=(server_state)
```

### 5. User authentication at upstream IdP

User logs in to Google. Google approves the scope request. Google redirects back to the sidecar:

```
GET /wiki/oauth/callback?
  code=google_auth_code&
  state=(server_state)
```

### 6. Token exchange upstream

Sidecar receives callback:
1. Validates state.
2. Exchanges code for access and refresh tokens at Google.
3. Decodes ID token to extract user claims (sub, email, etc.).
4. **Encrypts upstream refresh token** with AES-GCM and stores in SQLite.
5. Generates a local authorization code (random, >= 128 bits, 10-min TTL).
6. Redirects client back to its original redirect_uri with local code:

```
HTTP/1.1 302 Found
Location: mcp://localhost:5000/callback?
  code=(local_code)&
  state=abcd1234
```

### 7. Token endpoint (local JWT issuance)

Client redeems local code for JWT:

```
POST /wiki/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=(local_code)&
code_verifier=abc123...&
client_id=d1234567890abcdef&
client_secret=s9876543210fedcba
```

Sidecar:
1. Validates PKCE verifier against stored code_challenge.
2. Looks up local code, validates TTL.
3. Decrypts upstream refresh token from storage.
4. Issues a **local JWT** signed with sidecar's Ed25519 private key:

```json
{
  "iss": "https://mcp.example.com/wiki",
  "aud": "wiki",
  "sub": "google-user-id-123",
  "scope": "openid email",
  "iat": 1234567890,
  "exp": 1234571490,
  "kid": "abc123def456"
}
```

Returns:

```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_abc123...",
  "scope": "openid email"
}
```

### 8. Authenticated MCP call

Client calls MCP API with JWT:

```
GET /wiki/data
Authorization: Bearer eyJhbGc...
```

Plugin:
1. Extracts JWT from `Authorization: Bearer` header.
2. Decodes JWT, checks `kid` in header.
3. Fetches JWKS from sidecar (cached, TTL 5 min).
4. Verifies JWT signature with public key from JWKS.
5. Validates `iss == "https://mcp.example.com/wiki"`.
6. Validates `aud == "wiki"`.
7. Validates `exp` (with 60-second clock skew tolerance).
8. Checks `nbf` if present.
9. If configured with `requiredScopes`, validates scopes.
10. Extracts `sub` and `scope` from JWT.
11. Adds to request headers:
    - `X-Mcp-Sub: google-user-id-123`
    - `X-Mcp-Scopes: openid email`
12. Forwards to MCP server.

MCP server receives authenticated request with user context in headers:

```
GET /data
X-Mcp-Sub: google-user-id-123
X-Mcp-Scopes: openid email
```

Server can use these to enforce authorization logic.

### 9. Refresh token flow (optional)

Client's access token expires. Client reuses refresh token to get a new access token:

```
POST /wiki/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=refresh_abc123...&
client_id=d1234567890abcdef&
client_secret=s9876543210fedcba
```

Sidecar:
1. Validates refresh token (stored in SQLite, encrypted).
2. Optionally refreshes the upstream token (if expired).
3. Issues a new local JWT with updated `iat` and `exp`.

Returns new JWT and optionally new refresh token.

## Key rotation during flow

If the sidecar rotates keys while a client holds a JWT:

1. Sidecar creates new Ed25519 keypair, status="next", KID2.
2. After overlap period (default 24 hours), KID2 becomes "active", KID1 becomes "retiring".
3. Plugin fetches JWKS, sees both KID1 and KID2.
4. JWT signed with KID1 still validates (kid in header, public key in JWKS).
5. New JWTs are signed with KID2.
6. After all KID1 tokens expire, KID1 is removed from JWKS and database.

No disruption: old tokens work until expiry, new tokens use new key.
