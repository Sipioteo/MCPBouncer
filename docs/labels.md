# Plugin Label Reference

Each label is prefixed with `traefik.http.middlewares.<name>.plugin.mcpbouncer.` where `<name>` is your middleware identifier (e.g., `mcpb-wiki`).

## Required labels

### providerIssuer

**Type:** string  
**Default:** none (required)

OIDC issuer URL. The sidecar uses this to discover the upstream authorization server's endpoints via `.well-known/openid-configuration`.

**Examples:**
```
https://accounts.google.com
https://auth.example.com (Zitadel)
https://login.microsoftonline.com/common (Azure AD)
```

The sidecar will fetch and cache the discovery document from `{providerIssuer}/.well-known/openid-configuration`.

---

### clientID

**Type:** string  
**Default:** none (required)

OAuth 2.0 client ID registered at the upstream identity provider. The bouncer uses this to authenticate itself when exchanging authorization codes or refreshing tokens.

**Example:**
```
12345.apps.googleusercontent.com
```

For Zitadel:
```
268450265168027648@bouncer
```

---

### clientSecret

**Type:** string  
**Default:** none (required)

OAuth 2.0 client secret corresponding to `clientID`. Stored encrypted in the sidecar's SQLite database.

**Security note:** Provide this via environment variable interpolation in `docker-compose.yml`:
```yaml
labels:
  - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.clientSecret=${GOOGLE_CLIENT_SECRET}
```

Never hardcode secrets in labels or compose files checked into version control.

---

### resource

**Type:** string  
**Default:** none (required)

Resource name. Used as the OAuth 2.0 `aud` (audience) claim in issued JWTs and as the unique identifier for this MCP instance in the sidecar's database.

**Constraints:**
- Alphanumeric and hyphens only (validate before use).
- Must be unique across all MCPs served by the sidecar.
- Used in database tables and JWKS endpoints.

**Examples:**
```
wiki
world
api-docs
```

Token issued for `wiki` will not validate for `world` (audience check in the plugin).

---

### sidecarURL

**Type:** string  
**Default:** none (required)

Internal URL of the sidecar. Must be reachable from Traefik via Docker's internal network (not exposed to the internet).

**Format:**
```
http://<hostname>:<port>
```

**Examples:**
```
http://bouncer:8080
http://mcpbouncer.internal:8080
```

Typical setup: both Traefik and the sidecar are on the same Docker network (`edge` or `bouncer_internal`).

---

## Optional labels

### scopes

**Type:** string  
**Default:** (none; sidecar uses minimal defaults)

Space-separated list of OAuth 2.0 scopes to request from the upstream IdP. These are forwarded to the provider's authorization endpoint.

**Common values:**
```
openid email profile
openid email profile groups
offline_access openid email
```

If empty, the sidecar requests only `openid` from the upstream IdP.

**JWT scope claim:** The scopes granted by the upstream IdP are included in the local JWT as the `scope` claim. Clients can check this claim to determine what operations they are authorized for.

---

### audience

**Type:** string  
**Default:** same as `resource`

Alternative `aud` (audience) claim for JWTs. If not provided, `audience` defaults to the value of `resource`.

**Use case:** if you want the resource name in logs/database to differ from the audience claim, set this explicitly.

**Example:**
```yaml
labels:
  - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.resource=wiki-internal
  - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.audience=wiki-api
```

The JWT will have `aud: "wiki-api"` and the plugin will validate against `"wiki-api"`.

---

### jwksCacheTTLSeconds

**Type:** int  
**Default:** `300` (5 minutes)

Cache TTL for the sidecar's JWKS endpoint. The plugin fetches the sidecar's JWKS once per TTL period (or on-demand if a `kid` miss occurs).

**Valid range:** `10` to `3600` seconds (10 seconds to 1 hour).

**Tuning:**
- **Shorter TTL (10–60s):** More responsive to key rotation, higher load on sidecar.
- **Longer TTL (600–3600s):** Less frequent JWKS fetches, slightly stale keys during rotation (acceptable due to key overlap).

**Default (300s):** balances responsiveness and performance.

---

### requiredScopes

**Type:** string  
**Default:** (none; no scope enforcement)

Space-separated list of scopes that **must** be present in the JWT's `scope` claim for the request to be forwarded to the MCP.

If a scope is missing, the plugin returns `401 Unauthorized`.

**Example:**
```yaml
labels:
  - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.requiredScopes=admin write
```

If the JWT has `scope: "openid email admin"`, the request is forwarded (both `admin` and `write` are present — wait, `write` is not present, so 401).

Correct example:
```yaml
labels:
  - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.requiredScopes=admin
```

JWT with `scope: "openid email admin"` passes; JWT with `scope: "openid email"` is rejected.

---

## Complete example

Docker Compose with multiple MCPs and different IdPs:

```yaml
services:
  wiki-mcp:
    image: myorg/wiki-mcp:latest
    networks: [edge]
    labels:
      - traefik.enable=true
      - traefik.http.routers.wiki.rule=Host(`mcp.example.com`) && PathPrefix(`/wiki`)
      - traefik.http.routers.wiki.middlewares=mcpb-wiki@docker
      - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.providerIssuer=https://accounts.google.com
      - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.clientID=${GOOGLE_CLIENT_ID}
      - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.clientSecret=${GOOGLE_CLIENT_SECRET}
      - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.resource=wiki
      - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.scopes=openid email profile
      - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.sidecarURL=http://bouncer:8080
      - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.audience=wiki

  world-mcp:
    image: myorg/world-mcp:latest
    networks: [edge]
    labels:
      - traefik.enable=true
      - traefik.http.routers.world.rule=Host(`mcp.example.com`) && PathPrefix(`/world`)
      - traefik.http.routers.world.middlewares=mcpb-world@docker
      - traefik.http.middlewares.mcpb-world.plugin.mcpbouncer.providerIssuer=https://auth.zitadel.example.com
      - traefik.http.middlewares.mcpb-world.plugin.mcpbouncer.clientID=${ZITADEL_CLIENT_ID}
      - traefik.http.middlewares.mcpb-world.plugin.mcpbouncer.clientSecret=${ZITADEL_CLIENT_SECRET}
      - traefik.http.middlewares.mcpb-world.plugin.mcpbouncer.resource=world
      - traefik.http.middlewares.mcpb-world.plugin.mcpbouncer.scopes=openid email groups
      - traefik.http.middlewares.mcpb-world.plugin.mcpbouncer.sidecarURL=http://bouncer:8080
      - traefik.http.middlewares.mcpb-world.plugin.mcpbouncer.jwksCacheTTLSeconds=600

  bouncer:
    image: mcpbouncer/sidecar:latest
    networks: [edge]
    environment:
      - BOUNCER_ENCRYPTION_KEY=${BOUNCER_ENCRYPTION_KEY}
    volumes:
      - bouncer-data:/data

networks:
  edge:

volumes:
  bouncer-data:
```

Both MCPs are served by a single sidecar with different upstream IdPs. Clients authenticate against each independently.
