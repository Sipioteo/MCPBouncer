# Security Policy

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Please report them via GitHub Security Advisories:
[https://github.com/Sipioteo/MCPBouncer/security/advisories/new](https://github.com/Sipioteo/MCPBouncer/security/advisories/new)

Include a description of the issue, reproduction steps, and any relevant version information.

## Response Time

Acknowledgment within **72 hours** on a best-effort basis. We will keep you updated as we triage and work toward a fix.

## Supported Versions

We actively support the most recent minor release of each module:

| Module  | Supported tag pattern |
|---------|----------------------|
| Plugin  | `plugin-v*` (latest minor) |
| Sidecar | `sidecar-v*` (latest minor) |

Older minor versions do not receive security backports.

## Scope

This policy covers code in the **Sipioteo/MCPBouncer** repository.

**Out of scope:**
- Vulnerabilities in upstream OIDC/OAuth providers (Zitadel, Google, Okta, etc.)
- Vulnerabilities in Traefik itself
- Vulnerabilities in MCP client implementations
- Third-party dependencies (please report those upstream)
