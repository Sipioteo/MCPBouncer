package tokens

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/config"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/keys"
)

// Issuer mints local JWTs and opaque refresh tokens.
type Issuer struct {
	rotator    *keys.Rotator
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewIssuer creates a new Issuer.
func NewIssuer(rotator *keys.Rotator, accessTTL, refreshTTL time.Duration) *Issuer {
	return &Issuer{rotator: rotator, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

// MintAccessToken creates a signed EdDSA JWT access token.
func (i *Issuer) MintAccessToken(ctx context.Context, rc *config.ResourceConfig, sub, scopes string, extraClaims map[string]any) (token string, expiresAt time.Time, err error) {
	k, priv, err := i.rotator.ActiveKey(ctx)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("MintAccessToken: %w", err)
	}

	now := time.Now()
	exp := now.Add(i.accessTTL)

	jtiBytes := make([]byte, 16)
	if _, readErr := io.ReadFull(rand.Reader, jtiBytes); readErr != nil {
		return "", time.Time{}, fmt.Errorf("MintAccessToken jti: %w", readErr)
	}
	jti := hex.EncodeToString(jtiBytes)

	headerJSON, err := json.Marshal(map[string]string{
		"alg": "EdDSA",
		"typ": "JWT",
		"kid": k.Kid,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("MintAccessToken header marshal: %w", err)
	}

	// aud MUST be the resource URI (RFC 8707 + MCP auth spec).
	// The client compares aud against the "resource" field in
	// /.well-known/oauth-protected-resource, which is always the publicBase.
	claims := map[string]any{
		"iss":   rc.PublicBase,
		"aud":   rc.PublicBase,
		"sub":   sub,
		"scope": scopes,
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   exp.Unix(),
		"jti":   jti,
	}
	for kk, v := range extraClaims {
		if _, exists := claims[kk]; !exists {
			claims[kk] = v
		}
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("MintAccessToken claims marshal: %w", err)
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsEnc := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerEnc + "." + claimsEnc

	sig := ed25519.Sign(priv, []byte(signingInput))
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigEnc, exp, nil
}

// AccessTTL returns the configured access token TTL.
func (i *Issuer) AccessTTL() time.Duration { return i.accessTTL }

// RefreshTTL returns the configured refresh token TTL.
func (i *Issuer) RefreshTTL() time.Duration { return i.refreshTTL }

// MintRefreshToken generates a new opaque refresh token.
// Returns raw (to send to client), hash (to store), and expiry.
func (i *Issuer) MintRefreshToken() (raw string, hash string, expiresAt time.Time, err error) {
	b := make([]byte, 32)
	if _, readErr := io.ReadFull(rand.Reader, b); readErr != nil {
		return "", "", time.Time{}, fmt.Errorf("MintRefreshToken: %w", readErr)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	hash = HashToken(raw)
	expiresAt = time.Now().Add(i.refreshTTL)
	return raw, hash, expiresAt, nil
}

// HashToken returns the SHA-256 hex digest of raw.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
