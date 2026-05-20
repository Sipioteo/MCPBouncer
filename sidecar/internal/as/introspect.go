package as

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/config"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/keys"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/tokens"
)

// inactive is the RFC 7662 §2.2 response for any token that is not active.
// Per RFC 7662 §2.2 the server MUST NOT include additional information to
// prevent leaking whether the token existed.
var inactive = map[string]any{"active": false}

// HandleIntrospect implements RFC 7662 Token Introspection.
//
// Restriction: for access tokens the introspecting client_id MUST match the
// token's client_id claim. This prevents a resource server from introspecting
// tokens issued to a different client; the tradeoff is intentional — resource
// servers that need to validate arbitrary tokens should verify the JWT
// signature directly instead.
func HandleIntrospect(s *store.Store, rotator *keys.Rotator, rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "cannot parse form")
		return
	}

	// Authenticate the client — identical pattern to HandleToken / HandleRevoke.
	clientID, clientSecret, err := extractClientCredentials(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	client, err := s.GetClient(r.Context(), clientID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to look up client")
		return
	}
	if client == nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}

	// Confidential clients MUST supply their secret.
	if client.ClientSecretHash != "" {
		if clientSecret == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
			writeError(w, http.StatusUnauthorized, "invalid_client", "client_secret required")
			return
		}
		if sha256Hex(clientSecret) != client.ClientSecretHash {
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
			writeError(w, http.StatusUnauthorized, "invalid_client", "invalid client_secret")
			return
		}
	}

	token := r.FormValue("token")
	if token == "" {
		// RFC 7662 §2.1: token is required.
		writeJSON(w, http.StatusOK, inactive)
		return
	}

	hint := r.FormValue("token_type_hint")

	// When hint is "refresh_token" or absent, try the opaque refresh token store first.
	// When hint is "access_token" skip directly to JWT verification.
	if hint != "access_token" {
		hash := tokens.HashToken(token)
		rt, lookupErr := s.GetRefreshTokenByHash(r.Context(), hash)
		if lookupErr == nil && rt != nil {
			// Found in refresh token store.
			if time.Now().After(rt.ExpiresAt) {
				writeJSON(w, http.StatusOK, inactive)
				return
			}
			// Ownership check: token must belong to the authenticating client.
			if rt.ClientID != clientID {
				writeJSON(w, http.StatusOK, inactive)
				return
			}
			resp := map[string]any{
				"active":     true,
				"sub":        rt.Sub,
				"client_id":  rt.ClientID,
				"scope":      rt.Scopes,
				"exp":        rt.ExpiresAt.Unix(),
				"token_type": "refresh_token",
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		// Not a refresh token — fall through to JWT path (if hint was absent or unrecognised).
		if hint == "refresh_token" {
			writeJSON(w, http.StatusOK, inactive)
			return
		}
	}

	// --- Access token (JWT) path ---
	claims, jwtErr := verifyAccessJWT(r.Context(), token, rotator, rc)
	if jwtErr != nil {
		writeJSON(w, http.StatusOK, inactive)
		return
	}

	// Deliberate restriction: only the issuing client may introspect its own tokens.
	// Resource servers that need to verify arbitrary tokens should check the JWT
	// signature against the JWKS endpoint instead of using introspection.
	tokenClientID, _ := claims["client_id"].(string)
	if tokenClientID != clientID {
		writeJSON(w, http.StatusOK, inactive)
		return
	}

	resp := map[string]any{
		"active": true,
	}
	for _, field := range []string{"sub", "client_id", "scope", "exp", "iat", "iss", "jti"} {
		if v, ok := claims[field]; ok {
			resp[field] = v
		}
	}
	if aud, ok := claims["aud"]; ok {
		resp["aud"] = aud
	}
	writeJSON(w, http.StatusOK, resp)
}

// verifyAccessJWT parses and verifies an EdDSA JWT access token against
// the rotator's current publishable keys. It checks exp, nbf, iss, and aud.
func verifyAccessJWT(ctx context.Context, token string, rotator *keys.Rotator, rc *config.ResourceConfig) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed jwt")
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header decode: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("header parse: %w", err)
	}
	alg, _ := header["alg"].(string)
	if alg != "EdDSA" {
		return nil, fmt.Errorf("unsupported alg %q", alg)
	}
	kid, _ := header["kid"].(string)

	// Load publishable keys and find a match by kid.
	signingKeys, err := rotator.AllPublishableKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list signing keys: %w", err)
	}

	var pub ed25519.PublicKey
	for _, k := range signingKeys {
		if k.Kid != kid {
			continue
		}
		pub, err = decodePublicPEM(k.PublicPEM)
		if err != nil {
			return nil, fmt.Errorf("decode public key: %w", err)
		}
		break
	}
	if pub == nil {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}

	// Verify signature.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("sig decode: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(pub, signingInput, sig) {
		return nil, fmt.Errorf("signature invalid")
	}

	// Decode claims.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload decode: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("payload parse: %w", err)
	}

	now := time.Now().Unix()

	// Verify exp.
	if expRaw, ok := claims["exp"]; ok {
		switch e := expRaw.(type) {
		case float64:
			if now > int64(e) {
				return nil, fmt.Errorf("token expired")
			}
		}
	}

	// Verify nbf.
	if nbfRaw, ok := claims["nbf"]; ok {
		switch n := nbfRaw.(type) {
		case float64:
			if now < int64(n) {
				return nil, fmt.Errorf("token not yet valid")
			}
		}
	}

	// Verify iss.
	if iss, _ := claims["iss"].(string); iss != rc.PublicBase {
		return nil, fmt.Errorf("iss mismatch: got %q want %q", iss, rc.PublicBase)
	}

	// Verify aud contains the expected audience.
	expectedAud := rc.PublicBase + "/"
	if !audContains(claims["aud"], expectedAud) {
		return nil, fmt.Errorf("aud mismatch")
	}

	return claims, nil
}

func audContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func decodePublicPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not Ed25519 key")
	}
	return edPub, nil
}
