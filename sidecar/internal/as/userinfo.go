package as

import (
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
)

// profileClaims is the set of identity claims we will echo back from the JWT.
var profileClaims = map[string]bool{
	"sub":                true,
	"email":              true,
	"email_verified":     true,
	"name":               true,
	"given_name":         true,
	"family_name":        true,
	"picture":            true,
	"locale":             true,
	"preferred_username": true,
	"hd":                 true,
}

// HandleUserinfo handles GET/POST /oauth/userinfo per OIDC Core §5.3.
// It accepts a Bearer JWT minted by this server, verifies it, and returns
// the profile claims that were embedded in it.
func HandleUserinfo(s *store.Store, rotator *keys.Rotator, rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	// Extract Bearer token.
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oauth", error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "missing Authorization header")
		return
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oauth", error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "Authorization scheme must be Bearer")
		return
	}
	rawToken := strings.TrimPrefix(authHeader, prefix)
	if rawToken == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oauth", error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "empty Bearer token")
		return
	}

	// Build key-lookup function from the rotator's publishable keys.
	signingKeys, err := rotator.AllPublishableKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load signing keys")
		return
	}
	keyMap := make(map[string]ed25519.PublicKey, len(signingKeys))
	for _, k := range signingKeys {
		pub, parseErr := parseEd25519PublicPEM(k.PublicPEM)
		if parseErr != nil {
			continue
		}
		keyMap[k.Kid] = pub
	}

	getKey := func(kid, alg string) (interface{}, error) {
		if alg != "EdDSA" {
			return nil, fmt.Errorf("unsupported alg %q", alg)
		}
		if kid == "" {
			// If no kid, try active key.
			active, _, err := rotator.ActiveKey(r.Context())
			if err != nil {
				return nil, fmt.Errorf("no kid and no active key: %w", err)
			}
			pub, ok := keyMap[active.Kid]
			if !ok {
				return nil, fmt.Errorf("active key not found in publishable set")
			}
			return pub, nil
		}
		pub, ok := keyMap[kid]
		if !ok {
			return nil, fmt.Errorf("unknown kid %q", kid)
		}
		return pub, nil
	}

	claims, err := verifyLocalJWT(rawToken, getKey)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oauth", error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "token verification failed: "+err.Error())
		return
	}

	// Validate standard time claims.
	now := time.Now().Unix()
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < now {
			w.Header().Set("WWW-Authenticate", `Bearer realm="oauth", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", "token expired")
			return
		}
	}
	if nbf, ok := claims["nbf"].(float64); ok {
		if int64(nbf) > now {
			w.Header().Set("WWW-Authenticate", `Bearer realm="oauth", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", "token not yet valid")
			return
		}
	}
	// Validate issuer.
	if iss, ok := claims["iss"].(string); ok && iss != rc.PublicBase {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oauth", error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "invalid issuer")
		return
	}

	// Build profile response: only profile-style claims.
	profile := make(map[string]any)
	for k, v := range claims {
		if profileClaims[k] {
			profile[k] = v
		}
	}

	writeJSON(w, http.StatusOK, profile)
}

// verifyLocalJWT parses and verifies a compact JWT using getKey for key lookup.
// It handles EdDSA only (our sidecar only mints EdDSA). Replicates the pattern
// from plugin/jwt_verify.go without importing the plugin module.
func verifyLocalJWT(token string, getKey func(kid, alg string) (interface{}, error)) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 parts")
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header decode: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("header parse: %w", err)
	}
	alg, _ := header["alg"].(string)
	switch alg {
	case "":
		return nil, fmt.Errorf("missing alg")
	case "none":
		return nil, fmt.Errorf("alg=none not allowed")
	case "EdDSA":
		// ok
	default:
		return nil, fmt.Errorf("unsupported alg %q", alg)
	}
	kid, _ := header["kid"].(string)

	pub, err := getKey(kid, alg)
	if err != nil {
		return nil, fmt.Errorf("key lookup: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519.PublicKey for EdDSA")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("signature decode: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(edPub, signingInput, sig) {
		return nil, fmt.Errorf("EdDSA signature invalid")
	}

	// Decode payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload decode: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("payload parse: %w", err)
	}
	return claims, nil
}

// parseEd25519PublicPEM decodes a PEM-encoded PKIX Ed25519 public key.
func parseEd25519PublicPEM(pemBytes []byte) (ed25519.PublicKey, error) {
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
		return nil, fmt.Errorf("not Ed25519, got %T", pub)
	}
	return edPub, nil
}
