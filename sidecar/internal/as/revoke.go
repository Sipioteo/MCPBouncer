package as

import (
	"log/slog"
	"net/http"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/tokens"
)

// HandleRevoke handles POST /oauth/revoke (RFC 7009 Token Revocation).
func HandleRevoke(s *store.Store, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "cannot parse form")
		return
	}

	// Authenticate client — identical block to HandleToken.
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

	// Enforce client_secret for confidential clients (those with a stored hash).
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
		// RFC 7009 §2.1: token is required.
		writeError(w, http.StatusBadRequest, "invalid_request", "missing token")
		return
	}

	hint := r.FormValue("token_type_hint")

	switch hint {
	case "access_token":
		// JWTs are stateless; we have no revocation list for access tokens.
		// TODO: implement a JTI blacklist to support access-token revocation.
		w.WriteHeader(http.StatusOK)
		return
	default:
		// "refresh_token", absent, or any unrecognised hint: treat as refresh token.
		hash := tokens.HashToken(token)
		rt, lookupErr := s.GetRefreshTokenByHash(r.Context(), hash)
		if lookupErr != nil {
			// Log and still respond 200 per RFC 7009 §2.2.
			slog.Debug("revoke: GetRefreshTokenByHash error", "error", lookupErr)
			w.WriteHeader(http.StatusOK)
			return
		}
		if rt == nil {
			// Token not found — RFC says MUST NOT distinguish from "revoked".
			w.WriteHeader(http.StatusOK)
			return
		}
		// Verify ownership: token must belong to the authenticating client.
		if rt.ClientID != client.ClientID {
			slog.Debug("revoke: token belongs to different client, ignoring",
				"token_client", rt.ClientID,
				"req_client", client.ClientID,
			)
			// RFC 7009 §2.2: respond 200 but do not delete.
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = s.DeleteRefreshTokenByHash(r.Context(), hash)
		w.WriteHeader(http.StatusOK)
	}
}
