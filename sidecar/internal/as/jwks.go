package as

import (
	"net/http"

	"github.com/sipiote/mcpbouncer-sidecar/internal/keys"
)

// HandleJWKS returns the publishable JWKS for the sidecar's signing keys.
// The same keypair is shared across all resources; the ?resource query parameter
// is accepted but ignored — JWKS keys are global.
func HandleJWKS(rotator *keys.Rotator, w http.ResponseWriter, r *http.Request) {
	pubKeys, err := rotator.AllPublishableKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to retrieve keys")
		return
	}
	jwks, err := keys.PublishableJWKS(pubKeys)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to build JWKS")
		return
	}
	writeJSON(w, http.StatusOK, jwks)
}
