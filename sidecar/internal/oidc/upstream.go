package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Provider holds discovered OIDC provider metadata.
type Provider struct {
	Issuer           string
	AuthEndpoint     string
	TokenEndpoint    string
	UserinfoEndpoint string
	JWKSURI          string
}

// Manager handles OIDC provider discovery and token exchange with in-memory caching.
type Manager struct {
	httpClient *http.Client
	cache      map[string]*Provider
	mu         sync.RWMutex
}

// NewManager creates a new Manager with a 10s HTTP timeout.
func NewManager() *Manager {
	return &Manager{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      make(map[string]*Provider),
	}
}

// Discover fetches and caches the OIDC configuration for the given issuer.
func (m *Manager) Discover(ctx context.Context, issuer string) (*Provider, error) {
	m.mu.RLock()
	if p, ok := m.cache[issuer]; ok {
		m.mu.RUnlock()
		return p, nil
	}
	m.mu.RUnlock()

	wellKnown := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("Discover new request: %w", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Discover fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Discover: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("Discover read: %w", err)
	}

	var meta struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("Discover parse: %w", err)
	}

	if meta.Issuer != issuer {
		return nil, fmt.Errorf("Discover: issuer mismatch: got %q, want %q", meta.Issuer, issuer)
	}

	p := &Provider{
		Issuer:           meta.Issuer,
		AuthEndpoint:     meta.AuthorizationEndpoint,
		TokenEndpoint:    meta.TokenEndpoint,
		UserinfoEndpoint: meta.UserinfoEndpoint,
		JWKSURI:          meta.JWKSURI,
	}

	m.mu.Lock()
	m.cache[issuer] = p
	m.mu.Unlock()

	return p, nil
}

// TokenResponse holds the response from a token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
}

// ExchangeCode exchanges an authorization code for tokens using client_secret_post auth.
func (m *Manager) ExchangeCode(ctx context.Context, p *Provider, clientID, clientSecret, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if codeVerifier != "" {
		params.Set("code_verifier", codeVerifier)
	}
	return m.postToken(ctx, p.TokenEndpoint, params)
}

// RefreshTokens refreshes tokens using a refresh token.
func (m *Manager) RefreshTokens(ctx context.Context, p *Provider, clientID, clientSecret, refreshToken string) (*TokenResponse, error) {
	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	return m.postToken(ctx, p.TokenEndpoint, params)
}

func (m *Manager) postToken(ctx context.Context, endpoint string, params url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("postToken new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("postToken do: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("postToken read: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("postToken: status %d: %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("postToken parse: %w", err)
	}
	return &tr, nil
}

// Userinfo fetches user claims from the userinfo endpoint. Returns empty map if endpoint absent.
func (m *Manager) Userinfo(ctx context.Context, p *Provider, accessToken string) (map[string]any, error) {
	if p.UserinfoEndpoint == "" {
		return map[string]any{}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("Userinfo new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Userinfo do: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("Userinfo read: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return map[string]any{}, nil
	}

	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return map[string]any{}, nil
	}
	return claims, nil
}

// DecodeIDToken splits a JWT and decodes the payload claims without verifying the signature.
// Trust assumption: we trust the token was received over HTTPS from a known issuer endpoint,
// so signature verification is not performed here. Callers should not use this for authorization
// decisions beyond extracting opaque user identifiers (sub, email) returned by the IdP.
func DecodeIDToken(idToken string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("DecodeIDToken: malformed JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("DecodeIDToken decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("DecodeIDToken parse claims: %w", err)
	}
	return claims, nil
}
