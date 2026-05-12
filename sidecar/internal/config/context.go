package config

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sipiote/mcpbouncer-sidecar/internal/crypto"
	"github.com/sipiote/mcpbouncer-sidecar/internal/store"
)

// ResourceConfig holds per-resource OAuth configuration extracted from X-MCPB-* headers.
type ResourceConfig struct {
	Name           string
	PublicBase     string
	ProviderIssuer string
	ClientID       string
	ClientSecret   string
	Scopes         string
	Audience       string
}

// FromRequest reads X-MCPB-* headers from r and returns a ResourceConfig.
// Returns an error if any required field is missing or empty.
func FromRequest(r *http.Request) (*ResourceConfig, error) {
	rc := &ResourceConfig{
		Name:           r.Header.Get("X-MCPB-Resource"),
		PublicBase:     r.Header.Get("X-MCPB-Public-Base"),
		ProviderIssuer: r.Header.Get("X-MCPB-Provider-Issuer"),
		ClientID:       r.Header.Get("X-MCPB-Client-ID"),
		ClientSecret:   r.Header.Get("X-MCPB-Client-Secret"),
		Scopes:         r.Header.Get("X-MCPB-Scopes"),
		Audience:       r.Header.Get("X-MCPB-Audience"),
	}

	for field, val := range map[string]string{
		"X-MCPB-Resource":        rc.Name,
		"X-MCPB-Public-Base":     rc.PublicBase,
		"X-MCPB-Provider-Issuer": rc.ProviderIssuer,
		"X-MCPB-Client-ID":       rc.ClientID,
		"X-MCPB-Client-Secret":   rc.ClientSecret,
		"X-MCPB-Scopes":          rc.Scopes,
		"X-MCPB-Audience":        rc.Audience,
	} {
		if val == "" {
			return nil, fmt.Errorf("config.FromRequest: missing required header %s", field)
		}
	}

	return rc, nil
}

// PersistEncrypted upserts this ResourceConfig into the store with ClientSecret AES-GCM encrypted.
func (rc *ResourceConfig) PersistEncrypted(ctx context.Context, s *store.Store, c *crypto.Cipher) error {
	enc, err := c.Encrypt([]byte(rc.ClientSecret))
	if err != nil {
		return fmt.Errorf("PersistEncrypted encrypt: %w", err)
	}
	return s.UpsertResourceConfig(ctx, store.ResourceConfig{
		Name:            rc.Name,
		ProviderIssuer:  rc.ProviderIssuer,
		ClientID:        rc.ClientID,
		ClientSecretEnc: enc,
		Scopes:          rc.Scopes,
		Audience:        rc.Audience,
		UpdatedAt:       time.Now(),
	})
}

// LoadResourceConfig loads a ResourceConfig from the store by name and decrypts the client secret.
func LoadResourceConfig(ctx context.Context, s *store.Store, c *crypto.Cipher, name string) (*ResourceConfig, error) {
	row, err := s.GetResourceConfig(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("LoadResourceConfig: %w", err)
	}
	if row == nil {
		return nil, nil
	}
	secret, err := c.Decrypt(row.ClientSecretEnc)
	if err != nil {
		return nil, fmt.Errorf("LoadResourceConfig decrypt: %w", err)
	}
	return &ResourceConfig{
		Name:           row.Name,
		ProviderIssuer: row.ProviderIssuer,
		ClientID:       row.ClientID,
		ClientSecret:   string(secret),
		Scopes:         row.Scopes,
		Audience:       row.Audience,
	}, nil
}
