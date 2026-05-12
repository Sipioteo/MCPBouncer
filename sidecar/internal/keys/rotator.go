package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/sipiote/mcpbouncer-sidecar/internal/store"
)

type Rotator struct {
	store            *store.Store
	rotationInterval time.Duration
	overlap          time.Duration
	maxTokenTTL      time.Duration
	now              func() time.Time
}

func New(s *store.Store, rotationInterval, overlap, maxTokenTTL time.Duration) *Rotator {
	return &Rotator{
		store:            s,
		rotationInterval: rotationInterval,
		overlap:          overlap,
		maxTokenTTL:      maxTokenTTL,
		now:              time.Now,
	}
}

func (r *Rotator) Ensure(ctx context.Context) error {
	active, err := r.store.GetActiveSigningKey(ctx)
	if err != nil {
		return fmt.Errorf("Ensure: %w", err)
	}
	if active != nil {
		return nil
	}
	privPEM, pubPEM, kid, err := generateEd25519()
	if err != nil {
		return fmt.Errorf("Ensure generate: %w", err)
	}
	retiresAt := r.now().Add(r.rotationInterval + r.maxTokenTTL + 48*time.Hour)
	return r.store.InsertSigningKey(ctx, kid, "EdDSA", privPEM, pubPEM, retiresAt, "active")
}

func (r *Rotator) Run(ctx context.Context) error {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			if err := r.rotate(ctx); err != nil {
				// log and continue; non-fatal
				_ = err
			}
		}
	}
}

func (r *Rotator) rotate(ctx context.Context) error {
	now := r.now()
	keys, err := r.store.ListSigningKeys(ctx)
	if err != nil {
		return fmt.Errorf("rotate list: %w", err)
	}

	var active, next *store.SigningKey
	for i := range keys {
		switch keys[i].Status {
		case "active":
			active = &keys[i]
		case "next":
			next = &keys[i]
		}
	}

	// Promote next → active if overlap has passed.
	if active != nil && next != nil {
		if next.CreatedAt.Add(r.overlap).Before(now) {
			retiresAt := now.Add(r.maxTokenTTL + time.Hour)
			if err := r.store.UpdateSigningKeyStatus(ctx, active.Kid, "retiring", retiresAt); err != nil {
				return fmt.Errorf("rotate retire old: %w", err)
			}
			if err := r.store.UpdateSigningKeyStatus(ctx, next.Kid, "active", next.RetiresAt); err != nil {
				return fmt.Errorf("rotate promote next: %w", err)
			}
			active = next
			next = nil
		}
	}

	// Generate next key if active is old enough and no next exists.
	if active != nil && next == nil {
		if active.CreatedAt.Add(r.rotationInterval).Before(now) {
			privPEM, pubPEM, kid, err := generateEd25519()
			if err != nil {
				return fmt.Errorf("rotate generate: %w", err)
			}
			retiresAt := now.Add(r.rotationInterval + r.maxTokenTTL + 48*time.Hour)
			if err := r.store.InsertSigningKey(ctx, kid, "EdDSA", privPEM, pubPEM, retiresAt, "next"); err != nil {
				return fmt.Errorf("rotate insert next: %w", err)
			}
		}
	}

	return r.store.DeleteExpiredSigningKeys(ctx)
}

func (r *Rotator) ActiveKey(ctx context.Context) (*store.SigningKey, ed25519.PrivateKey, error) {
	k, err := r.store.GetActiveSigningKey(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("ActiveKey: %w", err)
	}
	if k == nil {
		return nil, nil, fmt.Errorf("ActiveKey: no active key")
	}
	priv, err := decodePrivatePEM(k.PrivatePEM)
	if err != nil {
		return nil, nil, fmt.Errorf("ActiveKey decode: %w", err)
	}
	return k, priv, nil
}

func (r *Rotator) AllPublishableKeys(ctx context.Context) ([]store.SigningKey, error) {
	return r.store.ListSigningKeys(ctx)
}

// generateEd25519 creates a new Ed25519 keypair and returns PEM-encoded keys and a kid.
func generateEd25519() (privPEM, pubPEM []byte, kid string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generateEd25519: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generateEd25519 marshal priv: %w", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generateEd25519 marshal pub: %w", err)
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	h := sha256.Sum256(pubPEM)
	kid = hex.EncodeToString(h[:8])

	return privPEM, pubPEM, kid, nil
}

func decodePrivatePEM(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("decodePrivatePEM: no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("decodePrivatePEM parse: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("decodePrivatePEM: not Ed25519")
	}
	return priv, nil
}
