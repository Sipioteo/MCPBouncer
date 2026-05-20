// Package crypto provides AES-256-GCM encryption with key versioning.
//
// Ciphertext formats:
//
//  1. Legacy (pre-versioning): nonce(12) || ciphertext || tag.
//     Produced by older builds that used a single env-derived key.
//
//  2. Versioned: 0xC1 0x70 || key_id_len(uint8) || key_id (UTF-8) ||
//     nonce(12) || ciphertext || tag.
//     The two-byte magic 0xC1 0x70 disambiguates from legacy ciphertexts;
//     key_id is additionally constrained to [A-Za-z0-9_-]{1,63}.
//
// All new encryptions emit format (2) using the active key from the
// encryption_keys table. Decryption sniffs the magic and falls back to
// the bootstrap (env) key for legacy ciphertexts.
package crypto

import (
	"context"
	"crypto/aes"
	gocrypto "crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
)

// Magic bytes for versioned ciphertext. Two random bytes colliding with this
// in a legacy nonce is 1/65536; we additionally validate key_id format.
var versionedMagic = [2]byte{0xC1, 0x70}

// bootstrapKeyID is the key_id assigned to the env-derived key on first boot.
const bootstrapKeyID = "k1"

// keyIDPattern bounds the on-the-wire key_id alphabet so legacy ciphertexts
// whose first bytes happen to match the magic can be rejected cleanly.
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)

// Cipher performs AES-256-GCM encryption with key versioning.
//
// New ciphertexts are produced with the active key and the versioned format.
// On decryption, the version magic is sniffed: versioned ciphertexts are
// decrypted with the embedded key_id (looked up in the keys map); legacy
// ciphertexts (no magic) are decrypted with the bootstrap key.
type Cipher struct {
	mu       sync.RWMutex
	keys     map[string]gocrypto.AEAD // key_id -> AEAD (all DB keys, active + retired)
	activeID string                   // key_id used for new encryptions
	legacy   gocrypto.AEAD            // bootstrap env-derived key, used for legacy ciphertexts
}

// NewCipher builds an in-memory Cipher seeded only by the bootstrap env key,
// without any database backing. Encryption uses the bootstrap key (treated as
// active under id "k1"); decryption also accepts legacy ciphertexts encrypted
// with the same material.
//
// This constructor is intended for tests and lightweight tools. Production
// code should use NewCipherWithStore so that rotated keys persist.
func NewCipher(keyBase64 string) (*Cipher, error) {
	aead, err := aeadFromBase64(keyBase64)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		keys:     map[string]gocrypto.AEAD{bootstrapKeyID: aead},
		activeID: bootstrapKeyID,
		legacy:   aead,
	}, nil
}

// NewCipherWithStore builds a Cipher backed by the encryption_keys table.
//
// Behavior:
//   - If the table is empty (first boot after upgrade or fresh install), the
//     bootstrap env key is derived, stored as key_id="k1" with status="active",
//     and used for new encryptions.
//   - If the table is non-empty, all rows are loaded into the in-memory map
//     (active + retired, so both still decrypt). The row with status="active"
//     is used for new encryptions. The bootstrap env key is loaded as the
//     legacy-decryption fallback only (never used for new encryptions). This
//     lets operators rotate by adding a new active row in the table while
//     existing legacy ciphertexts (and any with key_id="k1" matching the env
//     material) still decrypt.
func NewCipherWithStore(ctx context.Context, s *store.Store, bootstrapKeyBase64 string) (*Cipher, error) {
	legacyAEAD, err := aeadFromBase64(bootstrapKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("NewCipherWithStore bootstrap: %w", err)
	}

	rows, err := s.ListEncryptionKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewCipherWithStore list: %w", err)
	}

	c := &Cipher{
		keys:   make(map[string]gocrypto.AEAD),
		legacy: legacyAEAD,
	}

	if len(rows) == 0 {
		// First boot: persist the bootstrap key as the active key under "k1".
		mat, err := decodeKeyMaterial(bootstrapKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("NewCipherWithStore decode bootstrap: %w", err)
		}
		if err := s.InsertEncryptionKey(ctx, store.EncryptionKey{
			KeyID:     bootstrapKeyID,
			Material:  mat,
			Status:    "active",
			CreatedAt: time.Now(),
		}); err != nil {
			return nil, fmt.Errorf("NewCipherWithStore seed: %w", err)
		}
		c.keys[bootstrapKeyID] = legacyAEAD
		c.activeID = bootstrapKeyID
		return c, nil
	}

	for _, row := range rows {
		if !keyIDPattern.MatchString(row.KeyID) {
			return nil, fmt.Errorf("NewCipherWithStore: invalid key_id %q in DB", row.KeyID)
		}
		aead, err := aeadFromRaw(row.Material)
		if err != nil {
			return nil, fmt.Errorf("NewCipherWithStore load %s: %w", row.KeyID, err)
		}
		c.keys[row.KeyID] = aead
		if row.Status == "active" {
			if c.activeID != "" {
				return nil, fmt.Errorf("NewCipherWithStore: multiple active keys (%s, %s)", c.activeID, row.KeyID)
			}
			c.activeID = row.KeyID
		}
	}
	if c.activeID == "" {
		return nil, fmt.Errorf("NewCipherWithStore: no active key in encryption_keys")
	}
	return c, nil
}

// Encrypt produces a versioned ciphertext using the active key.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	c.mu.RLock()
	aead := c.keys[c.activeID]
	id := c.activeID
	c.mu.RUnlock()
	if aead == nil {
		return nil, fmt.Errorf("Encrypt: no active key")
	}
	if !keyIDPattern.MatchString(id) {
		return nil, fmt.Errorf("Encrypt: invalid active key_id %q", id)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("Encrypt nonce: %w", err)
	}

	idBytes := []byte(id)
	// header = magic(2) || key_id_len(1) || key_id
	header := make([]byte, 0, 3+len(idBytes))
	header = append(header, versionedMagic[0], versionedMagic[1], byte(len(idBytes)))
	header = append(header, idBytes...)

	// Allocate: header || nonce || ciphertext+tag.
	out := make([]byte, 0, len(header)+len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, header...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// Decrypt accepts both versioned and legacy ciphertexts.
func (c *Cipher) Decrypt(blob []byte) ([]byte, error) {
	if id, nonce, ct, ok := parseVersioned(blob); ok {
		c.mu.RLock()
		aead := c.keys[id]
		c.mu.RUnlock()
		if aead == nil {
			return nil, fmt.Errorf("Decrypt: unknown key_id %q", id)
		}
		pt, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return nil, fmt.Errorf("Decrypt versioned: %w", err)
		}
		return pt, nil
	}

	// Legacy path.
	if c.legacy == nil {
		return nil, fmt.Errorf("Decrypt: no legacy key available")
	}
	ns := c.legacy.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("Decrypt legacy: blob too short")
	}
	nonce, ct := blob[:ns], blob[ns:]
	pt, err := c.legacy.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("Decrypt legacy: %w", err)
	}
	return pt, nil
}

// parseVersioned attempts to read a versioned-ciphertext header. Returns
// (key_id, nonce, ciphertext+tag, true) on success; (_, _, _, false) when the
// blob is not a versioned ciphertext and should be tried as legacy.
//
// "Not versioned" covers: blob too short for the magic; magic mismatch;
// length byte out of range; key_id fails the alphabet check; remaining bytes
// too short for a nonce. Any of these falls back to the legacy path.
func parseVersioned(blob []byte) (string, []byte, []byte, bool) {
	const nonceSize = 12 // AES-GCM standard nonce size; verified below against legacy too.
	if len(blob) < 3 {
		return "", nil, nil, false
	}
	if blob[0] != versionedMagic[0] || blob[1] != versionedMagic[1] {
		return "", nil, nil, false
	}
	idLen := int(blob[2])
	if idLen < 1 || idLen > 63 {
		return "", nil, nil, false
	}
	if len(blob) < 3+idLen+nonceSize {
		return "", nil, nil, false
	}
	id := string(blob[3 : 3+idLen])
	if !keyIDPattern.MatchString(id) {
		return "", nil, nil, false
	}
	nonce := blob[3+idLen : 3+idLen+nonceSize]
	ct := blob[3+idLen+nonceSize:]
	return id, nonce, ct, true
}

// ActiveKeyID returns the key_id currently used for new encryptions.
// Exposed primarily for tests and diagnostics.
func (c *Cipher) ActiveKeyID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.activeID
}

// RandomKey returns a fresh 32-byte AES-256 key encoded as standard base64.
func RandomKey() string {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// decodeKeyMaterial parses one of the accepted base64 flavors and returns
// the raw 32-byte material.
func decodeKeyMaterial(keyBase64 string) ([]byte, error) {
	keyBase64 = strings.TrimSpace(keyBase64)
	candidates := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range candidates {
		key, err := enc.DecodeString(keyBase64)
		if err == nil {
			if len(key) != 32 {
				return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
			}
			return key, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("decode key: %w", lastErr)
}

func aeadFromBase64(keyBase64 string) (gocrypto.AEAD, error) {
	key, err := decodeKeyMaterial(keyBase64)
	if err != nil {
		return nil, err
	}
	return aeadFromRaw(key)
}

func aeadFromRaw(key []byte) (gocrypto.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := gocrypto.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return aead, nil
}
