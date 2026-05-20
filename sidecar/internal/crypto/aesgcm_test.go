package crypto_test

import (
	"bytes"
	"context"
	"crypto/aes"
	gocrypto "crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"path/filepath"
	"testing"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/crypto"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
)

// newTestStore opens a fresh SQLite store backed by a temp file.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return store.NewStore(db)
}

// rawAESGCMSeal builds a legacy-format ciphertext (nonce||ciphertext||tag)
// directly via stdlib, mirroring what the old Cipher emitted.
func rawAESGCMSeal(t *testing.T, keyBase64 string, plaintext []byte) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := gocrypto.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil)
}

// TestRoundTrip exercises the basic single-key Encrypt/Decrypt path via the
// store-backed constructor (mirrors production wiring).
func TestRoundTrip(t *testing.T) {
	s := newTestStore(t)
	key := crypto.RandomKey()
	c, err := crypto.NewCipherWithStore(context.Background(), s, key)
	if err != nil {
		t.Fatalf("NewCipherWithStore: %v", err)
	}
	if c.ActiveKeyID() != "k1" {
		t.Fatalf("ActiveKeyID = %q, want k1", c.ActiveKeyID())
	}

	plaintext := []byte("hello, MCPBouncer!")
	blob, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Versioned ciphertext must carry the magic prefix.
	if len(blob) < 2 || blob[0] != 0xC1 || blob[1] != 0x70 {
		t.Fatalf("expected versioned magic, got first bytes %x", blob[:min(2, len(blob))])
	}
	got, err := c.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: %s", got)
	}
}

// TestDecryptLegacyCiphertext ensures that ciphertexts produced before key
// versioning (raw nonce||ciphertext||tag) still decrypt via the bootstrap
// fallback path.
func TestDecryptLegacyCiphertext(t *testing.T) {
	s := newTestStore(t)
	envKey := crypto.RandomKey()

	// Build a legacy ciphertext directly with stdlib AEAD.
	legacyBlob := rawAESGCMSeal(t, envKey, []byte("legacy-secret"))

	// First boot: this also seeds the env key into encryption_keys as k1.
	c, err := crypto.NewCipherWithStore(context.Background(), s, envKey)
	if err != nil {
		t.Fatalf("NewCipherWithStore: %v", err)
	}
	got, err := c.Decrypt(legacyBlob)
	if err != nil {
		t.Fatalf("Decrypt legacy: %v", err)
	}
	if string(got) != "legacy-secret" {
		t.Fatalf("legacy decrypt mismatch: %s", got)
	}
}

// TestDecryptAfterRetire ensures a key that's been retired in the DB can
// still decrypt ciphertexts that were sealed with it (only encryption uses
// the active key; decryption uses the embedded key_id).
func TestDecryptAfterRetire(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	envKey := crypto.RandomKey()

	c, err := crypto.NewCipherWithStore(ctx, s, envKey)
	if err != nil {
		t.Fatalf("NewCipherWithStore: %v", err)
	}
	blob, err := c.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Retire k1 directly in the DB and reload.
	if err := s.SetEncryptionKeyStatus(ctx, "k1", "retired"); err != nil {
		t.Fatalf("SetEncryptionKeyStatus: %v", err)
	}
	// Add a fresh k2 active key.
	k2 := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k2); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := s.InsertEncryptionKey(ctx, store.EncryptionKey{KeyID: "k2", Material: k2, Status: "active"}); err != nil {
		t.Fatalf("InsertEncryptionKey: %v", err)
	}

	c2, err := crypto.NewCipherWithStore(ctx, s, envKey)
	if err != nil {
		t.Fatalf("reload NewCipherWithStore: %v", err)
	}
	if c2.ActiveKeyID() != "k2" {
		t.Fatalf("ActiveKeyID after rotate = %q, want k2", c2.ActiveKeyID())
	}

	// Existing ciphertext (sealed with k1) still decrypts.
	got, err := c2.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt with retired k1 still needed: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("decrypt mismatch: %s", got)
	}

	// New encryptions go through k2: verify by inspecting the embedded id.
	newBlob, err := c2.Encrypt([]byte("post-rotate"))
	if err != nil {
		t.Fatalf("Encrypt post-rotate: %v", err)
	}
	// header layout: magic(2) || idLen(1) || id...
	idLen := int(newBlob[2])
	gotID := string(newBlob[3 : 3+idLen])
	if gotID != "k2" {
		t.Fatalf("new ciphertext key_id = %q, want k2", gotID)
	}
	pt, err := c2.Decrypt(newBlob)
	if err != nil {
		t.Fatalf("Decrypt post-rotate: %v", err)
	}
	if string(pt) != "post-rotate" {
		t.Fatalf("post-rotate decrypt mismatch: %s", pt)
	}
}

// TestDecryptWrongKey verifies that decryption with an unrelated key fails.
func TestDecryptWrongKey(t *testing.T) {
	c1, err := crypto.NewCipher(crypto.RandomKey())
	if err != nil {
		t.Fatalf("NewCipher c1: %v", err)
	}
	c2, err := crypto.NewCipher(crypto.RandomKey())
	if err != nil {
		t.Fatalf("NewCipher c2: %v", err)
	}
	blob, err := c1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Both have id "k1" but different material — Decrypt should fail at GCM open.
	if _, err := c2.Decrypt(blob); err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestNewCipherBadKey(t *testing.T) {
	if _, err := crypto.NewCipher("dG9vc2hvcnQ="); err == nil {
		t.Fatal("expected error for short key")
	}
}
