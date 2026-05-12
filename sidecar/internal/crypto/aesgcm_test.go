package crypto_test

import (
	"bytes"
	"testing"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/crypto"
)

func TestRoundTrip(t *testing.T) {
	key := crypto.RandomKey()
	c, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	plaintext := []byte("hello, MCPBouncer!")
	blob, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := c.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: %s", got)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	c1, _ := crypto.NewCipher(crypto.RandomKey())
	c2, _ := crypto.NewCipher(crypto.RandomKey())

	blob, err := c1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = c2.Decrypt(blob)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestNewCipherBadKey(t *testing.T) {
	_, err := crypto.NewCipher("dG9vc2hvcnQ=") // "tooshort"
	if err == nil {
		t.Fatal("expected error for short key")
	}
}
