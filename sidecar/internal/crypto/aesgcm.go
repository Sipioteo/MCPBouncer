package crypto

import (
	"crypto/aes"
	gocrypto "crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type Cipher struct {
	aead gocrypto.AEAD
}

func NewCipher(keyBase64 string) (*Cipher, error) {
	key, err := base64.RawStdEncoding.DecodeString(keyBase64)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(keyBase64)
		if err != nil {
			return nil, fmt.Errorf("NewCipher decode key: %w", err)
		}
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("NewCipher: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("NewCipher aes: %w", err)
	}
	aead, err := gocrypto.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("NewCipher gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("Encrypt nonce: %w", err)
	}
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (c *Cipher) Decrypt(blob []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("Decrypt: blob too short")
	}
	nonce, ciphertext := blob[:ns], blob[ns:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("Decrypt: %w", err)
	}
	return plaintext, nil
}

func RandomKey() string {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}
