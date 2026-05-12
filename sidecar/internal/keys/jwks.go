package keys

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
)

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	X   string `json:"x,omitempty"`
	// RSA fields for future use.
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func PublishableJWKS(keys []store.SigningKey) (JWKS, error) {
	var jwks JWKS
	for _, k := range keys {
		jwk, err := signingKeyToJWK(k)
		if err != nil {
			return JWKS{}, fmt.Errorf("PublishableJWKS key %s: %w", k.Kid, err)
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}
	return jwks, nil
}

func signingKeyToJWK(k store.SigningKey) (JWK, error) {
	block, _ := pem.Decode(k.PublicPEM)
	if block == nil {
		return JWK{}, fmt.Errorf("signingKeyToJWK: no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return JWK{}, fmt.Errorf("signingKeyToJWK parse: %w", err)
	}
	switch p := pub.(type) {
	case ed25519.PublicKey:
		return JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			Kid: k.Kid,
			Alg: "EdDSA",
			Use: "sig",
			X:   base64.RawURLEncoding.EncodeToString([]byte(p)),
		}, nil
	default:
		return JWK{}, fmt.Errorf("signingKeyToJWK: unsupported key type %T", pub)
	}
}
