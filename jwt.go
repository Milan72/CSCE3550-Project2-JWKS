package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"
)

// jwk represents the public RSA information published by the JWKS endpoint.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwks is the JSON object returned by /.well-known/jwks.json.
type jwks struct {
	Keys []jwk `json:"keys"`
}

// jwtHeader contains the JOSE header fields used by this project.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// jwtClaims contains the small mock-authentication payload used by Project 2.
type jwtClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// createJWT creates an RS256-signed JWT using a private key loaded from
// SQLite. The database kid is copied into the JOSE header so verifiers can
// locate the corresponding public key in the JWKS response.
func createJWT(key storedKey) (string, error) {
	if key.PrivateKey == nil {
		return "", errors.New("sign JWT: private key is nil")
	}

	header := jwtHeader{
		Alg: "RS256",
		Typ: "JWT",
		Kid: strconv.FormatInt(key.Kid, 10),
	}

	payload := jwtClaims{
		Sub: "fake-user",
		Iat: time.Now().Unix(),
		Exp: key.ExpiresAt.Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal JWT header: %w", err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal JWT payload: %w", err)
	}

	headerPart := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadPart := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerPart + "." + payloadPart
	hash := sha256.Sum256([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		key.PrivateKey,
		crypto.SHA256,
		hash[:],
	)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	signaturePart := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signaturePart, nil
}

// publicKeyToJWK converts a stored RSA private key to its public JWK form.
// Private RSA material is never included in the HTTP response.
func publicKeyToJWK(key storedKey) jwk {
	publicKey := key.PrivateKey.PublicKey

	modulus := base64.RawURLEncoding.EncodeToString(
		publicKey.N.Bytes(),
	)

	exponentBytes := big.NewInt(
		int64(publicKey.E),
	).Bytes()

	exponent := base64.RawURLEncoding.EncodeToString(
		exponentBytes,
	)

	return jwk{
		Kty: "RSA",
		Kid: strconv.FormatInt(key.Kid, 10),
		Use: "sig",
		Alg: "RS256",
		N:   modulus,
		E:   exponent,
	}
}
