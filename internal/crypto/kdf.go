// Package crypto holds the Silent Tunnel inner-crypto primitives:
// token-derived keys, the AEAD framing connection, the pairing token
// and the self-signed certificate helpers.
package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// KeyLen is the size in bytes of every derived key (ChaCha20-Poly1305).
	KeyLen = 32

	// authInfo is the HKDF info string for the one-shot handshake key.
	authInfo = "silent/v1/auth"
	// dataInfo is the HKDF info string for the persistent data keys.
	dataInfo = "silent/v1/data"
)

// AuthKey derives the one-shot key that encrypts the auth proof frames.
func AuthKey(token, salt []byte) ([]byte, error) {
	return deriveKey(token, salt, []byte(authInfo), KeyLen)
}

// DataKeys derives the two direction keys for the persistent AEAD layer.
// The salt is clientSalt||serverSalt; the first key is used by the client
// (node) side to send, the second by the server (hub) side.
func DataKeys(token, clientSalt, serverSalt []byte) (c2s, s2c []byte, err error) {
	salt := make([]byte, 0, len(clientSalt)+len(serverSalt))
	salt = append(salt, clientSalt...)
	salt = append(salt, serverSalt...)
	okm, err := deriveKey(token, salt, []byte(dataInfo), 2*KeyLen)
	if err != nil {
		return nil, nil, err
	}
	return okm[:KeyLen], okm[KeyLen:], nil
}

func deriveKey(secret, salt, info []byte, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}
	return key, nil
}
