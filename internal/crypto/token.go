package crypto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// TokenPrefix marks a Silent Tunnel pairing token.
const TokenPrefix = "st1_"

// Pairing is the self-contained payload of a pairing token: everything the
// node needs to reach the hub and authenticate. The Key is the shared secret
// (32 bytes, JSON-encoded as base64) — anyone holding the token can use the
// tunnel, so it must be treated like a private key.
type Pairing struct {
	V    int      `json:"v"`
	Host string   `json:"host"` // public IP or domain of the hub
	Port int      `json:"port"` // TLS port of the hub
	SNI  string   `json:"sni"`  // SNI presented in the TLS handshake
	Maps [][2]int `json:"maps,omitempty"`
	Key  []byte   `json:"key"` // 32-byte shared secret
	FP   string   `json:"fp"`  // SHA-256 fingerprint (hex) of the hub certificate
}

// SamePort reports whether the token uses the default identity mapping
// (listen port on hub == service port on node).
func (p *Pairing) SamePort() bool { return len(p.Maps) == 0 }

// RemoteFor resolves the node-side port for a hub listen port.
func (p *Pairing) RemoteFor(listen int) int {
	for _, m := range p.Maps {
		if m[0] == listen {
			return m[1]
		}
	}
	return listen
}

// EncodeToken serializes the pairing into the st1_ transport string.
func EncodeToken(p *Pairing) (string, error) {
	if p.V == 0 {
		p.V = 1
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("encode token: %w", err)
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeToken parses an st1_ pairing string and validates its fields.
func DecodeToken(s string) (*Pairing, error) {
	s = strings.TrimSpace(s)
	// Tolerate tokens pasted with surrounding shell quotes or line breaks.
	s = strings.Trim(s, "\"'")
	if i := strings.IndexAny(s, " \t\r\n"); i >= 0 {
		s = s[:i]
	}
	if !strings.HasPrefix(s, TokenPrefix) {
		return nil, errors.New("invalid token: missing st1_ prefix")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, TokenPrefix))
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	var p Pairing
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	switch {
	case p.V != 1:
		return nil, fmt.Errorf("unsupported token version %d", p.V)
	case p.Host == "":
		return nil, errors.New("token has no hub host")
	case p.Port < 1 || p.Port > 65535:
		return nil, errors.New("token has invalid hub port")
	case p.SNI == "":
		return nil, errors.New("token has no SNI")
	case len(p.Key) != KeyLen:
		return nil, errors.New("token has malformed key")
	case len(p.FP) != 64:
		return nil, errors.New("token has malformed certificate fingerprint")
	}
	return &p, nil
}
