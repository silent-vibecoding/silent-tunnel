package cli

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/fatih/color"

	"silenttunnel/internal/config"
	"silenttunnel/internal/crypto"
)

// tokenFor rebuilds the pairing token from the hub config and its
// certificate on disk.
func tokenFor(cfg *config.Hub) (string, error) {
	cert, err := crypto.LoadCert(cfg.Cert, cfg.CertKey)
	if err != nil {
		return "", err
	}
	return tokenForCert(cfg, cert)
}

// tokenForCert builds the pairing token from an in-memory certificate.
func tokenForCert(cfg *config.Hub, cert tls.Certificate) (string, error) {
	secret, err := cfg.Secret()
	if err != nil {
		return "", err
	}
	p := &crypto.Pairing{
		V:    1,
		Host: cfg.Host,
		Port: cfg.TLSPort,
		SNI:  cfg.SNI,
		Maps: cfg.Maps,
		Key:  secret,
		FP:   crypto.Fingerprint(cert),
	}
	return crypto.EncodeToken(p)
}

// colorToken wraps the token in bold for terminal copy.
func colorToken(t string) string { return color.New(color.Bold, color.FgHiWhite).Sprint(t) }

// cmdToken prints the pairing token again without touching anything.
func cmdToken() int {
	cfg, err := config.LoadHub(config.HubPath())
	if err != nil {
		errf("read hub config: %v", err)
		return 1
	}
	token, err := tokenFor(cfg)
	if err != nil {
		errf("build token: %v", err)
		return 1
	}
	fmt.Println(colorToken(token))
	return 0
}

// tokenFromInput resolves --token flag or asks for it interactively.
func tokenFromInput(flagVal string) (*crypto.Pairing, error) {
	raw := strings.TrimSpace(flagVal)
	if raw == "" {
		if !isTTY() {
			return nil, fmt.Errorf("token required: --token st1_...")
		}
		v, err := Ask("Paste the pairing token from the Iran server", "")
		if err != nil {
			return nil, uiErr(err)
		}
		raw = v
	}
	return crypto.DecodeToken(raw)
}

// configFromToken materializes the node config out of a pairing token.
func configFromToken(p *crypto.Pairing, pool int) *config.Node {
	return &config.Node{
		Version: 1,
		Role:    "node",
		Host:    p.Host,
		Port:    p.Port,
		SNI:     p.SNI,
		Key:     base64.StdEncoding.EncodeToString(p.Key),
		FP:      p.FP,
		Pool:    pool,
		Bind:    "127.0.0.1",
	}
}