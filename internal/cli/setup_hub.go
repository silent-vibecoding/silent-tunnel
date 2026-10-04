package cli

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"silenttunnel/internal/config"
	"silenttunnel/internal/crypto"
)

// cmdSetupHub creates the Iran-side config, certificate and pairing token.
// With flags it runs headless; interactively it walks through a wizard.
func cmdSetupHub(args []string) int {
	fs := flag.NewFlagSet("setup-hub", flag.ContinueOnError)
	fs.Usage = func() { fmt.Println("usage: silent setup-hub [--host IP] [--port 443] [--sni domain] [--maps 2087,44301|2087=8443,...] [--config path]") }
	host := fs.String("host", "", "public IP or domain of this server")
	port := fs.Int("port", 0, "TLS port the node dials (default 443)")
	sni := fs.String("sni", "", "fake SNI shown to DPI (default cloudflare.com)")
	maps := fs.String("maps", "", "forwarded ports: 2087,44301 (same-port) or 2087=8443,... (mapped)")
	conf := fs.String("config", "", "config path (default per-OS)")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	// Fill what the flags left out — from the wizard when possible.
	if *host == "" || *port == 0 || *sni == "" || *maps == "" {
		if !isTTY() {
			fs.Usage()
			return 1
		}
		h, p, s, m, err := hubWizard(*host, *port, *sni, *maps)
		if err != nil {
			errf("wizard cancelled: %v", err)
			return 1
		}
		*host, *port, *sni, *maps = h, p, s, m
	}
	if *port == 0 {
		*port = 443
	}
	if *sni == "" {
		*sni = "cloudflare.com"
	}
	if *host == "" {
		*host = detectLocalIP()
		tipf("could not detect the public IP; using the local IP %s — fix it in the config later", *host)
	}

	listen, mapping, err := parsePorts(*maps)
	if err != nil {
		errf("%v", err)
		return 1
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		errf("generate key: %v", err)
		return 1
	}

	base := config.BaseDir()
	if err := os.MkdirAll(base, 0o700); err != nil {
		errf("create config dir: %v", err)
		return 1
	}
	certPath := filepath.Join(base, "cert.pem")
	keyPath := filepath.Join(base, "cert.key")
	cert, err := crypto.GenerateSelfSigned(*sni)
	if err != nil {
		errf("generate certificate: %v", err)
		return 1
	}
	if err := crypto.SaveCert(cert, certPath, keyPath); err != nil {
		errf("save certificate: %v", err)
		return 1
	}

	cfg := &config.Hub{
		Version: 1,
		Role:    "hub",
		Host:    *host,
		TLSPort: *port,
		SNI:     *sni,
		Key:     base64.StdEncoding.EncodeToString(key),
		Cert:    certPath,
		CertKey: keyPath,
	}
	if mapping != nil {
		cfg.Maps = mapping
	} else {
		cfg.Listen = listen
	}

	path := *conf
	if path == "" {
		path = config.HubPath()
	}
	if err := config.Save(path, cfg); err != nil {
		errf("save config: %v", err)
		return 1
	}

	token, err := tokenForCert(cfg, cert)
	if err != nil {
		errf("build token: %v", err)
		return 1
	}

	fmt.Println()
	okf("hub created at %s (%s)", path, subtle("Iran"))
	fmt.Printf("  Tunnel port: %d    SNI: %s\n", cfg.TLSPort, cfg.SNI)
	if len(cfg.Maps) > 0 {
		for _, m := range cfg.Maps {
			fmt.Printf("  Forward: :%d -> node:%d\n", m[0], m[1])
		}
	} else {
		fmt.Printf("  Forward (same-port): %s\n", intsString(cfg.Listen))
	}
	fmt.Println()
	tipf("Pairing token — paste it into the wizard or 'setup-node' on the abroad server:")
	fmt.Println()
	fmt.Println(colorToken(token))
	fmt.Println()
	tipf("Open these ports in the firewall:")
	for _, p := range append([]int{cfg.TLSPort}, listen...) {
		fmt.Printf("    sudo ufw allow %d/tcp\n", p)
	}
	tipf("Run:  sudo silent hub   (or 'silent install' for the systemd service)")
	return 0
}

func hubWizard(host string, port int, sni, maps string) (string, int, string, string, error) {
	fmt.Println()
	tipf("Hub (Iran) setup wizard")
	if host == "" {
		detected := detectPublicIP()
		if detected == "" {
			detected = detectLocalIP()
		}
		h, err := Ask("Public IP or domain of this server", detected)
		if err != nil {
			return "", 0, "", "", uiErr(err)
		}
		host = h
	}
	if port == 0 {
		p, err := AskInt("TLS port for the node to dial", 443, 1, 65535)
		if err != nil {
			return "", 0, "", "", uiErr(err)
		}
		port = p
	}
	if sni == "" {
		s, err := Ask("Fake SNI (the domain DPI will see)", "cloudflare.com")
		if err != nil {
			return "", 0, "", "", uiErr(err)
		}
		sni = s
	}
	if maps == "" {
		m, err := Ask("Ports to forward, comma-separated (e.g. 44301,2087) — or mapped like 44301=8443", "44301")
		if err != nil {
			return "", 0, "", "", uiErr(err)
		}
		maps = m
	}
	return host, port, sni, maps, nil
}

// parsePorts accepts "2087,44301" (identity mapping) or "2087=8443"
// (explicit mapping) and returns the listen list plus the mapping (nil for
// same-port mode).
func parsePorts(s string) (listen []int, maps [][2]int, err error) {
	parts := strings.Split(strings.TrimSpace(s), ",")
	if len(parts) == 0 || parts[0] == "" {
		return nil, nil, fmt.Errorf("at least one port is required")
	}
	mapped := false
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if a, b, ok := strings.Cut(p, "="); ok {
			mapped = true
			l, e1 := strconv.Atoi(strings.TrimSpace(a))
			r, e2 := strconv.Atoi(strings.TrimSpace(b))
			if e1 != nil || e2 != nil {
				return nil, nil, fmt.Errorf("invalid mapping: %s", p)
			}
			maps = append(maps, [2]int{l, r})
			continue
		}
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return nil, nil, fmt.Errorf("invalid port: %s", p)
		}
		listen = append(listen, n)
	}
	if mapped && len(listen) > 0 {
		return nil, nil, fmt.Errorf("mixed format is not allowed: use = for all entries or for none")
	}
	if len(listen) == 0 && len(maps) == 0 {
		return nil, nil, fmt.Errorf("at least one port is required")
	}
	if mapped {
		return nil, maps, nil
	}
	return listen, nil, nil
}

func detectPublicIP() string {
	client := &http.Client{Timeout: 8 * time.Second}
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip"} {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		ip := strings.TrimSpace(string(b))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

func detectLocalIP() string {
	c, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func intsString(xs []int) string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strconv.Itoa(x)
	}
	return strings.Join(out, ",")
}
