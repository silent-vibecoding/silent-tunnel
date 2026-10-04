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
	fs.Usage = func() { fmt.Println("استفاده: silent setup-hub [--host IP] [--port 443] [--sni domain] [--maps 2087,44301|2087=8443,...] [--config path]") }
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
			errf("ویزارد لغو شد: %v", err)
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
		tipf("آی‌پی عمومی شناسایی نشد؛ از آی‌پی محلی %s استفاده می‌شود — بعداً در کانفیگ درستش کن", *host)
	}

	listen, mapping, err := parsePorts(*maps)
	if err != nil {
		errf("%v", err)
		return 1
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		errf("تولید کلید: %v", err)
		return 1
	}

	base := config.BaseDir()
	if err := os.MkdirAll(base, 0o700); err != nil {
		errf("ساخت پوشه‌ی کانفیگ: %v", err)
		return 1
	}
	certPath := filepath.Join(base, "cert.pem")
	keyPath := filepath.Join(base, "cert.key")
	cert, err := crypto.GenerateSelfSigned(*sni)
	if err != nil {
		errf("ساخت گواهی: %v", err)
		return 1
	}
	if err := crypto.SaveCert(cert, certPath, keyPath); err != nil {
		errf("ذخیره‌ی گواهی: %v", err)
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
		errf("ذخیره‌ی کانفیگ: %v", err)
		return 1
	}

	token, err := tokenForCert(cfg, cert)
	if err != nil {
		errf("ساخت توکن: %v", err)
		return 1
	}

	fmt.Println()
	okf("هاب روی %s ساخته شد (%s)", path, subtle("ایران"))
	fmt.Printf("  پورت تونل: %d    SNI: %s\n", cfg.TLSPort, cfg.SNI)
	if len(cfg.Maps) > 0 {
		for _, m := range cfg.Maps {
			fmt.Printf("  فوروارد: :%d → نود:%d\n", m[0], m[1])
		}
	} else {
		fmt.Printf("  فوروارد (هم‌نام): %s\n", intsString(cfg.Listen))
	}
	fmt.Println()
	tipf("توکن Pairing — روی سرور خارج در ویزارد یا setup-node پیستش کن:")
	fmt.Println()
	fmt.Println(colorToken(token))
	fmt.Println()
	tipf("پورت‌ها را در فایروال باز کن:")
	for _, p := range append([]int{cfg.TLSPort}, listen...) {
		fmt.Printf("    sudo ufw allow %d/tcp\n", p)
	}
	tipf("اجرا:  sudo silent hub   (یا silent → گزینه‌ی install برای سرویس systemd)")
	return 0
}

func hubWizard(host string, port int, sni, maps string) (string, int, string, string, error) {
	fmt.Println()
	tipf("ویزارد راه‌اندازی هاب (ایران)")
	if host == "" {
		detected := detectPublicIP()
		if detected == "" {
			detected = detectLocalIP()
		}
		h, err := Ask("آی‌پی عمومی یا دامنه‌ی این سرور", detected)
		if err != nil {
			return "", 0, "", "", uiErr(err)
		}
		host = h
	}
	if port == 0 {
		p, err := AskInt("پورت TLS که نود به آن وصل می‌شود", 443, 1, 65535)
		if err != nil {
			return "", 0, "", "", uiErr(err)
		}
		port = p
	}
	if sni == "" {
		s, err := Ask("SNI جعلی (دامنه‌ای که DPI می‌بیند)", "cloudflare.com")
		if err != nil {
			return "", 0, "", "", uiErr(err)
		}
		sni = s
	}
	if maps == "" {
		m, err := Ask("پورت‌های فوروارد با کاما (مثل 44301,2087) — یا نگاشت مثل 44301=8443", "44301")
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
		return nil, nil, fmt.Errorf("حداقل یک پورت لازم است")
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
				return nil, nil, fmt.Errorf("نگاشت نامعتبر: %s", p)
			}
			maps = append(maps, [2]int{l, r})
			continue
		}
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return nil, nil, fmt.Errorf("پورت نامعتبر: %s", p)
		}
		listen = append(listen, n)
	}
	if mapped && len(listen) > 0 {
		return nil, nil, fmt.Errorf("فرمت مخلوط مجاز نیست: همه را یا با = یا بدون = بنویس")
	}
	if len(listen) == 0 && len(maps) == 0 {
		return nil, nil, fmt.Errorf("حداقل یک پورت لازم است")
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
