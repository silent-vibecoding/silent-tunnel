package cli

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"silenttunnel/internal/config"
	"silenttunnel/internal/crypto"
	"silenttunnel/internal/node"
)

// cmdDoctor runs environment checks for whichever role is configured.
func cmdDoctor(args []string) int {
	if cfg, err := config.LoadHub(config.HubPath()); err == nil {
		return doctorHub(cfg)
	}
	if cfg, err := config.LoadNode(config.NodePath()); err == nil {
		return doctorNode(cfg)
	}
	errf("هیچ کانفیگی پیدا نشد — اول setup-hub یا setup-node را اجرا کن")
	return 1
}

func doctorHub(cfg *config.Hub) int {
	fmt.Println()
	tipf("تست سلامت هاب (ایران)")
	code := 0

	cert, err := crypto.LoadCert(cfg.Cert, cfg.CertKey)
	if err != nil {
		errf("گواهی: %v", err)
		code = 1
	} else {
		okf("گواهی سالم (اثر انگشت %s...)", crypto.Fingerprint(cert)[:16])
		if _, err := tokenFor(cfg); err != nil {
			errf("توکن pairing ساخته نمی‌شود: %v", err)
			code = 1
		} else {
			okf("توکن pairing آماده است (silent token)")
		}
	}

	for _, p := range append([]int{cfg.TLSPort}, cfg.Listen...) {
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(p))
		if err != nil {
			errf("پورت %d آزاد نیست: %v", p, err)
			code = 1
			continue
		}
		_ = ln.Close()
		okf("پورت %d آزاد است", p)
	}

	if hint := clockCheck(); hint != "" {
		fmt.Printf("  %s\n", warn(hint))
	}
	fmt.Println()
	return code
}

func doctorNode(cfg *config.Node) int {
	fmt.Println()
	tipf("تست سلامت نود (خارج)")

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		errf("TCP به هاب %s نمی‌رسد: %v", addr, err)
		fmt.Printf("  %s\n", warn("چک کن: آی‌پی/پورت درست است؟ فایروال ایران پورت "+strconv.Itoa(cfg.Port)+" را باز دارد؟"))
		return 1
	}
	_ = conn.Close()
	okf("TCP به هاب %s وصل شد", addr)

	if err := node.Probe(cfg); err != nil {
		errf("دست‌دادن داخلی: %v", err)
		fmt.Printf("  %s\n", warn("اگر خطا ساعت/زمان بود: هر دو سرور را با NTP هم‌زمان کن (timedatectl set-ntp true)"))
		fmt.Printf("  %s\n", warn("اگر fingerprint mismatch بود: کانفیگ هاب یا توکن عوض شده — token دوباره بگیر"))
		return 1
	}
	okf("احراز و رمز داخلی سالم است — تونل آماده است")
	fmt.Println()
	return 0
}

// clockCheck compares the local clock against Cloudflare's daytime service
// and returns a warning when the skew could break the ±2min auth window.
func clockCheck() string {
	resp, err := net.DialTimeout("tcp", "time.cloudflare.com:13", 4*time.Second)
	if err != nil {
		return ""
	}
	defer resp.Close()
	_ = resp.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 128)
	n, _ := resp.Read(buf)
	// NIST daytime: "87953 25-10-04 15:20:30 00 0 0 12.4 UTC(NIST) *"
	f := strings.Fields(string(buf[:n]))
	if len(f) < 3 {
		return ""
	}
	remote, err := time.Parse("06-01-02 15:04:05", f[1]+" "+f[2])
	if err != nil {
		return ""
	}
	remote = remote.UTC()
	skew := time.Since(remote).Round(time.Second)
	if skew < 0 {
		skew = -skew
	}
	if skew > 60*time.Second {
		return fmt.Sprintf("ساعت این سرور با مرجع جهانی %.0f ثانیه اختلاف دارد — با timedatectl set-ntp true هم‌زمانش کن", skew.Seconds())
	}
	return ""
}
