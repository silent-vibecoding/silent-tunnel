package cli

import (
	"flag"
	"fmt"

	"silenttunnel/internal/config"
)

// cmdSetupNode writes the abroad-side config from a pairing token.
func cmdSetupNode(args []string) int {
	fs := flag.NewFlagSet("setup-node", flag.ContinueOnError)
	fs.Usage = func() { fmt.Println("استفاده: silent setup-node --token st1_... [--pool 3] [--config path]") }
	token := fs.String("token", "", "pairing token printed by setup-hub")
	pool := fs.Int("pool", 3, "number of pooled tunnel connections (1-16)")
	conf := fs.String("config", "", "config path (default per-OS)")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	p, err := tokenFromInput(*token)
	if err != nil {
		errf("%v", err)
		return 1
	}
	if *pool < 1 {
		*pool = 3
	}
	if *pool > 16 {
		*pool = 16
	}

	cfg := configFromToken(p, *pool)
	path := *conf
	if path == "" {
		path = config.NodePath()
	}
	if err := config.Save(path, cfg); err != nil {
		errf("ذخیره‌ی کانفیگ: %v", err)
		return 1
	}

	fmt.Println()
	okf("نود روی %s ساخته شد (%s)", path, subtle("خارج"))
	fmt.Printf("  هاب: %s:%d    SNI: %s    استخر: %d اتصال\n", p.Host, p.Port, p.SNI, *pool)
	if len(p.Maps) > 0 {
		for _, m := range p.Maps {
			fmt.Printf("  نگاشت: ایران:%d → این‌جا:%d\n", m[0], m[1])
		}
	} else {
		tipf("حالت هم‌نام: سرویس‌ها باید روی همان پورت‌های ایران، روی 127.0.0.1 بالا باشند")
	}
	fmt.Println()
	tipf("تست:  sudo silent doctor")
	tipf("اجرا:  sudo silent node   (یا silent → گزینه‌ی install برای سرویس systemd)")
	return 0
}
