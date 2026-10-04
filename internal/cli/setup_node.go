package cli

import (
	"flag"
	"fmt"

	"silenttunnel/internal/config"
)

// cmdSetupNode writes the abroad-side config from a pairing token.
func cmdSetupNode(args []string) int {
	fs := flag.NewFlagSet("setup-node", flag.ContinueOnError)
	fs.Usage = func() { fmt.Println("usage: silent setup-node --token st1_... [--pool 3] [--config path]") }
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
		errf("save config: %v", err)
		return 1
	}

	fmt.Println()
	okf("node created at %s (%s)", path, subtle("abroad"))
	fmt.Printf("  Hub: %s:%d    SNI: %s    pool: %d connections\n", p.Host, p.Port, p.SNI, *pool)
	if len(p.Maps) > 0 {
		for _, m := range p.Maps {
			fmt.Printf("  Mapping: iran:%d -> here:%d\n", m[0], m[1])
		}
	} else {
		tipf("Same-port mode: your services must listen on 127.0.0.1 on the same ports as the Iran side")
	}
	fmt.Println()
	tipf("Test:  sudo silent doctor")
	tipf("Run:  sudo silent node   (or 'silent install' for the systemd service)")
	return 0
}
