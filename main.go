// Command silent is Silent Tunnel: a disguised, multiplexed reverse tunnel
// for Iran ⇄ abroad server setups.
package main

import (
	"os"

	"silenttunnel/internal/cli"
)

// version is set at build time: -ldflags "-X main.version=1.0.0"
var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Run(os.Args[1:]))
}
