package main

import (
	"fmt"
	"os"

	"github.com/cochaviz/bottle-warden/cmd/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
