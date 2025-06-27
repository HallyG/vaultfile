package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	cmd "github.com/HallyG/vaultfile/cmd/vaultfile"
)

func main() {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	if err := cmd.Main(ctx, os.Args, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
