package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"scal-p/internal/cli"
)

func main() {
	debug := false
	for _, arg := range os.Args[1:] {
		if arg == "--debug" {
			debug = true
			break
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	slog.SetDefault(slog.New(cli.NewHandler(debug)))

	if err := cli.RunContext(ctx, os.Args[1:]); err != nil {
		if debug {
			slog.Error(err.Error())
		} else {
			fmt.Fprintln(os.Stderr, err.Error())
		}
		os.Exit(1)
	}
}
