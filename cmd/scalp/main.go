package main

import (
	"fmt"
	"log/slog"
	"os"

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

	slog.SetDefault(slog.New(cli.NewHandler(debug)))

	if err := cli.Run(os.Args[1:]); err != nil {
		if debug {
			slog.Error(err.Error())
		} else {
			fmt.Fprintln(os.Stderr, err.Error())
		}
		os.Exit(1)
	}
}
