package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"scal-p/internal/hash"
)

func runChecksum(ctx context.Context, args []string) error {
	fs := newFlagSet("checksum")
	output := fs.String("output", "", "write output to file instead of stdout")

	if err := fs.Parse(args); err != nil {
		return err
	}

	files := fs.Args()
	if len(files) == 0 {
		return fmt.Errorf("at least one file required")
	}

	var lines string

	for _, f := range files {
		h, err := hash.File(ctx, f)
		if err != nil {
			return fmt.Errorf("hash %s: %w", f, err)
		}
		lines += fmt.Sprintf("%s  %s\n", h, filepath.Base(f))
	}

	if *output != "" {
		if err := os.WriteFile(*output, []byte(lines), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", *output, err)
		}
	} else {
		fmt.Print(lines)
	}

	return nil
}
