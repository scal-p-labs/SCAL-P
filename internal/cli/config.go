package cli

import (
	"cmp"
	"log/slog"

	"scal-p/internal/pkgmanager"
)

type cliConfig struct {
	policyPath   string
	pm           string
	guarded      bool
	ci           bool
	report       string
	artifact     string
	checksumFile string
	sarifReport  string
}

func applyDefaults(cfg *cliConfig) {
	cfg.policyPath = cmp.Or(cfg.policyPath, ".scalp/policy.json")
	if cfg.pm == "" {
		detected, err := pkgmanager.Detect()
		if err == nil {
			cfg.pm = detected
		} else {
			slog.Debug("auto-detect package manager", "err", err)
			cfg.pm = "npm"
		}
	}
}
