package cli

import "cmp"

type cliConfig struct {
	policyPath   string
	pm           string
	guarded      bool
	ci           bool
	report       string
	artifact     string
	checksumFile string
}

func applyDefaults(cfg *cliConfig) {
	cfg.policyPath = cmp.Or(cfg.policyPath, ".scalp/policy.json")
	cfg.pm = cmp.Or(cfg.pm, "npm")
}
