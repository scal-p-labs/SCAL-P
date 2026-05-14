package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// ApplyEnforcement applies the enforcement mode to violations.
func ApplyEnforcement(mode string, violations []Violation) error {
	if len(violations) == 0 {
		return nil
	}

	message := formatViolations(violations)
	switch mode {
	case EnforceBlock:
		data, err := json.Marshal(violations)
		if err != nil {
			return errors.New(message)
		}
		return fmt.Errorf("ci failed: %s", string(data))
	case EnforceWarn:
		slog.Warn("policy violations detected", "details", message)
		return nil
	case EnforceLog:
		return nil
	default:
		slog.Warn("policy violations detected", "details", message)
		return nil
	}
}

func formatViolations(violations []Violation) string {
	lines := make([]string, 0, len(violations)+1)
	lines = append(lines, "policy violations detected:")
	for _, v := range violations {
		lines = append(lines, fmt.Sprintf("- %s (%s: %s)", v.PackageID, v.Reason, v.Rule))
	}
	return strings.Join(lines, "\n")
}
