package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"scal-p/internal/audit"
	"scal-p/internal/policy"
	"scal-p/internal/trust"
)

// BinaryVerifyResult holds the outcome of verifying a release artifact
// against its expected checksum.
type BinaryVerifyResult struct {
	Artifact string `json:"artifact"`
	Passed   bool   `json:"passed"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

// AuditData contains all information gathered during an audit run, used by
// renderers to produce reports in various formats (Markdown, JSON, etc.).
type AuditData struct {
	Timestamp     string               `json:"timestamp"`
	Version       string               `json:"version"`
	Commit        string               `json:"commit"`
	PolicyPath    string               `json:"policy_path"`
	PolicyLoaded  bool                 `json:"policy_loaded"`
	PolicyJSON    string               `json:"policy_json,omitempty"`
	PM            string               `json:"pm"`
	Status        string               `json:"status"` // "passed" | "failed"
	TotalPackages int                  `json:"total_packages"`
	Events        []audit.Event        `json:"events,omitempty"`
	Violations    []policy.Violation   `json:"violations,omitempty"`
	TrustScores   []trust.PackageScore `json:"trust_scores,omitempty"`
	CVEs          map[string][]string  `json:"cves,omitempty"`
	BinaryResults []BinaryVerifyResult `json:"binary_results,omitempty"`
	Enforcement   string               `json:"enforcement,omitempty"`
}

// WriteAuditReport detects the report format from the file extension and
// writes the report. Supported extensions: .md / .markdown, .sarif.
// When path is "-" it writes to stdout.
func WriteAuditReport(path string, data AuditData) error {
	format := formatFromExt(path)
	var content []byte
	var err error

	switch format {
	case "md", "markdown":
		content, err = RenderAuditMarkdown(data)
	case "sarif":
		content, err = RenderSarif(data)
	default:
		return fmt.Errorf("unsupported report format: %s (supported: .md, .sarif)", format)
	}
	if err != nil {
		return fmt.Errorf("render %s report: %w", format, err)
	}

	if path == "-" {
		fmt.Println(string(content))
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create report dir: %w", err)
	}
	return os.WriteFile(path, content, 0o644)
}

func formatFromExt(path string) string {
	if path == "-" {
		return "md"
	}
	ext := strings.TrimPrefix(filepath.Ext(path), ".")
	if ext == "" {
		return "md"
	}
	return strings.ToLower(ext)
}
