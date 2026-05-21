package reporter

import (
	"encoding/json"
	"fmt"
	"strings"

	"scal-p/internal/policy"
)

type SarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool        SarifTool         `json:"tool"`
	Results     []SarifResult     `json:"results"`
	Invocations []SarifInvocation `json:"invocations,omitempty"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SarifRule `json:"rules,omitempty"`
}

type SarifRule struct {
	ID               string            `json:"id"`
	ShortDescription SarifMessage      `json:"shortDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level,omitempty"`
	Message   SarifMessage    `json:"message"`
	Locations []SarifLocation `json:"locations"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifInvocation struct {
	EndTimeUtc          string `json:"endTimeUtc,omitempty"`
	ExecutionSuccessful bool   `json:"executionSuccessful"`
}

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
	helpURI      = "https://github.com/scal-p-labs/SCAL-P"
)

type ruleInfo struct {
	id          string
	description string
	level       string
}

var knownRules = map[string]ruleInfo{
	"require_hash":   {id: "require_hash", description: "Package hash is required but missing from the lockfile", level: "error"},
	"min_score":      {id: "min_score", description: "Package trust score is below the minimum threshold", level: "error"},
	"allowlist":      {id: "allowlist", description: "Package is not in the allowed list", level: "error"},
	"denylist":       {id: "denylist", description: "Package matched a deny rule", level: "error"},
	"name":           {id: "name", description: "Package matched a deny rule by name", level: "error"},
	"pattern":        {id: "pattern", description: "Package matched a deny rule by pattern", level: "error"},
	"max_depth":      {id: "max_depth", description: "Transitive dependency exceeds maximum allowed depth", level: "warning"},
	"binary_verify":  {id: "binary_verify", description: "Release artifact checksum verification failed", level: "error"},
	"hash_integrity": {id: "hash_integrity", description: "Installed package hash does not match the lockfile", level: "error"},
	"stage_verify":   {id: "stage_verify", description: "Staged package tarball verification failed", level: "error"},
}

func RenderSarif(data AuditData) ([]byte, error) {
	rules, ruleIndex := buildRules(data.Violations)
	results := buildResults(data.Violations, ruleIndex)
	passed := data.Status == "passed"

	log := SarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []SarifRun{{
			Tool: SarifTool{
				Driver: SarifDriver{
					Name:           "SCAL-P",
					Version:        data.Version,
					InformationURI: helpURI,
					Rules:          rules,
				},
			},
			Results: results,
			Invocations: []SarifInvocation{{
				EndTimeUtc:          data.Timestamp,
				ExecutionSuccessful: passed,
			}},
		}},
	}

	return json.MarshalIndent(log, "", "  ")
}

func RenderSarifFromViolations(
	version string,
	timestamp string,
	passed bool,
	violations []policy.Violation,
	artifactURI string,
) ([]byte, error) {
	rules, ruleIndex := buildRulesFromPolicy(violations)
	results := buildResultsFromPolicy(violations, ruleIndex, artifactURI)

	log := SarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []SarifRun{{
			Tool: SarifTool{
				Driver: SarifDriver{
					Name:           "SCAL-P",
					Version:        version,
					InformationURI: helpURI,
					Rules:          rules,
				},
			},
			Results: results,
			Invocations: []SarifInvocation{{
				EndTimeUtc:          timestamp,
				ExecutionSuccessful: passed,
			}},
		}},
	}

	return json.MarshalIndent(log, "", "  ")
}

func normalizeRuleID(rule string) string {
	if idx := strings.IndexByte(rule, ':'); idx != -1 {
		return rule[:idx]
	}

	if rule == "allowlist" || rule == "denylist" {
		return rule
	}

	return rule
}

func ruleLevel(ruleID string) string {
	if info, ok := knownRules[ruleID]; ok {
		return info.level
	}
	return "error"
}

func buildRules(violations []policy.Violation) ([]SarifRule, map[string]int) {
	return buildRulesFromPolicy(violations)
}

func buildRulesFromPolicy(violations []policy.Violation) ([]SarifRule, map[string]int) {
	seen := make(map[string]int)
	var rules []SarifRule

	for _, v := range violations {
		rid := normalizeRuleID(v.Rule)
		if _, ok := seen[rid]; ok {
			continue
		}
		desc := ""
		if info, ok := knownRules[rid]; ok {
			desc = info.description
		} else {
			desc = fmt.Sprintf("Policy violation: %s", rid)
		}

		seen[rid] = len(rules)
		rules = append(rules, SarifRule{
			ID:               rid,
			ShortDescription: SarifMessage{Text: desc},
			HelpURI:          helpURI,
		})
	}

	return rules, seen
}

func buildResults(violations []policy.Violation, ruleIndex map[string]int) []SarifResult {
	return buildResultsFromPolicy(violations, ruleIndex, "")
}

func buildResultsFromPolicy(violations []policy.Violation, ruleIndex map[string]int, artifactURI string) []SarifResult {
	if len(violations) == 0 {
		return []SarifResult{}
	}

	results := make([]SarifResult, 0, len(violations))
	for _, v := range violations {
		rid := normalizeRuleID(v.Rule)
		idx := ruleIndex[rid]

		pkgName := packageName(v.PackageID)
		level := ruleLevel(rid)

		uri := fmt.Sprintf("node_modules/%s", pkgName)
		if artifactURI != "" {
			uri = fmt.Sprintf("%s/%s", artifactURI, pkgName)
		}

		results = append(results, SarifResult{
			RuleID:    rid,
			RuleIndex: idx,
			Level:     level,
			Message:   SarifMessage{Text: v.Reason},
			Locations: []SarifLocation{{
				PhysicalLocation: SarifPhysicalLocation{
					ArtifactLocation: SarifArtifactLocation{
						URI: uri,
					},
				},
			}},
		})
	}

	return results
}

func packageName(pkgID string) string {
	if idx := strings.LastIndexByte(pkgID, '@'); idx != -1 {
		return pkgID[:idx]
	}
	return pkgID
}
