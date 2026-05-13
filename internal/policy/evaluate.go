package policy

import (
	"fmt"
	"strings"

	"scal-p/internal/pkgmanager"
)

// Violation represents a policy violation.
type Violation struct {
    PackageID string
    Reason    string
    Rule      string
}

// Evaluate validates a node list against the policy.
func Evaluate(pol Policy, nodes []pkgmanager.PackageNode) ([]Violation, error) {
    if pol.Trust.Mode == TrustAuditOnly {
        return nil, nil
    }

    var violations []Violation
    for _, node := range nodes {
        pkgID := fmt.Sprintf("%s@%s", node.Name, node.Version)

        if pol.Transitive.MaxDepth > 0 && node.Depth > pol.Transitive.MaxDepth {
            violations = append(violations, Violation{
                PackageID: pkgID,
                Reason:    "transitive_depth_exceeded",
                Rule:      fmt.Sprintf("max_depth:%d", pol.Transitive.MaxDepth),
            })
        }

        if pol.Trust.Mode == TrustAllowlist {
            if !matchesAllow(pol.Packages.Allow, node) {
                violations = append(violations, Violation{
                    PackageID: pkgID,
                    Reason:    "not_in_allowlist",
                    Rule:      "allowlist",
                })
                continue
            }
        }

        if pol.Trust.Mode == TrustDenylist {
            if match, rule := matchesDeny(pol.Packages.Deny, node); match {
                violations = append(violations, Violation{
                    PackageID: pkgID,
                    Reason:    "denylist_match",
                    Rule:      rule,
                })
            }
        }
    }

    return violations, nil
}

func matchesAllow(rules []PackageRule, node pkgmanager.PackageNode) bool {
    if len(rules) == 0 {
        return false
    }
    for _, rule := range rules {
        if rule.Name != "" {
            if matchName(rule.Name, node.Name) {
                return true
            }
        }
        if rule.Pattern != "" {
            if matchPattern(rule.Pattern, node.Name) {
                return true
            }
        }
    }
    return false
}

func matchesDeny(rules []PackageRule, node pkgmanager.PackageNode) (bool, string) {
    for _, rule := range rules {
        if rule.Name != "" {
            if matchName(rule.Name, node.Name) {
                return true, fmt.Sprintf("name:%s", rule.Name)
            }
        }
        if rule.Pattern != "" {
            if matchPattern(rule.Pattern, node.Name) {
                return true, fmt.Sprintf("pattern:%s", rule.Pattern)
            }
        }
    }
    return false, ""
}

func matchName(ruleName, pkgName string) bool {
    return strings.EqualFold(ruleName, pkgName)
}

func matchPattern(pattern, pkgName string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "@") && strings.HasSuffix(pattern, "/*") {
		scope := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(pkgName, scope+"/")
	}
	// *substr* → contains (must come before bare prefix/suffix)
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") && len(pattern) > 2 {
		substr := pattern[1 : len(pattern)-1]
		return strings.Contains(pkgName, substr)
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(pkgName, suffix)
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(pkgName, prefix)
	}
	return strings.EqualFold(pattern, pkgName)
}
