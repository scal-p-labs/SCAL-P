package trust

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"scal-p/internal/ctxutil"
	"scal-p/internal/lockfile"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/policy"
)

const (
	ptsHashVerified  = 30
	ptsMaturity      = 15
	ptsMaxDownloads  = 20
	ptsNoCVEs        = 15
	defaultWorkers   = 10
)

type ScoreBreakdown struct {
	HashVerified int `json:"hash_verified"`
	Maturity     int `json:"maturity"`
	Downloads    int `json:"downloads"`
	NoCVEs       int `json:"no_cves"`
}

type PackageScore struct {
	PackageID  string         `json:"package_id"`
	Total      int            `json:"total"`
	Breakdown  ScoreBreakdown `json:"breakdown"`
}

type Scorer struct {
	cachePath string
	client    *http.Client
	apiURL    string
	auditFunc func(ctx context.Context) map[string][]string
	workers   int
}

func NewScorer(cachePath string) *Scorer {
	return &Scorer{
		cachePath: cachePath,
		client:    &http.Client{Timeout: 10 * time.Second},
		apiURL:    "https://api.npmjs.org",
		workers:   defaultWorkers,
	}
}

// SetWorkers sets the number of concurrent HTTP workers for
// download prefetching. Default is 10. Values <= 0 reset to default.
func (s *Scorer) SetWorkers(n int) {
	if n <= 0 {
		n = defaultWorkers
	}
	s.workers = n
}

func (s *Scorer) SetHTTPClient(c *http.Client) {
	s.client = c
}

func (s *Scorer) SetAPIURL(url string) {
	s.apiURL = url
}

func (s *Scorer) SetAuditFunc(fn func(ctx context.Context) map[string][]string) {
	s.auditFunc = fn
}

func (s *Scorer) Evaluate(ctx context.Context, pol policy.Policy, nodes []pkgmanager.PackageNode, lf *lockfile.Lockfile) ([]policy.Violation, error) {
	if pol.Trust.MinScore <= 0 && !pol.Trust.RequireHash {
		return nil, nil
	}
	if err := ctxutil.Check(ctx); err != nil {
		return nil, err
	}

	cache, err := LoadCache(s.cachePath)
	if err != nil {
		return nil, fmt.Errorf("load trust cache: %w", err)
	}

	auditCVEs := s.fetchAuditCVEs(ctx)
	s.prefetchDownloads(ctx, nodes, cache)

	var violations []policy.Violation
	for _, node := range nodes {
		key := fmt.Sprintf("%s@%s", node.Name, node.Version)

		if pol.Trust.RequireHash && !hasLockfileHash(node, lf) {
			violations = append(violations, policy.Violation{
				PackageID: key,
				Reason:    "hash_required: package integrity not in lockfile",
				Rule:      "require_hash:true",
			})
			continue
		}

		score := s.computeScore(ctx, node, lf, cache, auditCVEs)

		if score.total < pol.Trust.MinScore {
			violations = append(violations, policy.Violation{
				PackageID: key,
				Reason: fmt.Sprintf("trust_score: %d/%d (hash:%d, maturity:%d, dl:%d, cves:%d)",
					score.total, pol.Trust.MinScore, score.hash, score.maturity, score.downloads, score.noCVEs),
				Rule: fmt.Sprintf("min_score:%d", pol.Trust.MinScore),
			})
		}
	}

	if err := cache.Save(); err != nil {
		return nil, fmt.Errorf("save trust cache: %w", err)
	}

	return violations, nil
}

type computedScore struct {
	total     int
	hash      int
	maturity  int
	downloads int
	noCVEs    int
}

func (s *Scorer) computeScore(ctx context.Context, node pkgmanager.PackageNode, lf *lockfile.Lockfile, cache *TrustCache, auditCVEs map[string][]string) computedScore {
	hash := scoreHash(node, lf)
	maturity := ScoreMaturity(node.Version)
	downloads := s.scoreDownloadsCached(ctx, node.Name, cache)
	noCVEs := scoreCVEs(node.Name, node.Version, auditCVEs, cache)

	return computedScore{
		total:     hash + maturity + downloads + noCVEs,
		hash:      hash,
		maturity:  maturity,
		downloads: downloads,
		noCVEs:    noCVEs,
	}
}

func hasLockfileHash(node pkgmanager.PackageNode, lf *lockfile.Lockfile) bool {
	if lf == nil {
		return false
	}
	key := fmt.Sprintf("%s@%s", node.Name, node.Version)
	if entry, ok := lf.Packages[key]; ok && entry.Integrity != "" {
		return true
	}
	return false
}

func scoreHash(node pkgmanager.PackageNode, lf *lockfile.Lockfile) int {
	if hasLockfileHash(node, lf) {
		return ptsHashVerified
	}
	return 0
}

func ScoreMaturity(version string) int {
	major, _, _ := parseVersion(version)
	if major >= 1 {
		return ptsMaturity
	}
	return 0
}

func parseVersion(v string) (major, minor, patch int) {
	v = strings.TrimLeft(v, "^~>=< ")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) > 0 {
		major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) > 2 {
		patchStr := strings.Fields(parts[2])[0]
		patch, _ = strconv.Atoi(patchStr)
	}
	return
}

func (s *Scorer) prefetchDownloads(ctx context.Context, nodes []pkgmanager.PackageNode, cache *TrustCache) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.workers)

	for _, node := range nodes {
		entry, ok := cache.Get(node.Name)
		if ok && !IsExpired(entry, DefaultTTL) {
			continue
		}

		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			downloads, err := s.fetchWeeklyDownloads(ctx, name)
			if err != nil {
				return
			}
			cache.SetDownloads(name, downloads)
		}(node.Name)
	}
	wg.Wait()
}

func (s *Scorer) scoreDownloadsCached(ctx context.Context, pkgName string, cache *TrustCache) int {
	entry, ok := cache.Get(pkgName)
	if ok && !IsExpired(entry, DefaultTTL) {
		return ScoreDownloadsByCount(entry.WeeklyDownloads)
	}

	downloads, err := s.fetchWeeklyDownloads(ctx, pkgName)
	if err != nil {
		if ok {
			return ScoreDownloadsByCount(entry.WeeklyDownloads)
		}
		return ptsMaxDownloads / 2
	}

	cache.SetDownloads(pkgName, downloads)
	return ScoreDownloadsByCount(downloads)
}

func (s *Scorer) fetchWeeklyDownloads(ctx context.Context, pkgName string) (int, error) {
	url := s.apiURL + "/downloads/point/last-week/" + pkgName

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch downloads: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}

	var dl struct {
		Downloads int `json:"downloads"`
	}
	if err := json.Unmarshal(body, &dl); err != nil {
		return 0, fmt.Errorf("parse downloads response: %w", err)
	}

	return dl.Downloads, nil
}

func ScoreDownloadsByCount(n int) int {
	switch {
	case n >= 100000:
		return 20
	case n >= 10000:
		return 15
	case n >= 1000:
		return 10
	case n >= 100:
		return 5
	default:
		return 0
	}
}

func scoreCVEs(pkgName, version string, auditCVEs map[string][]string, cache *TrustCache) int {
	cves, hasAudit := auditCVEs[pkgName]
	if hasAudit {
		if len(cves) > 0 {
			cache.SetVersionCVEs(pkgName, version, cves)
			return 0
		}
		cache.SetVersionCVEs(pkgName, version, nil)
		return ptsNoCVEs
	}

	versionCVEs := cache.GetVersionCVEs(pkgName, version)
	if versionCVEs != nil {
		if len(versionCVEs) > 0 {
			return 0
		}
		return ptsNoCVEs
	}

	entry, ok := cache.Get(pkgName)
	if ok && len(entry.CVEs) > 0 {
		return 0
	}
	if ok {
		return ptsNoCVEs
	}

	return ptsNoCVEs / 2
}

func (s *Scorer) fetchAuditCVEs(ctx context.Context) map[string][]string {
	if s.auditFunc != nil {
		return s.auditFunc(ctx)
	}
	cmd := exec.CommandContext(ctx, "npm", "audit", "--json")
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	return parseNpmAuditJSON(output)
}

type npmAuditVulnerability struct {
	Name       string `json:"name"`
	Severity   string `json:"severity"`
}

type npmAuditResponse struct {
	Vulnerabilities map[string]npmAuditVulnerability `json:"vulnerabilities"`
}

func parseNpmAuditJSON(data []byte) map[string][]string {
	var resp npmAuditResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil
	}
	result := make(map[string][]string, len(resp.Vulnerabilities))
	for name, vuln := range resp.Vulnerabilities {
		result[name] = append(result[name], vuln.Severity)
	}
	return result
}

func ScoreFromBreakdown(b ScoreBreakdown) PackageScore {
	return PackageScore{
		Total:     b.HashVerified + b.Maturity + b.Downloads + b.NoCVEs,
		Breakdown: b,
	}
}
