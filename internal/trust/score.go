package trust

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
	ptsHashVerified = 30
	ptsMaturity     = 15
	ptsMaxDownloads = 20
	ptsNoCVEs       = 15
)

type ScoreBreakdown struct {
	HashVerified int `json:"hash_verified"`
	Maturity     int `json:"maturity"`
	Downloads    int `json:"downloads"`
	NoCVEs       int `json:"no_cves"`
}

type PackageScore struct {
	PackageID string         `json:"package_id"`
	Total     int            `json:"total"`
	Breakdown ScoreBreakdown `json:"breakdown"`
}

type inflightFetch struct {
	wg    sync.WaitGroup
	score int
	err   error
}

type Scorer struct {
	cachePath  string
	apiURL     string
	pm         string
	auditFunc  func(ctx context.Context) map[string][]string
	scores     []PackageScore
	lastCVEs   map[string][]string
	inflightMu sync.Mutex
	inflight   map[string]*inflightFetch
}

func NewScorer(cachePath string) *Scorer {
	return &Scorer{
		cachePath: cachePath,
		apiURL:    "https://api.npmjs.org",
		inflight:  make(map[string]*inflightFetch),
	}
}

func (s *Scorer) SetAPIURL(url string) {
	s.apiURL = url
}

func (s *Scorer) SetPM(pm string) {
	s.pm = pm
}

func (s *Scorer) SetAuditFunc(fn func(ctx context.Context) map[string][]string) {
	s.auditFunc = fn
}

func (s *Scorer) Evaluate(ctx context.Context, pol policy.Policy, nodes []pkgmanager.PackageNode, lf *lockfile.Lockfile) ([]policy.Violation, error) {
	if pol.Trust.Mode == policy.TrustAuditOnly {
		return nil, nil
	}
	if pol.Trust.MinScore <= 0 && !pol.Trust.RequireHash {
		return nil, nil
	}
	if err := ctxutil.Check(ctx); err != nil {
		return nil, err
	}

	// First pass: check require_hash only (no network needed).
	// Packages that pass become candidates for trust scoring.
	var violations []policy.Violation
	var scoreNodes []pkgmanager.PackageNode
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

		scoreNodes = append(scoreNodes, node)
	}

	// Second pass: trust scoring for packages that passed require_hash.
	if pol.Trust.MinScore > 0 && len(scoreNodes) > 0 {
		cache, err := LoadCache(s.cachePath)
		if err != nil {
			return nil, fmt.Errorf("load trust cache: %w", err)
		}

		s.lastCVEs = s.fetchAuditCVEs(ctx)
		auditCVEs := s.lastCVEs
		s.scores = nil

		for _, node := range scoreNodes {
			key := fmt.Sprintf("%s@%s", node.Name, node.Version)

	failClosed := pol.Trust.FailClosed != nil && *pol.Trust.FailClosed
	hash := scoreHash(node, lf)
	maturity := ScoreMaturity(node.Version)
	noCVEs := scoreCVEs(node.Name, node.Version, auditCVEs, cache, failClosed)

	// Early skip: if max possible score is below min_score,
	// don't bother fetching download data.
	maxWithoutDownloads := hash + maturity + noCVEs
	var downloads int
	if maxWithoutDownloads+ptsMaxDownloads >= pol.Trust.MinScore {
		downloads = s.scoreDownloadsCached(ctx, node.Name, cache, failClosed)
	}

			total := maxWithoutDownloads + downloads

			s.scores = append(s.scores, PackageScore{
				PackageID: key,
				Total:     total,
				Breakdown: ScoreBreakdown{
					HashVerified: hash,
					Maturity:     maturity,
					Downloads:    downloads,
					NoCVEs:       noCVEs,
				},
			})

			if total < pol.Trust.MinScore {
				violations = append(violations, policy.Violation{
					PackageID: key,
					Reason: fmt.Sprintf("trust_score: %d/%d (hash:%d, maturity:%d, dl:%d, cves:%d)",
						total, pol.Trust.MinScore, hash, maturity, downloads, noCVEs),
					Rule: fmt.Sprintf("min_score:%d", pol.Trust.MinScore),
				})
			}
		}

		if err := cache.Save(); err != nil {
			return nil, fmt.Errorf("save trust cache: %w", err)
		}
	}

	return violations, nil
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

// scoreDownloadsCached returns the download score for a package name.
// It uses a dedup mechanism so concurrent calls for the same name
// share a single HTTP fetch.
func (s *Scorer) scoreDownloadsCached(ctx context.Context, pkgName string, cache *TrustCache, failClosed bool) int {
	entry, ok := cache.Get(pkgName)
	if ok && !IsExpired(entry, DefaultTTL) {
		return ScoreDownloadsByCount(entry.WeeklyDownloads)
	}

	// Dedup concurrent fetches for the same package name.
	s.inflightMu.Lock()
	if inf, exists := s.inflight[pkgName]; exists {
		s.inflightMu.Unlock()
		inf.wg.Wait()
		if inf.err == nil {
			return inf.score
		}
		// Inflight fetch failed — fall through to try again.
	} else {
		inf = &inflightFetch{}
		inf.wg.Add(1)
		s.inflight[pkgName] = inf
		s.inflightMu.Unlock()

		go func() {
			defer inf.wg.Done()
			downloads, err := s.fetchWeeklyDownloads(ctx, pkgName)
			inf.err = err
			if err == nil {
				inf.score = ScoreDownloadsByCount(downloads)
				cache.SetDownloads(pkgName, downloads)
			}
		}()

		inf.wg.Wait()
		if inf.err == nil {
			return inf.score
		}
	}

	// All fetch attempts failed.
	if ok {
		return ScoreDownloadsByCount(entry.WeeklyDownloads)
	}
	if failClosed {
		return 0
	}
	return ptsMaxDownloads / 2
}

// FetchDownloadsFunc is the signature for downloading weekly counts.
type FetchDownloadsFunc func(ctx context.Context, apiURL, pkgName string) (int, error)

var fetchDownloads FetchDownloadsFunc = defaultFetchDownloads

var downloadClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSHandshakeTimeout: 3 * time.Second,
	},
	Timeout: 10 * time.Second,
}

func defaultFetchDownloads(ctx context.Context, apiURL, pkgName string) (int, error) {
	u := apiURL + "/downloads/point/last-week/" + pkgName
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := downloadClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var dl struct {
		Downloads int `json:"downloads"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dl); err != nil {
		return 0, fmt.Errorf("parse response: %w", err)
	}

	return dl.Downloads, nil
}

func (s *Scorer) fetchWeeklyDownloads(ctx context.Context, pkgName string) (int, error) {
	return fetchDownloads(ctx, s.apiURL, pkgName)
}

// SetFetchDownloads overrides the weekly-downloads fetch function for testing.
// It returns a restore function that reverts to the previous value.
func SetFetchDownloads(fn FetchDownloadsFunc) func() {
	old := fetchDownloads
	fetchDownloads = fn
	return func() { fetchDownloads = old }
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

func scoreCVEs(pkgName, version string, auditCVEs map[string][]string, cache *TrustCache, failClosed bool) int {
	if auditCVEs != nil {
		cves, ok := auditCVEs[pkgName]
		if !ok {
			cache.SetVersionCVEs(pkgName, version, nil)
			return ptsNoCVEs
		}
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

	if failClosed {
		return 0
	}
	return ptsNoCVEs / 2
}

// Scores returns per-package score breakdowns from the last Evaluate call.
func (s *Scorer) Scores() []PackageScore {
	return s.scores
}

// CVEs returns the CVE data from the last Evaluate call.
func (s *Scorer) CVEs() map[string][]string {
	return s.lastCVEs
}

func (s *Scorer) fetchAuditCVEs(ctx context.Context) map[string][]string {
	if s.auditFunc != nil {
		return s.auditFunc(ctx)
	}

	switch s.pm {
	case "pnpm":
		return runAudit(ctx, "pnpm", parsePnpmAuditJSON, "audit", "--json")
	case "yarn":
		return runAudit(ctx, "yarn", parseNpmAuditJSON, "npm", "audit", "--json")
	case "bun":
		return nil
	default:
		return runAudit(ctx, "npm", parseNpmAuditJSON, "audit", "--json")
	}
}

func runAudit(ctx context.Context, name string, parse func([]byte) map[string][]string, arg ...string) map[string][]string {
	cmd := exec.CommandContext(ctx, name, arg...)
	output, err := cmd.Output()
	if err != nil {
		// pnpm audit --json exits 1 when vulnerabilities are found.
		// The output is still valid JSON — parse it unless output is empty.
		if len(output) == 0 {
			slog.Debug("audit failed — CVE data unavailable", "pm", name, "err", err)
			return nil
		}
	}
	return parse(output)
}

type npmAuditVulnerability struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
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

func parsePnpmAuditJSON(data []byte) map[string][]string {
	var resp struct {
		Advisories map[string]struct {
			ModuleName string `json:"module_name"`
			Severity   string `json:"severity"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil
	}
	result := make(map[string][]string, len(resp.Advisories))
	for _, adv := range resp.Advisories {
		name := adv.ModuleName
		result[name] = append(result[name], adv.Severity)
	}
	return result
}

func ScoreFromBreakdown(b ScoreBreakdown) PackageScore {
	return PackageScore{
		Total:     b.HashVerified + b.Maturity + b.Downloads + b.NoCVEs,
		Breakdown: b,
	}
}
