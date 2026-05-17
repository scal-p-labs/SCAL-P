package trust_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"scal-p/internal/lockfile"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/policy"
	"scal-p/internal/trust"
)

func testScorer(t *testing.T, downloads int) *trust.Scorer {
	t.Helper()
	s := trust.NewScorer(t.TempDir() + "/trust.json")
	restore := trust.SetFetchDownloads(func(ctx context.Context, apiURL, pkgName string) (int, error) {
		return downloads, nil
	})
	t.Cleanup(restore)
	return s
}

func TestScoreHash(t *testing.T) {
	scorer := testScorer(t, 0)

	t.Run("hash verified gives 30 pts", func(t *testing.T) {
		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages: map[string]lockfile.LockEntry{
				"lodash@4.17.21": {Integrity: "sha512-abc"},
			},
		}
		node := pkgmanager.PackageNode{Name: "lodash", Version: "4.17.21"}
		pol := policy.Policy{Trust: policy.Trust{MinScore: 30}}

		nodes := []pkgmanager.PackageNode{node}
		violations, err := scorer.Evaluate(context.Background(), pol, nodes, &lf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 0 {
			t.Errorf("expected 0 violations for hash verified, got %d", len(violations))
		}
	})

	t.Run("no hash gives violation due to low score", func(t *testing.T) {
		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages:    map[string]lockfile.LockEntry{},
		}
		node := pkgmanager.PackageNode{Name: "unverified", Version: "0.5.0"}
		pol := policy.Policy{Trust: policy.Trust{MinScore: 30}}

		violations, err := scorer.Evaluate(context.Background(), pol, []pkgmanager.PackageNode{node}, &lf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) == 0 {
			t.Fatal("expected violation for unverified package")
		}
		if violations[0].PackageID != "unverified@0.5.0" {
			t.Errorf("expected unverified@0.5.0, got %s", violations[0].PackageID)
		}
	})
}

func TestRequireHash(t *testing.T) {
	scorer := testScorer(t, 0)

	t.Run("RequireHash blocks package without lockfile entry", func(t *testing.T) {
		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages:    map[string]lockfile.LockEntry{},
		}
		node := pkgmanager.PackageNode{Name: "fresh", Version: "1.0.0"}
		pol := policy.Policy{Trust: policy.Trust{RequireHash: true, MinScore: 0}}

		violations, err := scorer.Evaluate(context.Background(), pol, []pkgmanager.PackageNode{node}, &lf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation with RequireHash, got %d", len(violations))
		}
		if !strings.Contains(violations[0].Reason, "hash_required") {
			t.Errorf("expected hash_required reason, got %s", violations[0].Reason)
		}
		if violations[0].PackageID != "fresh@1.0.0" {
			t.Errorf("expected fresh@1.0.0, got %s", violations[0].PackageID)
		}
	})

	t.Run("RequireHash passes package with lockfile integrity", func(t *testing.T) {
		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages: map[string]lockfile.LockEntry{
				"safe@2.0.0": {Integrity: "sha512-xyz"},
			},
		}
		node := pkgmanager.PackageNode{Name: "safe", Version: "2.0.0"}
		pol := policy.Policy{Trust: policy.Trust{RequireHash: true, MinScore: 0}}

		violations, err := scorer.Evaluate(context.Background(), pol, []pkgmanager.PackageNode{node}, &lf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 0 {
			t.Errorf("expected 0 violations for hashed package with RequireHash, got %d", len(violations))
		}
	})

	t.Run("RequireHash+MinScore both enforced independently", func(t *testing.T) {
		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages: map[string]lockfile.LockEntry{
				"no-hash@1.0.0":   {},
				"low-score@0.1.0": {Integrity: "sha512-abc"},
			},
		}
		nodes := []pkgmanager.PackageNode{
			{Name: "no-hash", Version: "1.0.0"},
			{Name: "low-score", Version: "0.1.0"},
		}
		pol := policy.Policy{Trust: policy.Trust{RequireHash: true, MinScore: 50}}

		violations, err := scorer.Evaluate(context.Background(), pol, nodes, &lf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 2 {
			t.Fatalf("expected 2 violations (hash + score), got %d", len(violations))
		}
	})
}

func TestScoreMaturity(t *testing.T) {
	tests := []struct {
		version string
		pts     int
	}{
		{"1.0.0", 15},
		{"2.3.4", 15},
		{"1.0.0-alpha", 15},
		{"0.1.0", 0},
		{"0.9.9", 0},
		{"0.0.1", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := trust.ScoreMaturity(tt.version)
		if got != tt.pts {
			t.Errorf("ScoreMaturity(%q) = %d, want %d", tt.version, got, tt.pts)
		}
	}
}

func TestDownloadsThreshold(t *testing.T) {
	tests := []struct {
		n   int
		pts int
	}{
		{0, 0},
		{50, 0},
		{99, 0},
		{100, 5},
		{500, 5},
		{999, 5},
		{1000, 10},
		{5000, 10},
		{9999, 10},
		{10000, 15},
		{50000, 15},
		{99999, 15},
		{100000, 20},
		{1000000, 20},
	}
	for _, tt := range tests {
		got := trust.ScoreDownloadsByCount(tt.n)
		if got != tt.pts {
			t.Errorf("ScoreDownloadsByCount(%d) = %d, want %d", tt.n, got, tt.pts)
		}
	}
}

func TestEvaluate_offlineUnknownGetsHalfPoints(t *testing.T) {
	scorer := testScorer(t, 0)

	lf := lockfile.Lockfile{
		LockVersion: 1,
		Packages: map[string]lockfile.LockEntry{
			"pkg@1.0.0": {Integrity: "sha512-abc"},
		},
	}
	node := pkgmanager.PackageNode{Name: "pkg", Version: "1.0.0"}
	pol := policy.Policy{Trust: policy.Trust{MinScore: 70}}

	violations, err := scorer.Evaluate(context.Background(), pol, []pkgmanager.PackageNode{node}, &lf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) == 0 {
		t.Fatal("expected violation when score < min_score")
	}
	v := violations[0]
	if !strings.Contains(v.Reason, "hash:30") {
		t.Errorf("expected hash:30 in reason, got %s", v.Reason)
	}
	if !strings.Contains(v.Reason, "maturity:15") {
		t.Errorf("expected maturity:15 in reason, got %s", v.Reason)
	}
}

func TestScoreWithZeroCVEs(t *testing.T) {
	score := trust.ScoreFromBreakdown(trust.ScoreBreakdown{
		HashVerified: 30,
		Maturity:     15,
		Downloads:    10,
		NoCVEs:       0,
	})
	if score.Total != 55 {
		t.Fatalf("expected 55 total with 0 CVE, got %d", score.Total)
	}
}

func TestEvaluate_minScoreZeroSkips(t *testing.T) {
	scorer := testScorer(t, 0)

	pol := policy.Policy{Trust: policy.Trust{MinScore: 0}}
	violations, err := scorer.Evaluate(context.Background(), pol, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected 0 violations with min_score=0, got %d", len(violations))
	}
}

func TestEvaluate_multiplePackages(t *testing.T) {
	scorer := testScorer(t, 0)

	lf := lockfile.Lockfile{
		LockVersion: 1,
		Packages: map[string]lockfile.LockEntry{
			"good@1.0.0": {Integrity: "sha512-abc"},
		},
	}
	nodes := []pkgmanager.PackageNode{
		{Name: "good", Version: "1.0.0"},
		{Name: "bad", Version: "0.5.0"},
	}
	pol := policy.Policy{Trust: policy.Trust{MinScore: 30}}

	violations, err := scorer.Evaluate(context.Background(), pol, nodes, &lf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].PackageID != "bad@0.5.0" {
		t.Errorf("expected bad@0.5.0, got %s", violations[0].PackageID)
	}
}

func TestEvaluate_withDownloadScore(t *testing.T) {
	scorer := testScorer(t, 500000)

	lf := lockfile.Lockfile{
		LockVersion: 1,
		Packages: map[string]lockfile.LockEntry{
			"popular@1.0.0": {Integrity: "sha512-abc"},
		},
	}
	nodes := []pkgmanager.PackageNode{
		{Name: "popular", Version: "1.0.0"},
	}
	pol := policy.Policy{Trust: policy.Trust{MinScore: 60}}

	violations, err := scorer.Evaluate(context.Background(), pol, nodes, &lf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected 0 violations with high score, got %d", len(violations))
	}
}

func TestCVEScoring(t *testing.T) {
	t.Run("npm audit succeeds with CVEs gives 0 pts", func(t *testing.T) {
		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages: map[string]lockfile.LockEntry{
				"evil@1.0.0": {Integrity: "sha512-abc"},
			},
		}
		node := pkgmanager.PackageNode{Name: "evil", Version: "1.0.0"}
		pol := policy.Policy{Trust: policy.Trust{MinScore: 100}}

		s2 := trust.NewScorer(t.TempDir() + "/trust.json")
		restore := trust.SetFetchDownloads(func(ctx context.Context, apiURL, pkgName string) (int, error) {
			return 0, nil
		})
		t.Cleanup(restore)
		s2.SetAuditFunc(func(ctx context.Context) map[string][]string {
			return map[string][]string{"evil": {"critical"}}
		})

		violations, err := s2.Evaluate(context.Background(), pol, []pkgmanager.PackageNode{node}, &lf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation for package with CVEs, got %d", len(violations))
		}
	})

	t.Run("npm audit succeeds without CVEs gives 15 pts", func(t *testing.T) {
		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages: map[string]lockfile.LockEntry{
				"clean@1.0.0": {Integrity: "sha512-abc"},
			},
		}
		node := pkgmanager.PackageNode{Name: "clean", Version: "1.0.0"}
		pol := policy.Policy{Trust: policy.Trust{MinScore: 60}}

		s2 := trust.NewScorer(t.TempDir() + "/trust.json")
		restore := trust.SetFetchDownloads(func(ctx context.Context, apiURL, pkgName string) (int, error) {
			return 0, nil
		})
		t.Cleanup(restore)
		s2.SetAuditFunc(func(ctx context.Context) map[string][]string {
			return map[string][]string{}
		})

		violations, err := s2.Evaluate(context.Background(), pol, []pkgmanager.PackageNode{node}, &lf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 0 {
			t.Errorf("expected 0 violations for package without CVEs, got %d", len(violations))
		}
	})

	t.Run("no audit data with version cache CVEs gives 0 pts", func(t *testing.T) {
		dir := t.TempDir()
		cachePath := dir + "/trust.json"
		cache, err := trust.LoadCache(cachePath)
		if err != nil {
			t.Fatal(err)
		}
		cache.SetVersionCVEs("pkg", "1.0.0", []string{"GHSA-xxx"})
		if err := cache.Save(); err != nil {
			t.Fatal(err)
		}

		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages: map[string]lockfile.LockEntry{
				"pkg@1.0.0": {Integrity: "sha512-abc"},
			},
		}
		node := pkgmanager.PackageNode{Name: "pkg", Version: "1.0.0"}
		pol := policy.Policy{Trust: policy.Trust{MinScore: 50}}

		s2 := trust.NewScorer(cachePath)
		restore := trust.SetFetchDownloads(func(ctx context.Context, apiURL, pkgName string) (int, error) {
			return 0, nil
		})
		t.Cleanup(restore)
		s2.SetAuditFunc(func(ctx context.Context) map[string][]string {
			return nil
		})

		violations, err := s2.Evaluate(context.Background(), pol, []pkgmanager.PackageNode{node}, &lf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation for cached-CVE package, got %d", len(violations))
		}
	})

	t.Run("no audit data, no cache gives 7 pts (half)", func(t *testing.T) {
		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages: map[string]lockfile.LockEntry{
				"unknown@1.0.0": {Integrity: "sha512-abc"},
			},
		}
		node := pkgmanager.PackageNode{Name: "unknown", Version: "1.0.0"}
		pol := policy.Policy{Trust: policy.Trust{MinScore: 70}}

		s2 := trust.NewScorer(t.TempDir() + "/trust.json")
		restore := trust.SetFetchDownloads(func(ctx context.Context, apiURL, pkgName string) (int, error) {
			return 0, nil
		})
		t.Cleanup(restore)
		s2.SetAuditFunc(func(ctx context.Context) map[string][]string {
			return nil
		})

		violations, err := s2.Evaluate(context.Background(), pol, []pkgmanager.PackageNode{node}, &lf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		score := 30 + 15 + 10 + 7 // hash + maturity + dl half + cve half
		if score >= 70 {
			t.Fatal("test setup error: score too high for violation")
		}
		if len(violations) != 1 {
			t.Errorf("expected 1 violation for unknown package (score=%d < 70), got %d", score, len(violations))
		}
	})
}

func TestAdversarial_cachePoisoning(t *testing.T) {
	t.Run("stale cache with expired entry triggers refresh", func(t *testing.T) {
		dir := t.TempDir()
		cachePath := dir + "/trust.json"
		cache, err := trust.LoadCache(cachePath)
		if err != nil {
			t.Fatal(err)
		}
		oldTime := time.Now().Add(-10 * 24 * time.Hour).UTC().Format(time.RFC3339)
		cache.Set("old-pkg", trust.CacheEntry{
			FetchedAt:       oldTime,
			WeeklyDownloads: 9999999,
		})
		if err := cache.Save(); err != nil {
			t.Fatal(err)
		}

		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages: map[string]lockfile.LockEntry{
				"old-pkg@1.0.0": {Integrity: "sha512-abc"},
			},
		}
		pol := policy.Policy{Trust: policy.Trust{MinScore: 50}}
		s2 := trust.NewScorer(cachePath)
		restore := trust.SetFetchDownloads(func(ctx context.Context, apiURL, pkgName string) (int, error) {
			return 0, nil
		})
		t.Cleanup(restore)
		s2.SetAuditFunc(func(ctx context.Context) map[string][]string { return nil })

		violations, err := s2.Evaluate(context.Background(), pol, []pkgmanager.PackageNode{
			{Name: "old-pkg", Version: "1.0.0"},
		}, &lf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		cache2, _ := trust.LoadCache(cachePath)
		entry, ok := cache2.Get("old-pkg")
		if !ok {
			t.Fatal("expected entry in cache after evaluation")
		}
		if entry.WeeklyDownloads == 9999999 {
			t.Error("expected stale download count to be refreshed")
		}
		if len(violations) != 0 {
			t.Errorf("expected 0 violations, got %d", len(violations))
		}
	})

	t.Run("cache with fake CVEs is treated as known bad", func(t *testing.T) {
		dir := t.TempDir()
		cachePath := dir + "/trust.json"
		cache, err := trust.LoadCache(cachePath)
		if err != nil {
			t.Fatal(err)
		}
		cache.SetVersionCVEs("poisoned", "1.0.0", []string{"GHSA-fake"})
		if err := cache.Save(); err != nil {
			t.Fatal(err)
		}

		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages: map[string]lockfile.LockEntry{
				"poisoned@1.0.0": {Integrity: "sha512-abc"},
			},
		}
		pol := policy.Policy{Trust: policy.Trust{MinScore: 50}}
		s2 := trust.NewScorer(cachePath)
		restore := trust.SetFetchDownloads(func(ctx context.Context, apiURL, pkgName string) (int, error) {
			return 0, nil
		})
		t.Cleanup(restore)
		s2.SetAuditFunc(func(ctx context.Context) map[string][]string { return nil })

		violations, err := s2.Evaluate(context.Background(), pol, []pkgmanager.PackageNode{
			{Name: "poisoned", Version: "1.0.0"},
		}, &lf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(violations) != 1 {
			t.Errorf("expected 1 violation for poisoned cache (has fake CVEs), got %d", len(violations))
		}
	})

	t.Run("corrupted cache JSON recovers gracefully", func(t *testing.T) {
		dir := t.TempDir()
		cachePath := dir + "/trust.json"
		os.WriteFile(cachePath, []byte("{corrupted json"), 0o644) //nolint:errcheck

		cache, err := trust.LoadCache(cachePath)
		if err == nil {
			t.Fatal("expected error for corrupted cache")
		}
		if cache != nil {
			t.Errorf("expected nil cache on error, got %+v", cache)
		}
	})

	t.Run("cache poisoned with future timestamp is not expired", func(t *testing.T) {
		future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
		entry := trust.CacheEntry{FetchedAt: future}
		if trust.IsExpired(entry, 7*24*time.Hour) {
			t.Error("expected future-dated entry to not be expired")
		}
	})
}

func TestScoreBreakdown(t *testing.T) {
	b := trust.ScoreBreakdown{
		HashVerified: 30,
		Maturity:     15,
		Downloads:    20,
		NoCVEs:       15,
	}
	ps := trust.ScoreFromBreakdown(b)
	if ps.Total != 80 {
		t.Errorf("expected total 80, got %d", ps.Total)
	}
}

func TestViolationMessageContainsBreakdown(t *testing.T) {
	scorer := testScorer(t, 0)

	lf := lockfile.Lockfile{
		LockVersion: 1,
		Packages:    map[string]lockfile.LockEntry{},
	}
	node := pkgmanager.PackageNode{Name: "test", Version: "0.1.0"}
	pol := policy.Policy{Trust: policy.Trust{MinScore: 50}}

	violations, err := scorer.Evaluate(context.Background(), pol, []pkgmanager.PackageNode{node}, &lf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) == 0 {
		t.Fatal("expected violation")
	}
	msg := violations[0].Reason
	if !strings.Contains(msg, "trust_score:") {
		t.Errorf("expected trust_score prefix, got %s", msg)
	}
	if !strings.Contains(msg, "hash:") || !strings.Contains(msg, "maturity:") ||
		!strings.Contains(msg, "dl:") || !strings.Contains(msg, "cves:") {
		t.Errorf("expected breakdown in violation message, got %s", msg)
	}
}
