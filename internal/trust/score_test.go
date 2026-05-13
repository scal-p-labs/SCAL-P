package trust_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scal-p/internal/lockfile"
	"scal-p/internal/pkgmanager"
	"scal-p/internal/policy"
	"scal-p/internal/trust"
)

func mockDownloadsServer(t *testing.T, downloads int) (*httptest.Server, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"downloads": ` + fmt.Sprintf("%d", downloads) + `}`)) //nolint:errcheck
	}))
	return server, server.Close
}

func testScorer(t *testing.T, server *httptest.Server) *trust.Scorer {
	t.Helper()
	s := trust.NewScorer(t.TempDir() + "/trust.json")
	s.SetHTTPClient(server.Client())
	s.SetAPIURL(server.URL)
	return s
}

func TestScoreHash(t *testing.T) {
	server, close := mockDownloadsServer(t, 0)
	defer close()

	t.Run("hash verified gives 30 pts", func(t *testing.T) {
		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages: map[string]lockfile.LockEntry{
				"lodash@4.17.21": {Integrity: "sha512-abc"},
			},
		}
		node := pkgmanager.PackageNode{Name: "lodash", Version: "4.17.21"}
		pol := policy.Policy{Trust: policy.Trust{MinScore: 30}}

		scorer := testScorer(t, server)
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

		scorer := testScorer(t, server)
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
	server, close := mockDownloadsServer(t, 0)
	defer close()

	t.Run("RequireHash blocks package without lockfile entry", func(t *testing.T) {
		lf := lockfile.Lockfile{
			LockVersion: 1,
			Packages:    map[string]lockfile.LockEntry{},
		}
		node := pkgmanager.PackageNode{Name: "fresh", Version: "1.0.0"}
		pol := policy.Policy{Trust: policy.Trust{RequireHash: true, MinScore: 0}}

		scorer := testScorer(t, server)
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

		scorer := testScorer(t, server)
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
				"no-hash@1.0.0": {},
				"low-score@0.1.0": {Integrity: "sha512-abc"},
			},
		}
		nodes := []pkgmanager.PackageNode{
			{Name: "no-hash", Version: "1.0.0"},
			{Name: "low-score", Version: "0.1.0"},
		}
		pol := policy.Policy{Trust: policy.Trust{RequireHash: true, MinScore: 50}}

		scorer := testScorer(t, server)
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
	server, close := mockDownloadsServer(t, 0)
	defer close()

	lf := lockfile.Lockfile{
		LockVersion: 1,
		Packages: map[string]lockfile.LockEntry{
			"pkg@1.0.0": {Integrity: "sha512-abc"},
		},
	}
	node := pkgmanager.PackageNode{Name: "pkg", Version: "1.0.0"}
	pol := policy.Policy{Trust: policy.Trust{MinScore: 70}}

	scorer := testScorer(t, server)
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
	server, close := mockDownloadsServer(t, 0)
	defer close()

	scorer := testScorer(t, server)
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
	server, close := mockDownloadsServer(t, 0)
	defer close()

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

	scorer := testScorer(t, server)
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"downloads": 500000}`)) //nolint:errcheck
	}))
	defer server.Close()

	scorer := trust.NewScorer(t.TempDir() + "/trust.json")
	scorer.SetHTTPClient(server.Client())
	scorer.SetAPIURL(server.URL)

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
	server, close := mockDownloadsServer(t, 0)
	defer close()

	lf := lockfile.Lockfile{
		LockVersion: 1,
		Packages:    map[string]lockfile.LockEntry{},
	}
	node := pkgmanager.PackageNode{Name: "test", Version: "0.1.0"}
	pol := policy.Policy{Trust: policy.Trust{MinScore: 50}}

	scorer := testScorer(t, server)
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
