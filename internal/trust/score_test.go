package trust_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

	t.Run("no hash gives 0 pts and violation", func(t *testing.T) {
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
		t.Errorf("expected 0 violations with 80pts >= 60, got %d", len(violations))
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
