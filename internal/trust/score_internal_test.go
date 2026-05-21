package trust

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"scal-p/internal/lockfile"
	"scal-p/internal/pkgmanager"
)

// ──────────────────────────────────────────────
// parseVersion
// ──────────────────────────────────────────────

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input     string
		wantMajor int
		wantMinor int
		wantPatch int
	}{
		{"1.2.3", 1, 2, 3},
		{"1.0.0-alpha", 1, 0, 0},
		{"1.0.0+build123", 1, 0, 0},
		{"^1.2.3", 1, 2, 3},
		{"~0.2.3", 0, 2, 3},
		{">=2.0.0", 2, 0, 0},
		{"<1.0.0", 1, 0, 0}, // TrimLeft strips <, result is "1.0.0"
		{"1", 1, 0, 0},
		{"1.2", 1, 2, 0},
		{"0.0.0", 0, 0, 0},
		{"abc", 0, 0, 0},
		{"../../../etc/passwd", 0, 0, 0},
		{"", 0, 0, 0},
		{"1.2.3 ", 1, 2, 3},
		{"  1.2.3", 1, 2, 3},
		{"1.2.3.4", 1, 2, 0},
	}
	for _, tt := range tests {
		major, minor, patch := parseVersion(tt.input)
		if major != tt.wantMajor || minor != tt.wantMinor || patch != tt.wantPatch {
			t.Errorf("parseVersion(%q) = (%d,%d,%d), want (%d,%d,%d)",
				tt.input, major, minor, patch,
				tt.wantMajor, tt.wantMinor, tt.wantPatch)
		}
	}
}

// ──────────────────────────────────────────────
// scoreHash
// ──────────────────────────────────────────────

func TestScoreHash_direct(t *testing.T) {
	tests := []struct {
		name string
		node pkgmanager.PackageNode
		lf   *lockfile.Lockfile
		want int
	}{
		{
			name: "hash present",
			node: pkgmanager.PackageNode{Name: "lodash", Version: "4.17.21"},
			lf: &lockfile.Lockfile{
				Packages: map[string]lockfile.LockEntry{
					"lodash@4.17.21": {Integrity: "sha512-abc"},
				},
			},
			want: ptsHashVerified,
		},
		{
			name: "lockfile is nil",
			node: pkgmanager.PackageNode{Name: "pkg", Version: "1.0.0"},
			lf:   nil,
			want: 0,
		},
		{
			name: "entry exists but no integrity",
			node: pkgmanager.PackageNode{Name: "pkg", Version: "1.0.0"},
			lf: &lockfile.Lockfile{
				Packages: map[string]lockfile.LockEntry{
					"pkg@1.0.0": {},
				},
			},
			want: 0,
		},
		{
			name: "package not in lockfile",
			node: pkgmanager.PackageNode{Name: "missing", Version: "2.0.0"},
			lf: &lockfile.Lockfile{
				Packages: map[string]lockfile.LockEntry{
					"other@1.0.0": {Integrity: "sha512-abc"},
				},
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scoreHash(tt.node, tt.lf)
			if got != tt.want {
				t.Errorf("scoreHash(%s@%s) = %d, want %d", tt.node.Name, tt.node.Version, got, tt.want)
			}
		})
	}
}

// ──────────────────────────────────────────────
// scoreCVEs — all 7 branches
// ──────────────────────────────────────────────

func TestScoreCVEs_direct(t *testing.T) {
	pkgName := "test-pkg"
	version := "1.0.0"

	t.Run("has audit with CVEs gives 0", func(t *testing.T) {
		cache := &TrustCache{entries: map[string]CacheEntry{}}
		auditCVEs := map[string][]string{pkgName: {"critical"}}

		got := scoreCVEs(pkgName, version, auditCVEs, cache)
		if got != 0 {
			t.Errorf("expected 0, got %d", got)
		}
		// cache should have the version CVEs now
		versionCVEs := cache.GetVersionCVEs(pkgName, version)
		if len(versionCVEs) != 1 || versionCVEs[0] != "critical" {
			t.Errorf("expected [critical] in cache, got %v", versionCVEs)
		}
	})

	t.Run("has audit without CVEs gives 15", func(t *testing.T) {
		cache := &TrustCache{entries: map[string]CacheEntry{}}
		auditCVEs := map[string][]string{pkgName: {}}

		got := scoreCVEs(pkgName, version, auditCVEs, cache)
		if got != ptsNoCVEs {
			t.Errorf("expected %d, got %d", ptsNoCVEs, got)
		}
		// cache stores nil when audit returns empty
		versionCVEs := cache.GetVersionCVEs(pkgName, version)
		if versionCVEs != nil {
			t.Errorf("expected nil version CVEs in cache, got %v", versionCVEs)
		}
	})

	t.Run("no audit, cached version CVEs present gives 0", func(t *testing.T) {
		cache := &TrustCache{entries: map[string]CacheEntry{
			pkgName: {
				Versions: map[string]VersionCache{
					version: {CVEs: []string{"GHSA-xxx"}},
				},
			},
		}}

		got := scoreCVEs(pkgName, version, nil, cache)
		if got != 0 {
			t.Errorf("expected 0, got %d", got)
		}
	})

	t.Run("no audit, cached version CVEs empty gives 15", func(t *testing.T) {
		cache := &TrustCache{entries: map[string]CacheEntry{
			pkgName: {
				Versions: map[string]VersionCache{
					version: {CVEs: []string{}},
				},
			},
		}}

		got := scoreCVEs(pkgName, version, nil, cache)
		if got != ptsNoCVEs {
			t.Errorf("expected %d, got %d", ptsNoCVEs, got)
		}
	})

	t.Run("no audit, no version CVEs, entry with CVEs gives 0", func(t *testing.T) {
		cache := &TrustCache{entries: map[string]CacheEntry{
			pkgName: {CVEs: []string{"GHSA-old"}},
		}}

		got := scoreCVEs(pkgName, version, nil, cache)
		if got != 0 {
			t.Errorf("expected 0, got %d", got)
		}
	})

	t.Run("no audit, no version CVEs, entry without CVEs gives 15", func(t *testing.T) {
		cache := &TrustCache{entries: map[string]CacheEntry{
			pkgName: {},
		}}

		got := scoreCVEs(pkgName, version, nil, cache)
		if got != ptsNoCVEs {
			t.Errorf("expected %d, got %d", ptsNoCVEs, got)
		}
	})

	t.Run("no audit, no version CVEs, no entry gives 7 (half)", func(t *testing.T) {
		cache := &TrustCache{entries: map[string]CacheEntry{}}

		got := scoreCVEs(pkgName, version, nil, cache)
		if got != ptsNoCVEs/2 {
			t.Errorf("expected %d, got %d", ptsNoCVEs/2, got)
		}
	})
}

// ──────────────────────────────────────────────
// scoreDownloadsCached
// ──────────────────────────────────────────────

func TestScoreDownloadsCached_hit(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "trust.json")
	s := NewScorer(cachePath)

	cache, err := LoadCache(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	cache.SetDownloads("lodash", 50000)

	got := s.scoreDownloadsCached(context.Background(), "lodash", cache)
	if want := ScoreDownloadsByCount(50000); got != want {
		t.Errorf("scoreDownloadsCached = %d, want %d", got, want)
	}
}

func TestScoreDownloadsCached_fallbackOnFetchFail(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "trust.json")
	s := NewScorer(cachePath)

	restore := SetFetchDownloads(func(ctx context.Context, _, _ string) (int, error) {
		return 0, os.ErrClosed
	})
	defer restore()

	cache, err := LoadCache(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	cache.Set("lodash", CacheEntry{
		WeeklyDownloads: 50000,
		FetchedAt:       "2026-01-01T00:00:00Z",
	})

	// Cache entry exists but is expired; fetch fails → fallback to stale value.
	got := s.scoreDownloadsCached(context.Background(), "lodash", cache)
	if want := ScoreDownloadsByCount(50000); got != want {
		t.Errorf("scoreDownloadsCached = %d, want %d", got, want)
	}
}

func TestScoreDownloadsCached_halfOnFetchFailNoCache(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "trust.json")
	s := NewScorer(cachePath)

	restore := SetFetchDownloads(func(ctx context.Context, _, _ string) (int, error) {
		return 0, os.ErrClosed
	})
	defer restore()

	cache, err := LoadCache(cachePath)
	if err != nil {
		t.Fatal(err)
	}

	got := s.scoreDownloadsCached(context.Background(), "newpkg", cache)
	if want := ptsMaxDownloads / 2; got != want {
		t.Errorf("scoreDownloadsCached = %d, want %d", got, want)
	}
}
