package trust_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"scal-p/internal/trust"
)

func TestLoadCache_missingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	c, err := trust.LoadCache(path)
	if err != nil {
		t.Fatalf("unexpected error for missing file: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil cache")
	}
}

func TestCache_saveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	c, err := trust.LoadCache(path)
	if err != nil {
		t.Fatal(err)
	}

	c.Set("lodash", trust.CacheEntry{
		FetchedAt:       time.Now().UTC().Format(time.RFC3339),
		WeeklyDownloads: 50000,
		CVEs:            []string{"high"},
	})

	if err := c.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	c2, err := trust.LoadCache(path)
	if err != nil {
		t.Fatalf("load after save: %v", err)
	}

	entry, ok := c2.Get("lodash")
	if !ok {
		t.Fatal("expected lodash entry after reload")
	}
	if entry.WeeklyDownloads != 50000 {
		t.Errorf("expected 50000 downloads, got %d", entry.WeeklyDownloads)
	}
	if len(entry.CVEs) != 1 || entry.CVEs[0] != "high" {
		t.Errorf("expected [high] CVEs, got %v", entry.CVEs)
	}
}

func TestCache_versionAware(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	c, err := trust.LoadCache(path)
	if err != nil {
		t.Fatal(err)
	}

	c.SetVersionCVEs("lodash", "4.17.21", []string{"GHSA-xxx"})
	c.SetVersionCVEs("lodash", "4.17.20", nil)

	cves := c.GetVersionCVEs("lodash", "4.17.21")
	if len(cves) != 1 || cves[0] != "GHSA-xxx" {
		t.Errorf("expected [GHSA-xxx] for 4.17.21, got %v", cves)
	}

	cves = c.GetVersionCVEs("lodash", "4.17.20")
	if len(cves) != 0 {
		t.Errorf("expected empty for 4.17.20, got %v", cves)
	}

	cves = c.GetVersionCVEs("lodash", "5.0.0")
	if cves != nil {
		t.Errorf("expected nil for unknown version, got %v", cves)
	}

	if err := c.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	c2, err := trust.LoadCache(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	cves = c2.GetVersionCVEs("lodash", "4.17.21")
	if len(cves) != 1 || cves[0] != "GHSA-xxx" {
		t.Errorf("expected [GHSA-xxx] after reload, got %v", cves)
	}
}

func TestCache_setDownloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	c, err := trust.LoadCache(path)
	if err != nil {
		t.Fatal(err)
	}

	c.SetDownloads("lodash", 50000)

	entry, ok := c.Get("lodash")
	if !ok {
		t.Fatal("expected entry after SetDownloads")
	}
	if entry.WeeklyDownloads != 50000 {
		t.Errorf("expected 50000 downloads, got %d", entry.WeeklyDownloads)
	}
}

func TestCache_saveWithoutChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	c, err := trust.LoadCache(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Save(); err != nil {
		t.Fatalf("save on clean cache should not error: %v", err)
	}

	_, err = os.Stat(path)
	if !os.IsNotExist(err) {
		t.Errorf("expected file not created for clean cache save, got %v", err)
	}
}

func TestCache_concurrentAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	c, err := trust.LoadCache(path)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			c.Set("pkg", trust.CacheEntry{})
			c.Get("pkg")
		}
		done <- struct{}{}
	}()
	go func() {
		for i := 0; i < 10; i++ {
			c.Get("other")
			c.Set("other", trust.CacheEntry{})
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}

func TestIsExpired(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)

	t.Run("fresh entry not expired", func(t *testing.T) {
		entry := trust.CacheEntry{FetchedAt: now}
		if trust.IsExpired(entry, 7*24*time.Hour) {
			t.Error("expected fresh entry to not be expired")
		}
	})

	t.Run("old entry is expired", func(t *testing.T) {
		old := time.Now().Add(-10 * 24 * time.Hour).UTC().Format(time.RFC3339)
		entry := trust.CacheEntry{FetchedAt: old}
		if !trust.IsExpired(entry, 7*24*time.Hour) {
			t.Error("expected old entry to be expired")
		}
	})

	t.Run("invalid date considered expired", func(t *testing.T) {
		entry := trust.CacheEntry{FetchedAt: "not-a-date"}
		if !trust.IsExpired(entry, 7*24*time.Hour) {
			t.Error("expected invalid date to be expired")
		}
	})
}
