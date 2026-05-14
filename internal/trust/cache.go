package trust

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"scal-p/internal/ioutil"
)

const (
	DefaultCacheDir  = ".scalp/cache"
	DefaultCacheFile = ".scalp/cache/trust.json"
	DefaultTTL       = 7 * 24 * time.Hour
	maxCacheBytes    = 50 * 1024 * 1024 // 50 MB limit
)

type VersionCache struct {
	FetchedAt string   `json:"fetched_at"`
	CVEs      []string `json:"cves,omitempty"`
}

type CacheEntry struct {
	FetchedAt       string                  `json:"fetched_at"`
	WeeklyDownloads int                     `json:"weekly_downloads,omitempty"`
	CVEs            []string                `json:"cves,omitempty"`
	Versions        map[string]VersionCache `json:"versions,omitempty"`
}

type TrustCache struct {
	path    string
	entries map[string]CacheEntry
	mu      sync.RWMutex
	dirty   bool
}

func LoadCache(path string) (*TrustCache, error) {
	c := &TrustCache{
		path:    path,
		entries: map[string]CacheEntry{},
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, fmt.Errorf("open trust cache: %w", err)
	}
	defer f.Close() //nolint:errcheck

	dec := json.NewDecoder(io.LimitReader(f, maxCacheBytes))
	if err := dec.Decode(&c.entries); err != nil {
		return nil, fmt.Errorf("invalid trust cache JSON: %w", err)
	}

	return c, nil
}

func (c *TrustCache) Get(pkgName string) (CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[pkgName]
	return e, ok
}

func (c *TrustCache) Set(pkgName string, entry CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[pkgName] = entry
	c.dirty = true
}

func (c *TrustCache) GetVersionCVEs(pkgName, version string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[pkgName]
	if !ok {
		return nil
	}
	if entry.Versions != nil {
		if vc, ok := entry.Versions[version]; ok {
			return vc.CVEs
		}
	}
	return nil
}

func (c *TrustCache) SetVersionCVEs(pkgName, version string, cves []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[pkgName]
	if entry.Versions == nil {
		entry.Versions = map[string]VersionCache{}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	entry.Versions[version] = VersionCache{
		FetchedAt: now,
		CVEs:      cves,
	}
	entry.FetchedAt = now
	c.entries[pkgName] = entry
	c.dirty = true
}

func (c *TrustCache) SetDownloads(pkgName string, downloads int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[pkgName]
	entry.FetchedAt = time.Now().UTC().Format(time.RFC3339)
	entry.WeeklyDownloads = downloads
	if entry.Versions == nil {
		entry.Versions = map[string]VersionCache{}
	}
	c.entries[pkgName] = entry
	c.dirty = true
}

func (c *TrustCache) Save() error {
	c.mu.RLock()
	if !c.dirty {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := json.Marshal(c.entries)
	if err != nil {
		return fmt.Errorf("marshal trust cache: %w", err)
	}
	if err := ioutil.WriteFileAtomic(c.path, data, 0o644); err != nil {
		return fmt.Errorf("save cache: %w", err)
	}
	c.dirty = false
	return nil
}

func IsExpired(entry CacheEntry, ttl time.Duration) bool {
	t, err := time.Parse(time.RFC3339, entry.FetchedAt)
	if err != nil {
		return true
	}
	return time.Since(t) > ttl
}
