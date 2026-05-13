package trust

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	DefaultCacheDir = ".scalp/cache"
	DefaultCacheFile = ".scalp/cache/trust.json"
	DefaultTTL       = 7 * 24 * time.Hour
)

type CacheEntry struct {
	FetchedAt       string   `json:"fetched_at"`
	WeeklyDownloads int      `json:"weekly_downloads,omitempty"`
	CVEs            []string `json:"cves,omitempty"`
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
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, fmt.Errorf("read trust cache: %w", err)
	}
	if err := json.Unmarshal(data, &c.entries); err != nil {
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

func (c *TrustCache) Save() error {
	c.mu.RLock()
	if !c.dirty {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	data, err := json.MarshalIndent(c.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal trust cache: %w", err)
	}
	if err := os.WriteFile(c.path, data, 0o644); err != nil {
		return fmt.Errorf("write trust cache: %w", err)
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
