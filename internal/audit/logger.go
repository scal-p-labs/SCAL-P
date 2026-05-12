package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"scal-p/internal/ctxutil"
)

// Event represents a structured audit log entry.
type Event struct {
	Timestamp string `json:"ts"`
	Event     string `json:"event"`
	Package   string `json:"pkg,omitempty"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	Rule      string `json:"rule,omitempty"`
	HashMatch bool   `json:"hash_match,omitempty"`
}

// Logger writes audit events to a NDJSON file.
type Logger struct {
	path string
	mu   sync.Mutex
}

// NewLogger constructs a new audit logger for the given path.
func NewLogger(path string) *Logger {
	return &Logger{path: path}
}

// Log appends audit events to the log file.
func (l *Logger) Log(ctx context.Context, events []Event) (err error) {
	if len(events) == 0 {
		return nil
	}
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return fmt.Errorf("create audit log dir: %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close audit log: %w", closeErr))
		}
	}()

	enc := json.NewEncoder(f)
	for _, ev := range events {
		if err := ctxutil.Check(ctx); err != nil {
			return err
		}
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode audit event: %w", err)
		}
	}
	return nil
}

// Close closes the logger. It exists for future-proofing.
func (l *Logger) Close() error {
	return nil
}
