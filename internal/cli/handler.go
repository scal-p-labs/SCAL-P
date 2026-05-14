package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

type cliHandler struct {
	debug bool
	inner slog.Handler
	w     io.Writer
}

func NewHandler(debug bool) *cliHandler {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if debug {
		opts.Level = slog.LevelDebug
	}
	return &cliHandler{
		debug: debug,
		inner: slog.NewTextHandler(os.Stderr, opts),
		w:     os.Stderr,
	}
}

func (h *cliHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *cliHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.debug {
		return h.inner.Handle(ctx, r)
	}

	msg := r.Message
	if strings.Contains(msg, "\n") {
		_, _ = fmt.Fprintln(h.w, msg)
		return nil
	}

	var details string
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "details" {
			details = a.Value.String()
			return false
		}
		return true
	})
	if details != "" {
		_, _ = fmt.Fprintln(h.w, msg)
		_, _ = fmt.Fprintln(h.w, details)
		return nil
	}

	var prefix string
	switch r.Level {
	case slog.LevelWarn:
		prefix = "! "
	default:
		prefix = ""
	}

	_, _ = fmt.Fprintln(h.w, prefix+msg)
	return nil
}

func (h *cliHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &cliHandler{
		debug: h.debug,
		inner: h.inner.WithAttrs(attrs),
		w:     h.w,
	}
}

func (h *cliHandler) WithGroup(name string) slog.Handler {
	return &cliHandler{
		debug: h.debug,
		inner: h.inner.WithGroup(name),
		w:     h.w,
	}
}
