package testlog

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

type options struct {
	writers    []io.Writer
	handlerOpt *slog.HandlerOptions
}

type Option func(*options)

func WithSlogHandlerOptions(handlerOpt *slog.HandlerOptions) Option {
	return func(opt *options) {
		opt.handlerOpt = handlerOpt
	}
}

func WithWriters(writers ...io.Writer) Option {
	return func(opt *options) {
		opt.writers = writers
	}
}

// New creates a new slog text logger than outputs to t.Log.
func New(t *testing.T, opts ...Option) *slog.Logger {
	t.Helper()

	var opt options
	for _, fn := range opts {
		if fn != nil {
			fn(&opt)
		}
	}

	buf := bytes.NewBuffer(nil)
	if opt.writers != nil {
		opt.writers = append(opt.writers, buf)
	} else {
		opt.writers = make([]io.Writer, 0)
		opt.writers = append(opt.writers, buf)
	}

	w := io.MultiWriter(opt.writers...)

	handler := slog.NewTextHandler(w, opt.handlerOpt)

	return slog.New(&slogHandler{
		delegate: handler,
		t:        t,
		buffer:   buf,
	})
}

type slogHandler struct {
	t        *testing.T
	delegate slog.Handler
	buffer   *bytes.Buffer
	mu       sync.Mutex
}

func (h *slogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.delegate.Enabled(ctx, level)
}

func (h *slogHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	err := h.delegate.Handle(ctx, r)
	if err != nil {
		return err
	}

	content := h.buffer.String()
	h.buffer.Reset()

	h.t.Helper()
	h.t.Log(strings.TrimSuffix(content, "\n"))

	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &slogHandler{
		t:        h.t,
		delegate: h.delegate.WithAttrs(attrs),
		buffer:   h.buffer,
	}
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	return &slogHandler{
		t:        h.t,
		delegate: h.delegate.WithGroup(name),
		buffer:   h.buffer,
	}
}
