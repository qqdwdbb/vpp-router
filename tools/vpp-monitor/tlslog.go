package main

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"time"
)

// tlsErrorLog limits repeated client rejections of the dashboard certificate.
type tlsErrorLog struct {
	mu         sync.Mutex
	output     io.Writer
	now        func() time.Time
	next       time.Time
	suppressed uint64
}

func (w *tlsErrorLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !bytes.Contains(p, []byte("http: TLS handshake error from ")) ||
		!bytes.Contains(p, []byte("remote error: tls: unknown certificate")) {
		return w.output.Write(p)
	}
	now := w.now()
	if now.Before(w.next) {
		w.suppressed++
		return len(p), nil
	}
	line := p
	if w.suppressed > 0 {
		line = []byte(fmt.Sprintf("%s (suppressed %d similar certificate rejections)\n",
			bytes.TrimRight(p, "\n"), w.suppressed))
	}
	if _, err := w.output.Write(line); err != nil {
		return 0, err
	}
	w.suppressed = 0
	w.next = now.Add(time.Minute)
	return len(p), nil
}
