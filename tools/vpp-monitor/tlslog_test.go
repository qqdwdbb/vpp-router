package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestTLSCertificateRejectionsAreRateLimited(t *testing.T) {
	var output bytes.Buffer
	now := time.Unix(100, 0)
	w := &tlsErrorLog{output: &output, now: func() time.Time { return now }}
	rejection := []byte("http: TLS handshake error from 10.61.30.43:1234: remote error: tls: unknown certificate\n")
	for i := 0; i < 10; i++ {
		n, err := w.Write(rejection)
		if err != nil || n != len(rejection) {
			t.Fatalf("write: %d, %v", n, err)
		}
	}
	if output.String() != string(rejection) {
		t.Fatal(output.String())
	}
	other := []byte("http: TLS handshake error from 10.61.30.43:4321: unexpected EOF\n")
	if _, err := w.Write(other); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), string(other)) {
		t.Fatal("unrelated error suppressed")
	}
	now = now.Add(time.Minute)
	if _, err := w.Write(rejection); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "suppressed 9 similar certificate rejections") {
		t.Fatal(output.String())
	}
}
