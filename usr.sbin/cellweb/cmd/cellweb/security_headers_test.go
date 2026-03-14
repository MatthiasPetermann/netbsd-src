package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithSecurityHeadersSetsHSTSWhenEnabledAndTLS(t *testing.T) {
	h := withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), true)

	req := httptest.NewRequest(http.MethodGet, "https://example.local/", nil)
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatalf("expected HSTS header when enabled over TLS")
	}
}

func TestWithSecurityHeadersSkipsHSTSWhenDisabled(t *testing.T) {
	h := withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), false)

	req := httptest.NewRequest(http.MethodGet, "https://example.local/", nil)
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("expected no HSTS header when disabled, got %q", got)
	}
}
