package main

import (
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveSecureCookieSetting(t *testing.T) {
	secure, err := resolveSecureCookieSetting("auto", false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !secure {
		t.Fatalf("expected secure cookies in auto mode when tls is enabled")
	}

	secure, err = resolveSecureCookieSetting("auto", false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secure {
		t.Fatalf("expected insecure cookies in auto mode when tls is disabled")
	}

	secure, err = resolveSecureCookieSetting("off", true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !secure {
		t.Fatalf("legacy secure cookies flag should force secure cookies")
	}
}

func TestBuildRequiredSANs(t *testing.T) {
	sans, err := buildRequiredSANs("127.0.0.1:18443", "cellweb.local,192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !containsString(sans.DNS, "localhost") {
		t.Fatalf("expected localhost in DNS SANs")
	}
	if !containsString(sans.DNS, "cellweb.local") {
		t.Fatalf("expected configured DNS SAN")
	}
	if !containsIP(sans.IPs, net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected listen host IP in SANs")
	}
	if !containsIP(sans.IPs, net.ParseIP("192.0.2.10")) {
		t.Fatalf("expected configured IP SAN")
	}
}

func TestBuildRequiredSANsRejectsInvalidEntry(t *testing.T) {
	_, err := buildRequiredSANs("127.0.0.1:18443", "bad name")
	if err == nil {
		t.Fatalf("expected error for invalid SAN")
	}
}

func TestMDNSSANFromHostname(t *testing.T) {
	mdns, ok := mdnsSANFromHostname("cells-gw.prod.example")
	if !ok {
		t.Fatalf("expected valid mDNS SAN")
	}
	if mdns != "cells-gw.local" {
		t.Fatalf("unexpected mDNS SAN: %q", mdns)
	}
}

func TestMDNSSANFromHostnameRejectsInvalid(t *testing.T) {
	if _, ok := mdnsSANFromHostname("bad_name"); ok {
		t.Fatalf("expected invalid hostname to be rejected")
	}
}

func TestRootCASubjectMatchesDefaults(t *testing.T) {
	cert := &x509.Certificate{}
	cert.Subject.CommonName = rootCACommonName
	cert.Subject.Organization = []string{rootCAOrganization}
	if !rootCASubjectMatches(cert) {
		t.Fatalf("expected root CA subject to match defaults")
	}
}

func TestPreferredBootstrapHostPrefersLocalDomain(t *testing.T) {
	host := preferredBootstrapHost(certSANs{
		DNS: []string{"localhost", "appliance.local", "example.net"},
	})
	if host != "appliance.local" {
		t.Fatalf("unexpected host: %q", host)
	}
}

func TestBootstrapBaseURLWithHostUsesPort(t *testing.T) {
	url := bootstrapBaseURLWithHost("https", "0.0.0.0:18443", "appliance.local")
	if url != "https://appliance.local:18443" {
		t.Fatalf("unexpected bootstrap URL: %q", url)
	}
}

func TestBuildTrustBootstrapLinesMaxWidth(t *testing.T) {
	fingerprint := "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
	lines := buildTrustBootstrapLines("0.0.0.0:18443", "very-long-hostname-for-bootstrap.local", fingerprint, "", 80)

	if len(lines) == 0 {
		t.Fatalf("expected bootstrap lines")
	}
	for i, line := range lines {
		if len(line) > 80 {
			t.Fatalf("line %d exceeds width: len=%d text=%q", i, len(line), line)
		}
	}
}

func TestFormatFingerprintForDisplayBreaksIntoMultipleLines(t *testing.T) {
	fingerprint := "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
	lines := formatFingerprintForDisplay(fingerprint, "  ", 80)
	if len(lines) < 2 {
		t.Fatalf("expected multi-line fingerprint output")
	}
}

func TestBuildTrustBootstrapLinesIncludesHTTPDownloadPathWhenConfigured(t *testing.T) {
	fingerprint := "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
	lines := buildTrustBootstrapLines("0.0.0.0:18443", "appliance.local", fingerprint, "0.0.0.0:18088", 80)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "http://appliance.local:18088"+localCACertRoute) {
		t.Fatalf("expected HTTP bootstrap download URL in output")
	}
	if strings.Contains(joined, "one-time security exception") {
		t.Fatalf("did not expect exception step when HTTP bootstrap is configured")
	}
}

func TestCertificateSHA256FingerprintFormat(t *testing.T) {
	fp := certificateSHA256Fingerprint([]byte("cellweb"))
	parts := strings.Split(fp, ":")
	if len(parts) != 32 {
		t.Fatalf("unexpected fingerprint segments: got %d want 32", len(parts))
	}
	for _, p := range parts {
		if len(p) != 2 {
			t.Fatalf("unexpected fingerprint segment %q", p)
		}
	}
}

func TestHTTPBootstrapHandlerServesBootstrapPageAndCACert(t *testing.T) {
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	h := newHTTPBootstrapHandler("0.0.0.0:18443", caPEM)

	pageReq := httptest.NewRequest(http.MethodGet, "http://appliance.local:18088/bootstrap", nil)
	pageRec := httptest.NewRecorder()
	h.ServeHTTP(pageRec, pageReq)

	if pageRec.Code != http.StatusOK {
		t.Fatalf("unexpected bootstrap page status: got %d want %d", pageRec.Code, http.StatusOK)
	}
	body := pageRec.Body.String()
	if !strings.Contains(body, "Download Root CA certificate") {
		t.Fatalf("expected bootstrap page to include download button")
	}
	if strings.Contains(body, "Root CA SHA-256 fingerprint") {
		t.Fatalf("did not expect fingerprint to be shown on bootstrap page")
	}
	if strings.Contains(body, "Bootstrap URL") {
		t.Fatalf("did not expect bootstrap URL text on bootstrap page")
	}
	if !strings.Contains(body, "https://appliance.local:18443/") {
		t.Fatalf("expected bootstrap page to include https login URL")
	}

	caReq := httptest.NewRequest(http.MethodGet, "http://appliance.local:18088"+localCACertRoute, nil)
	caRec := httptest.NewRecorder()
	h.ServeHTTP(caRec, caReq)

	if caRec.Code != http.StatusOK {
		t.Fatalf("unexpected ca cert status: got %d want %d", caRec.Code, http.StatusOK)
	}
	if got := caRec.Body.String(); got != string(caPEM) {
		t.Fatalf("unexpected CA cert payload: got %q want %q", got, string(caPEM))
	}
}

func TestHTTPBootstrapHandlerRedirectsUnknownPathToHTTPS(t *testing.T) {
	h := newHTTPBootstrapHandler("0.0.0.0:18443", []byte("pem"))
	req := httptest.NewRequest(http.MethodGet, "http://appliance.local:18088/api/me", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("unexpected status: got %d want %d", rec.Code, http.StatusMovedPermanently)
	}
	if got := rec.Header().Get("Location"); got != "https://appliance.local:18443/api/me" {
		t.Fatalf("unexpected redirect target: got %q", got)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsIP(values []net.IP, target net.IP) bool {
	want := normalizeIP(target)
	for _, value := range values {
		if normalizeIP(value).Equal(want) {
			return true
		}
	}
	return false
}
