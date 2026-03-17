package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	tlsModeOff        = "off"
	tlsModeSelfSigned = "selfsigned"
	tlsModeManual     = "manual"

	secureCookiesModeAuto = "auto"
	secureCookiesModeOn   = "on"
	secureCookiesModeOff  = "off"

	defaultPKIDir      = "/var/db/cellweb/pki"
	localCACertRoute   = "/.well-known/ca.crt"
	httpBootstrapRoute = "/bootstrap"

	rootCAOrganization = "Petermann Digital"
	rootCACommonName   = "NetBSD Cells Appliance Local Root CA"
)

type trustInfo struct {
	TLS                 bool   `json:"tls"`
	Mode                string `json:"mode"`
	CADownloadPath      string `json:"ca_download_path,omitempty"`
	CAFingerprintSHA256 string `json:"ca_fingerprint_sha256,omitempty"`
	CASubject           string `json:"ca_subject,omitempty"`
	CANotAfter          string `json:"ca_not_after,omitempty"`
	BootstrapHint       string `json:"bootstrap_hint,omitempty"`
}

type tlsRuntime struct {
	Enabled       bool
	Mode          string
	CertFile      string
	KeyFile       string
	CACertPEM     []byte
	BootstrapHost string
	Trust         trustInfo
}

type certSANs struct {
	DNS []string
	IPs []net.IP
}

func normalizeTLSMode(raw string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	if mode == "" {
		mode = tlsModeOff
	}
	switch mode {
	case tlsModeOff, tlsModeSelfSigned, tlsModeManual:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid TLS mode %q (expected off|selfsigned|manual)", raw)
	}
}

func resolveSecureCookieSetting(rawMode string, legacyEnable, tlsEnabled bool) (bool, error) {
	if legacyEnable {
		return true, nil
	}
	mode := strings.ToLower(strings.TrimSpace(rawMode))
	if mode == "" {
		mode = secureCookiesModeAuto
	}
	switch mode {
	case secureCookiesModeAuto:
		return tlsEnabled, nil
	case secureCookiesModeOn:
		return true, nil
	case secureCookiesModeOff:
		return false, nil
	default:
		return false, fmt.Errorf("invalid -secure-cookies-mode %q (expected auto|on|off)", rawMode)
	}
}

func secureCookiesModeFromEnv() string {
	if mode := strings.ToLower(strings.TrimSpace(os.Getenv("CELLWEB_SECURE_COOKIES_MODE"))); mode != "" {
		return mode
	}
	return secureCookiesModeAuto
}

func prepareTLSRuntime(
	listenAddr, modeRaw, pkiDir, certFile, keyFile, sanCSV, exportCA string,
	logger *log.Logger,
) (tlsRuntime, error) {
	mode, err := normalizeTLSMode(modeRaw)
	if err != nil {
		return tlsRuntime{}, err
	}

	runtime := tlsRuntime{Mode: mode, Trust: trustInfo{TLS: mode != tlsModeOff, Mode: mode}}

	switch mode {
	case tlsModeOff:
		if strings.TrimSpace(exportCA) != "" {
			return tlsRuntime{}, errors.New("-tls-export-ca requires TLS selfsigned mode")
		}
		return runtime, nil

	case tlsModeManual:
		certFile = strings.TrimSpace(certFile)
		keyFile = strings.TrimSpace(keyFile)
		if certFile == "" || keyFile == "" {
			return tlsRuntime{}, errors.New("manual TLS mode requires both -tls-cert and -tls-key")
		}
		if strings.TrimSpace(exportCA) != "" {
			return tlsRuntime{}, errors.New("-tls-export-ca is only supported in selfsigned mode")
		}
		runtime.Enabled = true
		runtime.CertFile = certFile
		runtime.KeyFile = keyFile
		runtime.Trust.BootstrapHint = "TLS is active with manual certificate files. Verify your certificate chain in the browser/OS trust store."
		return runtime, nil

	case tlsModeSelfSigned:
		pkiDir = strings.TrimSpace(pkiDir)
		if pkiDir == "" {
			pkiDir = defaultPKIDir
		}

		sans, err := buildRequiredSANs(listenAddr, sanCSV)
		if err != nil {
			return tlsRuntime{}, err
		}
		runtime.BootstrapHost = preferredBootstrapHost(sans)

		caCert, caKey, caPEM, caCreated, err := loadOrCreateRootCA(pkiDir, logger)
		if err != nil {
			return tlsRuntime{}, err
		}
		if logger != nil && caCreated {
			logger.Printf("created files: %s, %s", filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key"))
		}

		serverCertFile := filepath.Join(pkiDir, "server.crt")
		serverKeyFile := filepath.Join(pkiDir, "server.key")
		serverCreated, err := loadOrCreateServerCert(serverCertFile, serverKeyFile, caCert, caKey, sans, logger)
		if err != nil {
			return tlsRuntime{}, err
		}
		if logger != nil && serverCreated {
			logger.Printf("created files: %s, %s", serverCertFile, serverKeyFile)
		}

		if exportCA = strings.TrimSpace(exportCA); exportCA != "" {
			if err := exportCACertificate(exportCA, caPEM); err != nil {
				return tlsRuntime{}, fmt.Errorf("export root CA: %w", err)
			}
			if logger != nil {
				logger.Printf("created file: %s", exportCA)
			}
		}

		fp := certificateSHA256Fingerprint(caCert.Raw)
		runtime.Enabled = true
		runtime.CertFile = serverCertFile
		runtime.KeyFile = serverKeyFile
		runtime.CACertPEM = caPEM
		runtime.Trust = trustInfo{
			TLS:                 true,
			Mode:                mode,
			CADownloadPath:      localCACertRoute,
			CAFingerprintSHA256: fp,
			CASubject:           caCert.Subject.String(),
			CANotAfter:          caCert.NotAfter.UTC().Format(time.RFC3339),
			BootstrapHint:       "Download the Root CA, then verify this fingerprint against SSH/console output before importing into your browser or OS trust store.",
		}
		return runtime, nil

	default:
		return tlsRuntime{}, fmt.Errorf("unsupported tls mode: %s", mode)
	}
}

func buildRequiredSANs(listenAddr, sanCSV string) (certSANs, error) {
	dnsSet := map[string]struct{}{}
	ipSet := map[string]net.IP{}

	addDNS := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		dnsSet[name] = struct{}{}
	}
	addIP := func(ip net.IP) {
		if ip == nil {
			return
		}
		ip = normalizeIP(ip)
		ipSet[ip.String()] = ip
	}

	addDNS("localhost")
	addIP(net.ParseIP("127.0.0.1"))
	addIP(net.ParseIP("::1"))

	host := extractListenHost(listenAddr)
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsUnspecified() {
			addIP(ip)
		}
	} else if host != "" && host != "*" {
		addDNS(host)
	}

	if strings.TrimSpace(sanCSV) == "" {
		if mdnsName, ok := defaultMDNSSAN(); ok {
			addDNS(mdnsName)
		}
	}

	for _, token := range strings.Split(sanCSV, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if ip := net.ParseIP(token); ip != nil {
			addIP(ip)
			continue
		}
		if !isLikelyDNSName(token) {
			return certSANs{}, fmt.Errorf("invalid -tls-san entry %q", token)
		}
		addDNS(token)
	}

	dns := make([]string, 0, len(dnsSet))
	for name := range dnsSet {
		dns = append(dns, name)
	}
	sort.Strings(dns)

	ipKeys := make([]string, 0, len(ipSet))
	for key := range ipSet {
		ipKeys = append(ipKeys, key)
	}
	sort.Strings(ipKeys)
	ips := make([]net.IP, 0, len(ipKeys))
	for _, key := range ipKeys {
		ips = append(ips, ipSet[key])
	}

	return certSANs{DNS: dns, IPs: ips}, nil
}

func loadOrCreateRootCA(pkiDir string, logger *log.Logger) (*x509.Certificate, *ecdsa.PrivateKey, []byte, bool, error) {
	if err := ensureDirSecure(pkiDir); err != nil {
		return nil, nil, nil, false, fmt.Errorf("prepare pki dir: %w", err)
	}

	caCertPath := filepath.Join(pkiDir, "ca.crt")
	caKeyPath := filepath.Join(pkiDir, "ca.key")

	caCert, caPEM, certErr := loadCertificateFromPEMFile(caCertPath)
	caKey, keyErr := loadECDSAPrivateKeyFile(caKeyPath)
	if certErr == nil && keyErr == nil {
		if caCert.IsCA && rootCASubjectMatches(caCert) && time.Until(caCert.NotAfter) > 45*24*time.Hour {
			return caCert, caKey, caPEM, false, nil
		}
	}

	if (certErr == nil) != (keyErr == nil) {
		return nil, nil, nil, false, errors.New("incomplete root CA files: need both ca.crt and ca.key")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("generate root CA key: %w", err)
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerialNumber(),
		Subject:               pkix.Name{CommonName: rootCACommonName, Organization: []string{rootCAOrganization}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("create root CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("marshal root CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeFileAtomicWithMode(caCertPath, certPEM, 0644); err != nil {
		return nil, nil, nil, false, fmt.Errorf("write root CA cert: %w", err)
	}
	if err := writeFileAtomicWithMode(caKeyPath, keyPEM, 0600); err != nil {
		return nil, nil, nil, false, fmt.Errorf("write root CA key: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("parse generated root CA cert: %w", err)
	}

	return cert, key, certPEM, true, nil
}

func loadOrCreateServerCert(certPath, keyPath string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, sans certSANs, logger *log.Logger) (bool, error) {
	existingCert, _, certErr := loadCertificateFromPEMFile(certPath)
	existingKey, keyErr := loadECDSAPrivateKeyFile(keyPath)
	if certErr == nil && keyErr == nil {
		if serverCertMatches(existingCert, caCert, sans) && existingKey != nil {
			return false, nil
		}
	}

	if (certErr == nil) != (keyErr == nil) {
		return false, errors.New("incomplete server certificate files: need both server.crt and server.key")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, fmt.Errorf("generate server key: %w", err)
	}

	cn := "localhost"
	if len(sans.DNS) > 0 {
		cn = sans.DNS[0]
	} else if len(sans.IPs) > 0 {
		cn = sans.IPs[0].String()
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{rootCAOrganization}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(0, 0, 90),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     append([]string(nil), sans.DNS...),
		IPAddresses:  append([]net.IP(nil), sans.IPs...),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return false, fmt.Errorf("create server cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return false, fmt.Errorf("marshal server key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeFileAtomicWithMode(certPath, certPEM, 0644); err != nil {
		return false, fmt.Errorf("write server cert: %w", err)
	}
	if err := writeFileAtomicWithMode(keyPath, keyPEM, 0600); err != nil {
		return false, fmt.Errorf("write server key: %w", err)
	}

	return true, nil
}

func exportCACertificate(path string, certPEM []byte) error {
	if len(certPEM) == 0 {
		return errors.New("missing CA certificate data")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeFileAtomicWithMode(path, certPEM, 0644)
}

func loadCertificateFromPEMFile(path string) (*x509.Certificate, []byte, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("%s does not contain a certificate PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, pemData, nil
}

func loadECDSAPrivateKeyFile(path string) (*ecdsa.PrivateKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%s does not contain a PEM block", path)
	}

	if block.Type == "EC PRIVATE KEY" {
		return x509.ParseECPrivateKey(block.Bytes)
	}

	if block.Type == "PRIVATE KEY" {
		keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecdsaKey, ok := keyAny.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s private key is not ECDSA", path)
		}
		return ecdsaKey, nil
	}

	return nil, fmt.Errorf("unsupported private key type %q in %s", block.Type, path)
}

func serverCertMatches(cert, caCert *x509.Certificate, sans certSANs) bool {
	if cert == nil || caCert == nil {
		return false
	}
	if time.Until(cert.NotAfter) <= 7*24*time.Hour {
		return false
	}
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return false
	}

	certDNS := map[string]struct{}{}
	for _, name := range cert.DNSNames {
		certDNS[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	for _, requiredName := range sans.DNS {
		if _, ok := certDNS[strings.ToLower(requiredName)]; !ok {
			return false
		}
	}

	certIPs := map[string]struct{}{}
	for _, ip := range cert.IPAddresses {
		certIPs[normalizeIP(ip).String()] = struct{}{}
	}
	for _, requiredIP := range sans.IPs {
		if _, ok := certIPs[normalizeIP(requiredIP).String()]; !ok {
			return false
		}
	}

	return true
}

func ensureDirSecure(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

func writeFileAtomicWithMode(path string, data []byte, mode os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func extractListenHost(listenAddr string) string {
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(listenAddr)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.HasPrefix(listenAddr, ":") {
		return ""
	}
	return strings.Trim(listenAddr, "[]")
}

func isLikelyDNSName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 253 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

func randomSerialNumber() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil || n.Sign() <= 0 {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

func certificateSHA256Fingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	hexUpper := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(hexUpper)/2)
	for i := 0; i < len(hexUpper); i += 2 {
		parts = append(parts, hexUpper[i:i+2])
	}
	return strings.Join(parts, ":")
}

func startHTTPRedirectServer(logger *log.Logger, listenAddr, tlsAddr string, caCertPEM []byte) {
	handler := newHTTPBootstrapHandler(tlsAddr, caCertPEM)

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		if logger != nil {
			logger.Printf("http listener failed: %v", err)
		}
	}
}

func newHTTPBootstrapHandler(tlsAddr string, caCertPEM []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(caCertPEM) > 0 {
			switch r.URL.Path {
			case localCACertRoute:
				if r.Method != http.MethodGet {
					w.Header().Set("Allow", http.MethodGet)
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				w.Header().Set("Content-Type", "application/x-pem-file")
				w.Header().Set("Content-Disposition", `attachment; filename="cellweb-root-ca.crt"`)
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write(caCertPEM)
				return
			case "/style.css":
				if r.Method != http.MethodGet {
					w.Header().Set("Allow", http.MethodGet)
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				css, err := webAssets.ReadFile("web/style.css")
				if err != nil {
					http.Error(w, "style missing", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "text/css; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write(css)
				return
			case "/", httpBootstrapRoute:
				if r.Method != http.MethodGet {
					w.Header().Set("Allow", http.MethodGet)
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				httpsURL := (&url.URL{Scheme: "https", Host: buildHTTPSRedirectHost(r.Host, tlsAddr), Path: "/"}).String()
				page := buildHTTPBootstrapPageHTML(httpsURL)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write([]byte(page))
				return
			}
		}

		host := buildHTTPSRedirectHost(r.Host, tlsAddr)
		target := &url.URL{
			Scheme:   "https",
			Host:     host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}
		http.Redirect(w, r, target.String(), http.StatusMovedPermanently)
	})
}

func buildHTTPBootstrapPageHTML(httpsURL string) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="en" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>cellweb bootstrap</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="bg-orb orb-1"></div>
  <div class="bg-orb orb-2"></div>
  <div class="bg-grid"></div>

  <main class="layout">
    <section class="card login-card bootstrap-card reveal">
      <div class="card-header">
        <div class="brand">cellweb</div>
      </div>

      <h1>Browser trust bootstrap</h1>
      <p>Download the Root CA certificate, compare the fingerprint with your SSH/console output, then import it into your browser or OS trust store.</p>

      <ol class="bootstrap-help">
        <li>Download the Root CA certificate with the button below.</li>
        <li>Compare the certificate fingerprint with the one printed on startup.</li>
        <li>Import the certificate into your trust store.</li>
        <li>Continue to the HTTPS login page.</li>
      </ol>

      <div class="bootstrap-actions">
        <a class="btn action-default" href="%s" download="cellweb-root-ca.crt">Download Root CA certificate</a>
        <a class="btn ghost" href="%s">Continue to HTTPS login</a>
      </div>
    </section>
  </main>
</body>
</html>
`, localCACertRoute, html.EscapeString(httpsURL))
}

func buildHTTPSRedirectHost(requestHost, tlsListenAddr string) string {
	tlsHost, tlsPort := splitListenAddress(tlsListenAddr)
	host := strings.TrimSpace(requestHost)
	if host == "" {
		host = tlsHost
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")

	if host == "" || host == "0.0.0.0" || host == "::" {
		if tlsHost != "" && tlsHost != "0.0.0.0" && tlsHost != "::" {
			host = tlsHost
		} else {
			host = "localhost"
		}
	}

	if tlsPort == "" || tlsPort == "443" {
		return host
	}
	return net.JoinHostPort(host, tlsPort)
}

func splitListenAddress(addr string) (string, string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		return strings.Trim(host, "[]"), port
	}
	if strings.HasPrefix(addr, ":") {
		return "", strings.TrimPrefix(addr, ":")
	}
	return strings.Trim(addr, "[]"), ""
}

func joinIPsForLog(values []net.IP) string {
	if len(values) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(values))
	for _, ip := range values {
		parts = append(parts, normalizeIP(ip).String())
	}
	return strings.Join(parts, ", ")
}

func defaultMDNSSAN() (string, bool) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", false
	}
	return mdnsSANFromHostname(hostname)
}

func mdnsSANFromHostname(hostname string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(hostname))
	h = strings.Trim(h, ".")
	if h == "" {
		return "", false
	}
	if idx := strings.IndexByte(h, '.'); idx > 0 {
		h = h[:idx]
	}
	if h == "" || strings.Contains(h, ".") || !isLikelyDNSName(h) {
		return "", false
	}
	return h + ".local", true
}

func rootCASubjectMatches(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.Subject.CommonName != rootCACommonName {
		return false
	}
	if len(cert.Subject.Organization) == 0 {
		return false
	}
	return cert.Subject.Organization[0] == rootCAOrganization
}

func rootCARotationReason(cert *x509.Certificate) string {
	if cert == nil {
		return "existing root CA is missing or unreadable"
	}
	if !cert.IsCA {
		return "existing ca.crt is not a CA certificate"
	}
	if !rootCASubjectMatches(cert) {
		return "existing root CA subject does not match appliance defaults"
	}
	if time.Until(cert.NotAfter) <= 45*24*time.Hour {
		return "existing root CA expires in less than 45 days"
	}
	return "existing root CA requires refresh"
}

func printTrustBootstrapToStdout(tlsListenAddr, bootstrapHost, fingerprint, httpBootstrapListen string) {
	fp := strings.TrimSpace(fingerprint)
	if fp == "" {
		fp = "(fingerprint unavailable)"
	}

	bootstrapURL := bootstrapBaseURLWithHost("https", tlsListenAddr, bootstrapHost) + "/"
	if strings.TrimSpace(httpBootstrapListen) != "" {
		bootstrapURL = bootstrapBaseURLWithHost("http", httpBootstrapListen, bootstrapHost) + httpBootstrapRoute
	}

	fmt.Fprintf(os.Stdout, "Root CA SHA-256 fingerprint: %s\n", fp)
	fmt.Fprintf(os.Stdout, "Bootstrap URL: %s\n", bootstrapURL)
}

func buildTrustBootstrapLines(tlsListenAddr, bootstrapHost, fingerprint, httpBootstrapListen string, maxWidth int) []string {
	if maxWidth < 40 {
		maxWidth = 40
	}

	httpsBaseURL := bootstrapBaseURLWithHost("https", tlsListenAddr, bootstrapHost)
	httpBootstrapURL := ""
	if strings.TrimSpace(httpBootstrapListen) != "" {
		httpBootstrapURL = bootstrapBaseURLWithHost("http", httpBootstrapListen, bootstrapHost) + localCACertRoute
	}

	separator := strings.Repeat("-", maxWidth)
	lines := []string{
		separator,
		"CELLWEB TRUST BOOTSTRAP",
		separator,
		"Root CA SHA-256 fingerprint:",
	}

	lines = append(lines, formatFingerprintForDisplay(fingerprint, "  ", maxWidth)...)
	lines = append(lines, "")

	if httpBootstrapURL != "" {
		lines = append(lines, "1) Download the Root CA certificate (no browser exception required):")
		lines = append(lines, wrapWithIndent(httpBootstrapURL, "   ", maxWidth)...)
		lines = append(lines, "   If HSTS is cached for that hostname, use server IP with same path.")
		lines = append(lines, "2) Verify the downloaded certificate fingerprint against the value above.")
		lines = append(lines, "3) Import the Root CA certificate into your browser or OS trust store.")
		lines = append(lines, "4) Open your browser at:")
		lines = append(lines, wrapWithIndent(httpsBaseURL+"/", "   ", maxWidth)...)
		lines = append(lines, "5) Reload the page and continue with normal trusted HTTPS access.")
	} else {
		lines = append(lines, "1) Open your browser at:")
		lines = append(lines, wrapWithIndent(httpsBaseURL+"/", "   ", maxWidth)...)
		lines = append(lines, "2) Allow the one-time security exception for this first connection.")
		lines = append(lines, "3) Download the Root CA certificate from:")
		lines = append(lines, wrapWithIndent(httpsBaseURL+localCACertRoute, "   ", maxWidth)...)
		lines = append(lines, "4) Verify the downloaded certificate fingerprint against the value above.")
		lines = append(lines, "5) Import the Root CA certificate into your browser or OS trust store.")
		lines = append(lines, "6) Reload the page and continue with normal trusted HTTPS access.")
	}
	lines = append(lines, separator)

	return enforceLineWidth(lines, maxWidth)
}

func formatFingerprintForDisplay(fingerprint, indent string, maxWidth int) []string {
	parts := strings.Split(strings.TrimSpace(fingerprint), ":")
	if len(parts) == 0 {
		return wrapWithIndent(strings.TrimSpace(fingerprint), indent, maxWidth)
	}

	bytesPerLine := 8
	lines := make([]string, 0, (len(parts)+bytesPerLine-1)/bytesPerLine)
	for i := 0; i < len(parts); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(parts) {
			end = len(parts)
		}
		chunk := strings.Join(parts[i:end], ":")
		lines = append(lines, wrapWithIndent(chunk, indent, maxWidth)...)
	}
	return lines
}

func wrapWithIndent(text, indent string, maxWidth int) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return []string{indent}
	}

	available := maxWidth - len(indent)
	if available < 8 {
		available = 8
	}

	lines := make([]string, 0, 4)
	remaining := text
	for len(remaining) > available {
		segment := remaining[:available]
		split := strings.LastIndex(segment, " ")
		if split <= 0 {
			lines = append(lines, indent+segment)
			remaining = strings.TrimLeft(remaining[available:], " ")
			continue
		}
		lines = append(lines, indent+strings.TrimSpace(remaining[:split]))
		remaining = strings.TrimLeft(remaining[split+1:], " ")
	}
	if remaining != "" {
		lines = append(lines, indent+remaining)
	}
	return lines
}

func enforceLineWidth(lines []string, maxWidth int) []string {
	if maxWidth < 8 {
		return lines
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(line) <= maxWidth {
			out = append(out, line)
			continue
		}
		for len(line) > maxWidth {
			out = append(out, line[:maxWidth])
			line = line[maxWidth:]
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func bootstrapBaseURLWithHost(scheme, listenAddr, preferredHost string) string {
	host := strings.TrimSpace(preferredHost)
	listenHost, listenPort := splitListenAddress(listenAddr)
	if host == "" {
		host = strings.TrimSpace(listenHost)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}

	authority := host
	if listenPort != "" {
		authority = net.JoinHostPort(host, listenPort)
	}
	return scheme + "://" + authority
}

func preferredBootstrapHost(sans certSANs) string {
	for _, name := range sans.DNS {
		if strings.HasSuffix(name, ".local") {
			return name
		}
	}
	for _, name := range sans.DNS {
		if name != "localhost" {
			return name
		}
	}
	if len(sans.IPs) > 0 {
		return normalizeIP(sans.IPs[0]).String()
	}
	return ""
}
