//go:build unix

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	sessionCookieName      = "cellweb_session"
	defaultSessionIdleTTL  = 30 * time.Minute
	defaultSessionMaxTTL   = 10 * time.Hour
	defaultCommandTimeout  = 35 * time.Second
	defaultRefreshInterval = 4
	trendHistoryPoints     = 72
	maxJSONBodyBytes       = 1 << 20
	maxOutputBytes         = 512 * 1024
	ipcProtocolVersion     = 1
	ipcMaxPayloadBytes     = 64 * 1024 * 1024
)

var (
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	archivePattern = regexp.MustCompile(`^[A-Za-z0-9._/:-]+$`)
	ifMTUPattern   = regexp.MustCompile(`\bmtu\s+(\d+)\b`)
	bootSecPattern = regexp.MustCompile(`sec\s*=\s*([0-9]+)`)
)

//go:embed web/*
var webAssets embed.FS

type identity struct {
	Username string
	UID      uint32
	GID      uint32
	Groups   []uint32
	HomeDir  string
}

type session struct {
	ID        string
	CSRFToken string
	Identity  identity
	CreatedAt time.Time
	SeenAt    time.Time
	bridgeMu  sync.Mutex
	bridge    *ipcBridge
}

type sessionStore struct {
	mu      sync.RWMutex
	idleTTL time.Duration
	maxTTL  time.Duration
	items   map[string]*session
}

func newSessionStore(idleTTL, maxTTL time.Duration) *sessionStore {
	return &sessionStore{
		idleTTL: idleTTL,
		maxTTL:  maxTTL,
		items:   make(map[string]*session),
	}
}

func (s *sessionStore) create(id identity) (*session, error) {
	sid, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sess := &session{
		ID:        sid,
		CSRFToken: csrf,
		Identity:  id,
		CreatedAt: now,
		SeenAt:    now,
	}

	s.mu.Lock()
	s.items[sid] = sess
	s.mu.Unlock()

	return sess, nil
}

func (s *sessionStore) get(sessionID string) (*session, bool) {
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.items[sessionID]
	if !ok {
		return nil, false
	}
	if now.Sub(sess.CreatedAt) > s.maxTTL || now.Sub(sess.SeenAt) > s.idleTTL {
		delete(s.items, sessionID)
		closeSessionBridge(sess)
		return nil, false
	}
	sess.SeenAt = now
	return sess, true
}

func (s *sessionStore) delete(sessionID string) {
	s.mu.Lock()
	sess := s.items[sessionID]
	delete(s.items, sessionID)
	s.mu.Unlock()
	closeSessionBridge(sess)
}

func (s *sessionStore) cleanupExpired() {
	now := time.Now().UTC()
	expired := make([]*session, 0)
	s.mu.Lock()
	for id, sess := range s.items {
		if now.Sub(sess.CreatedAt) > s.maxTTL || now.Sub(sess.SeenAt) > s.idleTTL {
			delete(s.items, id)
			expired = append(expired, sess)
		}
	}
	s.mu.Unlock()

	for _, sess := range expired {
		closeSessionBridge(sess)
	}
}

type loginAttempt struct {
	Fails      int
	BlockedTo  time.Time
	LastFailed time.Time
}

type loginGuard struct {
	mu      sync.Mutex
	entries map[string]*loginAttempt
}

func newLoginGuard() *loginGuard {
	return &loginGuard{entries: make(map[string]*loginAttempt)}
}

func (l *loginGuard) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := l.entries[key]
	if entry == nil {
		return true, 0
	}
	now := time.Now().UTC()
	if now.Before(entry.BlockedTo) {
		return false, entry.BlockedTo.Sub(now)
	}
	return true, 0
}

func (l *loginGuard) noteFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now().UTC()
	entry := l.entries[key]
	if entry == nil {
		entry = &loginAttempt{}
		l.entries[key] = entry
	}
	if now.Sub(entry.LastFailed) > 2*time.Minute {
		entry.Fails = 0
	}
	entry.Fails++
	entry.LastFailed = now
	if entry.Fails >= 5 {
		entry.BlockedTo = now.Add(90 * time.Second)
		entry.Fails = 0
	}
}

func (l *loginGuard) noteSuccess(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

type commandResult struct {
	Output   string
	ExitCode int
}

type bridgeTransportError struct {
	msg string
}

func (e bridgeTransportError) Error() string {
	return e.msg
}

func isBridgeTransportError(err error) bool {
	var te bridgeTransportError
	return errors.As(err, &te)
}

func newBridgeTransportErrorf(format string, args ...any) error {
	return bridgeTransportError{msg: fmt.Sprintf(format, args...)}
}

type ipcHeader struct {
	Version int
	Type    string
	ID      uint64
	P1      uint64
	P2      uint64
	P3      uint64
	Len     uint64
}

type ipcBridge struct {
	id      identity
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdoutR io.ReadCloser
	stdout  *bufio.Reader
	nextID  uint64
	mu      sync.Mutex
	closed  bool
}

func startIPCBridge(id identity) (*ipcBridge, error) {
	cmd := exec.Command("cellmgr", "ipc", "serve", "--stdio")
	cmd.Dir = fallbackDir(id.HomeDir)
	cmd.Env = []string{
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/pkg/bin",
		"HOME=" + id.HomeDir,
		"USER=" + id.Username,
		"LOGNAME=" + id.Username,
		"LC_ALL=C",
		"TERM=dumb",
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    id.UID,
			Gid:    id.GID,
			Groups: id.Groups,
		},
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdoutPipe.Close()
		return nil, err
	}

	b := &ipcBridge{
		id:      id,
		cmd:     cmd,
		stdin:   stdin,
		stdoutR: stdoutPipe,
		stdout:  bufio.NewReader(stdoutPipe),
		nextID:  1,
	}

	if err := b.sendFrame("HELLO", 0, 0, 0, 0, nil); err != nil {
		b.close()
		return nil, newBridgeTransportErrorf("ipc hello send failed: %v", err)
	}
	hdr, _, err := b.readFrame()
	if err != nil {
		b.close()
		return nil, newBridgeTransportErrorf("ipc hello read failed: %v", err)
	}
	if hdr.Type != "HELLO" {
		b.close()
		return nil, newBridgeTransportErrorf("unexpected ipc handshake response: %s", hdr.Type)
	}

	return b, nil
}

func (b *ipcBridge) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeLocked()
}

func (b *ipcBridge) closeLocked() {
	if b.closed {
		return
	}
	b.closed = true

	if b.stdin != nil {
		_, _ = io.WriteString(b.stdin, "M 1 BYE 0 0 0 0 0\n")
		_ = b.stdin.Close()
	}
	if b.stdoutR != nil {
		_ = b.stdoutR.Close()
	}
	if b.cmd != nil && b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
		_, _ = b.cmd.Process.Wait()
	}
}

func (b *ipcBridge) callCapture(ctx context.Context, args []string) (commandResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return commandResult{}, newBridgeTransportErrorf("ipc bridge is closed")
	}

	done := make(chan struct {
		res commandResult
		err error
	}, 1)

	go func() {
		res, err := b.callCaptureLocked(args)
		done <- struct {
			res commandResult
			err error
		}{res: res, err: err}
	}()

	select {
	case out := <-done:
		if isBridgeTransportError(out.err) {
			b.closeLocked()
		}
		return out.res, out.err
	case <-ctx.Done():
		b.closeLocked()
		<-done
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return commandResult{}, fmt.Errorf("command timeout")
		}
		return commandResult{}, ctx.Err()
	}
}

func (b *ipcBridge) callCaptureLocked(args []string) (commandResult, error) {
	if len(args) == 0 {
		return commandResult{}, fmt.Errorf("missing command arguments")
	}

	payload, err := buildCallPayload(args)
	if err != nil {
		return commandResult{}, err
	}

	id := b.nextID
	b.nextID++

	if err := b.sendFrame("CALL", id, 0, uint64(len(args)), 0, payload); err != nil {
		return commandResult{}, newBridgeTransportErrorf("ipc call send failed: %v", err)
	}

	hdr, respPayload, err := b.readFrame()
	if err != nil {
		return commandResult{}, newBridgeTransportErrorf("ipc call read failed: %v", err)
	}

	if hdr.Type == "ERR" {
		msg := strings.TrimSpace(string(respPayload))
		if msg == "" {
			msg = "ipc error"
		}
		exit := int(hdr.P1)
		if exit == 0 {
			exit = 1
		}
		return commandResult{Output: truncateOutput(msg, maxOutputBytes), ExitCode: exit}, fmt.Errorf("exit status %d", exit)
	}

	if hdr.Type != "RET" || hdr.ID != id {
		return commandResult{}, newBridgeTransportErrorf("unexpected ipc response: type=%s id=%d", hdr.Type, hdr.ID)
	}

	stdoutLen := int(hdr.P2)
	stderrLen := int(hdr.P3)
	if stdoutLen < 0 || stderrLen < 0 || stdoutLen+stderrLen != len(respPayload) {
		return commandResult{}, newBridgeTransportErrorf("ipc response length mismatch")
	}

	combined := strings.TrimSpace(string(respPayload[:stdoutLen]) + string(respPayload[stdoutLen:]))
	res := commandResult{
		Output:   truncateOutput(combined, maxOutputBytes),
		ExitCode: int(hdr.P1),
	}
	if hdr.P1 != 0 {
		return res, fmt.Errorf("exit status %d", int(hdr.P1))
	}
	return res, nil
}

func buildCallPayload(args []string) ([]byte, error) {
	var buf bytes.Buffer
	for _, arg := range args {
		if strings.ContainsRune(arg, '\n') {
			return nil, fmt.Errorf("argument contains newline: %q", arg)
		}
		buf.WriteString(arg)
		buf.WriteByte('\n')
	}
	if buf.Len() > ipcMaxPayloadBytes {
		return nil, fmt.Errorf("ipc request payload too large")
	}
	return buf.Bytes(), nil
}

func (b *ipcBridge) sendFrame(frameType string, id, p1, p2, p3 uint64, payload []byte) error {
	if len(payload) > ipcMaxPayloadBytes {
		return fmt.Errorf("payload too large")
	}

	header := fmt.Sprintf("M %d %s %d %d %d %d %d\n",
		ipcProtocolVersion, frameType, id, p1, p2, p3, len(payload))
	if _, err := io.WriteString(b.stdin, header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := b.stdin.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (b *ipcBridge) readFrame() (ipcHeader, []byte, error) {
	line, err := b.stdout.ReadString('\n')
	if err != nil {
		return ipcHeader{}, nil, err
	}
	line = strings.TrimSuffix(line, "\n")

	hdr, err := parseIPCHeader(line)
	if err != nil {
		return ipcHeader{}, nil, err
	}
	if hdr.Len > ipcMaxPayloadBytes {
		return ipcHeader{}, nil, fmt.Errorf("payload too large")
	}

	payload := make([]byte, hdr.Len)
	if hdr.Len > 0 {
		if _, err := io.ReadFull(b.stdout, payload); err != nil {
			return ipcHeader{}, nil, err
		}
	}

	return hdr, payload, nil
}

func parseIPCHeader(line string) (ipcHeader, error) {
	var hdr ipcHeader
	scanned, err := fmt.Sscanf(line, "M %d %15s %d %d %d %d %d",
		&hdr.Version, &hdr.Type, &hdr.ID, &hdr.P1, &hdr.P2, &hdr.P3, &hdr.Len)
	if err != nil {
		return ipcHeader{}, err
	}
	if scanned != 7 {
		return ipcHeader{}, fmt.Errorf("invalid header")
	}
	if hdr.Version != ipcProtocolVersion {
		return ipcHeader{}, fmt.Errorf("unsupported protocol version %d", hdr.Version)
	}
	return hdr, nil
}

func closeSessionBridge(sess *session) {
	if sess == nil {
		return
	}
	sess.bridgeMu.Lock()
	bridge := sess.bridge
	sess.bridge = nil
	sess.bridgeMu.Unlock()
	if bridge != nil {
		bridge.close()
	}
}

type appServer struct {
	log            *log.Logger
	auth           authenticator
	sessions       *sessionStore
	loginGuard     *loginGuard
	trendStore     *systemTrendStore
	assetFS        fs.FS
	trust          trustInfo
	caCertPEM      []byte
	secureCookies  bool
	commandTimeout time.Duration
	refreshSeconds int
}

type authenticator interface {
	Authenticate(ctx context.Context, username, password string) error
}

type staticAuthenticator struct {
	username string
	password string
}

func (a staticAuthenticator) Authenticate(ctx context.Context, username, password string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(a.password)) == 1
	if !userOK || !passOK {
		return errors.New("invalid credentials")
	}
	return nil
}

type multiAuthenticator struct {
	chain []authenticator
}

func (m multiAuthenticator) Authenticate(ctx context.Context, username, password string) error {
	var lastErr error
	for _, auth := range m.chain {
		if err := auth.Authenticate(ctx, username, password); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		return errors.New("authentication failed")
	}
	return lastErr
}

func buildAuthenticator(pamService, adminUser, adminPass string) (authenticator, []string, error) {
	auths := make([]authenticator, 0, 2)
	names := make([]string, 0, 2)

	adminUser = strings.TrimSpace(adminUser)
	if adminUser != "" || adminPass != "" {
		if adminUser == "" || adminPass == "" {
			return nil, nil, errors.New("admin auth requires both -admin-user and -admin-pass")
		}
		if !namePattern.MatchString(adminUser) {
			return nil, nil, fmt.Errorf("invalid -admin-user value: %q", adminUser)
		}
		auths = append(auths, staticAuthenticator{username: adminUser, password: adminPass})
		names = append(names, "admin")
	}

	auths = append(auths, newPAMAuthenticator(pamService))
	names = append(names, "pam")

	if len(auths) == 1 {
		return auths[0], names, nil
	}
	return multiAuthenticator{chain: auths}, names, nil
}

func main() {
	tlsEnabled := flag.Bool("tls", envBoolOrDefault("CELLWEB_TLS", true), "enable TLS for the main web UI")
	httpsListen := flag.String("https-listen", envOrDefault("CELLWEB_HTTPS_LISTEN", "0.0.0.0:18443"), "HTTPS listen address (used when -tls=true)")
	httpListen := flag.String("http-listen", envOrDefault("CELLWEB_HTTP_LISTEN", "0.0.0.0:18088"), "HTTP listen address (bootstrap when TLS is on, main listener when TLS is off)")
	pamService := flag.String("pam-service", envOrDefault("CELLWEB_PAM_SERVICE", "login"), "PAM service name")
	adminUser := flag.String("admin-user", envOrDefault("CELLWEB_ADMIN_USER", ""), "optional admin username fallback")
	adminPass := flag.String("admin-pass", envOrDefault("CELLWEB_ADMIN_PASS", ""), "optional admin password fallback")
	secureCookiesMode := flag.String("secure-cookies-mode", secureCookiesModeFromEnv(), "secure cookies mode: auto|on|off")
	pkiDir := flag.String("pki-dir", envOrDefault("CELLWEB_PKI_DIR", defaultPKIDir), "PKI directory for selfsigned mode")
	tlsCert := flag.String("tls-cert", envOrDefault("CELLWEB_TLS_CERT", ""), "certificate path for manual TLS mode")
	tlsKey := flag.String("tls-key", envOrDefault("CELLWEB_TLS_KEY", ""), "private key path for manual TLS mode")
	tlsSAN := flag.String("tls-san", envOrDefault("CELLWEB_TLS_SAN", ""), "comma-separated additional TLS SAN entries (DNS names or IPs)")
	tlsExportCA := flag.String("tls-export-ca", envOrDefault("CELLWEB_TLS_EXPORT_CA", ""), "export root CA certificate to a path (selfsigned mode)")
	commandTimeout := flag.Duration("command-timeout", defaultCommandTimeout, "timeout for each cellmgr command")
	refreshSeconds := flag.Int("refresh-seconds", defaultRefreshInterval, "recommended client refresh interval in seconds")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags)

	sub, err := fs.Sub(webAssets, "web")
	if err != nil {
		logger.Fatalf("web assets: %v", err)
	}

	if *refreshSeconds < 2 {
		*refreshSeconds = 2
	}

	httpsListenAddr := strings.TrimSpace(*httpsListen)
	httpListenAddr := strings.TrimSpace(*httpListen)

	resolvedTLSMode, err := resolveTLSMode(*tlsEnabled, *tlsCert, *tlsKey)
	if err != nil {
		logger.Fatalf("tls setup failed: %v", err)
	}

	mainListenAddr := httpListenAddr
	if resolvedTLSMode != tlsModeOff {
		mainListenAddr = httpsListenAddr
	}
	if strings.TrimSpace(mainListenAddr) == "" {
		logger.Fatalf("network setup failed: main listen address is empty")
	}
	if resolvedTLSMode != tlsModeOff && strings.TrimSpace(httpsListenAddr) == "" {
		logger.Fatalf("network setup failed: -https-listen is required when -tls=true")
	}
	if resolvedTLSMode != tlsModeOff && httpListenAddr != "" && httpListenAddr == httpsListenAddr {
		logger.Fatalf("network setup failed: -http-listen and -https-listen must not be the same")
	}

	tlsRuntime, err := prepareTLSRuntime(
		mainListenAddr,
		resolvedTLSMode,
		*pkiDir,
		*tlsCert,
		*tlsKey,
		*tlsSAN,
		*tlsExportCA,
		logger,
	)
	if err != nil {
		logger.Fatalf("tls setup failed: %v", err)
	}

	httpBootstrapListen := ""
	if tlsRuntime.Enabled {
		httpBootstrapListen = httpListenAddr
	}

	if tlsRuntime.Mode == tlsModeSelfSigned {
		printTrustBootstrapToStdout(mainListenAddr, tlsRuntime.BootstrapHost, tlsRuntime.Trust.CAFingerprintSHA256, httpBootstrapListen)
	}

	secureCookies, err := resolveSecureCookieSetting(*secureCookiesMode, false, tlsRuntime.Enabled)
	if err != nil {
		logger.Fatalf("cookie setup failed: %v", err)
	}

	hstsEnabled := tlsRuntime.Enabled

	auth, authModes, err := buildAuthenticator(*pamService, *adminUser, *adminPass)
	if err != nil {
		logger.Fatalf("auth setup failed: %v", err)
	}

	networkConfig := "http-bind=" + configValue(mainListenAddr, "(unset)")
	tlsConfig := ""
	if tlsRuntime.Enabled {
		if httpBootstrapListen != "" {
			networkConfig = fmt.Sprintf("https-bind=%s http-bootstrap-bind=%s", configValue(mainListenAddr, "(unset)"), httpBootstrapListen)
		} else {
			networkConfig = fmt.Sprintf("https-bind=%s http-bootstrap=off", configValue(mainListenAddr, "(unset)"))
		}
		if tlsRuntime.Mode == tlsModeManual {
			tlsConfig = fmt.Sprintf(" cert=%s key=%s", configValue(*tlsCert, "(required)"), configValue(*tlsKey, "(required)"))
		} else {
			tlsConfig = fmt.Sprintf(" pki-dir=%s tls-san=%s", configValue(*pkiDir, "(default)"), configValue(*tlsSAN, "(auto)"))
		}
	}
	logger.Printf(
		"start config: mode=%s %s auth=%s pam-service=%s secure-cookies=%t refresh=%ds timeout=%s%s",
		tlsRuntime.Mode,
		networkConfig,
		strings.Join(authModes, ","),
		configValue(*pamService, "login"),
		secureCookies,
		*refreshSeconds,
		commandTimeout.String(),
		tlsConfig,
	)

	s := &appServer{
		log:            logger,
		auth:           auth,
		sessions:       newSessionStore(defaultSessionIdleTTL, defaultSessionMaxTTL),
		loginGuard:     newLoginGuard(),
		trendStore:     newSystemTrendStore(trendHistoryPoints),
		assetFS:        sub,
		trust:          tlsRuntime.Trust,
		caCertPEM:      tlsRuntime.CACertPEM,
		secureCookies:  secureCookies,
		commandTimeout: *commandTimeout,
		refreshSeconds: *refreshSeconds,
	}

	if id, err := lookupProcessIdentity(); err == nil {
		s.startSystemTrendSampler(id, time.Duration(s.refreshSeconds)*time.Second)
	}

	go func() {
		ticker := time.NewTicker(90 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			s.sessions.cleanupExpired()
		}
	}()

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	handler := withSecurityHeaders(mux, hstsEnabled)
	httpServer := &http.Server{
		Addr:              mainListenAddr,
		Handler:           handler,
		ErrorLog:          log.New(filteredHTTPServerErrorWriter{dst: os.Stderr}, "", log.LstdFlags),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if tlsRuntime.Enabled && httpBootstrapListen != "" {
		httpBootstrapURL := bootstrapBaseURLWithHost("http", httpBootstrapListen, tlsRuntime.BootstrapHost) + httpBootstrapRoute
		s.log.Printf("listener started: http bootstrap bind=%s url=%s", httpBootstrapListen, httpBootstrapURL)
		go startHTTPRedirectServer(s.log, httpBootstrapListen, mainListenAddr, tlsRuntime.CACertPEM)
	}

	if tlsRuntime.Enabled {
		httpsURL := bootstrapBaseURLWithHost("https", mainListenAddr, tlsRuntime.BootstrapHost) + "/"
		s.log.Printf("listener started: https bind=%s url=%s", mainListenAddr, httpsURL)
	} else {
		httpURL := bootstrapBaseURLWithHost("http", mainListenAddr, "") + "/"
		s.log.Printf("listener started: http bind=%s url=%s", mainListenAddr, httpURL)
	}

	var serveErr error
	if tlsRuntime.Enabled {
		serveErr = httpServer.ListenAndServeTLS(tlsRuntime.CertFile, tlsRuntime.KeyFile)
	} else {
		serveErr = httpServer.ListenAndServe()
	}
	if err := serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatalf("listen failed: %v", err)
	}
}

func (s *appServer) registerRoutes(mux *http.ServeMux) {
	assets := http.FileServer(http.FS(s.assetFS))
	mux.Handle("/app.js", assets)
	mux.Handle("/style.css", assets)
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/api/trust", s.handleTrustInfo)
	mux.HandleFunc(localCACertRoute, s.handleCACert)

	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/me", s.handleMe)
	mux.HandleFunc("/api/system", s.handleSystem)
	mux.HandleFunc("/api/cells", s.handleCells)
	mux.HandleFunc("/api/cells/action", s.handleCellsAction)
	mux.HandleFunc("/api/storage", s.handleStorage)
	mux.HandleFunc("/api/backups", s.handleBackups)
	mux.HandleFunc("/api/storage/action", s.handleStorageAction)
}

func (s *appServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	file, err := s.assetFS.Open("index.html")
	if err != nil {
		http.Error(w, "index missing", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := io.Copy(w, file); err != nil {
		s.log.Printf("serve index: %v", err)
	}
}

func (s *appServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *appServer) handleTrustInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": s.trust})
}

func (s *appServer) handleCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if len(s.caCertPEM) == 0 {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="cellweb-root-ca.crt"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.caCertPEM)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *appServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	remote := remoteKey(r)
	if allowed, wait := s.loginGuard.allow(remote); !allowed {
		writeAPIError(w, http.StatusTooManyRequests,
			fmt.Sprintf("Too many failed logins. Retry in %ds.", int(wait.Seconds()+0.5)), "")
		return
	}

	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "Invalid login payload", err.Error())
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeAPIError(w, http.StatusBadRequest, "Username and password are required", "")
		return
	}
	if !namePattern.MatchString(req.Username) {
		writeAPIError(w, http.StatusBadRequest, "Invalid username format", "")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := s.auth.Authenticate(ctx, req.Username, req.Password); err != nil {
		s.loginGuard.noteFailure(remote)
		writeAPIError(w, http.StatusUnauthorized, "Authentication failed", "invalid credentials")
		return
	}

	id, err := lookupIdentity(req.Username)
	if err != nil {
		s.loginGuard.noteFailure(remote)
		writeAPIError(w, http.StatusUnauthorized, "Authentication failed", "local user lookup failed")
		return
	}

	sess, err := s.sessions.create(id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "Session creation failed", err.Error())
		return
	}

	s.setSessionCookie(w, sess.ID)
	s.loginGuard.noteSuccess(remote)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"username":        id.Username,
		"refresh_seconds": s.refreshSeconds,
		"csrf_token":      sess.CSRFToken,
	})
}

func (s *appServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	sess, ok := s.mustAuth(w, r, true)
	if !ok {
		return
	}

	s.sessions.delete(sess.ID)
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *appServer) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	sess, ok := s.mustAuth(w, r, false)
	if !ok {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"username":        sess.Identity.Username,
		"uid":             sess.Identity.UID,
		"refresh_seconds": s.refreshSeconds,
		"csrf_token":      sess.CSRFToken,
	})
}

type cellRow struct {
	Name                string `json:"name"`
	CID                 string `json:"cid"`
	Running             bool   `json:"running"`
	Refs                string `json:"refs"`
	Procs               string `json:"procs"`
	Root                string `json:"root"`
	Autostart           string `json:"autostart"`
	CreateProfile       string `json:"create_profile"`
	CreateReservedPorts string `json:"create_reserved_ports"`
	CreateRlimitNofile  string `json:"create_rlimit_nofile"`
	CreateRlimitAS      string `json:"create_rlimit_as"`
	CreateRlimitCore    string `json:"create_rlimit_core"`
	SuperviseCmd        string `json:"supervise_cmd"`
	CPU1s               string `json:"cpu1s"`
	CPU10s              string `json:"cpu10s"`
	Memory              string `json:"memory"`
	Age                 string `json:"age"`
	ManifestPresent     bool   `json:"manifest_present"`
}

func (s *appServer) handleCells(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	sess, ok := s.mustAuth(w, r, false)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.commandTimeout)
	defer cancel()

	rows, err := s.loadCells(ctx, sess)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "Failed to load cells", err.Error())
		return
	}

	runningCount := 0
	missingManifest := 0
	for _, row := range rows {
		if row.Running {
			runningCount++
		}
		if !row.ManifestPresent {
			missingManifest++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"meta": map[string]any{
			"total":            len(rows),
			"running":          runningCount,
			"missing_manifest": missingManifest,
		},
		"rows": rows,
	})
}

type cellActionRequest struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	All    bool   `json:"all"`
}

func (s *appServer) handleCellsAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	sess, ok := s.mustAuth(w, r, true)
	if !ok {
		return
	}

	var req cellActionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "Invalid action payload", err.Error())
		return
	}
	req.Action = strings.TrimSpace(strings.ToLower(req.Action))
	req.Name = strings.TrimSpace(req.Name)

	var args []string
	var title string

	switch req.Action {
	case "start", "stop", "restart":
		title = strings.ToUpper(req.Action[:1]) + req.Action[1:]
		args = []string{"cell", req.Action}
		if req.All {
			args = append(args, "--all")
		} else {
			if req.Name == "" || !namePattern.MatchString(req.Name) {
				writeAPIError(w, http.StatusBadRequest, "Invalid cell name", "")
				return
			}
			args = append(args, req.Name)
		}
	case "apply":
		title = "Apply"
		args = []string{"apply", "--all"}
	case "shell", "edit":
		writeAPIError(w, http.StatusNotImplemented,
			"Interactive actions are not available over HTTP yet",
			"Use cellui for interactive shell/edit workflows.")
		return
	default:
		writeAPIError(w, http.StatusBadRequest, "Unknown action", req.Action)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.commandTimeout)
	defer cancel()

	res, err := s.runCellmgr(ctx, sess, args...)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, title+" failed", commandErrorMessage(err, res.Output))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": title + " done",
		"output":  res.Output,
	})
}

type volumeRow struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	ManifestPresent bool   `json:"manifest_present"`
	RuntimePresent  bool   `json:"runtime_present"`
	Mounted         bool   `json:"mounted"`
	Refs            string `json:"refs"`
	Mode            string `json:"mode"`
	Path            string `json:"path"`
	UsedBy          string `json:"used_by"`
}

type filesystemStat struct {
	Filesystem string `json:"filesystem"`
	Mountpoint string `json:"mountpoint"`
	SizeKB     uint64 `json:"size_kb"`
	UsedKB     uint64 `json:"used_kb"`
	AvailKB    uint64 `json:"avail_kb"`
	Capacity   int    `json:"capacity_percent"`
}

type memoryStat struct {
	TotalBytes uint64 `json:"total_bytes"`
	UsedBytes  uint64 `json:"used_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
	UsedPct    int    `json:"used_percent"`
}

type swapStat struct {
	TotalKB  uint64 `json:"total_kb"`
	UsedKB   uint64 `json:"used_kb"`
	AvailKB  uint64 `json:"avail_kb"`
	UsedPct  int    `json:"used_percent"`
	HasSwap  bool   `json:"has_swap"`
	Readable bool   `json:"readable"`
}

type interfaceStat struct {
	Name      string   `json:"name"`
	Status    string   `json:"status"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"`
	InBytes   uint64   `json:"in_bytes"`
	OutBytes  uint64   `json:"out_bytes"`
}

type ioDeviceStat struct {
	Device  string            `json:"device"`
	Metrics map[string]string `json:"metrics"`
}

type cpuTickStat struct {
	User   uint64 `json:"user"`
	Nice   uint64 `json:"nice"`
	System uint64 `json:"system"`
	Intr   uint64 `json:"intr"`
	Idle   uint64 `json:"idle"`
}

type systemTrendSnapshot struct {
	CPUUserPercent   []float64 `json:"cpu_user_percent"`
	CPUSystemPercent []float64 `json:"cpu_system_percent"`
	MemoryUsedPct    []float64 `json:"memory_used_percent"`
}

type systemTrendStore struct {
	mu        sync.RWMutex
	maxPoints int
	lastCPU   *cpuTickStat
	cpuUser   []float64
	cpuSystem []float64
	memory    []float64
}

func newSystemTrendStore(maxPoints int) *systemTrendStore {
	if maxPoints < 1 {
		maxPoints = 1
	}
	return &systemTrendStore{maxPoints: maxPoints}
}

func clampTrendPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func appendTrendValue(series []float64, value float64, max int) []float64 {
	series = append(series, clampTrendPercent(value))
	if len(series) <= max {
		return series
	}
	trim := len(series) - max
	copy(series, series[trim:])
	return series[:max]
}

func (s *systemTrendStore) pushMemoryPercent(value int) {
	s.mu.Lock()
	s.memory = appendTrendValue(s.memory, float64(value), s.maxPoints)
	s.mu.Unlock()
}

func (s *systemTrendStore) pushCPUTicks(ticks cpuTickStat) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lastCPU != nil {
		dUser := ticks.User - s.lastCPU.User
		dNice := ticks.Nice - s.lastCPU.Nice
		dSystem := ticks.System - s.lastCPU.System
		dIntr := ticks.Intr - s.lastCPU.Intr
		dIdle := ticks.Idle - s.lastCPU.Idle
		total := dUser + dNice + dSystem + dIntr + dIdle
		if total > 0 {
			s.cpuUser = appendTrendValue(s.cpuUser, (float64(dUser+dNice)*100)/float64(total), s.maxPoints)
			s.cpuSystem = appendTrendValue(s.cpuSystem, (float64(dSystem+dIntr)*100)/float64(total), s.maxPoints)
		}
	}

	copyTicks := ticks
	s.lastCPU = &copyTicks
}

func (s *systemTrendStore) snapshot() *systemTrendSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.cpuUser) == 0 && len(s.cpuSystem) == 0 && len(s.memory) == 0 {
		return nil
	}

	out := &systemTrendSnapshot{}
	if len(s.cpuUser) > 0 {
		out.CPUUserPercent = append([]float64(nil), s.cpuUser...)
	}
	if len(s.cpuSystem) > 0 {
		out.CPUSystemPercent = append([]float64(nil), s.cpuSystem...)
	}
	if len(s.memory) > 0 {
		out.MemoryUsedPct = append([]float64(nil), s.memory...)
	}
	return out
}

type systemSnapshot struct {
	Hostname    string               `json:"hostname"`
	Uptime      string               `json:"uptime"`
	LoadAverage string               `json:"load_average"`
	CPUTicks    cpuTickStat          `json:"cpu_ticks"`
	Trends      *systemTrendSnapshot `json:"trends,omitempty"`
	Memory      memoryStat           `json:"memory"`
	Swap        swapStat             `json:"swap"`
	Filesystems []filesystemStat     `json:"filesystems"`
	Interfaces  []interfaceStat      `json:"interfaces"`
	IO          []ioDeviceStat       `json:"io"`
	Warnings    []string             `json:"warnings"`
}

func (s *appServer) handleSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	sess, ok := s.mustAuth(w, r, false)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.commandTimeout)
	defer cancel()

	snap := s.collectSystemSnapshot(ctx, sess.Identity)
	if s.trendStore != nil {
		snap.Trends = s.trendStore.snapshot()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"meta": map[string]any{
			"filesystems": len(snap.Filesystems),
			"interfaces":  len(snap.Interfaces),
			"io_devices":  len(snap.IO),
			"warnings":    len(snap.Warnings),
		},
		"data": snap,
	})
}

func (s *appServer) handleStorage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	sess, ok := s.mustAuth(w, r, false)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.commandTimeout)
	defer cancel()

	rows, err := s.loadStorage(ctx, sess)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "Failed to load storage", err.Error())
		return
	}

	volumes := 0
	overlays := 0
	backupReady := 0
	for _, row := range rows {
		if row.Kind == "overlay" {
			overlays++
		} else {
			volumes++
		}
		if row.RuntimePresent && !row.Mounted {
			backupReady++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"meta": map[string]any{
			"total":        len(rows),
			"volumes":      volumes,
			"overlays":     overlays,
			"backup_ready": backupReady,
		},
		"rows": rows,
	})
}

type backupRow struct {
	Volume    string `json:"volume"`
	Timestamp string `json:"timestamp"`
	Size      string `json:"size"`
	Archive   string `json:"archive"`
}

func (s *appServer) handleBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	sess, ok := s.mustAuth(w, r, false)
	if !ok {
		return
	}

	kind := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("kind")))
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if (kind != "volume" && kind != "overlay") || !namePattern.MatchString(name) {
		writeAPIError(w, http.StatusBadRequest, "kind must be volume|overlay and name must be valid", "")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.commandTimeout)
	defer cancel()

	rows, err := s.loadBackups(ctx, sess, kind, name)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "Failed to load backups", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rows": rows})
}

type storageActionRequest struct {
	Action       string `json:"action"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Archive      string `json:"archive"`
	WithManifest bool   `json:"with_manifest"`
}

func (s *appServer) handleStorageAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	sess, ok := s.mustAuth(w, r, true)
	if !ok {
		return
	}

	var req storageActionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "Invalid action payload", err.Error())
		return
	}

	req.Action = strings.TrimSpace(strings.ToLower(req.Action))
	req.Kind = strings.TrimSpace(strings.ToLower(req.Kind))
	req.Name = strings.TrimSpace(req.Name)
	req.Archive = strings.TrimSpace(req.Archive)

	if (req.Kind != "volume" && req.Kind != "overlay") || !namePattern.MatchString(req.Name) {
		writeAPIError(w, http.StatusBadRequest, "Invalid storage target", "")
		return
	}
	if req.Archive != "" && !archivePattern.MatchString(req.Archive) {
		writeAPIError(w, http.StatusBadRequest, "Invalid archive path", "")
		return
	}

	targetRes := "volume"
	if req.Kind == "overlay" {
		targetRes = "cell"
	}

	var args []string
	var title string

	switch req.Action {
	case "create":
		title = "Create backup"
		args = []string{targetRes, "backup", "create", req.Name}
	case "restore":
		if req.Archive == "" {
			writeAPIError(w, http.StatusBadRequest, "Missing archive for restore", "")
			return
		}
		title = "Restore backup"
		args = []string{targetRes, "backup", "restore", req.Name, "--from", req.Archive}
		if req.WithManifest {
			args = append(args, "--manifest")
		}
		args = append(args, "--yes")
	case "delete":
		if req.Archive == "" {
			writeAPIError(w, http.StatusBadRequest, "Missing archive for delete", "")
			return
		}
		title = "Delete backup"
		args = []string{targetRes, "backup", "delete", req.Name, "--from", req.Archive, "--yes"}
	default:
		writeAPIError(w, http.StatusBadRequest, "Unknown storage action", req.Action)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.commandTimeout)
	defer cancel()

	res, err := s.runCellmgr(ctx, sess, args...)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, title+" failed", commandErrorMessage(err, res.Output))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": title + " done",
		"output":  res.Output,
	})
}

func (s *appServer) mustAuth(w http.ResponseWriter, r *http.Request, requireCSRF bool) (*session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		writeAPIError(w, http.StatusUnauthorized, "Not authenticated", "")
		return nil, false
	}

	sess, ok := s.sessions.get(cookie.Value)
	if !ok {
		s.clearSessionCookie(w)
		writeAPIError(w, http.StatusUnauthorized, "Session expired", "")
		return nil, false
	}

	if requireCSRF {
		provided := r.Header.Get("X-CSRF-Token")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(sess.CSRFToken)) != 1 {
			writeAPIError(w, http.StatusForbidden, "Bad CSRF token", "")
			return nil, false
		}
	}

	return sess, true
}

func (s *appServer) setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(defaultSessionMaxTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.secureCookies,
	})
}

func (s *appServer) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.secureCookies,
	})
}

func (s *appServer) runCellmgr(ctx context.Context, sess *session, args ...string) (commandResult, error) {
	bridge, err := s.getOrCreateBridge(sess)
	if err != nil {
		return commandResult{}, err
	}

	res, err := bridge.callCapture(ctx, args)
	if !isBridgeTransportError(err) {
		return res, err
	}

	s.log.Printf("ipc bridge transport error for user=%s, recreating bridge: %v", sess.Identity.Username, err)
	closeSessionBridge(sess)

	bridge, createErr := s.getOrCreateBridge(sess)
	if createErr != nil {
		return commandResult{}, createErr
	}
	return bridge.callCapture(ctx, args)
}

func (s *appServer) getOrCreateBridge(sess *session) (*ipcBridge, error) {
	if sess == nil {
		return nil, fmt.Errorf("missing session")
	}

	sess.bridgeMu.Lock()
	defer sess.bridgeMu.Unlock()

	if sess.bridge != nil {
		return sess.bridge, nil
	}

	bridge, err := startIPCBridge(sess.Identity)
	if err != nil {
		return nil, err
	}
	sess.bridge = bridge
	return bridge, nil
}

func runHostCommandAsUser(ctx context.Context, id identity, bin string, args ...string) (commandResult, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = fallbackDir(id.HomeDir)
	cmd.Env = []string{
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/pkg/bin",
		"HOME=" + id.HomeDir,
		"USER=" + id.Username,
		"LOGNAME=" + id.Username,
		"LC_ALL=C",
		"TERM=dumb",
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    id.UID,
			Gid:    id.GID,
			Groups: id.Groups,
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	combined := truncateOutput(strings.TrimSpace(stdout.String()+stderr.String()), maxOutputBytes)

	if err == nil {
		return commandResult{Output: combined, ExitCode: 0}, nil
	}

	exitCode := -1
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return commandResult{Output: combined, ExitCode: exitCode}, err
	}
	exitCode = exitErr.ExitCode()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return commandResult{Output: combined, ExitCode: exitCode}, fmt.Errorf("command timeout")
	}

	return commandResult{Output: combined, ExitCode: exitCode}, fmt.Errorf("exit status %d", exitCode)
}

func (s *appServer) runHostOutput(ctx context.Context, id identity, bin string, args ...string) (string, error) {
	res, err := runHostCommandAsUser(ctx, id, bin, args...)
	if err != nil {
		cmdText := strings.TrimSpace(strings.Join(append([]string{bin}, args...), " "))
		return res.Output, fmt.Errorf("%s: %s", cmdText, commandErrorMessage(err, res.Output))
	}
	return res.Output, nil
}

func (s *appServer) collectSystemSnapshot(ctx context.Context, id identity) systemSnapshot {
	snap := systemSnapshot{Warnings: make([]string, 0, 8)}

	if hostOut, err := s.runHostOutput(ctx, id, "hostname"); err == nil {
		snap.Hostname = strings.TrimSpace(hostOut)
	} else {
		host, hostErr := os.Hostname()
		if hostErr == nil {
			snap.Hostname = host
		} else {
			snap.Hostname = "-"
		}
		snap.Warnings = append(snap.Warnings, "hostname unavailable: "+err.Error())
	}

	if upOut, err := s.runHostOutput(ctx, id, "uptime"); err == nil {
		snap.Uptime, snap.LoadAverage = parseUptimeAndLoad(upOut)
	} else {
		snap.Uptime = "-"
		snap.LoadAverage = "-"
		snap.Warnings = append(snap.Warnings, "uptime unavailable: "+err.Error())
	}

	if fsRows, err := s.collectFilesystems(ctx, id); err == nil {
		snap.Filesystems = fsRows
	} else {
		snap.Warnings = append(snap.Warnings, err.Error())
	}

	if cpu, err := s.collectCPUTicks(ctx, id); err == nil {
		snap.CPUTicks = cpu
	} else {
		snap.Warnings = append(snap.Warnings, err.Error())
	}

	if mem, err := s.collectMemory(ctx, id); err == nil {
		snap.Memory = mem
	} else {
		snap.Warnings = append(snap.Warnings, err.Error())
	}

	if sw, err := s.collectSwap(ctx, id); err == nil {
		snap.Swap = sw
	} else {
		snap.Warnings = append(snap.Warnings, err.Error())
	}

	if ifs, err := s.collectInterfaces(ctx, id); err == nil {
		snap.Interfaces = ifs
	} else {
		snap.Warnings = append(snap.Warnings, err.Error())
	}

	if ioRows, err := s.collectIOStats(ctx, id); err == nil {
		snap.IO = ioRows
	} else {
		snap.Warnings = append(snap.Warnings, err.Error())
	}

	return snap
}

func (s *appServer) startSystemTrendSampler(id identity, interval time.Duration) {
	if s.trendStore == nil {
		return
	}
	if interval < 2*time.Second {
		interval = 2 * time.Second
	}

	go func() {
		s.sampleSystemTrendPoint(id)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			s.sampleSystemTrendPoint(id)
		}
	}()
}

func (s *appServer) sampleSystemTrendPoint(id identity) {
	ctx, cancel := context.WithTimeout(context.Background(), s.commandTimeout)
	defer cancel()

	if mem, err := s.collectMemory(ctx, id); err == nil {
		s.trendStore.pushMemoryPercent(mem.UsedPct)
	}

	if cpu, err := s.collectCPUTicks(ctx, id); err == nil {
		s.trendStore.pushCPUTicks(cpu)
	}
}

func parseUptimeAndLoad(raw string) (string, string) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return "-", "-"
	}

	loadLabel := "load averages:"
	idx := strings.Index(line, loadLabel)
	if idx < 0 {
		loadLabel = "load average:"
		idx = strings.Index(line, loadLabel)
	}

	uptime := line
	load := "-"
	if idx >= 0 {
		load = strings.TrimSpace(line[idx+len(loadLabel):])
		uptime = strings.TrimSpace(line[:idx])
	}
	if upIdx := strings.Index(uptime, " up "); upIdx >= 0 {
		uptime = strings.TrimSpace(uptime[upIdx+4:])
	}
	if uptime == "" {
		uptime = "-"
	}
	if load == "" {
		load = "-"
	}
	return uptime, load
}

func (s *appServer) collectFilesystems(ctx context.Context, id identity) ([]filesystemStat, error) {
	output, err := s.runHostOutput(ctx, id, "df", "-P", "-k", "-t", "ffs")
	if err != nil {
		output, err = s.runHostOutput(ctx, id, "df", "-k", "-t", "ffs")
		if err != nil {
			return nil, fmt.Errorf("filesystem stats unavailable: %w", err)
		}
	}

	rows := make([]filesystemStat, 0, 16)
	for _, line := range splitLines(output) {
		if strings.HasPrefix(line, "Filesystem") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		sizeKB, ok1 := parseUint(fields[1])
		usedKB, ok2 := parseUint(fields[2])
		availKB, ok3 := parseUint(fields[3])
		capPct, ok4 := parsePercent(fields[4])
		if !ok1 || !ok2 || !ok3 || !ok4 {
			continue
		}
		rows = append(rows, filesystemStat{
			Filesystem: fields[0],
			SizeKB:     sizeKB,
			UsedKB:     usedKB,
			AvailKB:    availKB,
			Capacity:   capPct,
			Mountpoint: strings.Join(fields[5:], " "),
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Mountpoint < rows[j].Mountpoint
	})

	return rows, nil
}

func (s *appServer) collectMemory(ctx context.Context, id identity) (memoryStat, error) {
	total, err := s.sysctlUint(ctx, id, "hw.physmem64")
	if err != nil {
		total, err = s.sysctlUint(ctx, id, "hw.physmem")
		if err != nil {
			return memoryStat{}, fmt.Errorf("memory stats unavailable: %w", err)
		}
	}

	pageSize, pageErr := s.sysctlUint(ctx, id, "hw.pagesize")
	freePages, freeErr := s.collectFreePages(ctx, id)

	if pageErr != nil || freeErr != nil {
		summary, vmErr := s.collectVMStatSummary(ctx, id)
		if vmErr == nil {
			if pageErr != nil && summary.HasPageSize {
				pageSize = summary.PageSize
				pageErr = nil
			}
			if freeErr != nil && summary.HasFreePages {
				freePages = summary.FreePages
				freeErr = nil
			}
		}

		if pageErr != nil {
			if vmErr != nil {
				pageErr = fmt.Errorf("%w; vmstat fallback failed: %v", pageErr, vmErr)
			}
			return memoryStat{}, fmt.Errorf("memory page size unavailable: %w", pageErr)
		}
		if freeErr != nil {
			if vmErr != nil {
				freeErr = fmt.Errorf("%w; vmstat fallback failed: %v", freeErr, vmErr)
			}
			return memoryStat{}, fmt.Errorf("memory free pages unavailable: %w", freeErr)
		}
	}

	free := freePages * pageSize
	if free > total {
		free = total
	}
	used := total - free
	pct := 0
	if total > 0 {
		pct = int((used * 100) / total)
	}

	return memoryStat{
		TotalBytes: total,
		UsedBytes:  used,
		FreeBytes:  free,
		UsedPct:    pct,
	}, nil
}

type vmstatSummary struct {
	FreePages    uint64
	PageSize     uint64
	HasFreePages bool
	HasPageSize  bool
}

func (s *appServer) collectFreePages(ctx context.Context, id identity) (uint64, error) {
	freePages, err := s.sysctlUint(ctx, id, "vm.uvmexp.free")
	if err == nil {
		return freePages, nil
	}

	freePages, err = s.sysctlStructUint(ctx, id, "vm.uvmexp2", "free")
	if err == nil {
		return freePages, nil
	}

	freePages, err = s.sysctlStructUint(ctx, id, "vm.uvmexp", "free")
	if err == nil {
		return freePages, nil
	}

	return 0, err
}

func (s *appServer) collectVMStatSummary(ctx context.Context, id identity) (vmstatSummary, error) {
	output, err := s.runHostOutput(ctx, id, "vmstat", "-s")
	if err != nil {
		return vmstatSummary{}, err
	}
	return parseVMStatSummary(output), nil
}

func parseVMStatSummary(raw string) vmstatSummary {
	summary := vmstatSummary{}

	for _, line := range splitLines(raw) {
		fields := strings.Fields(strings.ReplaceAll(line, ",", ""))
		if len(fields) == 0 {
			continue
		}

		value, ok := parseUint(fields[0])
		if !ok {
			continue
		}

		lower := strings.ToLower(line)
		if !summary.HasFreePages && strings.Contains(lower, "pages free") {
			summary.FreePages = value
			summary.HasFreePages = true
		}
		if !summary.HasPageSize && (strings.Contains(lower, "bytes per page") || strings.Contains(lower, "page size")) {
			summary.PageSize = value
			summary.HasPageSize = true
		}

		if summary.HasFreePages && summary.HasPageSize {
			break
		}
	}

	return summary
}

func (s *appServer) collectSwap(ctx context.Context, id identity) (swapStat, error) {
	output, err := s.runHostOutput(ctx, id, "swapctl", "-lk")
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "not configured") || strings.Contains(lower, "no swap") {
			return swapStat{HasSwap: false, Readable: true}, nil
		}
		return swapStat{}, fmt.Errorf("swap stats unavailable: %w", err)
	}

	total := uint64(0)
	used := uint64(0)
	avail := uint64(0)
	found := false

	for _, line := range splitLines(output) {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if strings.EqualFold(fields[0], "device") {
			continue
		}
		if strings.EqualFold(fields[0], "total") {
			t, ok1 := parseUint(fields[1])
			u, ok2 := parseUint(fields[2])
			a, ok3 := parseUint(fields[3])
			if ok1 && ok2 && ok3 {
				total, used, avail = t, u, a
				found = true
				break
			}
		}
	}

	if !found {
		for _, line := range splitLines(output) {
			fields := strings.Fields(line)
			if len(fields) < 4 || strings.EqualFold(fields[0], "device") {
				continue
			}
			t, ok1 := parseUint(fields[1])
			u, ok2 := parseUint(fields[2])
			a, ok3 := parseUint(fields[3])
			if ok1 && ok2 && ok3 {
				total += t
				used += u
				avail += a
				found = true
			}
		}
	}

	if !found {
		return swapStat{HasSwap: false, Readable: true}, nil
	}

	pct := 0
	if total > 0 {
		pct = int((used * 100) / total)
	}

	return swapStat{
		TotalKB:  total,
		UsedKB:   used,
		AvailKB:  avail,
		UsedPct:  pct,
		HasSwap:  total > 0,
		Readable: true,
	}, nil
}

func (s *appServer) collectInterfaces(ctx context.Context, id identity) ([]interfaceStat, error) {
	ifconfigOut, err := s.runHostOutput(ctx, id, "ifconfig", "-a")
	if err != nil {
		return nil, fmt.Errorf("ifconfig stats unavailable: %w", err)
	}

	interfaces := parseIfconfig(ifconfigOut)
	if len(interfaces) == 0 {
		return interfaces, nil
	}

	counterByName := map[string][2]uint64{}
	netstatOut, err := s.runHostOutput(ctx, id, "netstat", "-inb")
	if err == nil {
		counterByName = parseNetstatInterfaceBytes(netstatOut)
	}

	for i := range interfaces {
		if counters, ok := counterByName[interfaces[i].Name]; ok {
			interfaces[i].InBytes = counters[0]
			interfaces[i].OutBytes = counters[1]
		}
	}

	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Name < interfaces[j].Name })
	return interfaces, nil
}

func parseIfconfig(output string) []interfaceStat {
	rows := make([]interfaceStat, 0, 16)
	byName := map[string]int{}

	for _, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}

		if len(raw) > 0 && raw[0] != ' ' && raw[0] != '\t' {
			idx := strings.Index(raw, ":")
			if idx <= 0 {
				continue
			}
			name := strings.TrimSpace(raw[:idx])
			row := interfaceStat{Name: name, Status: "unknown", MTU: -1}
			if m := ifMTUPattern.FindStringSubmatch(raw); len(m) == 2 {
				if mtu, err := strconv.Atoi(m[1]); err == nil {
					row.MTU = mtu
				}
			}
			rows = append(rows, row)
			byName[name] = len(rows) - 1
			continue
		}

		if len(rows) == 0 {
			continue
		}

		row := &rows[len(rows)-1]
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "status:"):
			row.Status = strings.TrimSpace(strings.TrimPrefix(line, "status:"))
		case strings.HasPrefix(line, "inet "):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				row.Addresses = appendIfMissing(row.Addresses, fields[1])
			}
		case strings.HasPrefix(line, "inet6 "):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				row.Addresses = appendIfMissing(row.Addresses, fields[1])
			}
		}
	}

	_ = byName
	return rows
}

func parseNetstatInterfaceBytes(output string) map[string][2]uint64 {
	out := map[string][2]uint64{}
	for _, line := range splitLines(output) {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		name := fields[0]
		if strings.EqualFold(name, "name") || strings.EqualFold(name, "kernel") {
			continue
		}
		inB, outB, ok := parseLastTwoUint(fields)
		if !ok {
			continue
		}
		curr := out[name]
		curr[0] += inB
		curr[1] += outB
		out[name] = curr
	}
	return out
}

func parseLastTwoUint(fields []string) (uint64, uint64, bool) {
	nums := make([]uint64, 0, 2)
	for i := len(fields) - 1; i >= 0 && len(nums) < 2; i-- {
		if v, ok := parseUint(fields[i]); ok {
			nums = append(nums, v)
		}
	}
	if len(nums) < 2 {
		return 0, 0, false
	}
	return nums[1], nums[0], true
}

func appendIfMissing(in []string, value string) []string {
	for _, v := range in {
		if v == value {
			return in
		}
	}
	return append(in, value)
}

func (s *appServer) collectIOStats(ctx context.Context, id identity) ([]ioDeviceStat, error) {
	output, err := s.runHostOutput(ctx, id, "iostat", "-dx", "1", "2")
	if err != nil {
		output, err = s.runHostOutput(ctx, id, "iostat", "-x")
		if err != nil {
			return nil, fmt.Errorf("i/o stats unavailable: %w", err)
		}
	}

	rows := parseIostat(output)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Device < rows[j].Device })
	return rows, nil
}

func parseIostat(output string) []ioDeviceStat {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return nil
	}

	headerIdx := -1
	var headerFields []string
	for i := len(lines) - 1; i >= 0; i-- {
		f := strings.Fields(strings.TrimSpace(lines[i]))
		if len(f) < 2 {
			continue
		}
		first := strings.ToLower(f[0])
		if first == "device" || first == "disk" {
			headerIdx = i
			headerFields = f
			break
		}
	}
	if headerIdx < 0 {
		return nil
	}

	rows := make([]ioDeviceStat, 0, 16)
	byDevice := map[string]int{}
	for i := headerIdx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			if len(rows) > 0 {
				break
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := strings.ToLower(f[0])
		if name == "tty" || name == "cpu" || name == "device" {
			continue
		}

		metrics := make(map[string]string, len(headerFields)-1)
		for h := 1; h < len(headerFields) && h < len(f); h++ {
			metrics[strings.ToLower(headerFields[h])] = f[h]
		}

		key := normalizeIODeviceName(f[0])
		if idx, ok := byDevice[key]; ok {
			for metric, value := range metrics {
				rows[idx].Metrics[metric] = value
			}
			continue
		}

		rows = append(rows, ioDeviceStat{Device: f[0], Metrics: metrics})
		byDevice[key] = len(rows) - 1
	}

	return rows
}

func normalizeIODeviceName(name string) string {
	normalized := strings.ToLower(strings.TrimSpace(name))
	normalized = strings.TrimSuffix(normalized, ":")
	return normalized
}

func (s *appServer) collectCPUTicks(ctx context.Context, id identity) (cpuTickStat, error) {
	output, err := s.runHostOutput(ctx, id, "sysctl", "-n", "kern.cp_time")
	if err != nil {
		return cpuTickStat{}, fmt.Errorf("cpu stats unavailable: %w", err)
	}

	ticks, ok := parseCPUTicks(output)
	if !ok {
		return cpuTickStat{}, fmt.Errorf("cpu stats unavailable: cannot parse kern.cp_time")
	}
	return ticks, nil
}

func parseCPUTicks(raw string) (cpuTickStat, bool) {
	tokens := strings.FieldsFunc(strings.TrimSpace(raw), func(r rune) bool {
		return r < '0' || r > '9'
	})

	vals := make([]uint64, 0, 5)
	for _, token := range tokens {
		if token == "" {
			continue
		}
		if v, ok := parseUint(token); ok {
			vals = append(vals, v)
			if len(vals) == 5 {
				break
			}
		}
	}

	if len(vals) < 5 {
		return cpuTickStat{}, false
	}

	return cpuTickStat{
		User:   vals[0],
		Nice:   vals[1],
		System: vals[2],
		Intr:   vals[3],
		Idle:   vals[4],
	}, true
}

func (s *appServer) sysctlUint(ctx context.Context, id identity, key string) (uint64, error) {
	output, err := s.runHostOutput(ctx, id, "sysctl", "-n", key)
	if err != nil {
		return 0, err
	}
	line := strings.TrimSpace(output)
	if line == "" {
		return 0, fmt.Errorf("empty sysctl output for %s", key)
	}

	if v, ok := parseUint(line); ok {
		return v, nil
	}
	if m := bootSecPattern.FindStringSubmatch(line); len(m) == 2 {
		if v, ok := parseUint(m[1]); ok {
			return v, nil
		}
	}
	return 0, fmt.Errorf("cannot parse sysctl %s value: %q", key, line)
}

func (s *appServer) sysctlStructUint(ctx context.Context, id identity, key, field string) (uint64, error) {
	output, err := s.runHostOutput(ctx, id, "sysctl", "-n", key)
	if err != nil {
		return 0, err
	}
	if v, ok := parseSysctlStructUintField(output, field); ok {
		return v, nil
	}
	return 0, fmt.Errorf("cannot parse sysctl %s field %s", key, field)
}

func parseSysctlStructUintField(raw, field string) (uint64, bool) {
	target := strings.ToLower(strings.TrimSpace(field))
	if target == "" {
		return 0, false
	}

	normalized := strings.NewReplacer("{", "", "}", "", "\n", ",", "\r", ",").Replace(raw)
	for _, segment := range strings.Split(normalized, ",") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		parts := strings.SplitN(segment, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if key != target {
			continue
		}
		value := strings.TrimSpace(parts[1])
		for _, token := range strings.Fields(value) {
			token = strings.Trim(token, ",")
			if v, ok := parseUint(token); ok {
				return v, true
			}
		}
		if v, ok := parseUint(strings.Trim(value, ",")); ok {
			return v, true
		}
		return 0, false
	}

	return 0, false
}

func parseUint(s string) (uint64, bool) {
	if s == "" || s == "-" {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func parsePercent(s string) (int, bool) {
	s = strings.TrimSuffix(strings.TrimSpace(s), "%")
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	if v < 0 {
		v = 0
	}
	if v > 100 {
		v = 100
	}
	return v, true
}

func (s *appServer) loadCells(ctx context.Context, sess *session) ([]cellRow, error) {
	res, err := s.runCellmgr(ctx, sess,
		"cell", "list", "--view", "merged", "-T", "-H", "-o",
		"name,cid,refs,procs,root,autostart,create_profile,create_reserved_ports,create_rlimit_nofile,create_rlimit_as,create_rlimit_core,supervise_cmd,cpu1s,cpu10s,memory,age,running,manifest",
	)
	if err != nil {
		return nil, fmt.Errorf("cell list failed: %s", commandErrorMessage(err, res.Output))
	}

	var rows []cellRow
	for _, line := range splitLines(res.Output) {
		fields, ok := splitTSVFixed(line, 18)
		if !ok {
			continue
		}
		running, err := parseTSVBool(fields[16])
		if err != nil {
			continue
		}
		manifest, err := parseTSVBool(fields[17])
		if err != nil {
			continue
		}
		rows = append(rows, cellRow{
			Name:                fields[0],
			CID:                 fields[1],
			Refs:                fields[2],
			Procs:               fields[3],
			Root:                fields[4],
			Autostart:           fallback(fields[5], "NO"),
			CreateProfile:       fields[6],
			CreateReservedPorts: fields[7],
			CreateRlimitNofile:  fields[8],
			CreateRlimitAS:      fields[9],
			CreateRlimitCore:    fields[10],
			SuperviseCmd:        fields[11],
			CPU1s:               fields[12],
			CPU10s:              fields[13],
			Memory:              fields[14],
			Age:                 fields[15],
			Running:             running,
			ManifestPresent:     manifest,
		})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

func (s *appServer) loadStorage(ctx context.Context, sess *session) ([]volumeRow, error) {
	volRes, err := s.runCellmgr(ctx, sess,
		"volume", "list", "--view", "merged", "-T", "-H", "-o",
		"name,manifest,runtime,mounted,refs,mode,path,used_by",
	)
	if err != nil {
		return nil, fmt.Errorf("volume list failed: %s", commandErrorMessage(err, volRes.Output))
	}

	cellRes, err := s.runCellmgr(ctx, sess,
		"cell", "list", "--view", "merged", "-T", "-H", "-o",
		"name,manifest,running,root",
	)
	if err != nil {
		return nil, fmt.Errorf("cell list for overlays failed: %s", commandErrorMessage(err, cellRes.Output))
	}

	rows := make([]volumeRow, 0, 64)
	for _, line := range splitLines(volRes.Output) {
		fields, ok := splitTSVFixed(line, 8)
		if !ok {
			continue
		}
		manifest, err1 := parseTSVBool(fields[1])
		runtime, err2 := parseTSVBool(fields[2])
		mounted, err3 := parseTSVBool(fields[3])
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		rows = append(rows, volumeRow{
			Kind:            "volume",
			Name:            fields[0],
			ManifestPresent: manifest,
			RuntimePresent:  runtime,
			Mounted:         mounted,
			Refs:            fields[4],
			Mode:            fields[5],
			Path:            fields[6],
			UsedBy:          fields[7],
		})
	}

	for _, line := range splitLines(cellRes.Output) {
		fields, ok := splitTSVFixed(line, 4)
		if !ok {
			continue
		}
		manifest, err1 := parseTSVBool(fields[1])
		mounted, err2 := parseTSVBool(fields[2])
		if err1 != nil || err2 != nil {
			continue
		}
		root := strings.TrimSpace(fields[3])
		runtime := root != "" && root != "-"
		rows = append(rows, volumeRow{
			Kind:            "overlay",
			Name:            fields[0],
			ManifestPresent: manifest,
			RuntimePresent:  runtime,
			Mounted:         mounted,
			Refs:            "-",
			Mode:            "-",
			Path:            overlayPath(root),
			UsedBy:          fields[0],
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Kind != rows[j].Kind {
			return rows[i].Kind < rows[j].Kind
		}
		return rows[i].Name < rows[j].Name
	})

	return rows, nil
}

func (s *appServer) loadBackups(ctx context.Context, sess *session, kind, name string) ([]backupRow, error) {
	resource := "volume"
	if kind == "overlay" {
		resource = "cell"
	}

	res, err := s.runCellmgr(ctx, sess, resource, "backup", "list", name, "-T", "-H")
	if err != nil {
		return nil, fmt.Errorf("backup list failed: %s", commandErrorMessage(err, res.Output))
	}

	rows := make([]backupRow, 0, 32)
	for _, line := range splitLines(res.Output) {
		fields, ok := splitTSVFixed(line, 4)
		if !ok {
			continue
		}
		rows = append(rows, backupRow{
			Volume:    fields[0],
			Timestamp: fields[1],
			Size:      fields[2],
			Archive:   fields[3],
		})
	}

	return rows, nil
}

func parseTSVBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "yes", "true":
		return true, nil
	case "0", "no", "false", "":
		return false, nil
	default:
		return false, fmt.Errorf("invalid bool value %q", v)
	}
}

func splitTSVFixed(line string, expected int) ([]string, bool) {
	if strings.TrimSpace(line) == "" {
		return nil, false
	}
	parts := strings.Split(line, "\t")
	if len(parts) != expected {
		return nil, false
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts, true
}

func splitLines(s string) []string {
	raw := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func overlayPath(root string) string {
	if root == "" || root == "-" {
		return ""
	}
	if strings.HasSuffix(root, "/root") {
		return strings.TrimSuffix(root, "/root") + "/.overlay"
	}
	return root + "/.overlay"
}

func commandErrorMessage(err error, output string) string {
	msg := strings.TrimSpace(err.Error())
	if output == "" {
		return msg
	}
	return msg + ": " + output
}

func truncateOutput(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 6 {
		return s[:max]
	}
	return s[:max-6] + "\n[...]"
}

func lookupIdentity(username string) (identity, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return identity{}, err
	}
	return buildIdentityFromUser(u)
}

func lookupProcessIdentity() (identity, error) {
	euid := strconv.Itoa(os.Geteuid())
	u, err := user.LookupId(euid)
	if err != nil {
		return identity{}, err
	}
	return buildIdentityFromUser(u)
}

func buildIdentityFromUser(u *user.User) (identity, error) {
	if u == nil {
		return identity{}, fmt.Errorf("nil user")
	}

	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return identity{}, fmt.Errorf("parse uid: %w", err)
	}
	gid64, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return identity{}, fmt.Errorf("parse gid: %w", err)
	}

	gidStrs, err := u.GroupIds()
	if err != nil {
		return identity{}, fmt.Errorf("lookup groups: %w", err)
	}

	groups := make([]uint32, 0, len(gidStrs))
	for _, gs := range gidStrs {
		g, err := strconv.ParseUint(gs, 10, 32)
		if err != nil {
			continue
		}
		groups = append(groups, uint32(g))
	}
	if len(groups) == 0 {
		groups = []uint32{uint32(gid64)}
	}

	return identity{
		Username: u.Username,
		UID:      uint32(uid64),
		GID:      uint32(gid64),
		Groups:   groups,
		HomeDir:  fallback(u.HomeDir, "/"),
	}, nil
}

func fallback(value, alt string) string {
	if strings.TrimSpace(value) == "" {
		return alt
	}
	return value
}

func configValue(value, alt string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return alt
	}
	return v
}

func resolveTLSMode(enabled bool, certFile, keyFile string) (string, error) {
	if !enabled {
		if strings.TrimSpace(certFile) != "" || strings.TrimSpace(keyFile) != "" {
			return "", errors.New("-tls=false cannot be combined with -tls-cert or -tls-key")
		}
		return tlsModeOff, nil
	}

	hasCert := strings.TrimSpace(certFile) != ""
	hasKey := strings.TrimSpace(keyFile) != ""
	if hasCert != hasKey {
		return "", errors.New("manual TLS requires both -tls-cert and -tls-key")
	}
	if hasCert {
		return tlsModeManual, nil
	}
	return tlsModeSelfSigned, nil
}

type filteredHTTPServerErrorWriter struct {
	dst io.Writer
}

func (w filteredHTTPServerErrorWriter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if strings.Contains(line, "http: TLS handshake error") {
		return len(p), nil
	}
	if w.dst == nil {
		return len(p), nil
	}
	if _, err := w.dst.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func fallbackDir(home string) string {
	if home == "" {
		return "/"
	}
	if st, err := os.Stat(home); err == nil && st.IsDir() {
		return home
	}
	return "/"
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()

	limited := io.LimitReader(r.Body, maxJSONBodyBytes)
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("multiple JSON values in body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, message, detail string) {
	writeJSON(w, status, map[string]any{
		"ok":      false,
		"error":   message,
		"details": detail,
	})
}

func methodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeAPIError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
}

func remoteKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envBoolOrDefault(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func withSecurityHeaders(next http.Handler, enableHSTS bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		if enableHSTS && r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
