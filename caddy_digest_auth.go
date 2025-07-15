package caddy_digest_auth

import (
	"bufio"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// The rug ties the room together (for context cleanup)
var rugCleanup sync.Once

// stranger: sometimes there's a logger, well, he's the logger for his time and place (unused)

func init() {
	caddy.RegisterModule(DigestAuth{})
	httpcaddyfile.RegisterHandlerDirective("digest_auth", parseCaddyfileDigestAuth)
}

// Algorithm constants
const (
	AlgorithmSHA256      = "SHA-256"
	AlgorithmSHA512256   = "SHA-512-256"
)

// DigestAuth implements HTTP Digest Authentication for Caddy
type DigestAuth struct {
	// Configuration fields
	Realm           string   `json:"realm,omitempty"`
	UserFile        string   `json:"user_file,omitempty"`
	Users           []User   `json:"users,omitempty"`             // Inline user credentials
	Algorithm       string   `json:"algorithm,omitempty"`         // MD5 (default), SHA-256, SHA-512-256
	ExcludePaths    []string `json:"exclude_paths,omitempty"`     // Paths that don't require authentication
	Expires         int      `json:"expires,omitempty"`           // Nonce expiration in seconds
	Replays         int      `json:"replays,omitempty"`           // Max nonce reuses
	Timeout         int      `json:"timeout,omitempty"`           // Nonce timeout in seconds
	RateLimitBurst  int      `json:"rate_limit_burst,omitempty"`  // Rate limiting burst
	RateLimitWindow int      `json:"rate_limit_window,omitempty"` // Rate limiting window in seconds
	EnableMetrics   bool     `json:"enable_metrics,omitempty"`    // Enable metrics collection

	// Internal state
	credentials map[string]credential
	nonces      map[string]*nonceData
	rateLimits  map[string]*rateLimitData
	salt        string
	mutex       sync.RWMutex
	logger      *zap.Logger
	metrics     *Metrics
}

// User represents an inline user credential
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// credential represents a user's digest authentication credentials
type credential struct {
	Realm     string `json:"realm"`
	Password  string `json:"password"`  // Store actual password for algorithm flexibility
}

// nonceData stores nonce metadata for validation and replay protection
type nonceData struct {
	Timestamp int64  `json:"timestamp"`
	Counter   int64  `json:"counter"`
	NonceSalt string `json:"nonce_salt"`
	Opaque    string `json:"opaque"`
	Uses      int    `json:"uses"`
	ExpiresAt int64  `json:"expires_at"`
}

// rateLimitData tracks failed authentication attempts
type rateLimitData struct {
	Attempts  int   `json:"attempts"`
	FirstTry  int64 `json:"first_try"`
	BlockedAt int64 `json:"blocked_at"`
}

// Metrics tracks authentication statistics (optional)
type Metrics struct {
	TotalRequests   int64
	SuccessfulAuths int64
	FailedAuths     int64
	RateLimited     int64
	ChallengesSent  int64
	UserNotFound    int64
	InvalidResponse int64
	StaleNonce      int64
	RealmMismatch   int64
	OpaqueMismatch  int64
	mutex           sync.RWMutex
}

// IncrementMetric safely increments a metric counter
func (m *Metrics) IncrementMetric(metric *int64) {
	if m != nil {
		m.mutex.Lock()
		*metric++
		m.mutex.Unlock()
	}
}

// GetMetrics returns a copy of current metrics
func (m *Metrics) GetMetrics() map[string]int64 {
	if m == nil {
		return nil
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return map[string]int64{
		"total_requests":   m.TotalRequests,
		"successful_auths": m.SuccessfulAuths,
		"failed_auths":     m.FailedAuths,
		"rate_limited":     m.RateLimited,
		"challenges_sent":  m.ChallengesSent,
		"user_not_found":   m.UserNotFound,
		"invalid_response": m.InvalidResponse,
		"stale_nonce":      m.StaleNonce,
		"realm_mismatch":   m.RealmMismatch,
		"opaque_mismatch":  m.OpaqueMismatch,
	}
}

// CaddyModule returns the Caddy module information
func (DigestAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.digest_auth",
		New: func() caddy.Module { return new(DigestAuth) },
	}
}

// Provision sets up the module
func (da *DigestAuth) Provision(ctx caddy.Context) error {
	da.logger = ctx.Logger(da)
	da.setDefaults()
	da.initializeMaps()

	if err := da.generateSalt(); err != nil {
		return err
	}
	if err := da.loadCredentials(); err != nil {
		return fmt.Errorf("failed to load credentials: %v", err)
	}

	go da.cleanupRoutine()
	da.initMetrics()
	da.logProvisioningInfo()
	return nil
}

func (da *DigestAuth) setDefaults() {
	// Set string defaults
	if da.Realm == "" {
		da.Realm = "Restricted Area"
	}

	// Set integer defaults using struct slices
	intDefaults := []struct {
		field      *int
		condition  bool
		defaultVal int
	}{
		{&da.Expires, da.Expires == 0, 600},
		{&da.Replays, da.Replays == 0, 500},
		{&da.Timeout, da.Timeout == 0, 600},
		{&da.RateLimitBurst, da.RateLimitBurst == 0, 50},
		{&da.RateLimitWindow, da.RateLimitWindow == 0, 600},
	}

	for _, def := range intDefaults {
		if def.condition {
			*def.field = def.defaultVal
		}
	}
}

func (da *DigestAuth) initializeMaps() {
	da.credentials = make(map[string]credential)
	da.nonces = make(map[string]*nonceData)
	da.rateLimits = make(map[string]*rateLimitData)
}

func (da *DigestAuth) generateSalt() error {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return fmt.Errorf("failed to generate salt: %v", err)
	}
	da.salt = base64.StdEncoding.EncodeToString(saltBytes)
	return nil
}

func (da *DigestAuth) initMetrics() {
	if da.EnableMetrics {
		da.metrics = &Metrics{}
		da.logger.Info("metrics collection enabled")
	}
}

func (da *DigestAuth) logProvisioningInfo() {
	da.logger.Info("digest auth module provisioned",
		zap.String("realm", da.Realm),
		zap.Int("expires", da.Expires),
		zap.Int("replays", da.Replays),
		zap.Int("rate_limit_burst", da.RateLimitBurst),
		zap.Int("rate_limit_window", da.RateLimitWindow),
		zap.Int("exclude_paths", len(da.ExcludePaths)),
		zap.Bool("metrics_enabled", da.EnableMetrics))
}

// ServeHTTP handles the HTTP request
func (da *DigestAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	logger := da.createRequestLogger(r)
	da.trackRequestMetrics()

	if da.checkExcludedPath(r, logger) {
		return next.ServeHTTP(w, r)
	}

	if da.handleRateLimiting(w, r, logger) {
		return nil
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return da.handleMissingAuthHeader(w, logger)
	}

	return da.handleAuthHeader(w, r, authHeader, logger, next)
}

func (da *DigestAuth) createRequestLogger(r *http.Request) *zap.Logger {
	if da.logger == nil {
		return zap.NewNop()
	}
	return da.logger.With(
		zap.String("method", r.Method),
		zap.String("uri", r.URL.Path),
		zap.String("remote_addr", r.RemoteAddr),
	)
}

func (da *DigestAuth) trackRequestMetrics() {
	if da.metrics != nil {
		da.metrics.IncrementMetric(&da.metrics.TotalRequests)
	}
}

func (da *DigestAuth) checkExcludedPath(r *http.Request, logger *zap.Logger) bool {
	if da.isPathExcluded(r.URL.Path) {
		logger.Debug("path excluded from authentication")
		return true
	}
	return false
}

func (da *DigestAuth) handleRateLimiting(w http.ResponseWriter, r *http.Request, logger *zap.Logger) bool {
	if da.isRateLimited(r.RemoteAddr) {
		if da.metrics != nil {
			da.metrics.IncrementMetric(&da.metrics.RateLimited)
		}
		logger.Warn("client blocked by rate limiting",
			zap.Int("status", http.StatusTooManyRequests))
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return true
	}
	return false
}

func (da *DigestAuth) handleMissingAuthHeader(w http.ResponseWriter, logger *zap.Logger) error {
	if da.metrics != nil {
		da.metrics.IncrementMetric(&da.metrics.ChallengesSent)
	}
	logger.Debug("no authorization header, issuing challenge",
		zap.Int("status", http.StatusUnauthorized))
	return da.sendChallenge(w, false, logger)
}

func (da *DigestAuth) handleAuthHeader(w http.ResponseWriter, r *http.Request, authHeader string, logger *zap.Logger, next caddyhttp.Handler) error {
	ctx, err := da.parseAuthHeader(authHeader, r.Method)
	if err != nil {
		return da.handleAuthError(w, r, err, logger)
	}

	pass, stale := da.verify(ctx, r.RemoteAddr, logger)
	if !pass {
		return da.handleFailedAuth(w, r, ctx, stale, logger)
	}

	return da.handleSuccessfulAuth(w, r, ctx, logger, next)
}

func (da *DigestAuth) handleAuthError(w http.ResponseWriter, r *http.Request, err error, logger *zap.Logger) error {
	if da.metrics != nil {
		da.metrics.IncrementMetric(&da.metrics.FailedAuths)
	}
	logger.Warn("malformed authorization header",
		zap.Error(err),
		zap.Int("status", http.StatusBadRequest))
	da.incrementRateLimit(r.RemoteAddr)
	http.Error(w, "Bad Request", http.StatusBadRequest)
	return nil
}

func (da *DigestAuth) handleFailedAuth(w http.ResponseWriter, r *http.Request, ctx *authContext, stale bool, logger *zap.Logger) error {
	if da.metrics != nil {
		da.metrics.IncrementMetric(&da.metrics.FailedAuths)
	}
	da.incrementRateLimit(r.RemoteAddr)
	return da.sendChallenge(w, stale, logger)
}

func (da *DigestAuth) handleSuccessfulAuth(w http.ResponseWriter, r *http.Request, ctx *authContext, logger *zap.Logger, next caddyhttp.Handler) error {
	da.resetRateLimit(r.RemoteAddr)
	if da.metrics != nil {
		da.metrics.IncrementMetric(&da.metrics.SuccessfulAuths)
	}

	logger.Info("authentication successful",
		zap.String("username", ctx.user),
		zap.Int("status", http.StatusOK))

	return next.ServeHTTP(w, r)
}

// loadCredentials loads user credentials from the specified file or inline users
func (da *DigestAuth) loadCredentials() error {
	da.mutex.Lock()
	defer da.mutex.Unlock()

	if len(da.Users) > 0 {
		return da.loadInlineUsers()
	}
	if da.UserFile != "" {
		return da.loadUserFile()
	}
	return fmt.Errorf("no credentials configured")
}

func (da *DigestAuth) loadInlineUsers() error {
	for _, user := range da.Users {
		if user.Username == "" || user.Password == "" {
			return fmt.Errorf("username and password are required for inline users")
		}
		da.credentials[user.Username] = credential{
			Realm:    da.Realm,
			Password: user.Password,
		}
	}

	if da.logger != nil {
		da.logger.Info("loaded inline credentials",
			zap.Int("count", len(da.Users)),
			zap.String("realm", da.Realm))
	}
	return nil
}

func (da *DigestAuth) loadUserFile() error {
	file, err := os.Open(da.UserFile)
	if err != nil {
		return fmt.Errorf("failed to open user file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var loadedCount, skippedCount int

	for lineNum := 1; scanner.Scan(); lineNum++ {
		line := strings.TrimSpace(scanner.Text())
		l, s, err := da.processUserFileLine(line, lineNum)
		loadedCount += l
		skippedCount += s
		if err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading user file: %v", err)
	}

	da.logFileLoadStats(loadedCount, skippedCount)
	return nil
}

func (da *DigestAuth) processUserFileLine(line string, lineNum int) (loaded int, skipped int, err error) {
	if line == "" || strings.HasPrefix(line, "#") {
		return 0, 0, nil
	}

	username, realm, md5hash, skip, err := da.parseUserFileLine(line, lineNum)
	if err != nil || skip {
		return 0, 1, err
	}

	da.credentials[username] = credential{Realm: realm, Password: md5hash}
	return 1, 0, nil
}

func (da *DigestAuth) logFileLoadStats(loaded, skipped int) {
	if da.logger != nil {
		da.logger.Info("loaded credentials from file",
			zap.String("file", da.UserFile),
			zap.Int("loaded", loaded),
			zap.Int("skipped", skipped),
			zap.String("realm", da.Realm))
	}
}

func (da *DigestAuth) parseUserFileLine(line string, lineNum int) (string, string, string, bool, error) {
	parts := strings.Split(line, ":")
	if len(parts) != 3 {
		if da.logger != nil {
			da.logger.Warn("invalid htdigest format",
				zap.Int("line", lineNum),
				zap.String("line", line),
				zap.String("file", da.UserFile))
		}
		return "", "", "", true, nil
	}

	username := parts[0]
	realm := parts[1]
	md5hash := parts[2]

	if realm != da.Realm {
		if da.logger != nil {
			da.logger.Warn("realm mismatch",
				zap.String("username", username),
				zap.String("expected_realm", da.Realm),
				zap.String("file_realm", realm),
				zap.String("file", da.UserFile))
		}
		return "", "", "", true, nil
	}

	return username, realm, md5hash, false, nil // Note: md5hash is stored in Password field for MD5 compatibility
}

// generateNonce creates a new nonce with all required components
func (da *DigestAuth) generateNonce() (string, *nonceData, error) {
	// Generate random components
	randomBytes := make([]byte, 64)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}

	entropy := randomBytes[:32]
	nonceSalt := randomBytes[32:48]
	opaque := randomBytes[48:64]

	// Create nonce data
	now := time.Now().Unix()
	nonceData := &nonceData{
		Timestamp: now,
		Counter:   now, // Simplified counter
		NonceSalt: base64.StdEncoding.EncodeToString(nonceSalt),
		Opaque:    base64.StdEncoding.EncodeToString(opaque),
		Uses:      0,
		ExpiresAt: now + int64(da.Timeout),
	}

	// Create nonce string
	nonceComponents := []string{
		base64.StdEncoding.EncodeToString(entropy),
		strconv.FormatInt(nonceData.Counter, 10),
		strconv.FormatInt(now, 10),
		nonceData.NonceSalt,
		da.salt,
		nonceData.Opaque,
	}
	nonce := base64.StdEncoding.EncodeToString([]byte(strings.Join(nonceComponents, ":")))

	// Store nonce data
	da.mutex.Lock()
	da.nonces[nonce] = nonceData
	da.mutex.Unlock()

	return nonce, nonceData, nil
}

// sendChallenge sends a WWW-Authenticate header with digest challenge
func (da *DigestAuth) sendChallenge(w http.ResponseWriter, stale bool, logger *zap.Logger) error {
	nonce, nonceData, err := da.generateNonce()
	if err != nil {
		logger.Error("failed to generate nonce",
			zap.Error(err),
			zap.Int("status", http.StatusInternalServerError))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	// RFC 7616 requires UTF-8 and algorithm in challenge
	algorithm := da.Algorithm
	if algorithm == "" {
		algorithm = "MD5" // Default to RFC 2617 compatibility
	}
	// RFC 7616 requires UTF-8 and allows multiple quality of protection options
	challenge := fmt.Sprintf(
		`Digest realm="%s", charset="UTF-8", algorithm=%s, qop="auth,auth-int", nonce="%s", opaque="%s"`,
		da.Realm, algorithm, nonce, nonceData.Opaque)

	if stale {
		challenge += ", stale=true"
	}

	w.Header().Set("WWW-Authenticate", challenge)

	status := http.StatusUnauthorized
	logger.Info("authentication challenge sent",
		zap.Int("status", status),
		zap.Bool("stale", stale))

	http.Error(w, "Unauthorized", status)
	return nil
}

// parseAuthHeader parses the Authorization header
func (da *DigestAuth) parseAuthHeader(header string, method string) (*authContext, error) {
	if !strings.HasPrefix(header, "Digest ") {
		return nil, fmt.Errorf("not a digest authorization header")
	}

	ctx := &authContext{method: method}
	da.parseAuthKeyValues(strings.TrimPrefix(header, "Digest "), ctx)

	if err := da.validateAuthContext(ctx); err != nil {
		return nil, err
	}

	return ctx, nil
}

func (da *DigestAuth) parseAuthKeyValues(header string, ctx *authContext) {
	pairs := strings.Split(header, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if !strings.Contains(pair, "=") {
			continue
		}

		key, value := parseKeyValue(pair)
		da.assignAuthValue(key, value, ctx)
	}
}

func parseKeyValue(pair string) (string, string) {
	parts := strings.SplitN(pair, "=", 2)
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	// Remove quotes if present
	if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		value = value[1 : len(value)-1]
	}
	return key, value
}

func (da *DigestAuth) assignAuthValue(key, value string, ctx *authContext) {
	keyHandlers := map[string]func(string){
		"username": func(v string) { ctx.user = v },
		"realm":    func(v string) { ctx.realm = v },
		"nonce":    func(v string) { ctx.nonce = v },
		"uri":      func(v string) { ctx.uri = v },
		"response": func(v string) { ctx.response = v },
		"qop":      func(v string) { ctx.qop = v },
		"nc":       func(v string) { ctx.nc = v },
		"cnonce":   func(v string) { ctx.cnonce = v },
		"opaque":   func(v string) { ctx.opaque = v },
		"method":   func(v string) { ctx.method = v },
		"algorithm": func(v string) { ctx.algorithm = v },
	}

	if handler, exists := keyHandlers[key]; exists {
		handler(value)
	}
}

func (da *DigestAuth) validateAuthContext(ctx *authContext) error {
	if missingRequiredFields(ctx) {
		return fmt.Errorf("missing required fields")
	}
	if hasInvalidQop(ctx) {
		return fmt.Errorf("invalid qop value or missing cnonce/nc")
	}
	return nil
}

func missingRequiredFields(ctx *authContext) bool {
	required := []string{
		ctx.user,
		ctx.response,
		ctx.uri,
		ctx.nonce,
		ctx.realm,
	}
	for _, val := range required {
		if val == "" {
			return true
		}
	}
	return false
}

func hasInvalidQop(ctx *authContext) bool {
	if ctx.qop == "" {
		return false
	}
	return ctx.qop != "auth" || ctx.cnonce == "" || ctx.nc == ""
}

// authContext holds parsed authentication data
type authContext struct {
	user      string
	realm     string
	nonce     string
	uri       string
	response  string
	qop       string
	nc        string
	cnonce    string
	opaque    string
	method    string
	algorithm string
}

// verify validates the authentication response
func (da *DigestAuth) verify(ctx *authContext, remoteAddr string, logger *zap.Logger) (bool, bool) {
	cred, exists := da.getUserCredentials(ctx.user)
	if !exists {
		da.handleUserNotFound(ctx, remoteAddr, logger)
		return false, false
	}

	if !da.validateRealm(cred, ctx, remoteAddr, logger) {
		return false, false
	}

	stale, nonceData := da.validateNonce(ctx.nonce)
	if stale {
		da.handleStaleNonce(ctx, remoteAddr, logger, nonceData)
		return false, true
	}

	if !da.validateOpaque(ctx, nonceData, remoteAddr, logger) {
		return false, false
	}

	return da.validateResponseHash(ctx, cred, remoteAddr, logger), false
}

func (da *DigestAuth) getUserCredentials(username string) (credential, bool) {
	da.mutex.RLock()
	defer da.mutex.RUnlock()
	cred, exists := da.credentials[username]
	return cred, exists
}

func (da *DigestAuth) handleUserNotFound(ctx *authContext, remoteAddr string, logger *zap.Logger) {
	if da.metrics != nil {
		da.metrics.IncrementMetric(&da.metrics.UserNotFound)
	}
	logger.Warn("authentication failed: user not found",
		zap.String("remote_addr", remoteAddr),
		zap.String("username", ctx.user),
		zap.String("realm", ctx.realm),
		zap.Bool("user_exists", false),
		zap.Int("status", http.StatusUnauthorized))
}

func (da *DigestAuth) validateRealm(cred credential, ctx *authContext, remoteAddr string, logger *zap.Logger) bool {
	if cred.Realm == ctx.realm {
		return true
	}

	if da.metrics != nil {
		da.metrics.IncrementMetric(&da.metrics.RealmMismatch)
	}
	logger.Warn("authentication failed: realm mismatch",
		zap.String("remote_addr", remoteAddr),
		zap.String("username", ctx.user),
		zap.String("expected_realm", cred.Realm),
		zap.String("provided_realm", ctx.realm),
		zap.Int("status", http.StatusUnauthorized))
	return false
}

func (da *DigestAuth) handleStaleNonce(ctx *authContext, remoteAddr string, logger *zap.Logger, nonceData *nonceData) {
	if da.metrics != nil {
		da.metrics.IncrementMetric(&da.metrics.StaleNonce)
	}
	logger.Warn("authentication failed: nonce is stale or invalid",
		zap.String("remote_addr", remoteAddr),
		zap.String("username", ctx.user),
		zap.String("nonce", ctx.nonce),
		zap.Int("status", http.StatusUnauthorized))
}

func (da *DigestAuth) validateOpaque(ctx *authContext, nonceData *nonceData, remoteAddr string, logger *zap.Logger) bool {
	if ctx.opaque == "" || nonceData == nil || ctx.opaque == nonceData.Opaque {
		return true
	}

	if da.metrics != nil {
		da.metrics.IncrementMetric(&da.metrics.OpaqueMismatch)
	}
	logger.Warn("authentication failed: opaque mismatch",
		zap.String("remote_addr", remoteAddr),
		zap.String("username", ctx.user),
		zap.String("provided_opaque", ctx.opaque),
		zap.String("expected_opaque", nonceData.Opaque),
		zap.Int("status", http.StatusUnauthorized))
	return false
}

func (da *DigestAuth) validateResponseHash(ctx *authContext, cred credential, remoteAddr string, logger *zap.Logger) bool {
	expected := da.calculateExpectedResponse(ctx, cred)
	if expected == ctx.response {
		return true
	}

	if da.metrics != nil {
		da.metrics.IncrementMetric(&da.metrics.InvalidResponse)
	}
	logger.Warn("authentication failed: invalid response hash",
		zap.String("remote_addr", remoteAddr),
		zap.String("username", ctx.user),
		zap.String("method", ctx.method),
		zap.String("uri", ctx.uri),
		zap.Int("status", http.StatusUnauthorized))
	return false
}

func (da *DigestAuth) calculateExpectedResponse(ctx *authContext, cred credential) string {
	// Support RFC 7616 algorithms
	algorithm := da.getAlgorithmForClient(ctx)
	// RFC 7616 requires supporting both quoted and unquoted realm values
	effectiveRealm := strings.Trim(ctx.realm, `"`)
	
	// Handle username encoding per RFC 7616 section 3.3
	encodedUser := url.PathEscape(ctx.user)
	
	// Calculate hashes with proper encoding
	ha1 := da.digestHash(algorithm, fmt.Sprintf("%s:%s:%s", 
		encodedUser, effectiveRealm, cred.Password))
	ha2 := da.digestHash(algorithm, fmt.Sprintf("%s:%s", 
		ctx.method, url.PathEscape(ctx.uri)))

	if ctx.qop != "" {
		return da.digestHash(algorithm, fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			ha1, ctx.nonce, ctx.nc, ctx.cnonce, ctx.qop, ha2))
	}
	return da.digestHash(algorithm, fmt.Sprintf("%s:%s:%s", ha1, ctx.nonce, ha2))
}

// validateNonce checks if a nonce is valid and not stale
func (da *DigestAuth) validateNonce(nonce string) (bool, *nonceData) {
	da.mutex.Lock()
	defer da.mutex.Unlock()

	// Reject weak nonces
	if len(nonce) < 32 {
		return true, nil
	}

	nonceData, exists := da.nonces[nonce]
	if !exists {
		return true, nil
	}

	now := time.Now().Unix()

	// Check expiration
	if now > nonceData.ExpiresAt {
		delete(da.nonces, nonce)
		return true, nonceData
	}

	// Check if nonce is too old (additional security check)
	if now-nonceData.Timestamp > int64(da.Expires) {
		delete(da.nonces, nonce)
		return true, nonceData
	}

	// Check replay limit
	if nonceData.Uses >= da.Replays {
		delete(da.nonces, nonce)
		return true, nonceData
	}

	// Increment usage count
	nonceData.Uses++
	return false, nonceData
}

// digestHash calculates hash using configured algorithm
func (da *DigestAuth) digestHash(algorithm string, input string) string {
	inputBytes := []byte(input)
	
	switch algorithm {
	case AlgorithmSHA256:
		hash := sha256.Sum256(inputBytes)
		return fmt.Sprintf("%x", hash)
	case AlgorithmSHA512256:
		hash := sha512.Sum512_256(inputBytes)
		return fmt.Sprintf("%x", hash)
	default: // MD5 (RFC 2617)
		hash := md5.Sum(inputBytes)
		return fmt.Sprintf("%x", hash)
	}
}

// getAlgorithmForClient determines the best algorithm based on client capabilities
func (da *DigestAuth) getAlgorithmForClient(ctx *authContext) string {
	// Prefer client-specified algorithm if valid
	if ctx.algorithm != "" {
		switch strings.ToUpper(ctx.algorithm) {
		case AlgorithmSHA256, AlgorithmSHA512256, "MD5":
			return strings.ToUpper(ctx.algorithm)
		}
	}
	
	// Fall back to server configuration
	switch strings.ToUpper(da.Algorithm) {
	case AlgorithmSHA256, AlgorithmSHA512256:
		return da.Algorithm
	default:
		return "MD5" // Final fallback to RFC 2617
	}
}

// isRateLimited checks if a client is rate limited
func (da *DigestAuth) isRateLimited(remoteAddr string) bool {
	da.mutex.RLock()
	defer da.mutex.RUnlock()

	rateData, exists := da.rateLimits[remoteAddr]
	if !exists {
		return false
	}

	now := time.Now().Unix()
	if now-rateData.FirstTry > int64(da.RateLimitWindow) {
		// Reset if window has passed
		delete(da.rateLimits, remoteAddr)
		return false
	}

	return rateData.Attempts >= da.RateLimitBurst
}

// incrementRateLimit increments the rate limit counter for a client
func (da *DigestAuth) incrementRateLimit(remoteAddr string) {
	da.mutex.Lock()
	defer da.mutex.Unlock()

	now := time.Now().Unix()
	rateData, exists := da.rateLimits[remoteAddr]

	if !exists {
		rateData = &rateLimitData{
			Attempts: 1,
			FirstTry: now,
		}
		da.rateLimits[remoteAddr] = rateData
	} else {
		rateData.Attempts++
	}
}

// resetRateLimit resets the rate limit for a client
func (da *DigestAuth) resetRateLimit(remoteAddr string) {
	da.mutex.Lock()
	defer da.mutex.Unlock()
	delete(da.rateLimits, remoteAddr)
}

// cleanupRoutine periodically cleans up expired nonces and rate limits
// The Dude abides: this routine keeps things tidy, man
func (da *DigestAuth) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		da.mutex.Lock()

		now := time.Now().Unix()

		// Clean up expired nonces
		for nonce, nonceData := range da.nonces {
			if now > nonceData.ExpiresAt {
				delete(da.nonces, nonce)
			}
		}

		// Clean up expired rate limits
		for remoteAddr, rateData := range da.rateLimits {
			if now-rateData.FirstTry > int64(da.RateLimitWindow) {
				delete(da.rateLimits, remoteAddr)
			}
		}

		da.mutex.Unlock()
	}
}

// Validate validates the module configuration
func (da *DigestAuth) Validate() error {
	if err := da.validateBasicConfig(); err != nil {
		return err
	}
	da.validateSecuritySettings()
	if err := da.validateUserFile(); err != nil {
		return err
	}
	if err := da.validateAlgorithm(); err != nil {
		return err
	}
	return da.validateInlineUsers()
}

func (da *DigestAuth) validateAlgorithm() error {
	// Empty algorithm is valid (will auto-detect from client)
	if da.Algorithm == "" {
		return nil
	}
	
	validAlgorithms := map[string]bool{
		"MD5":             true,
		AlgorithmSHA256:   true,
		AlgorithmSHA512256: true,
	}
	
	algUpper := strings.ToUpper(da.Algorithm)
	if !validAlgorithms[algUpper] {
		return fmt.Errorf("invalid algorithm: %s. Valid options are MD5, %s, %s", 
			da.Algorithm, AlgorithmSHA256, AlgorithmSHA512256)
	}
	
	// RFC 7616 recommends against using MD5 if stronger algorithms are available
	if algUpper == "MD5" {
		da.logger.Warn("MD5 algorithm is deprecated for security reasons", 
			zap.String("recommendation", "Upgrade to SHA-256 or SHA-512-256"))
	}
	
	return nil
}

func (da *DigestAuth) validateBasicConfig() error {
	switch {
	case da.UserFile == "" && len(da.Users) == 0:
		return fmt.Errorf("either user_file or users must be specified")
	case da.UserFile != "" && len(da.Users) > 0:
		return fmt.Errorf("cannot specify both inline users and user_file")
	}
	return nil
}

func (da *DigestAuth) validateSecuritySettings() {
	da.checkSecurityThreshold("Expires", da.Expires > 3600, 3600, "use 300-600 seconds for better security")
	da.checkSecurityThreshold("RateLimitBurst", da.RateLimitBurst > 100, 100, "use 10-50 for better protection")
	da.checkSecurityThreshold("RateLimitWindow", da.RateLimitWindow < 60, 60, "use 300-600 seconds minimum")
	da.checkSecurityThreshold("Replays", da.Replays > 1000, 1000, "use 100-500 for better security")
}

func (da *DigestAuth) checkSecurityThreshold(name string, condition bool, threshold int, recommendation string) {
	if condition && da.logger != nil {
		da.logger.Warn(fmt.Sprintf("high %s may reduce security", name),
			zap.Int(name, threshold),
			zap.String("recommendation", recommendation))
	}
}

func (da *DigestAuth) validateUserFile() error {
	if da.UserFile == "" {
		return nil
	}
	if _, err := os.Stat(da.UserFile); os.IsNotExist(err) {
		return fmt.Errorf("user file does not exist: %s", da.UserFile)
	}
	return nil
}

func (da *DigestAuth) validateInlineUsers() error {
	for i, user := range da.Users {
		if user.Username == "" {
			return fmt.Errorf("inline user %d: username cannot be empty", i+1)
		}
		if user.Password == "" {
			return fmt.Errorf("inline user %d: password cannot be empty", i+1)
		}
		da.checkPasswordStrength(user)
	}
	return nil
}

func (da *DigestAuth) checkPasswordStrength(user User) {
	if len(user.Password) < 8 && da.logger != nil {
		da.logger.Warn("weak password detected",
			zap.String("username", user.Username),
			zap.String("recommendation", "use passwords with at least 8 characters"))
	}
}

// isPathExcluded checks if the given path should be excluded from authentication
func (da *DigestAuth) isPathExcluded(path string) bool {
	if len(da.ExcludePaths) == 0 {
		return false
	}

	for _, excludePath := range da.ExcludePaths {
		// Handle wildcard patterns
		if strings.HasSuffix(excludePath, "/*") {
			// Remove the wildcard and check prefix
			prefix := strings.TrimSuffix(excludePath, "/*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		} else {
			// Exact match or simple prefix matching
			if strings.HasPrefix(path, excludePath) {
				return true
			}
		}
	}
	return false
}

// parseCaddyfileDigestAuth parses the digest_auth directive in the Caddyfile
func parseCaddyfileDigestAuth(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	da := new(DigestAuth)
	err := da.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return da, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*DigestAuth)(nil)
	_ caddy.Validator             = (*DigestAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*DigestAuth)(nil)
)
