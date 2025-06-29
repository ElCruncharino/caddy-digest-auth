package caddy_digest_auth

import (
	"bufio"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

// The rug ties the room together (for context cleanup)
var rugCleanup sync.Once
// stranger: sometimes there's a logger, well, he's the logger for his time and place (unused)

func init() {
	caddy.RegisterModule(DigestAuth{})
	httpcaddyfile.RegisterHandlerDirective("digest_auth", parseCaddyfileDigestAuth)
}

// DigestAuth implements HTTP Digest Authentication for Caddy
type DigestAuth struct {
	// Configuration fields
	Realm           string   `json:"realm,omitempty"`
	UserFile        string   `json:"user_file,omitempty"`
	Users           []User   `json:"users,omitempty"`           // Inline user credentials
	ExcludePaths    []string `json:"exclude_paths,omitempty"`    // Paths that don't require authentication
	Expires         int      `json:"expires,omitempty"`         // Nonce expiration in seconds
	Replays         int      `json:"replays,omitempty"`         // Max nonce reuses
	Timeout         int      `json:"timeout,omitempty"`         // Nonce timeout in seconds
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
	Realm  string `json:"realm"`
	Cipher string `json:"cipher"` // MD5(username:realm:password)
}

// nonceData stores nonce metadata for validation and replay protection
type nonceData struct {
	Timestamp   int64  `json:"timestamp"`
	Counter     int64  `json:"counter"`
	NonceSalt   string `json:"nonce_salt"`
	Opaque      string `json:"opaque"`
	Uses        int    `json:"uses"`
	ExpiresAt   int64  `json:"expires_at"`
}

// rateLimitData tracks failed authentication attempts
type rateLimitData struct {
	Attempts   int   `json:"attempts"`
	FirstTry   int64 `json:"first_try"`
	BlockedAt  int64 `json:"blocked_at"`
}

// Metrics tracks authentication statistics (optional)
type Metrics struct {
	TotalRequests     int64
	SuccessfulAuths   int64
	FailedAuths       int64
	RateLimited       int64
	ChallengesSent    int64
	UserNotFound      int64
	InvalidResponse   int64
	StaleNonce        int64
	RealmMismatch     int64
	OpaqueMismatch    int64
	mutex             sync.RWMutex
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
		"total_requests":      m.TotalRequests,
		"successful_auths":    m.SuccessfulAuths,
		"failed_auths":        m.FailedAuths,
		"rate_limited":        m.RateLimited,
		"challenges_sent":     m.ChallengesSent,
		"user_not_found":      m.UserNotFound,
		"invalid_response":    m.InvalidResponse,
		"stale_nonce":         m.StaleNonce,
		"realm_mismatch":      m.RealmMismatch,
		"opaque_mismatch":     m.OpaqueMismatch,
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
	
	// Set defaults
	if da.Realm == "" {
		da.Realm = "Restricted Area"
	}
	if da.Expires == 0 {
		da.Expires = 600 // 10 minutes
	}
	if da.Replays == 0 {
		da.Replays = 500
	}
	if da.Timeout == 0 {
		da.Timeout = 600 // 10 minutes
	}
	if da.RateLimitBurst == 0 {
		da.RateLimitBurst = 50
	}
	if da.RateLimitWindow == 0 {
		da.RateLimitWindow = 600 // 10 minutes
	}

	// Initialize maps
	da.credentials = make(map[string]credential)
	da.nonces = make(map[string]*nonceData)
	da.rateLimits = make(map[string]*rateLimitData)

	// Generate global salt
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return fmt.Errorf("failed to generate salt: %v", err)
	}
	da.salt = base64.StdEncoding.EncodeToString(saltBytes)

	// Load user credentials
	if err := da.loadCredentials(); err != nil {
		return fmt.Errorf("failed to load credentials: %v", err)
	}

	// Start cleanup goroutine
	go da.cleanupRoutine()

	// Initialize metrics if enabled
	if da.EnableMetrics {
		da.metrics = &Metrics{}
		da.logger.Info("metrics collection enabled")
	}

	da.logger.Info("digest auth module provisioned",
		zap.String("realm", da.Realm),
		zap.Int("expires", da.Expires),
		zap.Int("replays", da.Replays),
		zap.Int("rate_limit_burst", da.RateLimitBurst),
		zap.Int("rate_limit_window", da.RateLimitWindow),
		zap.Int("exclude_paths", len(da.ExcludePaths)),
		zap.Bool("metrics_enabled", da.EnableMetrics))

	return nil
}

// ServeHTTP handles the HTTP request
func (da *DigestAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Get request-scoped logger
	logger := da.logger.With(
		zap.String("method", r.Method),
		zap.String("uri", r.URL.Path),
		zap.String("remote_addr", r.RemoteAddr),
	)

	// Track total requests
	da.metrics.IncrementMetric(&da.metrics.TotalRequests)

	// Check if path should be excluded from authentication
	if da.isPathExcluded(r.URL.Path) {
		logger.Debug("path excluded from authentication")
		return next.ServeHTTP(w, r)
	}

	// Check rate limiting
	if da.isRateLimited(r.RemoteAddr) {
		da.metrics.IncrementMetric(&da.metrics.RateLimited)
		logger.Warn("client blocked by rate limiting",
			zap.Int("status", http.StatusTooManyRequests))
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return nil
	}

	// Check for Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		da.metrics.IncrementMetric(&da.metrics.ChallengesSent)
		logger.Debug("no authorization header, issuing challenge",
			zap.Int("status", http.StatusUnauthorized))
		return da.sendChallenge(w, false, logger)
	}

	// Parse and validate the authorization header
	ctx, err := da.parseAuthHeader(authHeader, r.Method)
	if err != nil {
		da.metrics.IncrementMetric(&da.metrics.FailedAuths)
		logger.Warn("malformed authorization header",
			zap.Error(err),
			zap.Int("status", http.StatusBadRequest))
		da.incrementRateLimit(r.RemoteAddr)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return nil
	}

	// Verify the authentication
	pass, stale := da.verify(ctx, r.RemoteAddr, logger)
	if !pass {
		da.metrics.IncrementMetric(&da.metrics.FailedAuths)
		da.incrementRateLimit(r.RemoteAddr)
		return da.sendChallenge(w, stale, logger)
	}

	// Authentication successful, reset rate limit
	da.resetRateLimit(r.RemoteAddr)
	da.metrics.IncrementMetric(&da.metrics.SuccessfulAuths)
	
	logger.Info("authentication successful",
		zap.String("username", ctx.user),
		zap.Int("status", http.StatusOK))

	// Continue to next handler
	return next.ServeHTTP(w, r)
}

// loadCredentials loads user credentials from the specified file or inline users
func (da *DigestAuth) loadCredentials() error {
	da.mutex.Lock()
	defer da.mutex.Unlock()

	// Load from inline users if provided
	if len(da.Users) > 0 {
		for _, user := range da.Users {
			if user.Username == "" || user.Password == "" {
				return fmt.Errorf("username and password are required for inline users")
			}
			
			// Calculate MD5 hash: username:realm:password
			ha1 := da.md5Hash(fmt.Sprintf("%s:%s:%s", user.Username, da.Realm, user.Password))
			
			da.credentials[user.Username] = credential{
				Realm:  da.Realm,
				Cipher: ha1,
			}
		}
		da.logger.Info("loaded inline credentials", 
			zap.Int("count", len(da.Users)),
			zap.String("realm", da.Realm))
		return nil
	}

	// Load from htdigest file if provided
	if da.UserFile != "" {
		// Read the htdigest file
		file, err := os.Open(da.UserFile)
		if err != nil {
			return fmt.Errorf("failed to open user file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		loadedCount := 0
		skippedCount := 0
		
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			
			// Skip empty lines and comments
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			
			// Parse htdigest format: username:realm:md5hash
			parts := strings.Split(line, ":")
			if len(parts) != 3 {
				da.logger.Warn("invalid htdigest format", 
					zap.Int("line", lineNum), 
					zap.String("line", line),
					zap.String("file", da.UserFile))
				skippedCount++
				continue
			}
			
			username := parts[0]
			realm := parts[1]
			md5hash := parts[2]
			
			// Validate realm matches
			if realm != da.Realm {
				da.logger.Warn("realm mismatch", 
					zap.String("username", username),
					zap.String("expected_realm", da.Realm),
					zap.String("file_realm", realm),
					zap.String("file", da.UserFile))
				skippedCount++
				continue
			}
			
			da.credentials[username] = credential{
				Realm:  realm,
				Cipher: md5hash,
			}
			loadedCount++
		}
		
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading user file: %v", err)
		}
		
		da.logger.Info("loaded credentials from file",
			zap.String("file", da.UserFile),
			zap.Int("loaded", loadedCount),
			zap.Int("skipped", skippedCount),
			zap.String("realm", da.Realm))
		
		return nil
	}

	return fmt.Errorf("no credentials configured")
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

	challenge := fmt.Sprintf(`Digest realm="%s", qop="auth", algorithm=MD5, nonce="%s", opaque="%s"`,
		da.Realm, nonce, nonceData.Opaque)
	
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

	header = strings.TrimPrefix(header, "Digest ")
	
	ctx := &authContext{
		method: method,
	}
	
	// Parse key-value pairs
	pairs := strings.Split(header, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if strings.Contains(pair, "=") {
			parts := strings.SplitN(pair, "=", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			
			// Remove quotes if present
			if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
				value = value[1 : len(value)-1]
			}

			switch key {
			case "username":
				ctx.user = value
			case "realm":
				ctx.realm = value
			case "nonce":
				ctx.nonce = value
			case "uri":
				ctx.uri = value
			case "response":
				ctx.response = value
			case "qop":
				ctx.qop = value
			case "nc":
				ctx.nc = value
			case "cnonce":
				ctx.cnonce = value
			case "opaque":
				ctx.opaque = value
			case "method":
				ctx.method = value
			}
		}
	}

	// Validate required fields
	if ctx.user == "" || ctx.response == "" || ctx.uri == "" || ctx.nonce == "" || ctx.realm == "" {
		return nil, fmt.Errorf("missing required fields")
	}

	// Validate qop if present
	if ctx.qop != "" && (ctx.qop != "auth" || ctx.cnonce == "" || ctx.nc == "") {
		return nil, fmt.Errorf("invalid qop value or missing cnonce/nc")
	}

	return ctx, nil
}

// authContext holds parsed authentication data
type authContext struct {
	user     string
	realm    string
	nonce    string
	uri      string
	response string
	qop      string
	nc       string
	cnonce   string
	opaque   string
	method   string
}

// verify validates the authentication response
func (da *DigestAuth) verify(ctx *authContext, remoteAddr string, logger *zap.Logger) (bool, bool) {
	da.mutex.RLock()
	cred, exists := da.credentials[ctx.user]
	da.mutex.RUnlock()

	if !exists {
		da.metrics.IncrementMetric(&da.metrics.UserNotFound)
		logger.Warn("authentication failed: user not found",
			zap.String("remote_addr", remoteAddr),
			zap.String("username", ctx.user),
			zap.String("realm", ctx.realm),
			zap.Bool("user_exists", exists),
			zap.Int("status", http.StatusUnauthorized))
		return false, false
	}
	
	if cred.Realm != ctx.realm {
		da.metrics.IncrementMetric(&da.metrics.RealmMismatch)
		logger.Warn("authentication failed: realm mismatch",
			zap.String("remote_addr", remoteAddr),
			zap.String("username", ctx.user),
			zap.String("expected_realm", cred.Realm),
			zap.String("provided_realm", ctx.realm),
			zap.Int("status", http.StatusUnauthorized))
		return false, false
	}

	// Validate nonce
	stale, nonceData := da.validateNonce(ctx.nonce)
	if stale {
		da.metrics.IncrementMetric(&da.metrics.StaleNonce)
		logger.Warn("authentication failed: nonce is stale or invalid",
			zap.String("remote_addr", remoteAddr),
			zap.String("username", ctx.user),
			zap.String("nonce", ctx.nonce),
			zap.Int("status", http.StatusUnauthorized))
		return false, true
	}

	// Validate opaque if present
	if ctx.opaque != "" && nonceData != nil && ctx.opaque != nonceData.Opaque {
		da.metrics.IncrementMetric(&da.metrics.OpaqueMismatch)
		logger.Warn("authentication failed: opaque mismatch",
			zap.String("remote_addr", remoteAddr),
			zap.String("username", ctx.user),
			zap.String("provided_opaque", ctx.opaque),
			zap.String("expected_opaque", nonceData.Opaque),
			zap.Int("status", http.StatusUnauthorized))
		return false, false
	}

	// Calculate expected response
	ha1 := cred.Cipher
	ha2 := da.md5Hash(fmt.Sprintf("%s:%s", ctx.method, ctx.uri))

	var expectedResponse string
	if ctx.qop != "" {
		expectedResponse = da.md5Hash(fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			ha1, ctx.nonce, ctx.nc, ctx.cnonce, ctx.qop, ha2))
	} else {
		expectedResponse = da.md5Hash(fmt.Sprintf("%s:%s:%s", ha1, ctx.nonce, ha2))
	}

	if expectedResponse != ctx.response {
		da.metrics.IncrementMetric(&da.metrics.InvalidResponse)
		logger.Warn("authentication failed: invalid response hash",
			zap.String("remote_addr", remoteAddr),
			zap.String("username", ctx.user),
			zap.String("method", ctx.method),
			zap.String("uri", ctx.uri),
			zap.Int("status", http.StatusUnauthorized))
		return false, false
	}

	return true, false
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

// md5Hash calculates MD5 hash of a string
func (da *DigestAuth) md5Hash(input string) string {
	hash := md5.Sum([]byte(input))
	return fmt.Sprintf("%x", hash)
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
	if da.UserFile == "" && len(da.Users) == 0 {
		return fmt.Errorf("either user_file or users must be specified")
	}
	if da.UserFile != "" && len(da.Users) > 0 {
		return fmt.Errorf("cannot specify both inline users and user_file")
	}
	
	// Security warnings
	if da.Expires > 3600 {
		da.logger.Warn("long nonce expiration may reduce security",
			zap.Int("expires", da.Expires),
			zap.String("recommendation", "use 300-600 seconds for better security"))
	}
	
	if da.RateLimitBurst > 100 {
		da.logger.Warn("high rate limit burst may allow abuse",
			zap.Int("rate_limit_burst", da.RateLimitBurst),
			zap.String("recommendation", "use 10-50 for better protection"))
	}
	
	if da.RateLimitWindow < 60 {
		da.logger.Warn("very short rate limit window may block legitimate users",
			zap.Int("rate_limit_window", da.RateLimitWindow),
			zap.String("recommendation", "use 300-600 seconds minimum"))
	}
	
	if da.Replays > 1000 {
		da.logger.Warn("high replay limit may reduce security",
			zap.Int("replays", da.Replays),
			zap.String("recommendation", "use 100-500 for better security"))
	}
	
	// Validate user file exists if specified
	if da.UserFile != "" {
		if _, err := os.Stat(da.UserFile); os.IsNotExist(err) {
			return fmt.Errorf("user file does not exist: %s", da.UserFile)
		}
	}
	
	// Validate inline users
	for i, user := range da.Users {
		if user.Username == "" {
			return fmt.Errorf("inline user %d: username cannot be empty", i+1)
		}
		if user.Password == "" {
			return fmt.Errorf("inline user %d: password cannot be empty", i+1)
		}
		if len(user.Password) < 8 {
			da.logger.Warn("weak password detected",
				zap.String("username", user.Username),
				zap.String("recommendation", "use passwords with at least 8 characters"))
		}
	}
	
	return nil
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