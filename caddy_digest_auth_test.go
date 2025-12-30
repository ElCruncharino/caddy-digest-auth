package caddy_digest_auth

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

const testRealm = "Test Realm"

func TestDigestAuthValidation(t *testing.T) {
	tmpUserFile := "test_users.json"
	os.WriteFile(tmpUserFile, []byte(`[{"username":"admin","password":"password"}]`), 0600)
	defer os.Remove(tmpUserFile)

	tests := []struct {
		name    string
		config  DigestAuth
		wantErr bool
	}{
		{name: "valid inline users SHA-256", config: DigestAuth{Users: []User{{Username: "admin", Password: "password"}}, Algorithm: AlgorithmSHA256}, wantErr: false},
		{name: "valid inline users SHA-512-256", config: DigestAuth{Users: []User{{Username: "admin", Password: "password"}}, Algorithm: AlgorithmSHA512256}, wantErr: false},
		{name: "valid default MD5 algorithm", config: DigestAuth{Users: []User{{Username: "admin", Password: "password"}}}, wantErr: false},
		{name: "valid explicit MD5 algorithm", config: DigestAuth{Users: []User{{Username: "admin", Password: "password"}}, Algorithm: "MD5"}, wantErr: false},
		{name: "invalid algorithm", config: DigestAuth{Users: []User{{Username: "admin", Password: "password"}}, Algorithm: "SHA3-256"}, wantErr: true},
		{name: "valid user file", config: DigestAuth{UserFile: tmpUserFile, Algorithm: "MD5"}, wantErr: false},
		{name: "no users specified", config: DigestAuth{}, wantErr: true},
		{name: "both users and user file specified", config: DigestAuth{Users: []User{{Username: "admin", Password: "password"}}, UserFile: tmpUserFile}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runDigestAuthValidationTest(t, tt.config, tt.wantErr)
		})
	}
}

func runDigestAuthValidationTest(t *testing.T, config DigestAuth, wantErr bool) {
	err := config.Validate()
	if (err != nil) != wantErr {
		t.Errorf("DigestAuth.Validate() error = %v, wantErr %v", err, wantErr)
	}
}

func TestDigestAuthModuleInfo(t *testing.T) {
	da := DigestAuth{}
	info := da.CaddyModule()

	if info.ID != "http.handlers.digest_auth" {
		t.Errorf("Expected module ID 'http.handlers.digest_auth', got '%s'", info.ID)
	}

	if info.New == nil {
		t.Error("Expected New function to be set")
	}
}

func TestGetAlgorithmForClient(t *testing.T) {
	da := DigestAuth{Algorithm: AlgorithmSHA256}

	tests := []struct {
		name        string
		ctx         *authContext
		expectedAlg string
	}{
		{
			name:        "client specifies valid algorithm",
			ctx:         &authContext{algorithm: AlgorithmSHA512256},
			expectedAlg: AlgorithmSHA512256,
		},
		{
			name:        "client specifies invalid algorithm",
			ctx:         &authContext{algorithm: "INVALID"},
			expectedAlg: AlgorithmSHA256, // Should fall back to server's configured algorithm
		},
		{
			name:        "no client algorithm specified",
			ctx:         &authContext{},
			expectedAlg: AlgorithmSHA256,
		},
		{
			name:        "server configured MD5 with client spec",
			ctx:         &authContext{algorithm: AlgorithmSHA256},
			expectedAlg: AlgorithmSHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := da.getAlgorithmForClient(tt.ctx)
			if result != tt.expectedAlg {
				t.Errorf("Expected algorithm %s, got %s", tt.expectedAlg, result)
			}
		})
	}
}

type authFlowTestCase struct {
	name          string
	serverAlg     string
	clientAlg     string
	shouldSucceed bool
	qop           string
}

func setupDigestAuth(t *testing.T, serverAlg string) *DigestAuth {
	da := &DigestAuth{
		Users:     []User{{Username: "testuser", Password: "testpass"}},
		Realm:     testRealm,
		Algorithm: serverAlg,
	}
	if err := da.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	return da
}

func createAuthContext(da *DigestAuth, clientAlg, qop string) (*authContext, error) {
	nonce, nonceData, err := da.generateNonce()
	if err != nil {
		return nil, err
	}
	return &authContext{
		user:      "testuser",
		realm:     testRealm,
		nonce:     nonce,
		uri:       "/protected",
		method:    "GET",
		algorithm: clientAlg,
		qop:       qop,
		nc:        "00000001",
		cnonce:    "abcdef0123456789",
		opaque:    nonceData.Opaque,
	}, nil
}

func runAuthFlowTest(t *testing.T, tc authFlowTestCase) {
	da := setupDigestAuth(t, tc.serverAlg)

	authCtx, err := createAuthContext(da, tc.clientAlg, tc.qop)
	if err != nil {
		t.Fatalf("Failed to create auth context: %v", err)
	}

	testUserHA1 := da.digestHash(da.getAlgorithmForClient(authCtx), fmt.Sprintf("%s:%s:%s", "testuser", testRealm, "testpass"))
	cred := credential{HA1: testUserHA1, Realm: testRealm}
	authCtx.response = da.calculateExpectedResponse(authCtx, cred)

	valid, _ := da.verify(authCtx, "127.0.0.1", zap.NewNop())
	if valid != tc.shouldSucceed {
		t.Errorf("expected %v, got %v", tc.shouldSucceed, valid)
	}
}

func TestAuthenticationFlows(t *testing.T) {
	tests := []authFlowTestCase{
		{name: "MD5 fallback (server default, client no alg)", serverAlg: "", clientAlg: "", shouldSucceed: true, qop: "auth"},
		{name: "SHA-256 forced (server SHA-256, client SHA-256)", serverAlg: AlgorithmSHA256, clientAlg: AlgorithmSHA256, shouldSucceed: true, qop: "auth"},
		{name: "client requests unsupported algorithm (server SHA-256, client SHA3-512)", serverAlg: AlgorithmSHA256, clientAlg: "SHA3-512", shouldSucceed: true, qop: "auth"},
		{name: "MD5 with qop auth", serverAlg: "MD5", clientAlg: "MD5", shouldSucceed: true, qop: "auth"},
		{name: "SHA-256 with qop auth", serverAlg: AlgorithmSHA256, clientAlg: AlgorithmSHA256, shouldSucceed: true, qop: "auth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAuthFlowTest(t, tt)
		})
	}
}

func TestDigestAuthProvision(t *testing.T) {
	da := DigestAuth{
		Users: []User{
			{Username: "admin", Password: "password"},
		},
	}

	// Create a mock context
	ctx := caddy.Context{}

	err := da.Provision(ctx)
	if err != nil {
		t.Errorf("Provision failed: %v", err)
	}

	// Check that defaults were set
	if da.Realm == "" {
		t.Error("Expected realm to be set to default")
	}

	if da.Expires == 0 {
		t.Error("Expected expires to be set to default")
	}

	// Verify algorithm defaulting
	if da.Algorithm != "" {
		t.Errorf("Expected empty algorithm to default to MD5, got '%s'", da.Algorithm)
	}

	// Test MD5 warning
	daMD5 := DigestAuth{
		Users:     []User{{Username: "test", Password: "test"}},
		Algorithm: "MD5",
	}
	err = daMD5.Provision(ctx)
	if err != nil {
		t.Errorf("Provision with MD5 failed: %v", err)
	}
}

type caddyfileTestCase struct {
	name      string
	input     string
	wantErr   bool
	checkFunc func(*DigestAuth) error
}

func checkBasicConfig(da *DigestAuth) error {
	if da.Realm != "Test Realm" {
		return fmt.Errorf("expected realm 'Test Realm', got '%s'", da.Realm)
	}
	if da.Algorithm != "SHA-256" {
		return fmt.Errorf("expected algorithm 'SHA-256', got '%s'", da.Algorithm)
	}
	if len(da.Users) != 2 {
		return fmt.Errorf("expected 2 users, got %d", len(da.Users))
	}
	return nil
}

func checkUserFile(da *DigestAuth) error {
	if da.UserFile != "/etc/caddy/users.htdigest" {
		return fmt.Errorf("expected user_file '/etc/caddy/users.htdigest', got '%s'", da.UserFile)
	}
	return nil
}

func checkExcludePaths(da *DigestAuth) error {
	if len(da.ExcludePaths) != 3 {
		return fmt.Errorf("expected 3 exclude paths, got %d", len(da.ExcludePaths))
	}
	return nil
}

func checkRateLimiting(da *DigestAuth) error {
	if da.RateLimitBurst != 10 {
		return fmt.Errorf("expected rate_limit_burst 10, got %d", da.RateLimitBurst)
	}
	if da.RateLimitWindow != 300 {
		return fmt.Errorf("expected rate_limit_window 300, got %d", da.RateLimitWindow)
	}
	return nil
}

func checkExpiresAndReplays(da *DigestAuth) error {
	if da.Expires != 600 {
		return fmt.Errorf("expected expires 600, got %d", da.Expires)
	}
	if da.Replays != 100 {
		return fmt.Errorf("expected replays 100, got %d", da.Replays)
	}
	if da.Timeout != 900 {
		return fmt.Errorf("expected timeout 900, got %d", da.Timeout)
	}
	return nil
}

func runCaddyfileTest(t *testing.T, tc caddyfileTestCase) {
	d := caddyfile.NewTestDispenser(tc.input)
	da := new(DigestAuth)
	err := da.UnmarshalCaddyfile(d)

	if (err != nil) != tc.wantErr {
		t.Errorf("UnmarshalCaddyfile() error = %v, wantErr %v", err, tc.wantErr)
		return
	}

	if tc.checkFunc != nil && err == nil {
		if err := tc.checkFunc(da); err != nil {
			t.Errorf("checkFunc failed: %v", err)
		}
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []caddyfileTestCase{
		{
			name: "basic config with inline users",
			input: `digest_auth {
				realm "Test Realm"
				algorithm SHA-256
				users admin password123 user1 pass456
			}`,
			checkFunc: checkBasicConfig,
		},
		{
			name: "config with user file",
			input: `digest_auth {
				realm "File Realm"
				user_file /etc/caddy/users.htdigest
			}`,
			checkFunc: checkUserFile,
		},
		{
			name: "config with exclude paths",
			input: `digest_auth {
				realm "Test"
				users admin pass
				exclude_paths /public/* /health /metrics
			}`,
			checkFunc: checkExcludePaths,
		},
		{
			name: "config with rate limiting",
			input: `digest_auth {
				realm "Test"
				users admin pass
				rate_limit_burst 10
				rate_limit_window 300
			}`,
			checkFunc: checkRateLimiting,
		},
		{
			name: "config with expires and replays",
			input: `digest_auth {
				realm "Test"
				users admin pass
				expires 600
				replays 100
				timeout 900
			}`,
			checkFunc: checkExpiresAndReplays,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runCaddyfileTest(t, tt)
		})
	}
}

func TestRateLimiting(t *testing.T) {
	da := DigestAuth{
		RateLimitBurst:  3,
		RateLimitWindow: 60,
	}
	da.initializeMaps()

	remoteAddr := "127.0.0.1" // Test IP, no actual network connections made

	// Should not be rate limited initially
	if da.isRateLimited(remoteAddr) {
		t.Error("Should not be rate limited initially")
	}

	// Increment up to burst limit
	for i := 0; i < 3; i++ {
		da.incrementRateLimit(remoteAddr)
	}

	// Should now be rate limited
	if !da.isRateLimited(remoteAddr) {
		t.Error("Should be rate limited after reaching burst limit")
	}

	// Reset should clear the limit
	da.resetRateLimit(remoteAddr)
	if da.isRateLimited(remoteAddr) {
		t.Error("Should not be rate limited after reset")
	}
}

func TestPathExclusion(t *testing.T) {
	da := DigestAuth{
		ExcludePaths: []string{"/public/*", "/health", "/api/status"},
	}

	tests := []struct {
		path     string
		excluded bool
	}{
		{"/public/image.png", true},
		{"/public/css/style.css", true},
		{"/health", true},
		{"/api/status", true},
		{"/api/users", false},
		{"/admin", false},
		{"/healthcheck", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := da.isPathExcluded(tt.path)
			if result != tt.excluded {
				t.Errorf("isPathExcluded(%s) = %v, want %v", tt.path, result, tt.excluded)
			}
		})
	}
}

func TestHTDigestFileParsing(t *testing.T) {
	// Create a temporary htdigest file
	tmpFile, err := os.CreateTemp("", "test_htdigest_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write test data
	content := `admin:Test Realm:5f4dcc3b5aa765d61d8327deb882cf99
user1:Test Realm:098f6bcd4621d373cade4e832627b4f6
# This is a comment
user2:Wrong Realm:abc123def456
user3:invalid_format_only_two_parts
validuser:Test Realm:7c6a180b36896a0a8c02787eeafb0e4c
`
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	da := DigestAuth{
		UserFile: tmpFile.Name(),
		Realm:    testRealm,
	}
	da.initializeMaps()

	err = da.loadUserFile()
	if err != nil {
		t.Fatalf("loadUserFile failed: %v", err)
	}

	// Should load 2 users (admin and user1 and validuser with correct realm)
	expectedUsers := []string{"admin", "user1", "validuser"}
	for _, username := range expectedUsers {
		if _, exists := da.credentials[username]; !exists {
			t.Errorf("Expected user '%s' to be loaded", username)
		}
	}

	// user2 should not be loaded (wrong realm)
	if _, exists := da.credentials["user2"]; exists {
		t.Error("user2 should not be loaded (wrong realm)")
	}

	// user3 should not be loaded (invalid format)
	if _, exists := da.credentials["user3"]; exists {
		t.Error("user3 should not be loaded (invalid format)")
	}
}

func TestNonceExpiration(t *testing.T) {
	da := DigestAuth{
		Expires: 1, // 1 second expiration
		Replays: 10,
		Timeout: 1,
	}
	da.initializeMaps()

	if err := da.generateSalt(); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	nonce, _, err := da.generateNonce()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// Should be valid immediately
	stale, _ := da.validateNonce(nonce)
	if stale {
		t.Error("Nonce should be valid immediately after generation")
	}

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Should now be stale
	stale, _ = da.validateNonce(nonce)
	if !stale {
		t.Error("Nonce should be stale after expiration")
	}
}

func TestMetricsCollection(t *testing.T) {
	metrics := &Metrics{}

	// Test incrementing various metrics
	metrics.IncrementMetric(&metrics.TotalRequests)
	metrics.IncrementMetric(&metrics.SuccessfulAuths)
	metrics.IncrementMetric(&metrics.FailedAuths)

	result := metrics.GetMetrics()
	if result["total_requests"] != 1 {
		t.Errorf("Expected total_requests 1, got %d", result["total_requests"])
	}
	if result["successful_auths"] != 1 {
		t.Errorf("Expected successful_auths 1, got %d", result["successful_auths"])
	}
	if result["failed_auths"] != 1 {
		t.Errorf("Expected failed_auths 1, got %d", result["failed_auths"])
	}
}
