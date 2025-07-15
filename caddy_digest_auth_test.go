package caddy_digest_auth

import (
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func TestDigestAuthValidation(t *testing.T) {
	tmpUserFile := "test_users.json"
	os.WriteFile(tmpUserFile, []byte(`[{"username":"admin","password":"password"}]`), 0600)
	defer os.Remove(tmpUserFile)

	tests := []struct {
		name    string
		config  DigestAuth
		wantErr bool
	}{
		{
			name: "valid inline users SHA-256",
			config: DigestAuth{
				Users: []User{
					{Username: "admin", Password: "password"},
				},
				Algorithm: AlgorithmSHA256,
			},
			wantErr: false,
		},
		{
			name: "valid inline users SHA-512-256",
			config: DigestAuth{
				Users: []User{
					{Username: "admin", Password: "password"},
				},
				Algorithm: AlgorithmSHA512256,
			},
			wantErr: false,
		},
		{
			name: "valid default MD5 algorithm",
			config: DigestAuth{
				Users: []User{
					{Username: "admin", Password: "password"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid explicit MD5 algorithm",
			config: DigestAuth{
				Users: []User{
					{Username: "admin", Password: "password"},
				},
				Algorithm: "MD5",
			},
			wantErr: false,
		},
		{
			name: "invalid algorithm",
			config: DigestAuth{
				Users: []User{
					{Username: "admin", Password: "password"},
				},
				Algorithm: "SHA3-256",
			},
			wantErr: true,
		},
		{
			name: "valid user file",
			config: DigestAuth{
				UserFile: tmpUserFile,
				Algorithm: "MD5", // Explicitly set for test clarity
			},
			wantErr: false,
		},
		{
			name:    "no users specified",
			config:  DigestAuth{},
			wantErr: true,
		},
		{
			name: "both users and user file specified",
			config: DigestAuth{
				Users: []User{
					{Username: "admin", Password: "password"},
				},
				UserFile: tmpUserFile,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("DigestAuth.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
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
			name: "client specifies valid algorithm",
			ctx:  &authContext{algorithm: AlgorithmSHA512256},
			expectedAlg: AlgorithmSHA512256,
		},
		{
			name: "client specifies invalid algorithm",
			ctx:  &authContext{algorithm: "INVALID"},
			expectedAlg: AlgorithmSHA256, // Should fall back to server's configured algorithm
		},
		{
			name: "no client algorithm specified",
			ctx:  &authContext{},
			expectedAlg: AlgorithmSHA256,
		},
		{
			name: "server configured MD5 with client spec",
			ctx:  &authContext{algorithm: AlgorithmSHA256},
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

func TestAuthenticationFlows(t *testing.T) {
	da := DigestAuth{
		Users: []User{
			{Username: "testuser", Password: "testpass"},
		},
		Realm: "Test Realm",
	}
	
	// Provision with test logger
	ctx := caddy.Context{}
	err := da.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	tests := []struct {
		name          string
		serverAlg     string // Algorithm configured on the server
		clientAlg     string // Algorithm client claims to use
		shouldSucceed bool
		qop           string // Quality of protection
	}{
		{
			name:          "MD5 fallback (server default, client no alg)",
			serverAlg:     "", // Server defaults to MD5
			clientAlg:     "", // Client doesn't specify
			shouldSucceed: true,
			qop:           "auth",
		},
		{
			name:          "SHA-256 forced (server SHA-256, client SHA-256)",
			serverAlg:     AlgorithmSHA256,
			clientAlg:     AlgorithmSHA256,
			shouldSucceed: true,
			qop:           "auth",
		},
		{
			name:          "client requests unsupported algorithm (server SHA-256, client SHA3-512)",
			serverAlg:     AlgorithmSHA256,
			clientAlg:     "SHA3-512", // Client requests unsupported, server falls back to SHA-256
			shouldSucceed: true,       // Should succeed if server falls back and client's response matches server's algorithm
			qop:           "auth",
		},
		{
			name:          "MD5 with qop auth",
			serverAlg:     "MD5",
			clientAlg:     "MD5",
			shouldSucceed: true,
			qop:           "auth",
		},
		{
			name:          "SHA-256 with qop auth",
			serverAlg:     AlgorithmSHA256,
			clientAlg:     AlgorithmSHA256,
			shouldSucceed: true,
			qop:           "auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset algorithm for each test run
			da.Algorithm = tt.serverAlg

			// Generate a fresh nonce for each test case
			nonce, nonceData, err := da.generateNonce()
			if err != nil {
				t.Fatalf("Failed to generate nonce: %v", err)
			}

			// Simulate client context
			ctx := &authContext{
				user:      "testuser",
				realm:     "Test Realm",
				nonce:     nonce,
				uri:       "/protected",
				method:    "GET",
				algorithm: tt.clientAlg,
				qop:       tt.qop,
				nc:        "00000001", // Nonce count, typically starts at 1
				cnonce:    "abcdef0123456789", // Client nonce
				opaque:    nonceData.Opaque,
			}

			// Calculate expected response using the server's logic
			cred := credential{Password: "testpass"}
			expectedResponse := da.calculateExpectedResponse(ctx, cred)

			// Simulate client sending the calculated response
			ctx.response = expectedResponse

			valid, _ := da.verify(ctx, "127.0.0.1", zap.NewNop())
			if valid != tt.shouldSucceed {
				t.Errorf("Test %s failed: expected %v, got %v", tt.name, tt.shouldSucceed, valid)
			}
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
		Users: []User{{Username: "test", Password: "test"}},
		Algorithm: "MD5",
	}
	err = daMD5.Provision(ctx)
	if err != nil {
		t.Errorf("Provision with MD5 failed: %v", err)
	}
}
