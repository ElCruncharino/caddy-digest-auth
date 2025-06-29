package caddy_digest_auth

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestDigestAuthValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  DigestAuth
		wantErr bool
	}{
		{
			name: "valid inline users",
			config: DigestAuth{
				Users: []User{
					{Username: "admin", Password: "password"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid user file",
			config: DigestAuth{
				UserFile: "/etc/caddy/users.json",
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
				UserFile: "/etc/caddy/users.json",
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
} 