package caddy_digest_auth

import (
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile implements caddyfile.Unmarshaler interface
func (da *DigestAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			if err := da.parseCaddyfileBlock(d); err != nil {
				return err
			}
		}
	}
	return nil
}

func (da *DigestAuth) parseCaddyfileBlock(d *caddyfile.Dispenser) error {
	handlers := map[string]func(*caddyfile.Dispenser) error{
		"realm":             da.handleRealmDirective,
		"user_file":         da.handleUserFileDirective,
		"users":             da.handleUsersDirective,
		"exclude_paths":     da.handleExcludePathsDirective,
		"expires":           da.handleExpiresDirective,
		"replays":           da.handleReplaysDirective,
		"timeout":           da.handleTimeoutDirective,
		"rate_limit_burst":  da.handleRateLimitBurstDirective,
		"rate_limit_window": da.handleRateLimitWindowDirective,
		"algorithm":         da.handleAlgorithmDirective,
	}

	handler, exists := handlers[d.Val()]
	if !exists {
		return d.Errf("unknown subdirective: %s", d.Val())
	}
	return handler(d)
}

func (da *DigestAuth) handleExpiresDirective(d *caddyfile.Dispenser) error {
	return da.handleIntDirective(d, &da.Expires)
}

func (da *DigestAuth) handleReplaysDirective(d *caddyfile.Dispenser) error {
	return da.handleIntDirective(d, &da.Replays)
}

func (da *DigestAuth) handleTimeoutDirective(d *caddyfile.Dispenser) error {
	return da.handleIntDirective(d, &da.Timeout)
}

func (da *DigestAuth) handleRateLimitBurstDirective(d *caddyfile.Dispenser) error {
	return da.handleIntDirective(d, &da.RateLimitBurst)
}

func (da *DigestAuth) handleRateLimitWindowDirective(d *caddyfile.Dispenser) error {
	return da.handleIntDirective(d, &da.RateLimitWindow)
}

func (da *DigestAuth) handleRealmDirective(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	da.Realm = d.Val()
	return nil
}

func (da *DigestAuth) handleUserFileDirective(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	da.UserFile = d.Val()
	return nil
}

func (da *DigestAuth) handleUsersDirective(d *caddyfile.Dispenser) error {
	args := d.RemainingArgs()
	if len(args) == 0 {
		return d.ArgErr()
	}
	if len(args)%2 != 0 {
		return d.Errf("users must have even number of arguments (username password pairs)")
	}

	for i := 0; i < len(args); i += 2 {
		da.Users = append(da.Users, User{
			Username: args[i],
			Password: args[i+1],
		})
	}
	return nil
}

func (da *DigestAuth) handleExcludePathsDirective(d *caddyfile.Dispenser) error {
	da.ExcludePaths = d.RemainingArgs()
	if len(da.ExcludePaths) == 0 {
		return d.ArgErr()
	}
	return nil
}

func (da *DigestAuth) handleAlgorithmDirective(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	da.Algorithm = strings.ToUpper(d.Val())
	return nil
}

func (da *DigestAuth) handleIntDirective(d *caddyfile.Dispenser, field *int) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	val, err := strconv.Atoi(d.Val())
	if err != nil {
		return d.Errf("invalid %s value: %v", d.Val(), err)
	}
	*field = val
	return nil
}
