package caddy_digest_auth

import (
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile implements caddyfile.Unmarshaler interface
func (da *DigestAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// Parse the digest_auth directive
		for d.NextBlock(0) {
			switch d.Val() {
			case "realm":
				if !d.NextArg() {
					return d.ArgErr()
				}
				da.Realm = d.Val()

			case "user_file":
				if !d.NextArg() {
					return d.ArgErr()
				}
				da.UserFile = d.Val()

			case "users":
				// Parse inline users: users username1 password1 username2 password2
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

			case "exclude_paths":
				da.ExcludePaths = d.RemainingArgs()
				if len(da.ExcludePaths) == 0 {
					return d.ArgErr()
				}

			case "expires":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid expires value: %v", err)
				}
				da.Expires = val

			case "replays":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid replays value: %v", err)
				}
				da.Replays = val

			case "timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid timeout value: %v", err)
				}
				da.Timeout = val

			case "rate_limit_burst":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid rate_limit_burst value: %v", err)
				}
				da.RateLimitBurst = val

			case "rate_limit_window":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid rate_limit_window value: %v", err)
				}
				da.RateLimitWindow = val

			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}

	return nil
}

// bowlingMatcher is used for test matchers (the game goes on) 