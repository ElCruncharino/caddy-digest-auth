# Caddy Digest Authentication Module

[![Go Report Card](https://goreportcard.com/badge/github.com/ElCruncharino/caddy-digest-auth)](https://goreportcard.com/report/github.com/ElCruncharino/caddy-digest-auth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ElCruncharino/caddy-digest-auth)](https://go.dev/)
[![License](https://img.shields.io/github/license/ElCruncharino/caddy-digest-auth)](https://github.com/ElCruncharino/caddy-digest-auth/blob/main/LICENSE)
[![CI](https://github.com/ElCruncharino/caddy-digest-auth/workflows/CI/badge.svg)](https://github.com/ElCruncharino/caddy-digest-auth/actions)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/25249835d31149a8b0ddf72448b52147)](https://app.codacy.com/gh/ElCruncharino/caddy-digest-auth/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

A custom Caddy v2 module that provides HTTP Digest Authentication support for Caddy servers.

## Features

- **HTTP Digest Authentication** - RFC 2617 and RFC 7616 compliant
- **Multiple Algorithms** - Support for MD5, SHA-256, and SHA-512-256
- **Flexible Configuration** - Support for multiple users and realms
- **Path Exclusion** - Exclude specific paths from authentication
- **Caddy v2 Integration** - Native Caddy module with Caddyfile support
- **Performance Optimized** - Efficient authentication handling
- **Standalone Module** - No external dependencies required
- **Multiple User Management** - Support for inline, JSON, and htdigest user files

## Installation

### Building Caddy with this module

```bash
# Build Caddy with the digest authentication module
xcaddy build --with github.com/ElCruncharino/caddy-digest-auth
```

### Using with xcaddy

```bash
# Install xcaddy if you haven't already
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build Caddy with this custom module
xcaddy build --with github.com/ElCruncharino/caddy-digest-auth
```

## Configuration

The module supports three approaches for user management, allowing you to choose the best option for your use case:

### 1. Inline Users (Recommended for small numbers)

Perfect for sites with a few users (1-10):

```caddy
example.com {
    digest_auth {
        realm "Protected Area"
        users {
            admin "your_secure_password"
            user "user123"
        }
    }
    
    reverse_proxy localhost:8080
}
```

### 2. htdigest File (Traditional approach)

Compatible with Apache/nginx htdigest files:

```caddy
traditional.example.com {
    digest_auth {
        realm "Protected Area"
        user_file /etc/caddy/users.htdigest
        exclude_paths /public/*
    }
    
    reverse_proxy localhost:8080
}
```

**htdigest File Format** (`/etc/caddy/users.htdigest`):
```
admin:Protected Area:90af330081168b53fd7ed626e92faa70
user1:Protected Area:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
user2:Protected Area:b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7
```

Create htdigest files using:
```bash
# Create new file
htdigest -c users.htdigest "Protected Area" admin

# Add more users
htdigest users.htdigest "Protected Area" user1
```

## Configuration Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `realm` | string | Authentication realm | "Protected Area" |
| `algorithm` | string | Hash algorithm (MD5, SHA-256, SHA-512-256) | "MD5" |
| `users` | block | Inline user configuration | - |
| `user_file` | string | Path to htdigest user file | - |
| `exclude_paths` | array | Paths to exclude from auth | [] |
| `expires` | int | Nonce expiration in seconds | 600 |
| `replays` | int | Max nonce reuses | 500 |
| `timeout` | int | Nonce timeout in seconds | 600 |
| `rate_limit_burst` | int | Rate limiting burst | 50 |
| `rate_limit_window` | int | Rate limiting window in seconds | 600 |
| `enable_metrics` | bool | Enable metrics collection | false |

## Security Features

### Enhanced Security Validation
The module includes comprehensive security validation and warnings:

- **Nonce Security**: Rejects weak nonces (< 32 characters) and validates timestamps
- **Configuration Warnings**: Warns about potentially insecure settings
- **Password Strength**: Warns about weak passwords (< 8 characters)
- **File Validation**: Validates user file existence before startup

### Security Best Practices
```caddy
digest_auth {
    realm "Secure Area"
    user_file /etc/caddy/users.htdigest
    expires 300        # 5 minutes (shorter = more secure)
    replays 100        # Lower for high-security
    rate_limit_burst 10
    rate_limit_window 300
    exclude_paths /health /metrics /public/*
    enable_metrics true
}
```

### Configuration Warnings
The module will warn about:
- Long nonce expiration (> 3600 seconds)
- High rate limit burst (> 100)
- Very short rate limit window (< 60 seconds)
- High replay limit (> 1000)
- Weak passwords (< 8 characters)

## Metrics and Monitoring

### Optional Metrics Collection
Enable metrics to track authentication statistics:

```caddy
digest_auth {
    # ... other config
    enable_metrics true
}
```

### Available Metrics
When enabled, the module tracks:
- `total_requests`: Total authentication requests
- `successful_auths`: Successful authentications
- `failed_auths`: Failed authentication attempts
- `rate_limited`: Requests blocked by rate limiting
- `challenges_sent`: Authentication challenges sent
- `user_not_found`: User not found errors
- `invalid_response`: Invalid response hash errors
- `stale_nonce`: Stale/invalid nonce errors
- `realm_mismatch`: Realm mismatch errors
- `opaque_mismatch`: Opaque mismatch errors

### Accessing Metrics
Metrics are available through the module's internal state and can be exposed via:
- Custom endpoints (if implemented)
- Log analysis
- Integration with monitoring systems

## User Management Approaches

### When to Use Each Approach

| Approach | Best For | Pros | Cons |
|----------|----------|------|------|
| **Inline Users** | 1-10 users | Simple, no external files | Hard to manage many users |
| **htdigest File** | Legacy compatibility | Apache/nginx compatible | Less readable format |

### Managing Large User Lists

For sites with hundreds or thousands of users:

1. **Automate htdigest user creation** with scripts
2. **Use version control** for user files
3. **Implement proper file permissions** (600 for user files)

## Examples

### Basic Protection
```caddy
example.com {
    digest_auth {
        realm "My Site"
        algorithm SHA-256
        users {
            admin "secure_password"
        }
    }
    reverse_proxy localhost:8080
}
```

### Multiple Users with Exclusions
```caddy
example.com {
    digest_auth {
        realm "Protected Area"
        algorithm SHA-512-256
        users {
            admin "admin123"
            user "user123"
            guest "guest123"
        }
        exclude_paths /public/* /health /metrics /api/status
    }
    reverse_proxy localhost:8080
}
```

### Large-Scale Deployment
```caddy
enterprise.example.com {
    digest_auth {
        realm "Enterprise Portal"
        algorithm SHA-512-256
        user_file /etc/caddy/enterprise_users.htdigest
        exclude_paths /public/* /health /metrics /api/status /docs/*
        expires 1800
        replays 1000
        timeout 1800
        rate_limit_burst 100
        rate_limit_window 900
    }
    reverse_proxy localhost:8080
}
```

### Path-Specific Authentication
```caddy
example.com {
    # Public paths
    handle /public/* {
        reverse_proxy localhost:8080
    }
    
    # Protected paths
    handle /admin/* {
        digest_auth {
            realm "Admin Area"
            algorithm SHA-256
            users {
                admin "admin123"
            }
        }
        reverse_proxy localhost:8080
    }
    
    # Default handler
    handle {
        reverse_proxy localhost:8080
    }
}
```

## Troubleshooting

### Common Issues

#### "User not found" vs "Invalid credentials"
- **User not found**: The username doesn't exist in your user file/database
- **Invalid credentials**: The username exists but the password/realm is incorrect
- **Realm mismatch**: The user exists but in a different realm

#### Rate Limiting Issues
- **Too many 429 responses**: Increase `rate_limit_burst` or `rate_limit_window`
- **Legitimate users blocked**: Check if users are sharing IP addresses (NAT)

#### Nonce Expiration Issues
- **Frequent "stale nonce" errors**: Increase `expires` value
- **Security concerns**: Balance between security (shorter expiry) and usability

#### Performance Issues
- **High memory usage**: Monitor nonce cleanup frequency
- **Slow authentication**: Use JSON user files for large user bases
- **File parsing errors**: Check user file format and permissions

### Debug Logging
Enable debug logging to troubleshoot authentication issues:

```caddy
log {
    level DEBUG
    output stdout
}
```

### Security Recommendations
1. **Use strong passwords** (8+ characters)
2. **Keep nonce expiration short** (300-600 seconds)
3. **Monitor rate limiting** for abuse detection
4. **Regular user file audits** for unused accounts
5. **Use HTTPS** to protect authentication credentials

## Security Considerations

- Use strong, unique passwords for each user
- Consider using HTTPS to protect authentication credentials
- Regularly rotate passwords
- Monitor authentication logs for suspicious activity
- Use `exclude_paths` to avoid authentication on public resources
- For large deployments, consider using external user files for better security management
- Implement proper file permissions on user files:
  - 600 for htdigest files
- Store user files outside of web-accessible directories

## Algorithm Compatibility

The `HA1` hash (MD5(username:realm:password) or SHA-256(username:realm:password), etc.) is a crucial component in Digest Authentication. This module handles `HA1` differently based on how user credentials are provided:

- **Inline Users (`users` array in Caddyfile):**
  When you define users directly in your Caddyfile with plaintext passwords, the module calculates the `HA1` hash on the fly using the `algorithm` specified in your `digest_auth` block (e.g., `SHA-256`, `SHA-512-256`, or `MD5` by default). This means you can use stronger algorithms with inline users.

- **htdigest File (`user_file` option):**
  The `htdigest` file format inherently stores `HA1` hashes as MD5. Therefore, if you use a `user_file` to load credentials, the module will always treat the `HA1` values from that file as MD5 hashes, regardless of the `algorithm` setting in your Caddyfile. **It is crucial to only use MD5 when loading credentials from an `htdigest` file; using other algorithms will result in authentication failures.** If your `htdigest` file contains hashes generated with a different algorithm, authentication will fail.

## Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/ElCruncharino/caddy-digest-auth.git
cd caddy-digest-auth

# Build Caddy with this module
xcaddy build --with ./
```

### Testing

```bash
# Run tests
go test ./...

# Run with race detection
go test -race ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/ElCruncharino/caddy-digest-auth/issues) page
2. Create a new issue with detailed information about your problem
3. Include your Caddy version, configuration, and any error messages

## Changelog

### v1.0.0
- Initial release
- HTTP Digest Authentication support
- Path exclusion functionality
- Caddy v2 integration
- Inline user configuration support
- External user file support (JSON and htdigest) 
