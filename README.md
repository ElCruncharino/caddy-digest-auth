# Caddy Digest Authentication Module

[![Go Report Card](https://goreportcard.com/badge/github.com/ElCruncharino/caddy-digest-auth)](https://goreportcard.com/report/github.com/ElCruncharino/caddy-digest-auth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ElCruncharino/caddy-digest-auth)](https://go.dev/)
[![License](https://img.shields.io/github/license/ElCruncharino/caddy-digest-auth)](https://github.com/ElCruncharino/caddy-digest-auth/blob/main/LICENSE)
[![CI](https://github.com/ElCruncharino/caddy-digest-auth/workflows/CI/badge.svg)](https://github.com/ElCruncharino/caddy-digest-auth/actions)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/25249835d31149a8b0ddf72448b52147)](https://app.codacy.com/gh/ElCruncharino/caddy-digest-auth/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

HTTP Digest Authentication module for Caddy v2. Implements RFC 2617 and RFC 7616 with support for MD5, SHA-256, and SHA-512-256 algorithms.

## Installation

Build Caddy with this module using xcaddy:

```bash
xcaddy build --with github.com/ElCruncharino/caddy-digest-auth
```

## Configuration

### Inline Users

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

### htdigest File

```caddy
example.com {
    digest_auth {
        realm "Protected Area"
        user_file /etc/caddy/users.htdigest
        exclude_paths /public/*
    }

    reverse_proxy localhost:8080
}
```

Create htdigest files with the `htdigest` command:

```bash
htdigest -c users.htdigest "Protected Area" admin
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

## Security

The module validates nonce security, checks password strength, and warns about potentially insecure configurations. For production use:

```caddy
digest_auth {
    realm "Secure Area"
    algorithm SHA-256
    user_file /etc/caddy/users.htdigest
    expires 300
    replays 100
    rate_limit_burst 10
    rate_limit_window 300
    exclude_paths /health /metrics /public/*
}
```

Always use HTTPS in production. Digest auth is vulnerable to MITM attacks without TLS.

## Metrics

Enable metrics with `enable_metrics true`. Tracks auth successes, failures, rate limiting, and various error conditions. Access metrics through log analysis or custom monitoring integrations.

## Examples

Path-specific authentication:

```caddy
example.com {
    handle /admin/* {
        digest_auth {
            realm "Admin Area"
            algorithm SHA-256
            users {
                admin "secure_password"
            }
        }
        reverse_proxy localhost:8080
    }

    handle {
        reverse_proxy localhost:8080
    }
}
```

## Troubleshooting

Enable debug logging:

```caddy
log {
    level DEBUG
}
```

Common issues:
- Frequent "stale nonce" errors: increase `expires` value
- Rate limiting false positives: adjust `rate_limit_burst` and `rate_limit_window`
- htdigest file errors: verify file format matches `username:realm:hash` and realm matches config

## Algorithm Compatibility

Inline users support MD5, SHA-256, and SHA-512-256 algorithms. htdigest files always use MD5 hashes regardless of the `algorithm` setting.

## Development

Build and test:

```bash
xcaddy build --with ./
go test ./...
go test -race ./...
```

### Pre-commit Hooks

Option 1 - Using [pre-commit](https://pre-commit.com/):
```bash
pip install pre-commit
pre-commit install
```

Option 2 - Manual Git hook:
```bash
cp hooks/pre-commit .git/hooks/pre-commit
```

## License

MIT - see [LICENSE](LICENSE) file. 
