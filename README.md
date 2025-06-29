# Caddy Digest Authentication Module

[![Go Report Card](https://goreportcard.com/badge/github.com/ElCruncharino/caddy-digest-auth)](https://goreportcard.com/report/github.com/ElCruncharino/caddy-digest-auth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ElCruncharino/caddy-digest-auth)](https://go.dev/)
[![License](https://img.shields.io/github/license/ElCruncharino/caddy-digest-auth)](https://github.com/ElCruncharino/caddy-digest-auth/blob/main/LICENSE)
[![CI](https://github.com/ElCruncharino/caddy-digest-auth/workflows/CI/badge.svg)](https://github.com/ElCruncharino/caddy-digest-auth/actions)

A custom Caddy v2 module that provides HTTP Digest Authentication support for Caddy servers.

## Features

- **HTTP Digest Authentication** - RFC 2617 compliant digest authentication
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

### 2. JSON User File (Recommended for large numbers)

Ideal for sites with many users (10-1000+):

```caddy
large-site.example.com {
    digest_auth {
        realm "Protected Area"
        user_file /etc/caddy/users.json
        exclude_paths /public/* /health /metrics
    }
    
    reverse_proxy localhost:8080
}
```

**JSON User File Format** (`/etc/caddy/users.json`):
```json
[
  {
    "username": "admin",
    "password": "admin123"
  },
  {
    "username": "user1",
    "password": "password1"
  },
  {
    "username": "user2",
    "password": "password2"
  }
]
```

### 3. htdigest File (Traditional approach)

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
| `users` | block | Inline user configuration | - |
| `user_file` | string | Path to user file (.json or htdigest) | - |
| `exclude_paths` | array | Paths to exclude from auth | [] |
| `expires` | int | Nonce expiration in seconds | 600 |
| `replays` | int | Max nonce reuses | 500 |
| `timeout` | int | Nonce timeout in seconds | 600 |
| `rate_limit_burst` | int | Rate limiting burst | 50 |
| `rate_limit_window` | int | Rate limiting window in seconds | 600 |

## User Management Approaches

### When to Use Each Approach

| Approach | Best For | Pros | Cons |
|----------|----------|------|------|
| **Inline Users** | 1-10 users | Simple, no external files | Hard to manage many users |
| **JSON File** | 10-1000+ users | Easy to manage, readable | Requires file management |
| **htdigest File** | Legacy compatibility | Apache/nginx compatible | Less readable format |

### Managing Large User Lists

For sites with hundreds or thousands of users:

1. **Use JSON files** for easy management
2. **Automate user creation** with scripts
3. **Use version control** for user files
4. **Implement proper file permissions** (600 for user files)

Example JSON user management script:
```bash
#!/bin/bash
# add_user.sh - Add a new user to JSON file

USERNAME=$1
PASSWORD=$2
USERFILE="/etc/caddy/users.json"

# Add user to JSON file
jq --arg user "$USERNAME" --arg pass "$PASSWORD" \
   '. += [{"username": $user, "password": $pass}]' \
   "$USERFILE" > "$USERFILE.tmp" && mv "$USERFILE.tmp" "$USERFILE"

echo "User $USERNAME added successfully"
```

## Examples

### Basic Protection
```caddy
example.com {
    digest_auth {
        realm "My Site"
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
        user_file /etc/caddy/enterprise_users.json
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

## Security Considerations

- Use strong, unique passwords for each user
- Consider using HTTPS to protect authentication credentials
- Regularly rotate passwords
- Monitor authentication logs for suspicious activity
- Use `exclude_paths` to avoid authentication on public resources
- For large deployments, consider using external user files for better security management
- Implement proper file permissions on user files:
  - 644 for JSON files
  - 600 for htdigest files
- Store user files outside of web-accessible directories

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