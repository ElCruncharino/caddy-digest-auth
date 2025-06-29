# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI/CD workflow
- Comprehensive documentation
- Security policy and contributing guidelines

## [1.1.0] - 2025-06-29

### Added
- **Enhanced Security Validation**: Configuration warnings for potentially insecure settings
- **Nonce Security Hardening**: Rejects weak nonces and validates timestamps
- **Optional Metrics Collection**: Track authentication statistics and failures
- **Better Error Messages**: More descriptive authentication failure messages
- **Password Strength Warnings**: Warns about weak passwords (< 8 characters)
- **File Validation**: Validates user file existence before startup
- **Comprehensive Troubleshooting Guide**: Common issues and solutions

### Changed
- **Improved Logging**: All authentication responses now include HTTP status codes
- **Enhanced Configuration Validation**: More thorough validation with security warnings
- **Better Documentation**: Added security best practices and troubleshooting sections

### Security Improvements
- Nonce entropy validation (minimum 32 characters)
- Stricter timestamp validation for nonces
- Configuration warnings for long expiration times
- Rate limiting parameter validation
- User file existence validation

### New Configuration Options
- `enable_metrics`: Enable optional metrics collection (default: false)

### Metrics Available (when enabled)
- Total requests, successful/failed authentications
- Rate limiting events, challenges sent
- Detailed failure tracking (user not found, invalid response, etc.)

## [1.0.1] - 2025-06-29

### Changed
- Improved logging to follow Caddy module conventions
- All authentication responses now log the HTTP status code (e.g., 401, 429, 400)
- Log fields are now more consistent and structured (method, uri, remote_addr, status, username, etc.)
- Removed startup fmt.Printlns; startup info is now logged via Caddy's logger
- Credential loading logs now include loaded/skipped counts and file info

## [1.0.0] - 2024-01-XX

### Added
- Initial release of Caddy Digest Authentication Module
- HTTP Digest Authentication support (RFC 2617 compliant)
- Multiple user management approaches:
  - Inline user configuration
  - JSON user files
  - htdigest file support
- Path exclusion functionality
- Rate limiting and replay protection
- Nonce validation and expiration
- Comprehensive logging
- Caddy v2 integration
- Caddyfile directive support

### Features
- **Flexible Configuration**: Support for multiple users and realms
- **Path Exclusion**: Exclude specific paths from authentication
- **Performance Optimized**: Efficient authentication handling
- **Standalone Module**: No external dependencies required
- **Security Features**: Rate limiting, nonce validation, replay protection

### Configuration Options
- `realm`: Authentication realm (default: "Protected Area")
- `users`: Inline user configuration block
- `user_file`: Path to external user file (.json or htdigest)
- `exclude_paths`: Array of paths to exclude from authentication
- `expires`: Nonce expiration in seconds (default: 600)
- `replays`: Max nonce reuses (default: 500)
- `timeout`: Nonce timeout in seconds (default: 600)
- `rate_limit_burst`: Rate limiting burst (default: 50)
- `rate_limit_window`: Rate limiting window in seconds (default: 600)

### Examples
- Basic authentication setup
- Multiple users with exclusions
- Large-scale deployment configuration
- Path-specific authentication
- Integration with reverse proxies

### Documentation
- Comprehensive README with examples
- Configuration reference
- Security considerations
- Performance optimization guide
- User management best practices

---

## Version History

### v1.0.0
- Initial release with full HTTP Digest Authentication support
- Complete Caddy v2 integration
- Multiple user management approaches
- Security features and rate limiting
- Comprehensive documentation and examples

---

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 