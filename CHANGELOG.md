# Changelog

## [1.1.0] - 2025-06-29

- Security validation with config warnings
- Nonce validation (min 32 chars, timestamp checks)
- Optional metrics collection
- Password strength warnings
- File existence validation
- Structured logging with HTTP status codes

## [1.0.1] - 2025-06-29

- Improved logging following Caddy conventions
- HTTP status codes in all auth responses
- Structured log fields

## [1.0.0] - 2024-01-XX

Initial release:
- RFC 2617/7616 Digest Authentication
- Inline users and htdigest file support
- Path exclusion, rate limiting, replay protection
- Caddy v2 integration 