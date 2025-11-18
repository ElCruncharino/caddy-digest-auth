# Security Policy

## Reporting Vulnerabilities

**Do not report security issues through public GitHub issues.**

Email security reports to [security@elcruncharino.com](mailto:security@elcruncharino.com). Include:
- Issue description and type
- Source file paths
- Reproduction steps
- Proof of concept (if available)
- Potential impact

You should receive a response within 48 hours.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Security Considerations

Digest authentication (RFC 2617/7616) is more secure than basic auth but has limitations:
- Vulnerable to MITM attacks without HTTPS
- Passwords stored as hashes (HA1 = hash(username:realm:password))
- Requires nonce validation and replay protection (included)
- Rate limiting recommended to prevent brute force attacks (included)

Use HTTPS in production. Set htdigest file permissions to 600. Store user files outside web-accessible directories. 