# Security Policy

## Supported Versions

We release patches to fix security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to [security@elcruncharino.com](mailto:security@elcruncharino.com).

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the requested information listed below (as much as you can provide) to help us better understand the nature and scope of the possible issue:

- Type of issue (buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the vulnerability
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Preferred Languages

We prefer all communications to be in English.

## Disclosure Policy

When we receive a security bug report, we will assign it to a primary handler. This person will coordinate the fix and release process, involving the following steps:

1. Confirm the problem and determine the affected versions.
2. Audit code to find any similar problems.
3. Prepare fixes for all supported versions. These fixes will be released as fast as possible to the main branch.

## Comments on this Policy

If you have suggestions on how this process could be improved please submit a pull request.

## Security Best Practices

When using this module, please follow these security best practices:

1. **Use HTTPS**: Always use HTTPS in production to protect authentication credentials
2. **Strong Passwords**: Use strong, unique passwords for each user
3. **Regular Updates**: Keep Caddy and this module updated to the latest versions
4. **File Permissions**: Set appropriate file permissions on user files (600 for htdigest, 644 for JSON)
5. **Secure Storage**: Store user files outside of web-accessible directories
6. **Monitor Logs**: Regularly monitor authentication logs for suspicious activity
7. **Rate Limiting**: Configure appropriate rate limiting to prevent brute force attacks
8. **Path Exclusions**: Use `exclude_paths` to avoid authentication on public resources

## Security Considerations

This module implements HTTP Digest Authentication as specified in RFC 2617. While digest authentication is more secure than basic authentication, it has some limitations:

- **Replay Attacks**: The module includes nonce validation and replay protection
- **Man-in-the-Middle**: Digest authentication is vulnerable to MITM attacks without HTTPS
- **Password Storage**: Passwords are stored as MD5 hashes (username:realm:password)
- **Brute Force**: The module includes rate limiting to prevent brute force attacks

For maximum security, always use HTTPS and consider implementing additional security measures appropriate for your use case. 