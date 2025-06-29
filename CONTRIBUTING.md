# Contributing to Caddy Digest Authentication Module

Thank you for your interest in contributing to the Caddy Digest Authentication Module! This document provides guidelines and information for contributors.

## Development Setup

### Prerequisites

- Go 1.21 or later
- Git
- xcaddy (for building Caddy with the module)

### Getting Started

1. **Fork the repository**
   ```bash
   git clone https://github.com/ElCruncharino/caddy-digest-auth.git
   cd caddy-digest-auth
   ```

2. **Install xcaddy**
   ```bash
   go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
   ```

3. **Build Caddy with the module**
   ```bash
   xcaddy build --with ./
   ```

4. **Run tests**
   ```bash
   go test ./...
   ```

## Development Guidelines

### Code Style

- Follow Go conventions and the [Effective Go](https://golang.org/doc/effective_go.html) guidelines
- Use `gofmt` to format your code
- Keep functions focused and concise
- Add comments for exported functions and complex logic

### Testing

- Write tests for new functionality
- Ensure existing tests pass
- Use descriptive test names
- Test both success and failure cases

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in present tense (e.g., "Add", "Fix", "Update")
- Keep the first line under 50 characters
- Add more details in the body if needed

Example:
```
Add support for JSON user files

- Implement JSON user file loading
- Add validation for JSON format
- Update documentation with examples
```

## Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following the guidelines above
   - Add tests for new functionality
   - Update documentation if needed

3. **Test your changes**
   ```bash
   go test ./...
   xcaddy build --with ./
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add your descriptive commit message"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request**
   - Go to your fork on GitHub
   - Click "New Pull Request"
   - Select your feature branch
   - Fill out the PR template
   - Submit the PR

## Pull Request Template

When creating a pull request, please include:

### Description
Brief description of the changes made.

### Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

### Testing
- [ ] Tests pass locally
- [ ] Caddy builds successfully with the module
- [ ] Manual testing completed

### Checklist
- [ ] Code follows Go conventions
- [ ] Tests added for new functionality
- [ ] Documentation updated
- [ ] No breaking changes (or breaking changes documented)

## Issue Reporting

When reporting issues, please include:

1. **Environment details**
   - Go version
   - Caddy version
   - Operating system
   - Architecture

2. **Steps to reproduce**
   - Clear, step-by-step instructions
   - Sample configuration files
   - Expected vs actual behavior

3. **Error messages**
   - Full error output
   - Log files if applicable

4. **Additional context**
   - Any relevant configuration
   - Workarounds tried
   - Related issues

## Code of Conduct

- Be respectful and inclusive
- Focus on the code and technical discussions
- Help others learn and grow
- Report any inappropriate behavior

## Questions?

If you have questions about contributing:

1. Check the existing issues and discussions
2. Create a new issue with the "question" label
3. Join the Caddy community discussions

Thank you for contributing to the Caddy Digest Authentication Module! 