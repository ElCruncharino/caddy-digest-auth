# Contributing

## Setup

```bash
git clone https://github.com/ElCruncharino/caddy-digest-auth.git
cd caddy-digest-auth
xcaddy build --with ./
go test ./...
```

## Making Changes

1. Fork and create a feature branch
2. Install pre-commit hooks: `cp hooks/pre-commit .git/hooks/pre-commit`
3. Make your changes
4. Add tests for new functionality
5. Run `go test ./...` and `gofmt -w .`
6. Submit a PR

Pre-commit hooks will automatically run gofmt, go vet, and tests. Follow standard Go conventions. 