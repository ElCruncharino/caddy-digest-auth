#!/bin/bash

# Build script for Caddy with digest authentication module
# This script builds Caddy with the custom digest auth module

set -e

echo "Building Caddy with digest authentication module..."

# Check if xcaddy is installed
if ! command -v xcaddy &> /dev/null; then
    echo "Installing xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
fi

# Build Caddy with the module
echo "Building Caddy..."
xcaddy build --with github.com/ElCruncharino/caddy-digest-auth

echo "Build complete! Caddy binary is ready."
echo "You can now use the digest_auth handler in your Caddy configuration." 