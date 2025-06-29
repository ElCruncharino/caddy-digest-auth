@echo off
REM Build script for Caddy with digest authentication module (Windows)
REM This script builds Caddy with the custom digest auth module

echo Building Caddy with digest authentication module...

REM Check if xcaddy is installed
where xcaddy >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing xcaddy...
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
)

REM Build Caddy with the module
echo Building Caddy...
xcaddy build --with github.com/ElCruncharino/caddy-digest-auth

if %errorlevel% equ 0 (
    echo Build complete! Caddy binary is ready.
    echo You can now use the digest_auth handler in your Caddy configuration.
) else (
    echo Build failed!
    exit /b 1
) 