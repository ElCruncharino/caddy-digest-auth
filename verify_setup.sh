#!/bin/bash

echo "=== Caddy Digest Auth Module - GitHub Setup Verification ==="
echo

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    echo "❌ Error: go.mod not found. Please run this script from the module root directory."
    exit 1
fi

echo "✅ Found go.mod"

# Check module name
MODULE_NAME=$(grep "^module" go.mod | awk '{print $2}')
if [ "$MODULE_NAME" = "github.com/ElCruncharino/caddy-digest-auth" ]; then
    echo "✅ Module name is correct: $MODULE_NAME"
else
    echo "❌ Module name is incorrect: $MODULE_NAME"
    echo "   Expected: github.com/ElCruncharino/caddy-digest-auth"
fi

# Check required files
REQUIRED_FILES=(
    "README.md"
    "LICENSE"
    "go.mod"
    "go.sum"
    "caddy_digest_auth.go"
    "caddy_digest_auth_test.go"
    ".gitignore"
    "CHANGELOG.md"
    "CONTRIBUTING.md"
    "SECURITY.md"
    "Makefile"
)

echo
echo "Checking required files:"
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file (missing)"
    fi
done

# Check GitHub-specific files
echo
echo "Checking GitHub-specific files:"
GITHUB_FILES=(
    ".github/workflows/ci.yml"
    ".github/ISSUE_TEMPLATE/bug_report.md"
    ".github/ISSUE_TEMPLATE/feature_request.md"
    ".github/pull_request_template.md"
)

for file in "${GITHUB_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file (missing)"
    fi
done

# Check examples directory
echo
echo "Checking examples:"
if [ -d "examples" ]; then
    echo "✅ examples/ directory exists"
    EXAMPLE_FILES=$(ls examples/ 2>/dev/null | wc -l)
    echo "   Found $EXAMPLE_FILES example files"
else
    echo "❌ examples/ directory missing"
fi

# Check for any remaining references to old username (excluding this script)
echo
echo "Checking for old username references:"
OLD_REFS=$(grep -r "nickhaghiri" . --exclude-dir=.git --exclude=verify_setup.sh 2>/dev/null | wc -l)
if [ "$OLD_REFS" -eq 0 ]; then
    echo "✅ No references to old username found"
else
    echo "❌ Found $OLD_REFS references to old username:"
    grep -r "nickhaghiri" . --exclude-dir=.git --exclude=verify_setup.sh 2>/dev/null
fi

# Check Go module validity
echo
echo "Checking Go module:"
if command -v go >/dev/null 2>&1; then
    echo "✅ Go is installed"
    go mod verify >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✅ Go module is valid"
    else
        echo "❌ Go module validation failed"
    fi
else
    echo "⚠️  Go is not installed (cannot verify module)"
fi

echo
echo "=== Verification Complete ==="
echo
echo "If all checks passed, your repository is ready for GitHub!"
echo
echo "Next steps:"
echo "1. Create a new repository on GitHub named 'caddy-digest-auth'"
echo "2. Initialize git and push your code:"
echo "   git init"
echo "   git add ."
echo "   git commit -m 'Initial commit'"
echo "   git branch -M main"
echo "   git remote add origin https://github.com/ElCruncharino/caddy-digest-auth.git"
echo "   git push -u origin main"
echo
echo "3. Enable GitHub Actions in your repository settings"
echo "4. Add topics to your repository: caddy, authentication, digest-auth, go, http"
echo "5. Create a release with version 1.0.0" 