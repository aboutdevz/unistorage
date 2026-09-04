# UniStorage GitHub Repository Setup & Maintainer Guide

This guide details the administrative setup, security posture, branch governance, and release workflows required for maintainers of the **UniStorage** open-source repository.

---

## 1. Security & Code Scanning Setup

UniStorage enforces a Defense-in-Depth DevSecOps pipeline using GitHub Advanced Security and ecosystem tooling.

### CodeQL Code Scanning
- **Engine**: GitHub CodeQL Analysis (Default Setup).
- **Languages Analyzed**: Go, Actions.
- **Autofix**: Copilot Autofix enabled for actionable remediation suggestions.
- **Failure Thresholds**:
  - Security alert severity: `High or higher` blocks PR merges.
  - Standard alert severity: `Only errors`.
- **Third-Party SARIF Integration**:
  - Gosec AST security analysis outputs SARIF and uploads via `github/codeql-action/upload-sarif@v3` to GitHub Security center.

### Secret Detection
- **Gitleaks**: Configured via `.gitleaks.toml` to block secrets, credentials, S3 keys, and Argon2 passphrases from entering the Git history.
- **Push Protection**: Enable GitHub Secret Scanning and Secret Protection in repository settings to prevent credential leakage at push time.

### Dependency Security & Dependabot
- Configured in `.github/dependabot.yml` for weekly audits of:
  - `gomod` (Go modules and transitive dependencies)
  - `github-actions` (CI/CD action versions)
  - `docker` (Base container images in `Dockerfile`)
- Govulncheck runs on every push and pull request to detect known vulnerabilities (GO-XXXX).

---

## 2. Branch Protection Rules

Branch protection rules must be configured on the `main` branch and any release stabilization branches (`release/*`) in GitHub Repository Settings -> Branches:

1. **Require a pull request before merging**:
   - Required approvals: `1` minimum.
   - Dismiss stale pull request approvals when new commits are pushed.
   - Require review from Code Owners (defined in `.github/CODEOWNERS`).
2. **Require status checks to pass before merging**:
   - Require branches to be up to date before merging.
   - Required checks:
     - `Test (ubuntu-latest)`
     - `Test (windows-latest)`
     - `Test (macos-latest)`
     - `SAST Code Analysis`
     - `SCA Dependency Vulnerability Audit`
     - `Secret Detection (Gitleaks)`
     - `Native Path Sanitizer Fuzz Test`
     - `Docker Multi-Stage Build & Security Audit`
     - `SBOM Generation & Attestation`
3. **Require conversation resolution before merging**:
   - All review comments and discussions must be marked as resolved.
4. **Require signed commits**:
   - Maintainers and contributors should sign commits with GPG or SSH keys.
5. **Require linear history**:
   - Enforce `Squash and merge` or `Rebase and merge`. Merge commits are prohibited on `main`.
6. **Do not allow bypassing the above settings**:
   - Enforce restrictions for administrators as well.

---

## 3. First Release Tagging Workflow

UniStorage uses semantic versioning (`vMAJOR.MINOR.PATCH`) automated through GitHub Actions (`.github/workflows/release.yml`) and GoReleaser (`.goreleaser.yml`).

### Pre-Release Checklist
1. Ensure all features and fixes are merged to `main` with all SSDLC checks passing green.
2. Update `CHANGELOG.md` with release notes following the Keep a Changelog standard under the target version section.
3. Validate local test suite and fuzzing:
   ```bash
   go test -v -race ./...
   go test -v -fuzz=FuzzPathSanitizer -fuzztime=30s ./pkg/storage/local
   ```

### Tagging and Publishing
1. Create and push an annotated Git tag from `main`:
   ```bash
   git checkout main
   git pull origin main
   git tag -a v0.1.0 -m "Release v0.1.0: UniStorage MVP with multi-backend streaming, encrypted vault, and daemon API"
   git push origin v0.1.0
   ```
2. The `UniStorage CD & Release Pipeline` (`.github/workflows/release.yml`) will trigger automatically:
   - Compiles cross-platform static hardened binaries (Linux amd64/arm64, macOS amd64/arm64, Windows amd64/arm64).
   - Packages ZIP and TAR.GZ distribution archives with LICENSE and README.
   - Builds and publishes multi-arch container images to GitHub Container Registry (`ghcr.io/aboutdevz/unistorage`).
   - Generates SHA-256 checksums and CycloneDX SBOM with Syft.
   - Signs checksums keylessly with Cosign.
   - Publishes the official GitHub Release with release notes and downloadable assets.

### Post-Release Verification
- Verify the release assets and SHA-256 checksums on the GitHub Releases page.
- Pull the published container image and verify non-root execution:
  ```bash
  docker run --rm ghcr.io/aboutdevz/unistorage:latest version --json
  ```
