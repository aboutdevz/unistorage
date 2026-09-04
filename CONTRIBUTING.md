# Contributing to UniStorage

Thank you for your interest in contributing to **UniStorage**! We are committed to building a resilient, high-performance, and secure unified storage platform for the open-source community.

Please take a moment to review this guide before submitting contributions. By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Table of Contents

1. [Open-Core Architecture Philosophy](#open-core-architecture-philosophy)
2. [Prerequisites](#prerequisites)
3. [Local Development Environment](#local-development-environment)
4. [Testing & Quality Verification](#testing--quality-verification)
5. [Code Style & Linting](#code-style--linting)
6. [Git Pre-commit Hooks](#git-pre-commit-hooks)
7. [Commit Message Conventions](#commit-message-conventions)
8. [Pull Request Workflow](#pull-request-workflow)
9. [Reporting Security Issues](#reporting-security-issues)

---

## Open-Core Architecture Philosophy

UniStorage follows a strict **Open-Core** architectural model:
- **Core Engine (OSS / Apache 2.0)**: Located under `pkg/storage`, `pkg/vault`, `pkg/sync`, `pkg/entitlement`, `internal/daemon`, and `cmd/unistorage`. This includes the unified storage driver interface, local filesystem and S3 drivers, Argon2id encrypted vault, constant-memory streaming, and the loopback daemon.
- **Commercial Extensions**: Kept strictly isolated in a private repository. Core OSS packages must **never** directly import or depend on proprietary enterprise packages. The boundary is maintained through the `pkg/entitlement` interface contract and Go build tags.

---

## Prerequisites

Before contributing, ensure you have the following installed:
- **Go**: Version `1.22` or later (Go `1.24` recommended).
- **Docker & Docker Compose**: For running the local storage mock infrastructure (MinIO).
- **Git**: Version `2.30+`.
- *(Optional)* **golangci-lint**: For local static analysis (`go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`).
- *(Optional)* **govulncheck**: For dependency vulnerability audits (`go install golang.org/x/vuln/cmd/govulncheck@latest`).
- *(Optional)* **gitleaks**: For secret detection (`https://github.com/gitleaks/gitleaks`).

---

## Local Development Environment

1. **Clone the repository**:
   ```bash
   git clone https://github.com/aboutdevz/unistorage.git
   cd unistorage
   ```

2. **Start the local MinIO test environment**:
   ```bash
   docker compose up -d
   ```
   - **MinIO S3 API**: `http://127.0.0.1:9000`
   - **MinIO Web Console**: `http://127.0.0.1:9001` (Credentials: `minioadmin` / `minioadmin`)
   - Pre-created test bucket: `unistorage-dev`

3. **Build the CLI binary**:
   ```bash
   go build -o bin/unistorage ./cmd/unistorage
   ```

4. **Verify binary and versioning**:
   ```bash
   ./bin/unistorage version --json
   ```

---

## Testing & Quality Verification

All submitted code must pass our SSDLC test suite before merging.

### Running Unit & Integration Tests
```bash
# Run all tests
go test -v -count=1 ./...

# Run storage driver unit tests
go test -v ./pkg/storage/local ./pkg/storage/s3

# Run daemon integration tests
go test -v ./internal/daemon
```

### Path Sanitizer Fuzz Testing
Our local filesystem driver uses strict path boundary validation to prevent directory traversal exploits. Verify with Go native fuzzing:
```bash
go test -fuzz=FuzzPathSanitizer -fuzztime=10s ./pkg/storage/local
```

### Security & Vulnerability Audits
```bash
# Scan for dependency vulnerabilities
govulncheck ./...

# Run static application security testing (SAST)
golangci-lint run
```

---

## Code Style & Linting

We adhere to standard Go conventions:
- Format code using `gofmt -s -w .`.
- Group imports into: standard library, third-party packages, and internal packages.
- Ensure all public functions, types, and constants have clear godoc comments.
- Keep memory consumption bounded: all I/O transfers must stream through buffers rather than loading complete files into memory.

---

## Git Pre-commit Hooks

We provide pre-commit scripts to catch formatting issues and credential leaks before pushing code:

```bash
# Configure Git to use repo hooks
git config core.hooksPath .githooks
```

Alternatively, if you use the Python `pre-commit` framework:
```bash
pre-commit install
```

---

## Commit Message Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Each commit message must follow this structure:

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Allowed Types:
- `feat`: A new feature or capability.
- `fix`: A bug fix.
- `docs`: Documentation changes only.
- `test`: Adding or updating test suites.
- `refactor`: Code changes that neither fix a bug nor add a feature.
- `perf`: Performance improvements.
- `ci`: CI/CD pipeline and automation changes.
- `chore`: Maintenance, dependencies, or tooling updates.

### Examples:
- `feat(storage): add multi-part upload retry with exponential backoff`
- `fix(daemon): enforce exact host header match to prevent DNS rebinding`
- `docs(readme): add detailed CLI usage examples`

---

## Pull Request Workflow

1. **Create a topic branch**:
   ```bash
   git checkout -b feat/my-new-feature
   ```
2. **Commit your changes**: Ensure atomic, well-tested commits.
3. **Rebase against main**:
   ```bash
   git fetch origin
   git rebase origin/main
   ```
4. **Push your branch**:
   ```bash
   git push origin feat/my-new-feature
   ```
5. **Open a Pull Request**:
   - Complete all items in the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).
   - Ensure all automated GitHub Actions checks pass.
   - At least one maintainer approval is required before merging.

---

## Reporting Security Issues

**Do NOT report security vulnerabilities via public GitHub issues.**

Please follow our responsible disclosure guidelines detailed in [SECURITY.md](SECURITY.md) or use [GitHub Private Vulnerability Reporting](https://github.com/aboutdevz/unistorage/security/advisories/new).
