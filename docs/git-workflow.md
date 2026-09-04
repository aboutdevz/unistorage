# UniStorage Git Workflow & CI/CD Guide

## 1. Branching Model

UniStorage follows a **Trunk-Based Development** model with short-lived branches:

```
main (protected)
  ▲
  │ (PR with required CI checks & 1+ approvals)
  ├── feature/<feature-name>       # New capabilities & drivers
  ├── fix/<bug-description>        # Defect remediation
  ├── security/<cve-or-finding>    # Security patches (coordinated disclosure)
  ├── docs/<documentation-topic>   # Documentation additions
  └── release/v<X.Y.Z>             # Release stabilization branches
```

### Branch Rules
1. **`main` is protected**:
   - Direct push is prohibited.
   - All PRs must pass the `UniStorage SSDLC Quality Gate` CI workflow.
   - At least 1 code review approval is required.
   - Linear history enforced: Squash & Merge or Rebase & Merge.
2. **Branch Naming**:
   - `feature/s3-multipart-resilience`
   - `fix/windows-drive-path-resolver`
   - `security/govulncheck-eventstream-upgrade`
   - `docs/api-specification`

---

## 2. Commit Conventions (Conventional Commits)

Commit messages must strictly follow the [Conventional Commits](https://www.conventionalcommits.org/) standard:

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Allowed Types
| Type | Purpose | Example |
|---|---|---|
| `feat` | New user-facing feature or API | `feat(storage): add s3 multipart retry backoff` |
| `fix` | Bug fix | `fix(sync): resolve path collision on windows drive letters` |
| `docs` | Documentation changes | `docs(stride): document loopback dns rebinding controls` |
| `test` | Adding or refactoring tests | `test(e2e): implement tier 5 adversarial hardening tests` |
| `refactor` | Code change that neither fixes a bug nor adds a feature | `refactor(vault): optimize argon2id memory zeroing` |
| `perf` | Performance improvement | `perf(storage): pool 64kb streaming buffers` |
| `ci` | Changes to CI/CD workflows and tooling | `ci(ssdlc): add cosign release attestation job` |
| `chore` | Routine repository maintenance | `chore(deps): upgrade aws-sdk-go-v2 to v1.110.0` |

---

## 3. Pull Request & Review Lifecycle

1. **Local Pre-Flight Checks**:
   Before opening a PR, run:
   ```powershell
   # 1. Full test regression
   go test -count=1 ./...

   # 2. SCA vulnerability audit
   govulncheck ./...

   # 3. SAST security check
   gosec -severity=medium -confidence=medium -exclude=G104 ./cmd/... ./pkg/... ./internal/...
   ```
2. **Open PR**: Fill in `.github/PULL_REQUEST_TEMPLATE.md`.
3. **Automated CI Gate**:
   GitHub Actions executes `.github/workflows/ssdlc.yml`:
   - Job 1: Multi-OS Test Matrix (Ubuntu, Windows, macOS) with `-race`
   - Job 2: SAST (`golangci-lint` + `gosec`)
   - Job 3: SCA (`govulncheck`)
   - Job 4: Secret Detection (`gitleaks`)
   - Job 5: Native Fuzz Regression (`FuzzPathSanitizer`)
   - Job 6: Docker Multi-Stage Build & Non-Root (10001:10001) Audit
   - Job 7: CycloneDX SBOM generation & Cosign signature
4. **Merge**: Once green and approved, squash/rebase merge into `main`.

---

## 4. Continuous Delivery & Release Pipeline

Release automation is governed by `.github/workflows/release.yml`:

```
git tag v0.1.0 -> git push origin v0.1.0
  │
  ├── 1. Build Cross-Platform Static Binaries (Linux, macOS, Windows; amd64/arm64)
  ├── 2. Build & Publish Multi-Arch Docker Container (ghcr.io/aboutdevz/unistorage)
  ├── 3. Generate SHA-256 Checksums (checksums.txt)
  ├── 4. Sign Artifacts via Cosign Keyless Signing
  ├── 5. Generate CycloneDX SBOM with Syft
  └── 6. Publish GitHub Release with Release Notes & Attestations
```
