# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Web UI Dashboard with real-time WebSocket file browser.
- Additional storage drivers: SFTP, WebDAV, SMB/NFS, Azure Blob Storage, and Google Cloud Storage.
- Multi-cloud mesh and distributed peer-to-peer edge synchronization.

---

## [0.1.0] - 2026-09-05

### Added
- **Unified Driver Engine**: Abstracted storage interface (`pkg/storage`) providing uniform `Read`, `Write`, `List`, `Delete`, `Stat`, and `Stream` operations across heterogeneous providers.
- **Storage Drivers**:
  - **Local FS Driver**: Safe local filesystem storage with path-traversal prevention, atomic file writes, and directory walking.
  - **S3-Compatible Driver**: Support for AWS S3, MinIO, Cloudflare R2, and Ceph with automatic multipart uploads (>16 MB chunks) and path-style URL support.
- **Resilient Chunked Streaming**: Constant-memory buffer pipeline preventing out-of-memory (OOM) errors during multi-gigabyte transfers.
- **Encrypted Credential Vault**: Argon2id key derivation combined with AES-256-GCM authenticated encryption (`pkg/vault`) for zero-leakage credential management.
- **Hardened Loopback Daemon**: Local background daemon (`internal/daemon`) bound exclusively to `127.0.0.1`, protected by auto-generated Bearer tokens (`daemon.token`, mode `0600`) and anti-DNS-rebinding host validation.
- **Conflict-Proof Synchronization**: Resilient sync engine (`pkg/sync`) supporting hybrid change detection (Size + ModTime or SHA-256 checksum), parallel workers, orphaned target deletion, and automatic safety backups of conflicting files into `.conflicts/`.
- **Command-Line Interface**:
  - `unistorage remote <add|list|remove>`: Manage encrypted storage remote configurations.
  - `unistorage ls <target>`: List files and directory trees with recursive (`-r`), long format (`-l`), human-readable sizes (`-H`), and `--json` formatting.
  - `unistorage cp <src> <dest>`: Copy objects between local and remote endpoints with streaming.
  - `unistorage sync <src> <dest>`: Synchronize folders with conflict backup and checksum verification.
  - `unistorage rm <target>`: Remove files or directory trees with dry-run support.
  - `unistorage daemon <start|status|stop>`: Manage the loopback service.
  - `unistorage version [--json]`: Display binary version, commit hash, build date, and platform metadata.
- **Open-Core Entitlement Contract**: Strict boundary interface (`pkg/entitlement`) ensuring community core remains 100% unencumbered by commercial proprietary modules.
- **Container Infrastructure**:
  - Multi-stage non-root distroless production `Dockerfile` (UID/GID `10001:10001`).
  - Development `docker-compose.yml` pre-wired with MinIO mock and automatic bucket initialization.
- **Automated SSDLC Pipeline**: Comprehensive GitHub Actions workflows for multi-platform static compilation, SAST (`gosec`, `golangci-lint`), SCA (`govulncheck`), Secret Detection (`gitleaks`), Go Native Fuzzing (`FuzzPathSanitizer`), CycloneDX SBOM generation, and Cosign release attestation.

### Security
- Integrated `FuzzPathSanitizer` native fuzzing test suite verifying path boundary enforcement across Linux and Windows path separators.
- Implemented strict Host and Origin header validation on loopback HTTP endpoints to defeat DNS rebinding and CORS drive-by exploits.
- Ensured sensitive configuration values and credentials in memory and persistent storage utilize constant-time comparisons and AES-256-GCM encryption.
