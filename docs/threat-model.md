# Formal STRIDE Threat Model: UniStorage MVP

## 1. Executive Summary & System Overview

UniStorage is an open-source unified storage abstraction engine and command-line interface (CLI) written in Go. It provides unified primitives (`Read`, `Write`, `List`, `Delete`, `Stat`, `Stream`) across heterogeneous backends (local filesystem and S3-compatible object stores), accompanied by an authenticated background management daemon, an encrypted credential vault, enterprise extensions (snapshot backups, telemetry, alerting), and containerized deployments.

This document establishes the formal STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) threat model for the UniStorage MVP architecture, identifying trust boundaries, threat scenarios, implemented countermeasures, and verification controls.

---

## 2. Architecture & Trust Boundaries

The system comprises six primary subsystems, delineated by four strict trust boundaries:

```
+-----------------------------------------------------------------------------+
| User / Host Environment (Untrusted / Semi-Trusted)                         |
|                                                                             |
|  +---------------------+         +---------------------------------------+  |
|  | CLI (cmd/unistorage)|         | Host Web Browser / Local Processes    |  |
|  +----------+----------+         +-------------------+-------------------+  |
|             |                                        |                      |
|             | (Local Loopback TCP: Bearer Auth)      | (CORS / DNS Rebind)  |
|=============v========================================v======================|
| TRUST BOUNDARY 1: Loopback HTTP API (127.0.0.1:8080)                        |
|=============================================================================|
|                                                                             |
|  +-----------------------------------------------------------------------+  |
|  | UniStorage Daemon Core (internal/daemon)                              |  |
|  |  - Host Header Validation & CORS Origin Denial Block                  |  |
|  |  - High-Entropy Bearer Token Authenticator (0600 file permissions)     |  |
|  |  - REST API Routing & Enterprise Extension Hooks                      |  |
|  +-------------------+-------------------------------+-------------------+  |
|                      |                               |                      |
|                      v                               v                      |
|  +-------------------+---------------+   +-----------+-------------------+  |
|  | Secret Vault (pkg/vault)          |   | Snapshot Backup Engine        |  |
|  |  - AES-256-GCM AEAD Encryption    |   |  - Manifest Trees             |  |
|  |  - Argon2id Key Derivation        |   |  - Anti-Double-Run Mutex      |  |
|  |  - In-Memory Zeroing (MemZero)    |   |  - Last-N Retention Pruner    |  |
|  +-------------------+---------------+   +-----------+-------------------+  |
|                      |                               |                      |
|======================v===============================v======================|
| TRUST BOUNDARY 2: Storage Driver Layer (pkg/storage)                        |
|=============================================================================|
|                                                                             |
|  +-----------------------------------+   +-------------------------------+  |
|  | Local Driver (pkg/storage/local)  |   | S3 Driver (pkg/storage/s3)    |  |
|  |  - Path Sanitizer (Traversal-proof|   |  - Multipart Upload (>16MB)   |  |
|  |  - Symlink Resolution Escapes     |   |  - Exponential Backoff Jitter |  |
|  |  - Windows ADS / Device Checks    |   |  - Constant-Memory Streaming  |  |
|  +-------------------+---------------+   +---------------+---------------+  |
|                      |                                   |                  |
|======================v===================================v==================|
| TRUST BOUNDARY 3: Persistent Media & External Storage Network               |
|=============================================================================|
|                      |                                   |                  |
|                      v                                   v                  |
|  +-------------------+---------------+   +---------------+---------------+  |
|  | Local Filesystem Paths (/data)    |   | Remote S3 / MinIO (HTTPS)     |  |
|  +-----------------------------------+   +-------------------------------+  |
|                                                                             |
|=============================================================================|
| TRUST BOUNDARY 4: Container Isolation (Docker / Alpine Non-Root)            |
|=============================================================================|
|  - UID:GID 10001:10001 (unistorage)                                          |
|  - Read-Only Root Filesystem (`read_only: true`)                             |
|  - All Linux Capabilities Dropped (`cap_drop: [ALL]`)                       |
|  - No New Privileges Flag (`no-new-privileges: true`)                        |
+-----------------------------------------------------------------------------+
```

---

## 3. STRIDE Threat Analysis Matrix

| Threat Category | System Component | Specific Threat Scenario | Implemented Mitigation Strategy | Verification & Security Control |
|---|---|---|---|---|
| **S**poofing | Daemon API (`internal/daemon`) | Unauthorized local processes impersonate authorized operators to execute arbitrary file CRUD, trigger syncs, or modify remote configurations. | On startup, daemon generates a cryptographically secure 256-bit (64 hex character) Bearer token stored in `~/.unistorage/daemon.token` with strict POSIX `0600` permissions. All API endpoints validate `Authorization: Bearer <token>`. Missing or invalid tokens immediately return `401 Unauthorized`. | Automated unit and integration tests (`TestDaemonAuth`, `TestDaemonAuth_InvalidToken`, `adversarial_security_test.go`). |
| **S**poofing | Remote Storage (`pkg/storage/s3`) | Rogue or spoofed S3 storage server impersonates legitimate endpoint to harvest credentials or manipulate data transfers. | S3 driver enforces HTTPS TLS 1.3 verification with system root certificate authorities (`ca-certificates`). Self-signed certificates require explicit developer opt-in. | AWS SDK v2 secure TLS handshake configuration and S3 latency probe tests. |
| **T**ampering | Local Storage (`pkg/storage/local`) | Malicious path traversal payloads (`../../etc/passwd`, `..\win.ini`, URL-encoded `%2e%2e%2f`, Windows Alternate Data Streams `::$DATA`, or reserved device names `CON`, `NUL`, `AUX`) overwrite or read sensitive files outside sandbox root. | `SanitizePath` performs lexical cleansing via `filepath.Clean`, rejects null bytes, Windows reserved device names, ADS markers, evaluates symlinks with `filepath.EvalSymlinks`, and guarantees that the canonical target path strictly resides within the configured root boundary. | Native fuzz test `FuzzPathSanitizer` (continuous regression) and comprehensive adversarial suite `TestSanitizePath_Traversals`, `TestAdversarial_WindowsDeviceNames`, `TestAdversarial_SymlinkEscapes`. |
| **T**ampering | Data In-Flight / Sync (`pkg/sync`, `pkg/storage/s3`) | Man-in-the-middle bit flips, truncated network transfers, or silent file corruption during sync or multipart uploads. | S3 driver utilizes SHA-256 and ETag verification for multipart uploads. `unistorage sync --checksum` verifies full SHA-256 digest comparisons before replacing files. Displaced or modified files are safely backed up to `.conflicts/` rather than destroyed. | E2E sync checksum tests (`TestSync_ChecksumVerification`) and conflict backup tests (`TestConflictHandler`). |
| **R**epudiation | Entitlement & Backup (`pkg/entitlement`, commercial extension) | Operator disputes feature licensing or file versions in snapshot runs. | Strict entitlement gating denies commercial capabilities in community edition; enterprise backups generate immutable `manifest.json` trees. | Open-core entitlement gate unit tests (`TestCommunityChecker_DeniesEnterpriseFeatures`). |
| **I**nformation Disclosure | Secret Vault (`pkg/vault`) | Attacker with disk access or memory inspection reads backend credentials, S3 secret keys, or cloud access tokens in plaintext. | Remote backend credentials are encrypted at rest using AES-256-GCM authenticated encryption with Argon2id password-based key derivation (64MB memory, 3 iterations, 4 threads, 16-byte random salt). Secret byte slices are aggressively wiped from process RAM using `MemZero` with `runtime.KeepAlive`. | Vault ciphertext entropy tests, zero plaintext leakage in database dumps (`TestVault_Argon2idAESGCM`), and Gitleaks secret detection. |
| **I**nformation Disclosure | Loopback Daemon (`internal/daemon`) | Malicious website accessed in user's browser executes DNS-rebinding or cross-origin fetch attacks to query the daemon on `127.0.0.1:8080` and exfiltrate data. | Hardened middleware strictly enforces Host header validation (permitting only `127.0.0.1`, `localhost`, `[::1]`) and enforces blanket CORS origin rejection (any request with an `Origin` header is rejected with `403 Forbidden`). | Adversarial DNS-rebinding and CORS origin rejection test suite (`TestDaemon_DNSRebindingRejection`, `TestDaemon_CORSRejection`). |
| **D**enial of Service | Daemon & CLI Transfer (`pkg/storage`) | Multi-gigabyte file transfers or infinite data streams exhaust host system memory (OOM panic) or block server threads. | Unified `Driver` streaming interface implements constant-memory chunked streaming (`Stream`) using pooled 64 KiB buffer allocations ($O(1)$ memory consumption invariant regardless of file size). S3 multipart uploads split payloads into 16MB chunks with exponential backoff and jitter on retryable 5xx errors. | Constant-memory allocation benchmarks and stream leak tests (`TestAdversarial_ConstantMemoryStreaming`). |
| **D**enial of Service | Backup Scheduler & Sync | Rapid or overlapping cron backup triggers launch concurrent sync jobs that exhaust disk I/O and corrupt state. | Engine and extensions enforce job-level mutual exclusion (`anti-double-run mutex`) and concurrency locks with structured warning logs. | Concurrency lock and adversarial stress tests. |
| **E**levation of Privilege | Container Runtime (`Dockerfile`, `docker-compose.yml`) | Attacker exploits a daemon vulnerability to execute shell commands and attempts root container breakout to gain host root privileges. | Minimal runtime base (`alpine:3.20`) executes strictly under unprivileged user and group UID:GID `10001:10001` (`unistorage`) with shell disabled (`/sbin/nologin`). Container runs with read-only root filesystem (`read_only: true`), all Linux capabilities dropped (`cap_drop: [ALL]`), and `no-new-privileges: true`. | Docker build & runtime validation tests in CI (`TestDockerfile_StructureAndHardening`, `TestDockerCompose_SyntaxAndServices`). |

---

## 4. SSDLC Verification Controls & Enforcement Gate

The mitigations detailed above are continuously enforced across the software development lifecycle:

1. **Static Analysis & SAST**: `.golangci.yml` enforces `gosec` (AST vulnerability scan), `errcheck` (mandatory error handling), `staticcheck`, and `govet` on every commit.
2. **Software Composition Analysis (SCA)**: `govulncheck` audits Go call graphs against known CVEs in transitive dependencies.
3. **Secret Leak Prevention**: `.gitleaks.toml` scans commits for high-entropy Bearer tokens, S3 keys, and Argon2id secrets.
4. **Native Fuzz Testing**: `FuzzPathSanitizer` executes continuous randomized mutated input generation to detect edge-case traversal bypasses.
5. **Supply Chain & Provenance**: Anchore Syft generates CycloneDX/SPDX SBOMs; Sigstore Cosign signs build artifacts with keyless cryptographic attestations.
