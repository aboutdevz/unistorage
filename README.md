# UniStorage

[![CI / SSDLC](https://github.com/aboutdevz/unistorage/actions/workflows/ssdlc.yml/badge.svg)](https://github.com/aboutdevz/unistorage/actions/workflows/ssdlc.yml)
[![Release](https://github.com/aboutdevz/unistorage/actions/workflows/release.yml/badge.svg)](https://github.com/aboutdevz/unistorage/actions/workflows/release.yml)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/badge/Release-v0.1.0-brightgreen.svg)](CHANGELOG.md)
[![SSDLC](https://img.shields.io/badge/SSDLC-Hardened-success.svg)](SECURITY.md)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](Dockerfile)
[![Secret Scan](https://img.shields.io/badge/Gitleaks-Passing-brightgreen.svg)](.gitleaks.toml)

> **UniStorage** is an open-source, zero-dependency unified storage platform core engine and CLI written in Go. It abstracts heterogeneous storage backends (Local FS and S3-compatible object stores) behind a single unified interface with constant-memory chunked streaming.
>
> Built with enterprise security and SSDLC from day one, it features an Argon2id + AES-256-GCM encrypted secret vault, a loopback management daemon protected against DNS-rebinding and CORS drive-bys, unidirectional sync with hybrid change detection and `.conflicts/` safety backups, modular enterprise extensions (cron snapshot manifests, retention pruning, OS syscall disk monitoring, and webhook alerts), multi-stage non-root Docker infrastructure, and automated security verification.

---

## Table of Contents

- [Why UniStorage?](#why-unistorage)
- [System Architecture](#system-architecture)
- [Key Features](#key-features)
- [Open-Core Architecture](#open-core-architecture)
- [Quickstart Guide](#quickstart-guide)
  - [Prerequisites](#prerequisites)
  - [Building from Source](#building-from-source)
  - [Local Development Stack (MinIO + Docker)](#local-development-stack-minio--docker)
- [CLI Usage Guide](#cli-usage-guide)
  - [1. Remote Management (`remote`)](#1-remote-management-remote)
  - [2. Listing Objects (`ls`)](#2-listing-objects-ls)
  - [3. Copying Files (`cp`)](#3-copying-files-cp)
  - [4. Resilient Synchronization (`sync`)](#4-resilient-synchronization-sync)
  - [5. Removing Objects (`rm`)](#5-removing-objects-rm)
  - [6. Daemon Lifecycle (`daemon`)](#6-daemon-lifecycle-daemon)
  - [7. Version Inspection (`version`)](#7-version-inspection-version)
  - [Global Flags Reference](#global-flags-reference)
- [Daemon REST API](#daemon-rest-api)
- [Production Container Deployment](#production-container-deployment)
- [Security & SSDLC](#security--ssdlc)
- [Development Roadmap](#development-roadmap)
- [Contributing & Community](#contributing--community)
- [License](#license)

---

## Why UniStorage?

Managing files and backups across modern multi-cloud and on-premises environments is plagued by several core challenges:

1. **Vendor Lock-in & Inconsistent APIs**:
   AWS S3, MinIO, Cloudflare R2, Ceph, and POSIX filesystems each require distinct SDKs, auth patterns, and error handling. UniStorage unifies them into an intuitive, vendor-agnostic interface (`pkg/storage.Driver`).
2. **Out-of-Memory (OOM) Crashes on Large Transfers**:
   Many tools buffer large objects entirely in RAM. UniStorage streams all data through bounded, constant-memory chunks with automatic S3 multipart chunking (>16 MB), allowing multi-gigabyte transfers with minimal memory footprints.
3. **Plaintext Credential Exposure**:
   Most storage CLIs store API tokens and secret keys in unencrypted plaintext files (`~/.aws/credentials`, `.rclone.conf`). UniStorage encrypts all secrets at rest using **Argon2id** key derivation and **AES-256-GCM** authenticated encryption.
4. **Vulnerable Background Services**:
   Storage daemons exposed on `localhost` are historically susceptible to DNS-rebinding and CORS drive-by attacks from malicious browser scripts. UniStorage locks its daemon to loopback (`127.0.0.1`), generates high-entropy single-host Bearer tokens (`daemon.token`, mode `0600`), and validates HTTP `Host` and `Origin` headers strictly.
5. **Destructive Sync Collisions**:
   Unidirectional synchronization tools often overwrite modified files blindly. UniStorage performs hybrid change detection (Size + ModTime or SHA-256) and automatically archives displaced target files into `.conflicts/` safety backups.

---

## System Architecture

```
                                  ┌──────────────────────────┐
                                  │   UniStorage CLI Tool    │
                                  │     (cmd/unistorage)     │
                                  └─────────────┬────────────┘
                                                │ (Bearer Auth over Loopback HTTP)
                                                ▼
    ┌───────────────────────────────────────────────────────────────────────────┐
    │                          UniStorage Core Daemon                           │
    │                    (internal/daemon - Port 8080/Unix)                     │
    │   • Auth Middleware (Bearer Token & Anti-DNS Rebinding)                   │
    │   • REST API Controllers (/api/v1/...)                                    │
    ├─────────────────────────────────────┬─────────────────────────────────────┤
    │         Open-Source Core            │      Commercial Extensions          │
    │         (pkg/storage, sync, vault)  │      (Isolated Private Repo)        │
    ├─────────────────────────────────────┼─────────────────────────────────────┤
    │ • Universal Driver Interface        │ • Snapshot Backup Engine            │
    │ • Local FS Driver (anti-traversal)  │   (manifest.json, pruner, mutex)    │
    │ • S3 Multipart Driver (>16MB chunk) │ • Health & Uptime Probe             │
    │ • Argon2id + AES-256-GCM Vault      │   (Syscall disk stats, S3 ping)     │
    │ • Hybrid Sync Engine (Size/SHA256)  │ • Webhook Alert Dispatcher          │
    │ • Entitlement Boundary Contract     │ • Commercial License Validator      │
    │   (pkg/entitlement CommunityChecker)│   (Ed25519 Signature Checker)       │
    └─────────────────────────────────────┴─────────────────────────────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
        ┌───────────────────────┐               ┌───────────────────────┐
        │     Local Storage     │               │  S3-Compatible Cloud  │
        │ (Windows / Linux FS)  │               │  (AWS / MinIO / R2)   │
        └───────────────────────┘               └───────────────────────┘
```

---

## Key Features

- **Universal Driver Abstraction**: Unified primitives (`Read`, `Write`, `List`, `Delete`, `Stat`, `Stream`) for both local directories and cloud buckets.
- **Resilient Chunked Streaming**: Zero-OOM file transfers with automatic multipart splitting (>16 MB) and exponential backoff retries.
- **Argon2id + AES-256-GCM Vault**: Encrypted credential storage ensuring zero plaintext tokens on disk.
- **Hardened Local Daemon**: High-performance HTTP server protected against DNS rebinding, CORS hijacking, and unauthenticated requests.
- **Safe Synchronization**: Hybrid change detection (Size + ModTime or SHA-256) with automatic conflict retention in `.conflicts/`.
- **SSDLC from Day One**: Built-in SAST, SCA, Secret Scanning, Native Fuzz Testing, SBOM generation, and Cosign signature verification.
- **Non-Root Multi-Stage Docker**: Minimalist distroless runtime with UID/GID `10001:10001`.

---

## Open-Core Architecture

UniStorage embraces a transparent, dual-tier open-core model:
- **Open-Source Core (Apache 2.0)**: Contains all fundamental storage engines (`pkg/storage`), local FS and S3 drivers, encrypted vault (`pkg/vault`), resilient sync engine (`pkg/sync`), loopback daemon (`internal/daemon`), and CLI (`cmd/unistorage`). The OSS core has **zero** dependencies on proprietary code.
- **Entitlement Boundary (`pkg/entitlement`)**: An interface boundary contract separates community builds from commercial extensions (snapshots, telemetry probes, webhook dispatchers, license validation). Community binaries always run with unencumbered capabilities.

---

## Quickstart Guide

### Prerequisites
- **Go**: Version `1.22` or later (tested on Go `1.24`).
- **Docker & Docker Compose**: (Optional, for running local MinIO S3 mock).

### Building from Source

```bash
# Clone the repository
git clone https://github.com/aboutdevz/unistorage.git
cd unistorage

# Compile the CLI binary
go build -trimpath -ldflags="-s -w" -o bin/unistorage ./cmd/unistorage

# Verify installation
./bin/unistorage version
```

### Local Development Stack (MinIO + Docker)

Spin up an isolated MinIO S3 service and pre-configured test bucket:

```bash
# Start MinIO mock and UniStorage daemon
docker compose up -d

# Verify containers are healthy
docker compose ps
```
- **MinIO S3 API Endpoint**: `http://127.0.0.1:9000`
- **MinIO Console**: `http://127.0.0.1:9001` (User: `minioadmin` / Pass: `minioadmin`)
- **Default Dev Bucket**: `unistorage-dev`

---

## CLI Usage Guide

UniStorage commands use standard POSIX-compatible syntax:
```bash
unistorage [command] [subcommand] [flags]
```

### 1. Remote Management (`remote`)

Configure and manage encrypted remote profiles in the vault. Passwords and secret keys are encrypted before hitting disk.

```bash
# Add a Local Filesystem remote
unistorage remote add local-data local --path /var/data/storage

# Add an S3-compatible remote (MinIO / AWS / Cloudflare R2 / Ceph)
unistorage remote add minio-dev s3 \
  --endpoint http://127.0.0.1:9000 \
  --bucket unistorage-dev \
  --access-key minioadmin \
  --secret-key minioadmin \
  --region us-east-1 \
  --use-path-style

# List all configured remotes
unistorage remote list

# List configured remotes as structured JSON
unistorage remote list --json

# Remove a configured remote profile
unistorage remote remove minio-dev -f
```

### 2. Listing Objects (`ls`)

List objects and directories across local paths and remote targets:

```bash
# Basic listing of remote bucket root
unistorage ls minio-dev:

# Recursive listing with human-readable file sizes and timestamps
unistorage ls minio-dev:backups/ -r -l -H

# Output directory contents as structured JSON array
unistorage ls local-data:documents/ --json
```

### 3. Copying Files (`cp`)

Stream files between any combination of local paths and remote profiles without writing intermediate temp files:

```bash
# Copy single file from local to S3
unistorage cp ./report.pdf minio-dev:documents/report.pdf

# Copy file from S3 to local filesystem
unistorage cp minio-dev:documents/report.pdf ./downloads/report.pdf

# Copy directory recursively
unistorage cp ./assets/ minio-dev:static-assets/ -r

# Stream directly from S3 remote to another S3 remote
unistorage cp minio-dev:source/archive.tar.gz prod-s3:backups/archive.tar.gz
```

### 4. Resilient Synchronization (`sync`)

Synchronize source to destination with hybrid change detection and safety conflict preservation:

```bash
# Standard sync using Size + Modification Time
unistorage sync ./my-data minio-dev:sync-target

# Cryptographic sync with SHA-256 content verification
unistorage sync ./my-data minio-dev:sync-target --checksum

# Dry-run mode (simulate operations without modifying destination)
unistorage sync ./my-data minio-dev:sync-target --dry-run

# Delete orphaned files in destination that do not exist in source
unistorage sync ./my-data minio-dev:sync-target --delete

# Specify custom conflict backup directory (default: .conflicts)
unistorage sync ./my-data minio-dev:sync-target --conflict-dir /tmp/my-conflicts

# Set number of concurrent transfer workers (default: 4)
unistorage sync ./large-repo minio-dev:backups --workers 8 --json
```

### 5. Removing Objects (`rm`)

Delete files and directory trees safely:

```bash
# Delete a single object
unistorage rm minio-dev:temp/old-file.txt

# Recursively remove a remote directory prefix
unistorage rm minio-dev:temp/ -r -f

# Simulate removal with dry-run flag
unistorage rm minio-dev:obsolete-data/ -r --dry-run
```

### 6. Daemon Lifecycle (`daemon`)

Manage the local loopback daemon service:

```bash
# Start daemon in background
unistorage daemon start --port 8080

# Start daemon in foreground (ideal for Docker / systemd)
unistorage daemon start --foreground --port 8080

# Query daemon operational status and probe health endpoint
unistorage daemon status --json

# Gracefully stop the running background daemon
unistorage daemon stop
```

### 7. Version Inspection (`version`)

Display binary version, commit hash, build timestamp, and runtime environment:

```bash
# Plain text summary
unistorage version

# Full structured JSON output
unistorage version --json
```
Output:
```json
{
  "version": "0.1.0",
  "commit": "a1b2c3d",
  "build_time": "2026-09-05T00:00:00Z",
  "go_version": "go1.24.0",
  "compiler": "gc",
  "platform": "linux/amd64"
}
```

### Global Flags Reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `--config <path>` | | `~/.unistorage` | Base directory for vault and tokens |
| `--daemon-addr <url>` | | `http://127.0.0.1:8080` | Loopback daemon HTTP address |
| `--token <token>` | | Auto-detected | Bearer authorization token override |
| `--vault-passphrase <pass>` | | | Passphrase used to decrypt vault |
| `--json` | | `false` | Format CLI output as structured JSON |
| `--verbose` | `-v` | `false` | Enable verbose debug logging |
| `--quiet` | `-q` | `false` | Suppress non-essential informational messages |
| `--help` | `-h` | | Show help screen for command or subcommand |
| `--version` | | | Display binary version |

---

## Daemon REST API

When the UniStorage daemon runs, it exposes a local HTTP management API:

- **Base URL**: `http://127.0.0.1:8080`
- **Authentication**: `Authorization: Bearer <token>`
- **Token Location**: Stored at `~/.unistorage/daemon.token` (permissions `0600`).
- **Security Protections**: Rejects all non-loopback Host headers (`127.0.0.1`, `localhost`) to defeat DNS-rebinding exploits.

### Core Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Health check and version probe (unauthenticated) |
| `GET` | `/api/v1/remotes` | List all configured storage remote profiles |
| `POST` | `/api/v1/remotes` | Register new remote profile in vault |
| `DELETE` | `/api/v1/remotes/{name}` | Delete remote profile from vault |
| `GET` | `/api/v1/storage/list` | List objects within remote or local target |
| `POST` | `/api/v1/storage/copy` | Stream copy between source and destination |
| `POST` | `/api/v1/storage/sync` | Trigger synchronization job |
| `DELETE` | `/api/v1/storage/remove` | Delete file or directory tree |

### Example API Request

```bash
# Read auto-generated bearer token
TOKEN=$(cat ~/.unistorage/daemon.token)

# Query configured remotes
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8080/api/v1/remotes | jq .
```

---

## Production Container Deployment

Build and run a production-ready, non-root distroless container:

```bash
# Build multi-stage container image
docker build -t unistorage:latest -f Dockerfile .

# Run hardened container with dedicated non-root UID (10001:10001)
docker run -d \
  --name unistorage-daemon \
  --restart unless-stopped \
  --user 10001:10001 \
  -p 127.0.0.1:8080:8080 \
  -v unistorage-data:/data \
  unistorage:latest
```

---

## Security & SSDLC

UniStorage is engineered under a strict **Secure Software Development Life Cycle (SSDLC)**:

- **Static Application Security Testing (SAST)**: `golangci-lint` and `gosec` run on every pull request.
- **Software Composition Analysis (SCA)**: `govulncheck` continuously monitors third-party Go dependencies for CVEs.
- **Automated Secret Detection**: `gitleaks` audits all commits and pull requests to prevent credential leaks.
- **Path Traversal Fuzz Testing**: Native Go fuzzing (`FuzzPathSanitizer`) validates path sanitizers against directory escapes, null-byte injections, and Windows device-name collisions (`CON`, `NUL`, `AUX`).
- **Software Supply Chain Provenance**: Automated CycloneDX SBOM generation and cryptographic release signing using **Cosign**.
- **Formal Threat Modeling**: Documented STRIDE analysis available in [docs/threat-model.md](docs/threat-model.md).

For vulnerability reporting, please review our [Security Policy](SECURITY.md).

---

## Development Roadmap

### Phase 1: MVP Core (Completed)
- [x] Universal storage abstraction engine (`pkg/storage`).
- [x] Local filesystem driver with path sanitization and boundary defense.
- [x] S3-compatible cloud storage driver (AWS S3, MinIO, Cloudflare R2, Ceph).
- [x] Constant-memory streaming engine with automatic multipart upload (>16 MB).
- [x] Argon2id + AES-256-GCM encrypted credential vault (`pkg/vault`).
- [x] Loopback HTTP daemon protected against DNS-rebinding and CORS drive-bys.
- [x] Resilient sync with hybrid change detection and `.conflicts/` safety retention.
- [x] Modular open-core entitlement contract (`pkg/entitlement`).
- [x] Multi-stage non-root distroless Docker deployment & Compose dev stack.
- [x] Full SSDLC automated CI/CD quality gate (SAST, SCA, Gitleaks, Fuzzing).

### Phase 2: Web Dashboard & Real-Time Telemetry (Near-Term)
- [ ] Modern Web UI Dashboard built with React 18, TypeScript, and Tailwind CSS.
- [ ] Real-time WebSocket file browser, interactive uploads, and progress visualization.
- [ ] Native Prometheus metrics endpoint (`/metrics`) and OpenTelemetry trace exports.
- [ ] Bandwidth throttling and configurable chunk transfer rate limits.

### Phase 3: Advanced Storage Protocols & Cloud Providers
- [ ] SFTP (SSH File Transfer Protocol) driver.
- [ ] WebDAV driver (Nextcloud, ownCloud, NAS support).
- [ ] Network filesystem drivers: SMB/CIFS and NFS mounts.
- [ ] Native cloud driver integration for Microsoft Azure Blob Storage.
- [ ] Native cloud driver integration for Google Cloud Storage (GCS).

### Phase 4: Desktop GUI & Mobile Companion Apps
- [ ] Lightweight cross-platform Desktop client powered by Tauri (Rust + Web frontend).
- [ ] Native system tray integration with background sync scheduling.
- [ ] Mobile companion app (iOS & Android) with automatic camera roll backup and vault encryption.

### Phase 5: Distributed Multi-Cloud Mesh & P2P Replication
- [ ] Active-active multi-cloud sync mesh with distributed consensus.
- [ ] Content-addressable chunk deduplication (CAS) across heterogeneous backends.
- [ ] Peer-to-peer (P2P) edge sync protocol for air-gapped and hybrid environments.

---

## Contributing & Community

Contributions are welcome! Please check out the following resources to get started:

- **[CONTRIBUTING.md](CONTRIBUTING.md)**: Development setup, testing workflows, and pull request guidelines.
- **[docs/repository-setup.md](docs/repository-setup.md)**: Maintainer guide for GitHub repo settings, branch protection, and release procedures.
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)**: Community pledge and standards.
- **[SUPPORT.md](SUPPORT.md)**: Where to ask questions and get community support.
- **[CHANGELOG.md](CHANGELOG.md)**: Release notes and version history.
- **[SECURITY.md](SECURITY.md)**: Vulnerability disclosure guidelines.

Join our [GitHub Discussions](https://github.com/aboutdevz/unistorage/discussions) to brainstorm ideas and discuss the project roadmap.

---

## License

UniStorage Open-Source Core is licensed under the **[Apache License, Version 2.0](LICENSE)**.

```
Copyright 2026 UniStorage Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
