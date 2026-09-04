# UniStorage (Unified Storage Engine)

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![SSDLC](https://img.shields.io/badge/SSDLC-Hardened-success.svg)](SECURITY.md)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](Dockerfile)

> **UniStorage** adalah platform penyimpanan terpadu (*unified storage platform*) open-source berperforma tinggi yang mengabstraksikan berbagai backend penyimpanan (Local Filesystem, On-Premises, AWS S3, MinIO, Cloudflare R2, Ceph) ke dalam satu antarmuka universal yang konsisten, aman, dan dapat dikelola via CLI, REST/gRPC Daemon, dan Web/Desktop/Mobile di masa mendatang.

---

## 🌟 Fitur Utama (MVP)

- **Universal Driver Abstraction**: Operasi terpadu (`Read`, `Write`, `List`, `Delete`, `Stat`, `Stream`) untuk semua penyedia storage.
- **Resilient Chunked Streaming**: Dukungan transfer file besar dengan alokasi memori konstan (anti-OOM), S3 multipart otomatis (>16MB), dan retry exponential backoff.
- **Hardened Local Daemon**: API daemon loopback (`127.0.0.1:8080`) yang dilindungi auto-generated Bearer token (`~/.unistorage/daemon.token`, mode `0600`) dan pertahanan anti-DNS-rebinding.
- **Safe Synchronization (`unistorage sync`)**: Deteksi perubahan hybrid (Size + ModTime & flag `--checksum` SHA-256) dengan backup otomatis file konflik ke `.conflicts/`.
- **Argon2id Encrypted Vault**: Kredensial access key dan secret token remote disimpan terenkripsi dengan AES-256-GCM.
- **Open-Core Architecture**:
  - **OSS Core (`pkg/entitlement`)**: Kontrak antarmuka `EntitlementChecker`, fallback `CommunityChecker` unencumbered, dan hooking build tag `//go:build enterprise`.
  - **Commercial Extensions (Private Repo)**: Fitur enterprise (Snapshot Backup Engine, Disk Health & Telemetry Probe, Webhook Alerts, Ed25519 License Validation) diisolasi 100% pada repository privat terpisah demi proteksi IP dan kepatuhan dual-licensing.
- **SSDLC (Secure Software Development LifeCycle)**: Pipeline CI otomatis yang mencakup SAST (`gosec`, `golangci-lint`), SCA (`govulncheck`), Secret scanner (`gitleaks`), Go Native Fuzzing (`FuzzPathSanitizer`), SBOM CycloneDX, dan penandatanganan Cosign.
- **Docker-Ready**: Multi-stage non-root distroless container untuk production dan `docker-compose.yml` untuk development lokal (terintegrasi dengan MinIO mock S3).

---

## 🏗️ Arsitektur Sistem

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
    │         (pkg/storage, sync, vault)  │      (Separate Private Repo)        │
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

## 🚀 Panduan Memulai Cepat (Quickstart)

### Prasyarat
- Go 1.22 atau lebih baru
- Docker & Docker Compose (opsional, untuk stack MinIO lokal)

### 1. Build Binary
```bash
# Clone repository
git clone https://github.com/aboutdevz/unistorage.git
cd unistorage

# Build CLI
make build
# atau manual: go build -o bin/unistorage ./cmd/unistorage
```

### 2. Jalankan Daemon
```bash
# Menjalankan daemon di background
./bin/unistorage daemon start

# Cek status dan token
./bin/unistorage daemon status
```

### 3. Konfigurasi Remote Storage
```bash
# Tambah remote local storage
./bin/unistorage remote add my-local local --path /path/to/data

# Tambah remote S3-compatible (MinIO / AWS S3)
./bin/unistorage remote add my-s3 s3 \
  --endpoint http://localhost:9000 \
  --bucket test-bucket \
  --access-key minioadmin \
  --secret-key minioadmin \
  --region us-east-1
```

### 4. Operasi File & Sinkronisasi
```bash
# List file di remote
./bin/unistorage ls my-s3:/

# Copy file
./bin/unistorage cp my-local:/document.pdf my-s3:/backups/document.pdf

# Sinkronisasi direktori dengan checksum verification
./bin/unistorage sync my-local:/source my-s3:/backup --checksum
```

---

## 🐳 Docker Deployment (Dev & Prod)

### Development Environment (Docker Compose)
Menjalankan UniStorage Daemon bersama MinIO S3 lokal:
```bash
docker compose up -d
```
- **MinIO Console**: http://localhost:9001 (User: `minioadmin`, Pass: `minioadmin`)
- **MinIO S3 API**: http://localhost:9000
- **UniStorage Daemon**: http://localhost:8080
- **Prometheus Metrics**: http://localhost:8080/metrics

### Production Container (Multi-Stage Distroless)
Build container image non-root yang aman dan minimalis:
```bash
docker build -t unistorage:latest -f Dockerfile .
docker run -d -p 8080:8080 --user 10001:10001 -v unistorage-data:/data unistorage:latest
```

---

## 🔒 Keamanan & SSDLC (Secure Software Development LifeCycle)

Repositori ini menerapkan standar SSDLC ketat:
- **SAST**: `golangci-lint` dan `gosec` terintegrasi di pipeline CI.
- **SCA**: `govulncheck` mendeteksi CVE pada dependensi Go.
- **Secret Scanning**: `gitleaks` memblokir kredensial yang tidak sengaja ter-commit.
- **Fuzz Testing**: Go native fuzzing (`FuzzPathSanitizer`) memastikan ketahanan terhadap eksploitasi path-traversal.
- **Credential Vault**: Enkripsi AES-256-GCM berstandar militer dengan derivasi kunci Argon2id.
- **Supply Chain**: Pembuatan SBOM otomatis (CycloneDX) dan penandatanganan rilis dengan Cosign.

Untuk pelaporan kerentanan, silakan baca panduan di [SECURITY.md](SECURITY.md).

---

## 🗺️ Roadmap Pengembangan

- [x] **Fase 1 (MVP)**: Core Engine, Local FS & S3 Drivers, Resilient Streaming, Secure CLI/Daemon, Modular Enterprise Extensions (Backup & Health), SSDLC Pipeline, Docker Dev/Prod.
- [ ] **Fase 2**: Web UI Dashboard (React/Tailwind) terhubung ke REST/WebSocket Daemon.
- [ ] **Fase 3**: Driver On-Premises Lanjutan (SMB, NFS, WebDAV, SFTP, Google Drive, Azure Blob).
- [ ] **Fase 4**: Desktop Client (Tauri) dan Mobile Application (Flutter/Native Android & iOS).
