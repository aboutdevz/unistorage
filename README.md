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
- **Open-Core Enterprise Extensions**:
  - **Snapshot Backup Engine**: Backup otomatis terjadwal (cron), format pohon snapshot dengan `manifest.json`, lock mutex anti-double run, dan retensi $N$ snapshot otomatis.
  - **Disk Health & Telemetry Probe**: Monitoring kapasitas disk lokal via OS syscall (`GetDiskFreeSpaceEx`/`Statfs`), probe latensi S3, endpoint `/metrics` Prometheus, serta JSON webhook alert dispatcher untuk status WARNING/CRITICAL.
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
    │   • Prometheus /metrics Exporter                                          │
    │   • REST API Controllers (/api/v1/...)                                    │
    ├─────────────────────────────────────┬─────────────────────────────────────┤
    │         Open-Source Core            │      Modular Enterprise Layer       │
    │         (pkg/storage)               │      (pkg/enterprise)               │
    ├─────────────────────────────────────┼─────────────────────────────────────┤
    │ • Universal Driver Interface        │ • Snapshot Backup Engine            │
    │ • Pluggable Driver Registry         │   (manifest.json, pruner, mutex)    │
    │ • Local FS Driver (anti-traversal)  │ • Health & Uptime Probe             │
    │ • S3 Multipart Driver (>16MB chunk) │   (Syscall disk stats, S3 ping)     │
    │ • Argon2id + AES-256-GCM Vault      │ • Webhook Alert Dispatcher          │
    │ • Hybrid Sync Engine (Size/SHA256)  │ • Feature-Gate Entitlement Checker  │
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
