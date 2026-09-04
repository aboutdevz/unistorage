# Security Policy

## Supported Versions

UniStorage releases follow Semantic Versioning. The following versions currently receive security maintenance and vulnerability patches:

| Version | Supported          | Security Maintenance |
| ------- | ------------------ | -------------------- |
| 0.1.x   | :white_check_mark: | Active MVP Support   |
| < 0.1.0 | :x:                | Deprecated           |

---

## Reporting a Vulnerability

The UniStorage team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose findings.

### Reporting Channels

To report a security vulnerability, please use one of the following confidential channels:
- **Email**: Send encrypted reports to `security@aboutdevz.org`
- **GitHub**: Use [GitHub Private Vulnerability Reporting](https://github.com/aboutdevz/unistorage/security/advisories/new)

**CRITICAL: Please DO NOT submit public GitHub issues or discussions for security vulnerabilities.** Public exposure endangers users before a fix can be prepared and released.

---

## Disclosure Guidelines

When submitting a vulnerability report, please include as much information as possible to help us reproduce and remediate the issue quickly:
1. **Description**: Clear description of the vulnerability, threat model implications, and potential attack vector.
2. **Reproduction Steps / PoC**: Step-by-step instructions or minimal proof-of-concept (PoC) demonstrating the exploit.
3. **Impact Assessment**: Estimated severity and CVSS 3.1 vector or score if available.
4. **Affected Components**: Specific packages or subsystems involved (e.g., `cmd/unistorage`, `pkg/storage`, `pkg/vault`, `internal/daemon`).
5. **Environment**: Operating system, Go version, and storage backends used during reproduction.

---

## Response & Remediation SLA

We adhere to the following coordinated disclosure timelines:

- **Initial Acknowledgment**: Within 24 hours of report receipt.
- **Severity Triage & Status Update**: Within 72 hours of report receipt.
- **Fix & Advisory Release**: Within 30 days of confirmed reproduction and triage.

Security patches will be released via new patch versions along with a coordinated GitHub Security Advisory. Credit will be given to the reporter in the release notes unless anonymity is requested.
