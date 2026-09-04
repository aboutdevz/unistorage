# Getting Support for UniStorage

Thank you for using UniStorage! Here are the recommended ways to get help, ask questions, and report issues.

---

## Channels for Help

### 1. GitHub Discussions (Recommended for Questions)
For general questions, configuration help, usage best practices, and architecture ideas:
- Visit [GitHub Discussions](https://github.com/aboutdevz/unistorage/discussions).
- Search existing threads to see if your question has already been answered.
- Participate in community roadmap brainstorming.

### 2. GitHub Issues (Bug Reports & Feature Requests)
If you believe you encountered a bug or want to propose a new feature:
- Check existing [Open Issues](https://github.com/aboutdevz/unistorage/issues) first to avoid duplicates.
- Use our structured issue forms:
  - [Bug Report](.github/ISSUE_TEMPLATE/bug_report.yml)
  - [Feature Request](.github/ISSUE_TEMPLATE/feature_request.yml)
- Please provide exact reproduction steps, logs, OS, and backend details (e.g. MinIO vs AWS S3).

### 3. Security Vulnerabilities
**Do NOT file public issues for security vulnerabilities.**
- Follow the private reporting instructions in [SECURITY.md](SECURITY.md) or submit via [GitHub Private Vulnerability Reporting](https://github.com/aboutdevz/unistorage/security/advisories/new).
- Our team responds within 24 hours to acknowledge reports.

---

## Diagnostic Checklist Before Asking

When reporting an issue, please run these commands to collect environment details:

```bash
# 1. Check UniStorage version and build metadata
unistorage version --json

# 2. Check daemon status (if daemon is running)
unistorage daemon status --json

# 3. Check system environment
go version
docker compose version
```
