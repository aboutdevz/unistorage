## Pull Request Description

### Summary of Changes
<!-- Brief summary of what was changed, added, or fixed -->

### Type of Change
- [ ] `feat`: New feature / capability
- [ ] `fix`: Bug fix
- [ ] `docs`: Documentation updates
- [ ] `perf`: Performance optimization
- [ ] `refactor`: Code restructuring without behavioral changes
- [ ] `test`: New or updated tests
- [ ] `ci`: CI/CD pipeline or build configuration

---

## SSDLC & Quality Checklist

Please confirm that all items have been verified prior to requesting review:

- [ ] **Tests Passing**: Verified with `go test -count=1 ./...`
- [ ] **Race Detector**: Ran `go test -race ./...` (or verified via CI matrix)
- [ ] **SAST**: `gosec` and `golangci-lint` pass with zero findings
- [ ] **SCA**: `govulncheck ./...` reports 0 vulnerabilities
- [ ] **Secrets**: No tokens, private keys, or credentials committed
- [ ] **Path Traversal / Sanitization**: New paths validated against `storage.SanitizePath`
- [ ] **Documentation**: Updated `README.md`, `docs/`, or code comments where appropriate
- [ ] **Backwards Compatibility**: No breaking changes to existing `Driver` or `Vault` contracts

---

## Verification Evidence
<!-- Provide command outputs or test run logs confirming changes -->
```bash
go test -v -count=1 ./...
```
