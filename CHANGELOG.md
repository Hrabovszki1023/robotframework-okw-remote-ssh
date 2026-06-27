# Changelog

All notable changes to this project will be documented in this file.

## [0.4.1] - 2026-06-24

### CI/CD
- Add Stage 1 CI workflow for automated testing
- Add Stage 2 release workflow (TestPyPI upload on `v*` tag)

### Fixes
- Fix CI: add dummy secrets file for contract tests

## [0.4.0] - 2026-06-22

### Features
- `Set Remote File Mode` / `Verify Remote File Mode` /
  `Memorize Remote File Mode` — file permissions keywords
- `Close All Remote Sessions` — close all open SSH sessions at once
- `Verify Remote Directory Content` / `Memorize Remote Directory Content`
  — directory content verification and memorize

### Docs
- Add AI Test Generation section to libdoc class docstring
- Add Gitea issue template for new keywords
- Add SSHLibrary feature comparison

## [0.3.2] - 2026-06-22

### CI/CD
- Add libdoc and PyPI publish GitHub Actions workflows

### Docs
- Add okw-examples link to libdoc docstring

## [0.3.1] - 2026-06-22

### Docs
- Translate library docstring and README to English
- Remove local test generator prompt (centralized in okw4robot)

## [0.3.0] - 2026-06-21

### Highlights
- Three-phase model: Set Remote → Execute Remote → Verify/Memorize
- Structured ASR logging for all SFTP keywords

### Features
- 8 SFTP file transfer keywords (upload, download, remove, rename, ...)
- `Clear Remote Directory` / `Clear Remote Directory Recursively`
- `Verify Remote File Exists` / `Verify Remote Directory Exists`
  with YES/NO expected parameter
- Idempotent Remove keywords (no fail if target absent)
- WCM wildcard matching (`*` and `?` support) for all verify keywords
- OKW token handling (`$IGNORE`, `$EMPTY`) and `$MEM{KEY}` expansion
- Complete keyword contract with negative tests

### Docs
- Libdoc-compatible docstrings with `.robot` examples for all keywords
- Session Management and Secrets documentation with abstract/concrete examples
- KI-Testgenerator system prompt

## [0.2.0] - 2026-05-15

### Features
- Initial release: SSH command execution, verification, memorize keywords
- YAML-based session configuration with secrets management
- Paramiko backend
