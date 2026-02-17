# CONTRACT – robotframework-okw-remote-ssh

This document defines the public contract of `robotframework-okw-remote-ssh`.

## Keywords (Public API)

### Session Lifecycle

| Keyword | Parameters | Description |
|---------|-----------|-------------|
| `Open Remote Session` | `<session>` `<config_ref>` | Opens a named session using `<config_dir>/<config_ref>.yaml` |
| `Close Remote Session` | `<session>` | Closes session and releases resources |

### Execution

| Keyword | Parameters | Description |
|---------|-----------|-------------|
| `Set Remote` | `<session>` `<command>` | Executes command. FAIL on `exit_code != 0`. |
| `Set Remote And Continue` | `<session>` `<command>` | Executes command. Never fails on nonzero `exit_code`. |

### Verification – stdout

| Keyword | Parameters | Description |
|---------|-----------|-------------|
| `Verify Remote Response` | `<session>` `<expected>` | EXACT match on `stdout` |
| `Verify Remote Response WCM` | `<session>` `<pattern>` | Wildcard/contains match on `stdout` |
| `Verify Remote Response REGX` | `<session>` `<regex>` | Regex match on `stdout` |

### Verification – stderr

| Keyword | Parameters | Default | Description |
|---------|-----------|---------|-------------|
| `Verify Remote Stderr` | `<session>` `[expected]` | `$EMPTY` | EXACT match on `stderr`. Without `expected`: asserts stderr is empty. |
| `Verify Remote Stderr WCM` | `<session>` `[pattern]` | `$EMPTY` | Wildcard/contains match on `stderr` |
| `Verify Remote Stderr REGX` | `<session>` `[regex]` | `$EMPTY` | Regex match on `stderr` |

### Verification – exit_code / duration

| Keyword | Parameters | Description |
|---------|-----------|-------------|
| `Verify Remote Exit Code` | `<session>` `<expected>` | Numeric exact compare |
| `Verify Remote Duration` | `<session>` `<expr>` | Supports `>`, `>=`, `<`, `<=`, `==` and range `a..b` |

### Memorize

| Keyword | Parameters | Description |
|---------|-----------|-------------|
| `Memorize Remote Response Field` | `<session>` `<field>` `<key>` | Stores response field in `$MEM{KEY}` |

### File Transfer – Upload / Download

| Keyword | Parameters | Description |
|---------|-----------|-------------|
| `Put Remote File` | `<session>` `<local_path>` `<remote_path>` | Uploads a file via SFTP |
| `Get Remote File` | `<session>` `<remote_path>` `<local_path>` | Downloads a file via SFTP |
| `Put Remote Directory` | `<session>` `<local_dir>` `<remote_dir>` | Recursively uploads a directory via SFTP |
| `Get Remote Directory` | `<session>` `<remote_dir>` `<local_dir>` | Recursively downloads a directory via SFTP |

### File Transfer – Verify

| Keyword | Parameters | Description |
|---------|-----------|-------------|
| `Verify Remote File Exists` | `<session>` `<remote_path>` | Asserts that a file exists on the remote host |
| `Verify Remote Directory Exists` | `<session>` `<remote_dir>` | Asserts that a directory exists on the remote host |

### File Transfer – Remove

| Keyword | Parameters | Description |
|---------|-----------|-------------|
| `Remove Remote File` | `<session>` `<remote_path>` | Removes a file on the remote host |
| `Remove Remote Directory` | `<session>` `<remote_dir>` | Removes an empty directory on the remote host |
| `Remove Remote Directory Recursively` | `<session>` `<remote_dir>` | Removes a directory and all its contents |

## File Transfer Details

### `last_response` Structure

File transfer keywords store transfer metrics in `last_response`:

**Single file (`Put Remote File`, `Get Remote File`):**
- `action`: `put_file` or `get_file`
- `local_path`, `remote_path`: resolved paths
- `bytes`: number of bytes transferred
- `duration_ms`: transfer duration in milliseconds

**Directory (`Put Remote Directory`, `Get Remote Directory`):**
- `action`: `put_dir` or `get_dir`
- `local_dir`, `remote_dir`: resolved paths
- `files_transferred`: total number of files
- `dirs_created`: total number of directories created
- `bytes_total`: total bytes transferred
- `duration_ms`: transfer duration in milliseconds

### Transfer Behavior

- All transfers are **synchronous** and **deterministic**.
- SFTP errors (IO, permission, path not found) cause immediate **FAIL**.
- Remote parent directories are created automatically (like `mkdir -p`).
- `Remove Remote Directory` only removes empty directories; use `Remove Remote Directory Recursively` for non-empty directories.

## OKW Global Tokens

This library follows the OKW Global Token Model defined in `okw-contract-utils`.

Supported tokens:

- `$IGNORE` (supported)
  - For `Set Remote` / `Set Remote And Continue`: execution is skipped (no SSH call, `last_response` unchanged, PASS).
  - For verify keywords with an expected/pattern/expr parameter: verification is skipped (no-op, PASS).
  - For file transfer keywords: if any path parameter expands to `$IGNORE`, the transfer/verify/remove is skipped (PASS).

- `$EMPTY` (supported)
  - For verify keywords: `$EMPTY` means the checked field must be empty.

Not supported:

- `$DELETE` (not supported)
  - This library does not implement delete semantics.

## Token Evaluation Order

For parameters of type Value/Expected/Command:

1. Robot variable expansion (e.g., `${IGNORE}` → `$IGNORE`)
2. OKW value expansion (`$MEM{KEY}` → stored value)
3. Token parsing (`$IGNORE`, `$EMPTY`)
4. Keyword execution / verification

## Value Expansion

All Value, Command, Expected, and Expr parameters support `$MEM{KEY}` expansion (OKW Global Value Expansion Model).
Missing keys cause FAIL (no silent fallback).

## Default Semantics

- `Verify Remote Stderr <session>` without expected parameter: asserts stderr is empty.
- `Set Remote` fails immediately (AssertionError) on `exit_code != 0`, after logging and storing the response.
- `Set Remote And Continue` never fails on nonzero `exit_code`.

## ASR Logging

`Set Remote` / `Set Remote And Continue` log in the same keyword step:
- `command`, `stdout`, `stderr`, `exit_code`, `duration_ms`
- stdout/stderr are normalized (`\r\n` → `\n`, rstrip) before storing/logging.
