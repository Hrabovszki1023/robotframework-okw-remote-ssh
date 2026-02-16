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

## OKW Global Tokens

This library follows the OKW Global Token Model defined in `okw-contract-utils`.

Supported tokens:

- `$IGNORE` (supported)
  - For `Set Remote` / `Set Remote And Continue`: execution is skipped (no SSH call, `last_response` unchanged, PASS).
  - For verify keywords with an expected/pattern/expr parameter: verification is skipped (no-op, PASS).

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
