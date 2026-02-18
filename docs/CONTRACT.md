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
| `Set Remote` | `<session>` `<command>` | Queues command for later execution (no SSH call). |
| `Execute Remote` | `<session>` `[command]` | With command: executes immediately. Without: joins queued commands with `&&` and executes. FAIL on `exit_code != 0`. |
| `Execute Remote And Continue` | `<session>` `[command]` | Same as `Execute Remote`, but never fails on nonzero `exit_code`. |

### Verification – stdout

| Keyword | Parameters | Description |
|---------|-----------|-------------|
| `Verify Remote Response` | `<session>` `<expected>` | EXACT match on `stdout` |
| `Verify Remote Response WCM` | `<session>` `<pattern>` | Wildcard pattern match on `stdout` (`*` = any chars, `?` = one char) |
| `Verify Remote Response REGX` | `<session>` `<regex>` | Regex match on `stdout` |

### Verification – stderr

| Keyword | Parameters | Default | Description |
|---------|-----------|---------|-------------|
| `Verify Remote Stderr` | `<session>` `[expected]` | `$EMPTY` | EXACT match on `stderr`. Without `expected`: asserts stderr is empty. |
| `Verify Remote Stderr WCM` | `<session>` `[pattern]` | `$EMPTY` | Wildcard pattern match on `stderr` (`*` = any chars, `?` = one char) |
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

| Keyword | Parameters | Default | Description |
|---------|-----------|---------|-------------|
| `Verify Remote File Exists` | `<session>` `<remote_path>` `[expected]` | `YES` | Asserts file exists (`YES`) or does not exist (`NO`) |
| `Verify Remote Directory Exists` | `<session>` `<remote_dir>` `[expected]` | `YES` | Asserts directory exists (`YES`) or does not exist (`NO`) |

The ``expected`` parameter accepts ``YES``/``NO``, ``TRUE``/``FALSE``, or ``1``/``0`` (case-insensitive).
This follows the OKW ``YES/NO`` existence model defined in ``okw-contract-utils``.

### File Transfer – Clear (delete files, keep directory structure)

| Keyword | Parameters | Description |
|---------|-----------|-------------|
| `Clear Remote Directory` | `<session>` `<remote_dir>` | Deletes files directly in the directory (not in subdirectories) |
| `Clear Remote Directory Recursively` | `<session>` `<remote_dir>` | Deletes all files recursively, keeps entire directory tree |

### File Transfer – Remove (idempotent)

All remove keywords are **idempotent**: if the target does not exist, they log
an info message and return PASS (the target state "absent" is already reached).
Use `Verify Remote File Exists` / `Verify Remote Directory Exists` to
explicitly assert presence or absence.

| Keyword | Parameters | Description |
|---------|-----------|-------------|
| `Remove Remote File` | `<session>` `<remote_path>` | Removes a file (idempotent) |
| `Remove Remote Directory` | `<session>` `<remote_dir>` | Removes an empty directory (idempotent) |
| `Remove Remote Directory Recursively` | `<session>` `<remote_dir>` | Removes a directory and all its contents (idempotent) |

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
  - For `Set Remote`: the command is not added to the queue (PASS).
- For `Execute Remote` / `Execute Remote And Continue`: execution is skipped (no SSH call, `last_response` unchanged, PASS).
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
- `Execute Remote` fails immediately (AssertionError) on `exit_code != 0`, after logging and storing the response.
- `Execute Remote And Continue` never fails on nonzero `exit_code`.

## ASR Logging

Alle Keywords loggen ihre Aktionen und Ergebnisse im Robot Framework Log (`log.html`).
Die Ausgaben sind mehrzeilig und folgen einem festen Format pro Keyword-Kategorie.

### Execution Keywords

`Execute Remote` / `Execute Remote And Continue` loggen:

```
command:
<der ausgefuehrte Befehl>
stdout:
<Standardausgabe>
stderr:
<Fehlerausgabe>
exit_code: <0|1|...>
duration_ms: <Dauer in Millisekunden>
```

- stdout/stderr werden normalisiert (`\r\n` → `\n`, rstrip) bevor sie gespeichert und geloggt werden.

### SFTP Verify Keywords

`Verify Remote File Exists` / `Verify Remote Directory Exists` loggen:

```
command:
SFTP stat()
path:
<der geprueft Pfad>
exists: <YES|NO>
expected: <YES|NO>
```

- `command`: Die SFTP-Operation (`stat()`) die ausgefuehrt wird.
- `path`: Der geprueft Remote-Pfad.
- `exists`: **Ist-Wert** – was SFTP tatsaechlich auf dem Server gefunden hat.
- `expected`: **Soll-Wert** – was der Testfall erwartet.

### SFTP Remove Keywords

`Remove Remote File` loggt:

```
command:
SFTP remove()
path:
<der geloeschte Pfad>
result: removed
```

`Remove Remote Directory Recursively` loggt pro Eintrag:

```
SFTP remove(): <Dateipfad>
SFTP rmdir(): <Verzeichnispfad>
```

Wenn das Ziel nicht existiert (idempotent):

```
File does not exist (already absent): <Pfad>
Directory does not exist (already absent): <Pfad>
```

### SFTP Clear Keywords

`Clear Remote Directory` / `Clear Remote Directory Recursively` loggen pro geloeschte Datei:

```
SFTP remove(): <Dateipfad>
```

Danach die Transfer-Zusammenfassung (via `last_response`):

```
action: clear_dir | clear_dir_recursive
remote_dir: <Pfad>
files_removed: <Anzahl>
duration_ms: <Dauer>
```

### SFTP Transfer Keywords

`Put Remote File` / `Get Remote File` loggen:

```
action: put_file | get_file
local_path: <lokaler Pfad>
remote_path: <Remote-Pfad>
bytes: <Anzahl Bytes>
duration_ms: <Dauer>
```

`Put Remote Directory` / `Get Remote Directory` loggen:

```
action: put_dir | get_dir
local_dir: <lokales Verzeichnis>
remote_dir: <Remote-Verzeichnis>
bytes_total: <Gesamtbytes>
files_transferred: <Anzahl Dateien>
dirs_created: <Anzahl Verzeichnisse>
duration_ms: <Dauer>
```
