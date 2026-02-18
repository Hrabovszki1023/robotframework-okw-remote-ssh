# robotframework-okw-remote-ssh

Standalone Robot Framework library for deterministic, synchronous remote interaction via SSH.

Session-based command execution, structured verification (stdout, stderr, exit code, duration),
and SFTP file transfer. Designed for CI pipelines, infrastructure validation, and cross-platform
automation (Linux, macOS, Windows with OpenSSH).

**[Keyword Documentation (Libdoc)](https://hrabovszki1023.github.io/robotframework-okw-remote-ssh/RemoteSshLibrary.html)**

## Features

- **Session-based** SSH connections via Paramiko
- **Strict separation** of execution and verification
- **Command queuing**: `Set Remote` collects commands, `Execute Remote` sends them in one SSH call (preserves shell context)
- **Three match modes**: EXACT, WCM (wildcard: `*`, `?`), REGX (regex)
- **SFTP file transfer**: upload, download, verify, clear, remove (files and directories)
- **OKW token support**: `$IGNORE` (skip), `$EMPTY` (assert empty)
- **Value expansion**: `$MEM{KEY}` placeholders across all parameters
- **No GUI coupling**, no dependency on OKW Core

## Drei-Phasen-Modell

Alle Keywords folgen einem festen Zusammenspiel:

| Phase | Keywords | Aufgabe |
|-------|----------|---------|
| **Vorbereiten** | `Set Remote` | Kommandos sammeln (kein SSH-Aufruf) |
| **Ausführen** | `Execute Remote`, `Execute Remote And Continue` | Kommandos absenden, Ergebnis speichern |
| **Prüfen** | `Verify Remote Response`, `Verify Remote Stderr`, `Verify Remote Exit Code`, ... | Gespeichertes Ergebnis auswerten |

> **Hinweis:** *Vorbereiten* ist optional – `Execute Remote` kann auch direkt mit einem Kommando aufgerufen werden.
> Werden mehrere `Set Remote` gesammelt, baut `Execute Remote` sie mit `&&` zusammen und schickt sie als **einen** SSH-Aufruf.
> So bleibt der Shell-Kontext (Arbeitsverzeichnis, Variablen) erhalten.

## Installation

```bash
pip install robotframework-okw-remote-ssh
```

## Quick Start

```robot
*** Settings ***
Library    robotframework_okw_remote_ssh.RemoteSshLibrary

*** Test Cases ***
Single Command
    Open Remote Session      myhost    my_server
    Execute Remote           myhost    echo Hello
    Verify Remote Response   myhost    Hello
    Close Remote Session     myhost

Multi Command With Context
    Open Remote Session          myhost    my_server
    Set Remote                   myhost    cd /opt/app
    Set Remote                   myhost    ls -la
    Execute Remote               myhost
    Verify Remote Response WCM   myhost    *app*
    Close Remote Session         myhost

Tolerate Expected Errors
    Open Remote Session              myhost    my_server
    Execute Remote And Continue      myhost    cat /no/such/file
    Verify Remote Exit Code          myhost    1
    Verify Remote Stderr WCM         myhost    *No such file*
    Close Remote Session             myhost
```

## Session Configuration

Sessions are configured via YAML files in `remotes/` (or a custom config directory).

Example `remotes/my_server.yaml`:

```yaml
host: 10.0.0.1
port: 22
username: testuser
auth:
  type: password
  secret_id: "my_server/testuser"
```

Passwords are stored separately in `~/.okw/secrets.yaml` (never in the repository).

## Keywords

### Session Lifecycle

| Keyword | Description |
|---------|-------------|
| `Open Remote Session` | Opens a named SSH session using a YAML config reference |
| `Close Remote Session` | Closes the session and releases all resources |

### Execution

| Keyword | Description |
|---------|-------------|
| `Set Remote` | Queues a command for later execution (no SSH call). Supports `$MEM{KEY}` expansion. |
| `Execute Remote` | With command: executes immediately. Without: joins all queued `Set Remote` commands with `&&` and executes. FAIL on `exit_code != 0`. |
| `Execute Remote And Continue` | Same as `Execute Remote`, but never fails on nonzero exit code. |

### Verification -- stdout

| Keyword | Description |
|---------|-------------|
| `Verify Remote Response` | EXACT match on stdout |
| `Verify Remote Response WCM` | Wildcard match on stdout (`*` = any chars, `?` = one char) |
| `Verify Remote Response REGX` | Regex match on stdout |

### Verification -- stderr

| Keyword | Default | Description |
|---------|---------|-------------|
| `Verify Remote Stderr` | `$EMPTY` | EXACT match on stderr. Without argument: asserts empty |
| `Verify Remote Stderr WCM` | `$EMPTY` | Wildcard match on stderr |
| `Verify Remote Stderr REGX` | `$EMPTY` | Regex match on stderr |

### Verification -- exit code / duration

| Keyword | Description |
|---------|-------------|
| `Verify Remote Exit Code` | Numeric exact compare |
| `Verify Remote Duration` | Expression check: `>`, `>=`, `<`, `<=`, `==`, range `a..b` |

### Memorize

| Keyword | Description |
|---------|-------------|
| `Memorize Remote Response Field` | Stores a response field (`stdout`, `stderr`, `exit_code`, `duration_ms`) in `$MEM{KEY}` for later use |

### File Transfer -- Upload / Download

| Keyword | Description |
|---------|-------------|
| `Put Remote File` | Uploads a file via SFTP |
| `Get Remote File` | Downloads a file via SFTP |
| `Put Remote Directory` | Recursively uploads a directory via SFTP |
| `Get Remote Directory` | Recursively downloads a directory via SFTP |

### File Transfer -- Verify

| Keyword | Default | Description |
|---------|---------|-------------|
| `Verify Remote File Exists` | `YES` | Asserts file exists (`YES`) or does not exist (`NO`) |
| `Verify Remote Directory Exists` | `YES` | Asserts directory exists (`YES`) or does not exist (`NO`) |

The expected parameter accepts `YES`/`NO`, `TRUE`/`FALSE`, or `1`/`0` (case-insensitive).

### File Transfer -- Clear

| Keyword | Description |
|---------|-------------|
| `Clear Remote Directory` | Deletes files in the directory (not in subdirectories), keeps directory structure |
| `Clear Remote Directory Recursively` | Deletes all files recursively, keeps entire directory tree |

### File Transfer -- Remove (idempotent)

All remove keywords are **idempotent**: if the target does not exist, they return PASS.

| Keyword | Description |
|---------|-------------|
| `Remove Remote File` | Removes a single file |
| `Remove Remote Directory` | Removes an empty directory |
| `Remove Remote Directory Recursively` | Removes a directory and all its contents |

## OKW Token Support

| Token | Behavior |
|-------|----------|
| `$IGNORE` | Keyword becomes a no-op (PASS). Execution/verification/transfer is skipped. |
| `$EMPTY` | For verify keywords: asserts that the checked field is empty. |

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE) for details.
