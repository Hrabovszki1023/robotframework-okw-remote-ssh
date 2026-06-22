# Feature Comparison: SSHLibrary vs. okw-remote-ssh

Date: 2026-06-22

Reference: [SSHLibrary (MarketSquare)](https://github.com/MarketSquare/SSHLibrary)

---

## Philosophy

| | SSHLibrary | okw-remote-ssh |
|---|---|---|
| **Approach** | Full SSH client for Robot Framework | Deterministic, verification-oriented (Three-Phase Model) |
| **Command model** | Synchronous + asynchronous + interactive shell | Synchronous only (by design) |
| **Configuration** | Parameters on keywords | YAML files + secrets management |
| **Verification** | None built-in (use BuiltIn keywords) | Structured: stdout, stderr, exit code, duration |
| **Token support** | None | `$IGNORE`, `$EMPTY`, `$MEM{KEY}` |
| **Keywords** | 34 | 26 |

---

## What SSHLibrary has that okw-remote-ssh does NOT have

| Feature | SSHLibrary Keywords | Relevant for OKW? | Decision |
|---|---|---|---|
| SSH Tunneling | `Create Local SSH Tunnel` | Niche — useful for DB tests over SSH tunnel | Not planned |
| Async Commands | `Start Command` / `Read Command Output` | No — OKW is deliberately synchronous/deterministic | Excluded by design |
| Interactive Shell | `Write`, `Write Bare`, `Read`, `Read Until`, `Read Until Prompt`, `Read Until Regexp` | No — interactive shell contradicts the Three-Phase Model | Excluded by design |
| Directory Listing | `List Directory`, `List Files In Directory`, `List Directories In Directory` | Yes — useful for infrastructure tests | **Candidate** |
| Multi-Connection cleanup | `Close All Connections` | Yes — avoids session leaks on test abort | **Candidate** |
| SCP Transfer | `scp="ON"` parameter on all transfer keywords | Niche — SFTP is sufficient in most cases | Not planned |
| Auth: Public Key | `Login With Public Key` | OKW handles this via YAML config (`auth.type: key`) | Already covered |
| Auth: Jump Host | `jumphost_index_or_alias` parameter | Niche — ProxyJump in SSH config is more elegant | Not planned |
| Pre-Login Banner | `Get Pre Login Banner` | No — too specialized | Not planned |
| SSH Logging | `Enable SSH Logging` | No — OKW already logs in the Robot log | Not planned |
| File permissions | `mode="0744"` on `Put File` | Yes — needed when uploading scripts to execute | **Candidate** |
| Glob patterns | `Get File source=*.txt` | Nice-to-have, low priority | Not planned |

---

## What okw-remote-ssh has that SSHLibrary does NOT have

| Feature | OKW Keywords |
|---|---|
| Structured verification | `Verify Remote Response` (EXACT/WCM/REGX), `Verify Remote Stderr`, `Verify Remote Exit Code`, `Verify Remote Duration` |
| Command queuing | `Set Remote` -> `Execute Remote` (joined with `&&`, preserves shell context) |
| `$IGNORE` / `$EMPTY` tokens | Test control without control structures |
| `$MEM{KEY}` expansion | Value passing between steps |
| Idempotent removes | `Remove Remote File/Directory` — PASS when target absent |
| Clear directory | `Clear Remote Directory` (delete files, keep structure) |
| Duration verification | `Verify Remote Duration >500` |
| YAML-based config | Session configuration separated from test code |
| Secrets management | `~/.okw/secrets.yaml` — passwords never in the repo |

---

## Recommended additions

Based on this comparison, three features from SSHLibrary are worth adding
to okw-remote-ssh. They fit the OKW philosophy (deterministic, verifiable)
and address real gaps.

1. **`List Remote Directory`** — List directory contents, verifiable via
   `Verify Remote Response`. Common use case in infrastructure tests.

2. **`Close All Remote Sessions`** — Clean up all open sessions in one call.
   Prevents session leaks on test abort. Useful in suite teardown.

3. **File permissions on `Put Remote File`** — Optional `mode` parameter
   (e.g. `0755`). Important when uploading scripts that need to be executed.

---

## Deliberately excluded

These SSHLibrary features are **not** planned for okw-remote-ssh because
they contradict the OKW design principles:

- **Async commands** — OKW is synchronous by design. Every command has a
  clear result that can be verified immediately.
- **Interactive shell** (`Write`/`Read`/`Read Until`) — Contradicts the
  Three-Phase Model. Commands are queued and executed, not streamed.
- **SSH tunneling** — Too specialized. Can be achieved via SSH config
  (`ProxyJump`, `LocalForward`) outside the test framework.
