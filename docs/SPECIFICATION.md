## Value Expansion

This library complies with the OKW Global Value Expansion Model.
All Value and Command parameters support `$MEM{KEY}`.

- Expansion occurs before execution/verification.
- Missing keys MUST fail (no silent fallback).

## Remote Definition Directory

Remote definitions are stored as one YAML file per connection in:

    remotes/

Resolution:

    Open Remote Session    <session>    <config_ref>

resolves to:

    <config_dir>/<config_ref>.yaml

Default:

- config_dir: `remotes`

Rules:

- `<config_ref>` MUST be a file base name (no path traversal).
- The YAML file MUST exist, otherwise the keyword MUST fail.
- The YAML file MUST define at least:
  - `host` (string)
  - `username` (string)
- Optional keys:
  - `port` (default: 22)
  - `password` or `keyfile`
  - `timeout` (default: 10)
  - `encoding` (default: utf-8)
