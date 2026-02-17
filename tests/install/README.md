# Installation & Integration Tests

## 1. Install Smoke Test (clean machine)

Verifies that `pip install robotframework-okw-remote-ssh` works on a fresh system.

```bash
bash tests/install/test_install.sh
```

**What it checks:**
- pip install from PyPI succeeds
- All dependencies resolve (okw-contract-utils, paramiko, robotframework, PyYAML)
- Python import works
- Robot Framework discovers the library
- Minimal robot test runs (stub backend)

## 2. Live SSH Integration Test

Verifies real SSH command execution and SFTP against a running SSH server.

### Prerequisites

1. SSH server accessible from the test machine
2. Config file `~/.okw/configs/testhost.yaml`:

```yaml
host: <IP or hostname>
port: 22
username: <user>
```

3. Secrets file `~/.okw/secrets.yaml`:

```yaml
testhost:
  password: <password>
```

### Run

```bash
python -m robot tests/install/test_ssh_live.robot
```

## Proxmox VM Setup

Recommended setup for repeatable install testing:

1. Create a minimal Debian/Ubuntu VM
2. Install Python: `apt install python3 python3-pip python3-venv`
3. Take a **snapshot** (clean state)
4. Run `test_install.sh`
5. Run `test_ssh_live.robot` (with SSH config pointing to localhost or another host)
6. **Revert to snapshot** before next test run
