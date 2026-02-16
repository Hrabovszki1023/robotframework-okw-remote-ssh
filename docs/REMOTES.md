## Remotes YAML und Secrets lokal

Diese Seite beschreibt, wie `robotframework-okw-remote-ssh` Verbindungen konfiguriert – analog zu `locators/*.yaml`: **eine Datei pro „abstrakter Verbindung“**.

---

## Verzeichnisstruktur

Im **Library-Repo** (für Contract/Integration-Tests):

```
robotframework-okw-remote-ssh/
├─ remotes/
│  ├─ dummy.yaml
│  ├─ localhost.yaml
│  └─ ...
└─ tests/
```

Im **Testprojekt** (empfohlen, analog zu `okw/locators`):

```
<project-root>/
└─ okw/
   └─ remotes/
      ├─ build_server_01.yaml
      ├─ test_vm_02.yaml
      └─ ...
```

**Auflösung:**

`Open Remote Session    <session>    <config_ref>`
→ lädt `<config_dir>/<config_ref>.yaml`
Default `config_dir = remotes`.

---

## Remote-Definition: Schema (MVP)

Datei: `remotes/<config_ref>.yaml`

```yaml
host: "127.0.0.1"         # required
port: 22                  # optional (default: 22)
username: "Zoltan"        # required

auth:
  type: password          # MVP: only "password"
  secret_id: "localhost/windows11"   # required for password auth

timeout: 10               # optional (default: 10 seconds)
encoding: "utf-8"         # optional (default: utf-8)
```

### Regeln (wichtig)

* **Keine Passwörter im Repo.** In `remotes/*.yaml` ist `password:` verboten.
* `auth.type=password` + `auth.secret_id` referenziert **lokale** Secrets.
* Fehlende Pflichtfelder → **FAIL** (kein stilles Weiterlaufen).
* `config_ref` ist ein **Dateiname**, keine Pfadangabe (Path traversal wird geblockt).

---

## Vorlage: Windows (OpenSSH Server)

### 1) SSH Server installieren/aktivieren (Windows 11)

Admin-PowerShell:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# Firewall-Regel (Inbound 22)
New-NetFirewallRule -Name sshd `
  -DisplayName "OpenSSH Server (sshd)" `
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### 2) Remote YAML (Repo/Testprojekt)

`okw/remotes/localhost.yaml` (oder im Library-Repo `remotes/localhost.yaml`):

```yaml
host: "127.0.0.1"
port: 22
username: "Zoltan"
auth:
  type: password
  secret_id: "localhost/windows11"
timeout: 5
encoding: "utf-8"
```

### 3) Beispiel-Command (Windows)

Unter Windows ist das robust:

```robot
Set Remote    r1    cmd /c echo hello
```

---

## Vorlage: Linux (OpenSSH Server)

### 1) SSH Server installieren/aktivieren

Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y openssh-server
sudo systemctl enable --now ssh
```

RHEL/CentOS/Fedora (sinngemäß):

```bash
sudo dnf install -y openssh-server
sudo systemctl enable --now sshd
```

Firewall (wenn nötig):

```bash
sudo ufw allow 22/tcp
# oder firewalld:
sudo firewall-cmd --add-service=ssh --permanent
sudo firewall-cmd --reload
```

### 2) Remote YAML

`okw/remotes/linux_test_vm.yaml`:

```yaml
host: "192.168.1.50"
port: 22
username: "tester"
auth:
  type: password
  secret_id: "linux/tester@192.168.1.50"
timeout: 10
encoding: "utf-8"
```

### 3) Beispiel-Command (Linux)

```robot
Set Remote    r1    echo hello
```

---

## Vorlage: macOS (Remote Login / SSH)

### 1) SSH aktivieren

GUI:
**Systemeinstellungen → Allgemein → Freigabe → Remote Login** aktivieren.

CLI (falls gewünscht, kann je nach macOS-Version variieren):

```bash
sudo systemsetup -setremotelogin on
```

### 2) Remote YAML

`okw/remotes/macos_dev.yaml`:

```yaml
host: "192.168.1.60"
port: 22
username: "zoltan"
auth:
  type: password
  secret_id: "macos/zoltan@192.168.1.60"
timeout: 10
encoding: "utf-8"
```

### 3) Beispiel-Command (macOS)

```robot
Set Remote    r1    echo hello
```

---

## Lokale Secrets (Passwörter) – außerhalb des Repos

Passwörter werden **lokal** in einer Datei unter deinem User-Profil abgelegt.

### Default Pfad

* Windows: `%USERPROFILE%\.okw\secrets.yaml`
* Linux/macOS: `~/.okw/secrets.yaml`

### Format

`~/.okw/secrets.yaml`:

```yaml
secrets:
  localhost/windows11:
    password: "DEIN_WINDOWS_PASSWORT"
  linux/tester@192.168.1.50:
    password: "DEIN_LINUX_PASSWORT"
  macos/zoltan@192.168.1.60:
    password: "DEIN_MACOS_PASSWORT"
```

> Diese Datei wird **nicht** eingecheckt, sie liegt ausschließlich lokal.

---

## Windows: Datei-Rechte so setzen, dass nur der User Zugriff hat

Admin-PowerShell:

```powershell
$path = "$env:USERPROFILE\.okw\secrets.yaml"
$me = whoami

# Vererbung entfernen und nur dem aktuellen User Vollzugriff geben
icacls $path /inheritance:r
icacls $path /grant:r "${me}:(F)"

# Prüfen
icacls $path
```

Erwartung (sinngemäß):

```
C:\Users\Zoltan\.okw\secrets.yaml PC-ZOLTAN\Zoltan:(F)
```

---

## Quickstart-Beispiel (Robot)

Windows localhost (Paramiko Integration):

```robot
*** Settings ***
Library    robotframework_okw_remote_ssh.RemoteSshLibrary    backend=paramiko

*** Test Cases ***
Windows Localhost SSH
    Open Remote Session        r1    localhost
    Set Remote                 r1    cmd /c echo hello
    Verify Remote Response WCM    r1    hello
    Close Remote Session       r1
```

---
