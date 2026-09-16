# robotframework-okw-remote-ssh

[![PyPI](https://img.shields.io/pypi/v/robotframework-okw-remote-ssh)](https://pypi.org/project/robotframework-okw-remote-ssh/)
[![Python](https://img.shields.io/pypi/pyversions/robotframework-okw-remote-ssh)](https://pypi.org/project/robotframework-okw-remote-ssh/)
[![License](https://img.shields.io/badge/License-OKW_Community-orange.svg)](LICENSE)

Eigenständige Robot Framework Bibliothek für deterministische, synchrone Remote-Interaktion via SSH — Kommandoausführung, strukturierte Verifikation und SFTP-Dateitransfer.

> **English version:** [README.md](README.md)

## Signal vs. NOISE

| Signal (dein Test) | NOISE (versteckt in YAML) |
|---|---|
| `Execute Remote myhost echo Hello` | Paramiko-Verbindung, Auth, Channel-Setup |
| `Verify Remote Response Hello` | stdout-Capture, Zeilenumbruch-Normalisierung |
| `Put Remote File myhost /tmp/data.txt` | SFTP-Session, Retry, Berechtigungsbehandlung |

**[Keyword-Dokumentation (Libdoc)](https://hrabovszki1023.github.io/robotframework-okw-remote-ssh/RemoteSshLibrary.html)**

## Features

- **Session-basierte** SSH-Verbindungen via Paramiko
- **Absolut synchron**: `Execute Remote` kehrt erst zurück, wenn alle Kommandos vollständig ausgeführt sind — kein asynchrones Polling, kein Race Condition. Das ist der Grund für Paramiko statt SSHLibrary.
- **Strikte Trennung** von Ausführung und Verifikation
- **Command-Queuing**: `Set Remote` sammelt Kommandos, `Execute Remote` sendet sie in einem SSH-Aufruf (Shell-Kontext bleibt erhalten)
- **Drei Match-Modi**: EXACT, WCM (Wildcard: `*`, `?`), REGX (Regex)
- **SFTP-Dateitransfer**: Upload, Download, Verifikation, Löschen, Entfernen (Dateien und Verzeichnisse)
- **OKW-Token-Unterstützung**: `$IGNORE` (überspringen), `$EMPTY` (leer prüfen)
- **Wertersetzung**: `$MEM{KEY}`-Platzhalter in allen Parametern
- **Keine GUI-Kopplung**, keine Abhängigkeit zum OKW-Core

## Fünf-Phasen-Modell

Alle Keywords folgen einem festen Muster:

| Phase | Keywords | Zweck |
|-------|----------|-------|
| **Verbinden** | `Open Remote Session` | SSH-Session öffnen (YAML-Konfiguration) |
| **Vorbereiten** | `Set Remote` | Kommandos sammeln (kein SSH-Aufruf) |
| **Ausführen** | `Execute Remote`, `Execute Remote And Continue` | Kommandos senden und Ergebnis speichern |
| **Verifizieren** | `Verify Remote Response`, `Verify Remote Stderr`, `Verify Remote Exit Code`, ... | Gespeichertes Ergebnis auswerten |
| **Trennen** | `Close Remote Session`, `Close All Remote Sessions` | Session schließen und Ressourcen freigeben |

> **Hinweis:** *Vorbereiten* ist optional — `Execute Remote` kann auch direkt mit einem Kommando aufgerufen werden.
> Wenn mehrere `Set Remote`-Aufrufe gesammelt wurden, verbindet `Execute Remote` sie mit `&&` und sendet sie als **einen** SSH-Aufruf.
> Dadurch bleibt der Shell-Kontext erhalten (Arbeitsverzeichnis, Variablen).

## Alternative

Suchen Sie eine allgemeine SSH-Bibliothek? Siehe [SSHLibrary](https://github.com/MarketSquare/SSHLibrary).
Ein detaillierter [Feature-Vergleich](docs/comparison-sshlibrary.md) erklärt die Unterschiede im Ansatz.

## Installation

```bash
pip install robotframework-okw-remote-ssh
```

## Schnellstart

```robot
*** Settings ***
Library    robotframework_okw_remote_ssh.RemoteSshLibrary

*** Test Cases ***
Einzelnes Kommando
    Open Remote Session      myhost    my_server
    Execute Remote           myhost    echo Hello
    Verify Remote Response   myhost    Hello
    Close Remote Session     myhost

Mehrere Kommandos mit Kontext
    Open Remote Session          myhost    my_server
    Set Remote                   myhost    cd /opt/app
    Set Remote                   myhost    ls -la
    Execute Remote               myhost
    Verify Remote Response WCM   myhost    *app*
    Close Remote Session         myhost

Erwartete Fehler tolerieren
    Open Remote Session              myhost    my_server
    Execute Remote And Continue      myhost    cat /no/such/file
    Verify Remote Exit Code          myhost    1
    Verify Remote Stderr WCM         myhost    *No such file*
    Close Remote Session             myhost

Datei hochladen und prüfen
    Open Remote Session              myhost    my_server
    Put Remote File                  myhost    /tmp/config.ini    local/config.ini
    Verify Remote File Exists        myhost    /tmp/config.ini    YES
    Execute Remote                   myhost    cat /tmp/config.ini
    Verify Remote Response WCM       myhost    *database*
    Close Remote Session             myhost

Verzeichnis herunterladen und aufräumen
    Open Remote Session                  myhost    my_server
    Get Remote Directory                 myhost    /var/log/app    local/logs
    Verify Remote Directory Contains WCM myhost    /var/log/app    *.log
    Verify Remote Directory Count        myhost    /var/log/app    3
    Clear Remote Directory               myhost    /var/log/app
    Verify Remote Directory Count        myhost    /var/log/app    0
    Close Remote Session                 myhost
```

## Session-Konfiguration

Sessions werden über YAML-Dateien in `remotes/` (oder einem eigenen Konfigurationsverzeichnis) konfiguriert.

Beispiel `remotes/my_server.yaml`:

```yaml
host: 10.0.0.1
port: 22
username: testuser
auth:
  type: password
  secret_id: "my_server/testuser"
```

Passwörter werden separat in `~/.okw/secrets.yaml` gespeichert (nie im Repository).

## Keywords

### Session-Lebenszyklus

| Keyword | Beschreibung |
|---------|--------------|
| `Open Remote Session` | Öffnet eine benannte SSH-Session mit YAML-Konfigurationsreferenz |
| `Close Remote Session` | Schließt die Session und gibt alle Ressourcen frei |
| `Close All Remote Sessions` | Schließt alle offenen Sessions (idempotent, für Suite-Teardown) |

### Ausführung

| Keyword | Beschreibung |
|---------|--------------|
| `Set Remote` | Sammelt ein Kommando für spätere Ausführung (kein SSH-Aufruf). Unterstützt `$MEM{KEY}`-Expansion. |
| `Execute Remote` | Mit Kommando: sofortige Ausführung. Ohne: verbindet alle gesammelten `Set Remote`-Kommandos mit `&&` und führt sie aus. FAIL bei `exit_code != 0`. |
| `Execute Remote And Continue` | Wie `Execute Remote`, aber kein Fehler bei Exit-Code ungleich 0. |

### Verifikation — stdout

| Keyword | Beschreibung |
|---------|--------------|
| `Verify Remote Response` | EXACT-Match auf stdout |
| `Verify Remote Response WCM` | Wildcard-Match auf stdout (`*` = beliebige Zeichen, `?` = ein Zeichen) |
| `Verify Remote Response REGX` | Regex-Match auf stdout |

### Verifikation — stderr

| Keyword | Standard | Beschreibung |
|---------|----------|--------------|
| `Verify Remote Stderr` | `$EMPTY` | EXACT-Match auf stderr. Ohne Argument: prüft auf leer |
| `Verify Remote Stderr WCM` | `$EMPTY` | Wildcard-Match auf stderr |
| `Verify Remote Stderr REGX` | `$EMPTY` | Regex-Match auf stderr |

### Verifikation — Exit-Code / Dauer

| Keyword | Beschreibung |
|---------|--------------|
| `Verify Remote Exit Code` | Numerischer exakter Vergleich |
| `Verify Remote Duration` | Ausdruck-Prüfung: `>`, `>=`, `<`, `<=`, `==`, Bereich `a..b` |

### Memorize

| Keyword | Beschreibung |
|---------|--------------|
| `Memorize Remote Response Field` | Speichert ein Antwortfeld (`stdout`, `stderr`, `exit_code`, `duration_ms`) in `$MEM{KEY}` für spätere Verwendung |

### Dateitransfer — Upload / Download

| Keyword | Beschreibung |
|---------|--------------|
| `Put Remote File` | Lädt eine Datei via SFTP hoch |
| `Get Remote File` | Lädt eine Datei via SFTP herunter |
| `Put Remote Directory` | Lädt ein Verzeichnis rekursiv via SFTP hoch |
| `Get Remote Directory` | Lädt ein Verzeichnis rekursiv via SFTP herunter |

### Dateitransfer — Verifikation

| Keyword | Standard | Beschreibung |
|---------|----------|--------------|
| `Verify Remote File Exists` | `YES` | Prüft ob Datei existiert (`YES`) oder nicht existiert (`NO`) |
| `Verify Remote Directory Exists` | `YES` | Prüft ob Verzeichnis existiert (`YES`) oder nicht existiert (`NO`) |

Der Expected-Parameter akzeptiert `YES`/`NO`, `TRUE`/`FALSE` oder `1`/`0` (groß-/kleinschreibungsunabhängig).

### Dateitransfer — Verzeichnisinhalt prüfen

| Keyword | Beschreibung |
|---------|--------------|
| `Verify Remote Directory Contains` | EXACT-Namensabgleich gegen Verzeichniseinträge |
| `Verify Remote Directory Contains WCM` | Wildcard-Match (`*`, `?`) gegen Verzeichniseinträge |
| `Verify Remote Directory Contains REGX` | Regex-Match gegen Verzeichniseinträge |
| `Verify Remote Directory Count` | Prüft Anzahl der Einträge im Verzeichnis |

### Dateitransfer — Memorize

| Keyword | Beschreibung |
|---------|--------------|
| `Memorize Remote Directory Contents` | Speichert Verzeichnisliste (zeilengetrennt) in `$MEM{KEY}` |

### Dateitransfer — Berechtigungen

| Keyword | Beschreibung |
|---------|--------------|
| `Set Remote File Mode` | Setzt Dateiberechtigungen via SFTP chmod (z.B. `0755`) |
| `Verify Remote File Mode` | Prüft Dateiberechtigungen via SFTP stat (EXACT oktal) |
| `Memorize Remote File Mode` | Speichert Dateiberechtigungen (4-stellig oktal) in `$MEM{KEY}` |

`Put Remote File` und `Put Remote Directory` akzeptieren einen optionalen `mode`-Parameter.

### Dateitransfer — Leeren

| Keyword | Beschreibung |
|---------|--------------|
| `Clear Remote Directory` | Löscht Dateien im Verzeichnis (nicht in Unterverzeichnissen), behält Verzeichnisstruktur |
| `Clear Remote Directory Recursively` | Löscht alle Dateien rekursiv, behält gesamten Verzeichnisbaum |

### Dateitransfer — Entfernen (idempotent)

Alle Remove-Keywords sind **idempotent**: Wenn das Ziel nicht existiert, wird PASS zurückgegeben.

| Keyword | Beschreibung |
|---------|--------------|
| `Remove Remote File` | Entfernt eine einzelne Datei |
| `Remove Remote Directory` | Entfernt ein leeres Verzeichnis |
| `Remove Remote Directory Recursively` | Entfernt ein Verzeichnis und seinen gesamten Inhalt |

## OKW-Token-Unterstützung

| Token | Verhalten |
|-------|-----------|
| `$IGNORE` | Keyword wird zum No-Op (PASS). Ausführung/Verifikation/Transfer wird übersprungen. |
| `$EMPTY` | Für Verify-Keywords: prüft, dass das geprüfte Feld leer ist. |

## Lauffähige Beispiele

[okw-examples/ssh/](https://github.com/Hrabovszki1023/okw-examples/tree/main/ssh/) — Kommandoausführung, Dateitransfer, Fehlerbehandlung.

## Handbuch

[OKW4Robot Handbuch](https://hrabovszki1023.github.io/okw-examples/) — Schritt-für-Schritt-Anleitung.

## KI-Testgenerierung

Testfälle können mit jeder KI (Claude, ChatGPT, Copilot, ...) generiert werden.
Die System-Prompts für die Testgenerierung werden zentral in
[`robotframework-okw4robot/prompts/`](https://github.com/Hrabovszki1023/robotframework-okw4robot/tree/main/prompts) gepflegt.

Kopieren Sie den Prompt in Ihre KI und beschreiben Sie in natürlicher Sprache, was Sie testen möchten.
Die KI erzeugt eine lauffertige `.robot`-Datei.

## Lizenz

AGPL-3.0-or-later. Siehe [LICENSE](LICENSE) für Details.
