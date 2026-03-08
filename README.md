<div align="center">

```
██████╗  ██████╗ ██╗  ██╗███╗   ██╗
██╔══██╗██╔════╝ ██║ ██╔╝████╗  ██║
██║  ██║██║  ███╗█████╔╝ ██╔██╗ ██║
██║  ██║██║   ██║██╔═██╗ ██║╚██╗██║
██████╔╝╚██████╔╝██║  ██╗██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
```

# DGKN Crypto Suite v5.0

### Professionelle Dateiverschlüsselung mit Hidden Volumes, Keyfiles & Emergency Wipe

[![GitHub](https://img.shields.io/badge/GitHub-dogenc%2FdgknCryptoSuite-black?style=flat-square&logo=github)](https://github.com/dogenc/dgknCryptoSuite)
[![Release](https://img.shields.io/badge/Release-v5.0-purple?style=flat-square)](https://github.com/dogenc/dgknCryptoSuite/releases)
[![EXE](https://img.shields.io/badge/Download-.EXE-blue?style=flat-square&logo=windows)](https://github.com/dogenc/dgknCryptoSuite/releases/latest)
[![Crypto](https://img.shields.io/badge/Algo-XChaCha20--Poly1305-orange?style=flat-square)](#sicherheit)
[![KDF](https://img.shields.io/badge/KDF-PBKDF2--SHA512-red?style=flat-square)](#sicherheit)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=flat-square&logo=windows)](https://github.com/dogenc/dgknCryptoSuite/releases/latest)
[![License](https://img.shields.io/badge/Lizenz-MIT-green?style=flat-square)](#lizenz)

<br>

> **Keine Installation. Keine Python. Einfach herunterladen und starten.**
>
> `dgkn_crypto_v5.exe` — läuft direkt auf jedem Windows-System ab Windows 10.

</div>

---

## ⚡ Download

| Datei | Beschreibung |
|-------|-------------|
| [`dgkn_crypto_v5.exe`](https://github.com/dogenc/dgknCryptoSuite/releases/latest) | **Windows EXE — direkt ausführbar, keine Installation nötig** |
| [`dgkn_crypto_v5.py`](https://github.com/dogenc/dgknCryptoSuite/releases/latest) | Python Quellcode (Windows / Linux / macOS) |

> Die EXE enthält Python und alle Abhängigkeiten gebündelt — **kein Setup, keine Voraussetzungen, kein Microsoft Store**.
> Herunterladen, doppelklicken, fertig.

---

## Was ist DGKN Crypto Suite?

DGKN Crypto Suite ist eine **quelloffene, kostenlose Verschlüsselungssoftware** für Windows mit moderner grafischer Benutzeroberfläche. Sie ermöglicht:

- Dateien und Ordner in **verschlüsselte Container** zu packen — ähnlich wie VeraCrypt
- Einzelne Dateien direkt zu **ver- und entschlüsseln** (Original wird dabei sicher gelöscht)
- **Versteckte Volumes** (Hidden Volumes) für glaubhafte Abstreitbarkeit (Plausible Deniability)
- **Notfall-Wipe** per Tastenkürzel — alle offenen Volumes sofort sicher schließen

Alles in einer einzigen `.exe`-Datei. Kein Account. Keine Cloud. Keine Telemetrie. Keine Werbung.

---

## Features

### 🔐 Container-Verschlüsselung
- Beliebig große verschlüsselte Container erstellen (10 MB bis mehrere GB)
- Container **öffnen (mounten)** — Dateien erscheinen in einem temporären Ordner
- Nach dem Bearbeiten **speichern (unmounten)** — alles wird automatisch re-verschlüsselt
- Temp-Verzeichnis wird nach dem Schließen **sicher überschrieben und gelöscht**

### 🕵 Hidden Volumes
- Ein Container, **zwei Passwörter, zwei komplett getrennte Bereiche**
- Passwort A → normaler Bereich
- Passwort B → versteckter Bereich mit sensiblen Dateien
- Beide Bereiche sind kryptografisch **nicht voneinander zu unterscheiden**
- Plausible Deniability: niemand kann beweisen, dass ein zweites Volume existiert

### 🔒 Einzeldatei-Verschlüsselung
- Jede Datei direkt verschlüsseln — **Original wird sicher gelöscht**, `.dgkn5`-Datei erscheint
- Entschlüsseln stellt den **Original-Dateinamen automatisch** wieder her
- Verschlüsselte Datei wird nach Entschlüsselung **sicher gelöscht**
- Keyfile als zweiter Faktor unterstützt

### 🔑 Keyfiles
- Jede beliebige Datei als zweiten Faktor verwenden (Foto, MP3, PDF, USB-Datei …)
- Ohne die exakte Keyfile-Datei ist der Container **nicht zu öffnen**, auch nicht bei richtigem Passwort
- Keyfile auf separatem USB-Stick = Hardware-Zwei-Faktor-Authentifizierung

### 🚨 Sicherheits-Features
- **Emergency Wipe** (`Ctrl+Shift+W`) — alle Volumes sofort schließen, Temp-Daten sicher löschen
- Optional: Container-Header beim Wipe zerstören → Container dauerhaft unlesbar
- **Auto-Unmount** — automatisches Speichern nach konfigurierbarer Inaktivitätsdauer
- **Header-Backup & Restore** — JSON-Sicherungskopie, Schutz vor Bit-Corruption
- **Passwort ändern** ohne den Container neu erstellen zu müssen

### 🖥 Oberfläche
- Modernes dunkles Design
- Animierter **Splash Screen** mit Matrix-Regen-Effekt beim Start
- **Dashboard** mit Live-Anzeige aller aktiven Volumes und Buttons
- **Aktivitäts-Log** mit Timestamps für alle sicherheitsrelevanten Aktionen
- Vollständige Pfad-Vorschau, automatische Dateinamenerkennung

---

## Sicherheit

### Eingesetzte Algorithmen

| Komponente | Algorithmus | Details |
|-----------|-------------|---------|
| Verschlüsselung | **XChaCha20-Poly1305** | 256-bit Key, 192-bit Nonce, 128-bit Auth-Tag (AEAD) |
| Schlüsselableitung | **PBKDF2-SHA512** | 650.000 Iterationen, 64-Byte Output |
| Schlüsselexpansion | **HKDF-SHA256** | Separate Schlüssel für NORM / HIDE / FILE |
| Keyfile-Hash | **BLAKE2b-256** | Wird vor KDF an Passwort konkateniert |
| Salt | **CSPRNG** | 256-bit, zufällig, einmalig pro Container |
| Nonce | **CSPRNG** | 192-bit, einmalig pro Verschlüsselungsoperation |
| Authentifizierung | **Verschlüsselter Sentinel** | Kein Klartext-Passwort-Vergleich |

### Warum XChaCha20-Poly1305?

XChaCha20-Poly1305 gilt als **modernster Standard** für symmetrische Verschlüsselung:

- Im Einsatz bei **Google, Cloudflare, Signal, WireGuard und OpenSSH**
- **Keine Padding-Angriffe** möglich (im Gegensatz zu AES-CBC oder AES-ECB)
- **192-bit Nonce** — Nonce-Wiederholungs-Kollisionen sind in der Praxis ausgeschlossen
- Integrierte **Daten-Authentifizierung** (AEAD) — Manipulation wird zuverlässig erkannt
- **Schneller als AES** auf Systemen ohne Hardware-AES-Beschleunigung (ältere CPUs, ARM)
- Vom **IETF standardisiert** (RFC 8439)

### Warum 650.000 PBKDF2-Iterationen?

Die Schlüsselableitung ist absichtlich langsam — das macht Brute-Force-Angriffe extrem teuer:

- Auf einer **High-End-GPU** (RTX 4090): maximal einige Passwörter pro Sekunde testbar
- Ein **12-stelliges zufälliges Passwort** würde bei Vollauslastung **Jahrhunderte** dauern zu knacken
- Ein **20-stelliges Passwort** ist für jeden denkbaren Angreifer in absehbarer Zeit **nicht knackbar**

---

## Vergleich mit anderen Programmen

| Feature | **DGKN Crypto Suite** | VeraCrypt | BitLocker | 7-Zip (AES) | AxCrypt |
|---------|:--------------------:|:---------:|:---------:|:-----------:|:-------:|
| Kostenlos | ✅ | ✅ | ✅ (nur Win Pro) | ✅ | ⚠️ Freemium |
| Open Source | ✅ | ✅ | ❌ | ✅ | ⚠️ teilweise |
| Portable EXE (kein Setup) | ✅ | ❌ | ❌ | ✅ | ❌ |
| Hidden Volumes | ✅ | ✅ | ❌ | ❌ | ❌ |
| Keyfile-Support | ✅ | ✅ | ❌ | ❌ | ✅ |
| Einzeldatei-Verschlüsselung | ✅ | ❌ | ❌ | ✅ | ✅ |
| Emergency Wipe | ✅ | ❌ | ❌ | ❌ | ❌ |
| Auto-Unmount | ✅ | ✅ | ❌ | ❌ | ❌ |
| Header-Backup | ✅ | ✅ | ❌ | ❌ | ❌ |
| Passwort ändern (in-place) | ✅ | ✅ | ✅ | ❌ | ✅ |
| Modernes dunkles GUI | ✅ | ❌ veraltet | ✅ | ⚠️ | ✅ |
| **XChaCha20-Poly1305** | ✅ | ❌ AES | ❌ AES | ❌ AES | ❌ AES |
| Externer Sicherheitsaudit | ❌ | ✅ | ❌ | ❌ | ❌ |
| Windows | ✅ | ✅ | ✅ | ✅ | ✅ |
| Linux / macOS | ⚠️ Quellcode | ✅ | ❌ | ✅ | ⚠️ |

**Fazit:**
- **VeraCrypt** ist die Referenz für professionellen Enterprise-Einsatz mit externem Audit — aber kein portables EXE, kein modernes GUI, kein XChaCha20, kein Emergency Wipe
- **BitLocker** ist tief ins Windows-System integriert — aber closed source, kein Hidden Volume, kein Keyfile
- **DGKN Crypto Suite** kombiniert modernes GUI, modernsten Algorithmus (XChaCha20), Hidden Volumes und Emergency Wipe in einer einzigen portablen EXE-Datei — kostenlos und open source

---

## Bekannte Einschränkungen

> **Die Software ist vollständig funktionsfähig** für den täglichen Einsatz. Die nachfolgenden Punkte sind bekannte Einschränkungen der aktuellen Version.

| # | Einschränkung | Schwere | Status |
|---|--------------|---------|--------|
| 1 | **Container-Integritätsprüfung unzuverlässig** — der Button ist vorhanden, aber die Prüfung liefert in manchen Fällen falsche Ergebnisse. **Bitte nicht für kritische Entscheidungen verwenden.** | Mittel | 🔧 Fix in Arbeit |
| 2 | Passwörter liegen als Python-Strings im RAM und können nicht aktiv überschrieben werden | Gering (nur bei kompromittiertem System relevant) | 📋 Geplant |
| 3 | GUI kann bei sehr großen Dateien (>1 GB Einzeldatei) kurz einfrieren | Kosmetisch | 📋 Geplant |
| 4 | Keine native Linux/macOS EXE — Quellcode muss direkt ausgeführt werden | Gering | 📋 Geplant |
| 5 | Kein unabhängiger Sicherheitsaudit der Implementierung | Vertrauen in Quellcode erforderlich | 📋 Langfristig |

---

## Schnellstart

### Container erstellen & Dateien sichern

```
1. dgkn_crypto_v5.exe starten
2. „Neuen Container erstellen" → Pfad und Größe wählen
3. Passwort A eingeben (optional: Keyfile hinzufügen)
4. Optional: Passwort B + Größe für verstecktes Volume
5. „Erstellen" klicken
6. „Normales Volume" → Passwort eingeben → Explorer öffnet sich
7. Dateien in den Ordner kopieren
8. „Alle speichern & schließen" → alles wird verschlüsselt
```

### Einzeldatei direkt verschlüsseln

```
1. „Datei verschlüsseln" in der Seitenleiste
2. Datei auswählen (Zieldatei wird automatisch gesetzt)
3. Passwort eingeben → Enter
→ datei.pdf wird zu datei.pdf.dgkn5, Original sicher gelöscht
```

### Einzeldatei entschlüsseln

```
1. „Datei entschlüsseln" in der Seitenleiste
2. .dgkn5-Datei auswählen, Zieldatei LEER lassen
3. Passwort eingeben → Enter
→ Originaldatei wird wiederhergestellt, .dgkn5 sicher gelöscht
```

### Notfall

```
Ctrl + Shift + W → alle Volumes sofort sicher schließen
```

---

## Tastenkürzel

| Kürzel | Funktion |
|--------|----------|
| `Ctrl + O` | Container öffnen |
| `Ctrl + M` | Alle Volumes speichern & schließen |
| `Ctrl + Shift + W` | 🚨 Notfall-Wipe |
| `Enter` | Dialog bestätigen |

---

## Quellcode ausführen (Linux / macOS)

```bash
git clone https://github.com/dogenc/dgknCryptoSuite.git
cd dgknCryptoSuite
pip install cryptography
python dgkn_crypto_v5.py
```

Einzige externe Abhängigkeit: `cryptography` — alles weitere ist Python-Standardbibliothek.

---

## Lizenz

MIT License — kostenlos nutzbar, veränderbar und weitergabe-erlaubt.

---

## Haftungsausschluss

Diese Software wird ohne jegliche Garantie bereitgestellt. **Vergessene Passwörter können nicht wiederhergestellt werden.** Nach dem Erstellen eines Containers unbedingt ein **Header-Backup** anlegen und sicher aufbewahren. Der Entwickler übernimmt keine Haftung für Datenverlust.

---

<div align="center">

**[dogenc/dgknCryptoSuite](https://github.com/dogenc/dgknCryptoSuite)**

XChaCha20-Poly1305 · PBKDF2-SHA512 · BLAKE2b · Open Source · Kostenlos · Keine Installation

*Sicherheit sollte für jeden zugänglich sein.*

</div>
