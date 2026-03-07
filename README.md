<div align="center">

<img src="https://img.shields.io/badge/Version-2.0-00d4ff?style=for-the-badge&logo=python&logoColor=white" alt="Version"/>
<img src="https://img.shields.io/badge/Python-3.8+-00d4ff?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
<img src="https://img.shields.io/badge/License-MIT-00ff88?style=for-the-badge" alt="License"/>
<img src="https://img.shields.io/badge/Encryption-AES--256--GCM-ff3355?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="AES-256-GCM"/>
<img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-666666?style=for-the-badge" alt="Platform"/>

<br/><br/>

```
██████╗  ██████╗ ██╗  ██╗███╗   ██╗
██╔══██╗██╔════╝ ██║ ██╔╝████╗  ██║
██║  ██║██║  ███╗█████╔╝ ██╔██╗ ██║
██║  ██║██║   ██║██╔═██╗ ██║╚██╗██║
██████╔╝╚██████╔╝██║  ██╗██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
         CRYPTO SUITE  v2.0
```

**Professionelle Datei-Verschlüsselung · AES-256-GCM · Open Source · Python**

[🔒 Features](#-features) · [⚡ Quickstart](#-quickstart) · [🛡 Sicherheit](#-sicherheitsarchitektur) · [📊 Vergleich](#-vergleich-mit-anderen-tools) · [🤝 Contributing](#-contributing)

</div>

---

## 📖 Was ist DGKN Crypto Suite?

DGKN Crypto Suite ist ein **Open-Source Tool zur Datei-Verschlüsselung** mit grafischer Oberfläche (GUI), entwickelt für Windows, Linux und macOS. Es verschlüsselt beliebige Dateien mit **AES-256-GCM** – demselben Algorithmus, den Banken, Regierungen und Sicherheitsdienste weltweit einsetzen.

> **Für Einsteiger:** Du wählst eine Datei, gibst ein Passwort ein – fertig. Die Datei ist danach für niemanden lesbar, der das Passwort nicht kennt.

> **Für Entwickler:** AES-256-GCM mit PBKDF2-HMAC-SHA256 (600.000 Iterationen), Key Separation, Authenticate-then-Decrypt, HMAC-Integritätsschutz, Streaming/Chunk-Verarbeitung.

---

## ✨ Features

### 🔐 Sicherheit
- **AES-256-GCM** – Authenticated Encryption (Vertraulichkeit + Integrität in einem)
- **PBKDF2-HMAC-SHA256** mit 600.000 Iterationen (NIST SP 800-132 / 2023)
- **Key Separation** – separate Schlüssel für Verschlüsselung & HMAC
- **Authenticate-then-Decrypt** – Manipulation wird erkannt *bevor* entschlüsselt wird
- **HMAC-Signatur** auf der Key-Datei – schützt Metadaten vor Manipulation
- **Zufälliger 256-Bit Salt** pro Datei – kein Rainbow-Table-Angriff möglich

### 🖥 Benutzerfreundlichkeit
- **Grafische Oberfläche** (tkinter) – keine Terminal-Kenntnisse nötig
- **Drag & Drop** Dateiauswahl
- **Echtzeit-Fortschrittsanzeige** (kein Fake-Progress!)
- **Passwort-Stärke-Indikator** mit Echtzeit-Feedback
- **Automatische Key-Datei-Erkennung**

### ⚙️ Technische Stärken
- **Streaming / Chunk-Verarbeitung** (64 KB) – auch 100+ GB Dateien problemlos
- **Thread-sicheres UI** – kein Einfrieren während der Verschlüsselung
- **Secure Delete** (optional) – 3-Pass Überschreiben der Originaldatei
- **Generische Fehlermeldungen** – kein Python-Traceback für Angreifer sichtbar

---

## ⚡ Quickstart

### Voraussetzungen

```bash
Python 3.8 oder höher
```

### Installation

```bash
# 1. Repository klonen
git clone https://github.com/dogenc/dgknCryptoSuite.git
cd dgknCryptoSuite

# 2. Abhängigkeiten installieren
pip install cryptography

# Tkinter installieren (Linux)
sudo apt install python3-tk       # Debian / Ubuntu / Kali
sudo dnf install python3-tkinter  # Fedora
sudo pacman -S tk                 # Arch

# 3. Starten
python3 dgkn_crypto_v2.py
```

### Windows

```powershell
# Python von https://python.org installieren (tkinter ist enthalten)
pip install cryptography
python dgkn_crypto_v2.py
```

### macOS

```bash
brew install python-tk
pip3 install cryptography
python3 dgkn_crypto_v2.py
```

---

## 🖼 Screenshots

> 📸 *Screenshots folgen – Pull Requests mit Screenshots willkommen!*

```
┌─────────────────────────────────────────────┐
│  DGKN  CRYPTO  SUITE          v2.0          │
├─────────────────────────────────────────────┤
│  🔒 Verschlüsseln  │ 🔓 Entschlüsseln │ ℹ  │
├─────────────────────────────────────────────┤
│                                             │
│   📂  Datei auswählen  (Klick / Drag&Drop) │
│                                             │
│   Passwort:        [●●●●●●●●●●●●●●●●]      │
│   Bestätigen:      [●●●●●●●●●●●●●●●●]      │
│                                             │
│   Stärke: ████████████████░░  Sehr stark   │
│                                             │
│   ☑ Originaldatei sicher löschen (3-Pass)  │
│                                             │
│   [ 🔒 Jetzt verschlüsseln ]               │
├─────────────────────────────────────────────┤
│  ✔ Bereit              Fortschritt: ████░  │
└─────────────────────────────────────────────┘
```

---

## 🛡 Sicherheitsarchitektur

### Dateiformat `.dgkn2`

```
┌──────────────────────────────────────────────────────┐
│ Magic       5 Bytes   "DGKN2"  (Format-Kennung)      │
│ Version     1 Byte    Format-Version                  │
│ Salt       32 Bytes   PBKDF2-Salt  (256-Bit Zufall)  │
│ N_Chunks    4 Bytes   Anzahl Chunks (uint32)          │
│ ── pro Chunk: ──────────────────────────────────────  │
│   Nonce_i  12 Bytes   GCM-Nonce  (einzigartig/Chunk) │
│   Len_i     4 Bytes   Ciphertext-Länge                │
│   Data_i   var        AES-256-GCM Ciphertext + Tag    │
│ ── Ende: ───────────────────────────────────────────  │
│ HMAC       32 Bytes   HMAC-SHA256 über alles oben     │
└──────────────────────────────────────────────────────┘
```

### Schlüsselableitung

```
Passwort + Salt (256-Bit)
        │
        ▼
PBKDF2-HMAC-SHA256
(600.000 Iterationen)
        │
        ▼  64 Bytes
   ┌────┴────┐
   │         │
enc_key   mac_key
(32 B)    (32 B)
AES-256   HMAC-SHA256
```

### Warum AES-256-GCM?

| Eigenschaft | AES-256-GCM | AES-128-CBC (veraltet) |
|---|---|---|
| Schlüssellänge | 256 Bit | 128 Bit |
| Authentifizierung | ✅ eingebaut (GCM-Tag) | ❌ separat nötig |
| Manipulation erkennbar | ✅ sofort | ❌ nicht ohne MAC |
| Padding-Angriffe | ✅ immun | ⚠️ anfällig (POODLE etc.) |
| NIST-Status | ✅ empfohlen | ⚠️ nur mit Vorsicht |

### Passwort-Sicherheit

> **Faustregel:** Je länger das Passwort, desto sicherer – auch mit PBKDF2.

| Passwort-Typ | Beispiel | Sicherheit |
|---|---|---|
| Kurz / einfach | `hund123` | ❌ Minuten |
| Mittel | `Hund123!` | ⚠️ Stunden–Tage |
| Lang + komplex | `Tr0ub4dor&3#Kaffee!` | ✅ Jahrzehnte+ |
| Passphrase | `korrekt-pferd-batterie-heftklammer` | ✅ Sehr sicher |

---

## 📊 Vergleich mit anderen Tools

| Feature | **DGKN v2.0** | VeraCrypt | GPG | 7-Zip | Cryptomator |
|---|:---:|:---:|:---:|:---:|:---:|
| AES-256-GCM | ✅ | ⚠️ XTS | ✅ | ✅ | ✅ |
| GUI | ✅ | ✅ | ❌ CLI | ✅ | ✅ |
| Open Source | ✅ | ✅ | ✅ | ✅ | ✅ |
| Einzeldateien | ✅ | ⚠️ Container | ✅ | ✅ | ✅ |
| Streaming (große Dateien) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Secure Delete | ✅ | ✅ | ❌ | ❌ | ❌ |
| HMAC Integritätsschutz | ✅ | ✅ | ✅ | ❌ | ✅ |
| Kein Account nötig | ✅ | ✅ | ✅ | ✅ | ✅ |
| Mobil (iOS/Android) | ❌ | ❌ | ❌ | ❌ | ✅ |
| Laufwerk-Verschlüsselung | ❌ | ✅ | ❌ | ❌ | ❌ |
| Python / portabel | ✅ | ❌ | ❌ | ❌ | ❌ |

**DGKN eignet sich besonders für:** Einzeldateien verschlüsseln, volle Code-Kontrolle, plattformübergreifend ohne Installation eines großen Tools.

---

## 📁 Projektstruktur

```
dgknCryptoSuite/
│
├── dgkn_crypto_v2.py      # Hauptprogramm (alles in einer Datei)
├── README.md              # Diese Datei
├── LICENSE                # MIT Lizenz
├── requirements.txt       # Python-Abhängigkeiten
│
└── examples/              # Beispieldateien (optional)
    ├── test.txt
    ├── test.dgkn2
    └── test.key2
```

### `requirements.txt`

```
cryptography>=41.0.0
```

---

## 🔧 Verwendung (CLI-Modus)

Die Crypto-Engine kann auch ohne GUI direkt in Python genutzt werden:

```python
from dgkn_crypto_v2 import CryptoEngineV2

# Datei verschlüsseln
ok, enc_path, key_path, meta = CryptoEngineV2.encrypt_file(
    src_path   = "geheim.pdf",
    password   = "MeinSicheresPasswort!42",
    output_dir = "./encrypted/",
    secure_del = False,          # True = Original sicher löschen
)

if ok:
    print(f"✔ Verschlüsselt: {enc_path}")
    print(f"  Key-Datei:     {key_path}")
    print(f"  Algorithmus:   {meta['algo']}")

# Datei entschlüsseln
ok, out_path, meta, _ = CryptoEngineV2.decrypt_file(
    dgkn_path  = "geheim.dgkn2",
    password   = "MeinSicheresPasswort!42",
    key_path   = "geheim.key2",
    output_dir = "./decrypted/",
)

if ok:
    print(f"✔ Entschlüsselt: {out_path}")
else:
    print(f"✘ Fehler: {out_path}")
```

---

## 🤝 Contributing

Beiträge sind herzlich willkommen! So kannst du mitmachen:

### Bug melden

1. [Issue öffnen](https://github.com/dogenc/dgknCryptoSuite/issues/new)
2. Folgendes angeben:
   - Betriebssystem & Python-Version
   - Fehlerbeschreibung
   - Schritte zum Reproduzieren
   - Fehlermeldung (falls vorhanden)

### Feature vorschlagen

1. [Issue öffnen](https://github.com/dogenc/dgknCryptoSuite/issues/new) mit Label `enhancement`
2. Beschreibe den Anwendungsfall
3. Diskussion im Issue – dann ggf. Pull Request

### Code beitragen

```bash
# 1. Fork erstellen (GitHub: Fork-Button oben rechts)

# 2. Lokal klonen
git clone https://github.com/DEIN-USERNAME/dgknCryptoSuite.git
cd dgknCryptoSuite

# 3. Branch erstellen
git checkout -b feature/mein-neues-feature

# 4. Änderungen machen & committen
git add .
git commit -m "feat: Beschreibung des Features"

# 5. Push & Pull Request
git push origin feature/mein-neues-feature
# → GitHub: Pull Request erstellen
```

### Commit-Konventionen

```
feat:     Neues Feature
fix:      Bugfix
docs:     Dokumentation
security: Sicherheitsrelevante Änderung
refactor: Code-Umbau ohne Funktionsänderung
```

### Ideen für Contributions

- [ ] 🌍 Mehrsprachigkeit (EN/DE/FR)
- [ ] 📱 Mobile Version (Kivy?)
- [ ] 🗂 Ordner-Verschlüsselung (ZIP + encrypt)
- [ ] 🔑 YubiKey / Hardware-Token Support
- [ ] 🖼 Screenshots & Demo-GIFs für README
- [ ] 🧪 Unit Tests (pytest)
- [ ] 📦 pip-Package (`pip install dgkn-crypto`)

---

## ⚠️ Sicherheitshinweise

> **Passwort vergessen = Daten unwiederbringlich verloren.**
> Es gibt keine Passwort-Wiederherstellung – das ist gewollt.

- Bewahre `.dgkn2` und `.key2` **immer zusammen** auf
- Mache **Backups** der Key-Dateien an einem sicheren Ort
- Verwende ein **starkes Passwort** (≥ 16 Zeichen empfohlen)
- DGKN schützt **Dateien**, keine ganzen Laufwerke – für Laufwerke: VeraCrypt

### Sicherheitslücke melden

Bitte **keine** öffentlichen Issues für Sicherheitslücken!  
→ Direkt per GitHub Private Vulnerability Reporting oder E-Mail an den Maintainer.

---

## 📜 Lizenz

```
MIT License

Copyright (c) 2026 dogenc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 🙏 Danksagungen

- [**cryptography**](https://cryptography.io) – Python Kryptographie-Bibliothek
- [**NIST**](https://csrc.nist.gov) – AES & PBKDF2 Standards
- Community-Feedback & BlackBox.AI Code-Review für v2.0

---

<div align="center">

Made with ❤️ by [dogenc](https://github.com/dogenc)

⭐ **Wenn dir das Projekt gefällt, gib ihm einen Stern!** ⭐

</div>
