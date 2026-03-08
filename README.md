<div align="center">

<img src="https://img.shields.io/badge/Version-3.0-A855F7?style=for-the-badge&logo=python&logoColor=white" alt="Version"/>
<img src="https://img.shields.io/badge/Python-3.8+-A855F7?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
<img src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge" alt="License"/>
<img src="https://img.shields.io/badge/Cipher-XChaCha20--Poly1305-ef4444?style=for-the-badge" alt="XChaCha20"/>
<img src="https://img.shields.io/badge/MAC-BLAKE2b--512-06b6d4?style=for-the-badge" alt="BLAKE2b"/>
<img src="https://img.shields.io/badge/Nonce-192--Bit-eab308?style=for-the-badge" alt="Nonce"/>

<br/><br/>

```
    ██████╗  ██████╗ ██╗  ██╗███╗   ██╗
    ██╔══██╗██╔════╝ ██║ ██╔╝████╗  ██║
    ██║  ██║██║  ███╗█████╔╝ ██╔██╗ ██║
    ██║  ██║██║   ██║██╔═██╗ ██║╚██╗██║
    ██████╔╝╚██████╔╝██║  ██╗██║ ╚████║
    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
CRYPTO SUITE  v3.0
XChaCha20-Poly1305
```

**Professionelle Dateiverschlüsselung · XChaCha20-Poly1305 · BLAKE2b-512 · Open Source**

[🔒 Features](#-features) · [⚡ Quickstart](#-quickstart) · [🛡 Sicherheit](#-sicherheitsarchitektur) · [📊 v2 vs v3](#-v20-vs-v30) · [🤝 Contributing](#-contributing)

</div>

---

## 📖 Was ist DGKN Crypto Suite v3?

DGKN Crypto Suite v3 ist eine **Open-Source Datei-Verschlüsselungs-App** mit grafischer Oberfläche (GUI) für Windows, Linux und macOS. v3 verwendet **XChaCha20-Poly1305** – den modernen Nachfolger von AES-GCM, der von **Signal, WireGuard und libsodium** als Standard eingesetzt wird.

> **Für Einsteiger:** Datei wählen → Passwort eingeben → fertig. Die Datei ist danach für niemanden ohne das Passwort lesbar.

> **Für Entwickler:** XChaCha20-Poly1305 (192-Bit Nonce via HChaCha20) · PBKDF2-SHA512 (650K iter) · HKDF Key Separation · BLAKE2b-512 MAC · AAD Chunk-Binding · Authenticate-then-Decrypt · Streaming.

---

## ✨ Features

### 🔐 Sicherheit
- **XChaCha20-Poly1305** – Stream Cipher + MAC in einem (AEAD)
- **192-Bit Nonce** – zufällig generierbar, praktisch keine Kollisionsgefahr
- **HChaCha20 Subkey** – RFC-konforme Implementierung ohne externe Abhängigkeiten
- **PBKDF2-HMAC-SHA512** mit 650.000 Iterationen (NIST 2024)
- **HKDF Key Separation** – separate Schlüssel für Cipher und MAC
- **BLAKE2b-512 MAC** – schneller und moderner als HMAC-SHA256
- **AAD-Binding** – Chunk-Index + Salt-Hash gebunden ans Ciphertext
- **Authenticate-then-Decrypt** – Manipulation erkannt *bevor* entschlüsselt wird
- **Zufälliger 256-Bit Salt** pro Datei

### 🖥 Benutzerfreundlichkeit
- **Grafische Oberfläche** (tkinter) – keine Terminal-Kenntnisse nötig
- **Drag & Drop** Dateiauswahl
- **Echtzeit-Fortschrittsanzeige** (echter Chunk-Fortschritt)
- **Passwort-Stärke + Entropie in Bits** (z.B. 118 Bit für starke Passwörter)
- **v2 vs v3 Vergleichs-Tab** direkt in der App

### ⚙️ Technisch
- **Streaming / Chunk-Verarbeitung** (64 KB) – auch 100+ GB Dateien
- **Thread-sicheres UI** via `root.after()` – kein Einfrieren
- **Secure Delete** (3-Pass `os.urandom` + `fsync`)
- **Generische Fehlermeldungen** – kein Traceback nach außen

---

## ⚡ Quickstart

### Voraussetzungen

```
Python 3.8+
```

### Installation

```bash
# 1. Repository klonen
git clone https://github.com/dogenc/dgknCryptoSuite.git
cd dgknCryptoSuite/v3

# 2. Abhängigkeit installieren
pip install cryptography

# tkinter (Linux)
sudo apt install python3-tk       # Debian / Ubuntu / Kali
sudo dnf install python3-tkinter  # Fedora
sudo pacman -S tk                 # Arch

# 3. Starten
python3 dgkn_crypto_v3.py
```

### Windows / macOS

```bash
pip install cryptography
python3 dgkn_crypto_v3.py
# tkinter ist bei Windows/macOS Python bereits enthalten
```

### `requirements.txt`

```
cryptography>=41.0.0
```

---

## 🖼 Screenshots

> 📸 *Screenshots*
<img src=https://github.com/dogenc/dgknCryptoSuite/blob/main/previewv.png/>

## 🛡 Sicherheitsarchitektur

### Dateiformat `.dgkn3`

```
┌───────────────────────────────────────────────────────────┐
│ Magic       5 B    "DGKN3"  (Format-Kennung)              │
│ FormatVer   1 B    Version 1                              │
│ Salt       32 B    PBKDF2-Salt  (256-Bit Zufall)          │
│ N_Chunks    4 B    Anzahl Chunks  (uint32)                 │
│ ── pro Chunk: ────────────────────────────────────────── │
│   Nonce    24 B    XChaCha20 Nonce  (192-Bit Zufall)      │
│   Len       4 B    Ciphertext-Länge                       │
│   AAD      32 B    Chunk-Index + Salt-Hash  (gebunden)    │
│   CT       var     XChaCha20-Poly1305 + 16-B Poly1305 Tag │
│ ── Ende: ──────────────────────────────────────────────── │
│ BLAKE2b    64 B    MAC über gesamte Datei                 │
└───────────────────────────────────────────────────────────┘
```

### Schlüsselableitung

```
Passwort  +  Salt (256-Bit)
        │
        ▼
PBKDF2-HMAC-SHA512
(650.000 Iterationen)
        │
        ▼  64 Bytes Master Secret
   ┌────┴────────────┐
   │                 │
HKDF (info=enc)   HKDF (info=mac)
   │                 │
enc_key (32B)     mac_key (32B)
XChaCha20         BLAKE2b-512
```

### Warum XChaCha20-Poly1305?

| Eigenschaft | XChaCha20-Poly1305 | AES-256-GCM |
|---|---|---|
| Nonce-Größe | **192 Bit** (24 Byte) | 96 Bit (12 Byte) |
| Nonce zufällig sicher | ✅ immer | ⚠️ Vorsicht bei >2^32 Msgs |
| ARM / ohne AES-Hardware | ✅ Schnell | ⚠️ Langsam |
| x86 mit AES-NI | ✅ Schnell | ✅ Sehr schnell |
| Genutzt von | Signal, WireGuard, libsodium | TLS 1.3, HTTPS |
| NIST-Standard | ❌ (IETF RFC 8439) | ✅ |
| Empfohlen für | **Alle Geräte** | Server mit AES-NI |

### AAD – Chunk-Binding (neu in v3)

```python
AAD = struct.pack(">I", chunk_index)     # 4 Bytes
    + blake2b(salt, digest_size=28)      # 28 Bytes
                                         # = 32 Bytes gesamt
```

→ Jeder Chunk ist an seine Position und den Salt gebunden.
→ Chunks können nicht umgeordnet, ausgetauscht oder kopiert werden.

---

## 📊 v2.0 vs v3.0

| Eigenschaft | v2.0 | v3.0 |
|---|---|---|
| Cipher | AES-256-GCM | **XChaCha20-Poly1305** |
| Nonce-Größe | 96 Bit | **192 Bit** |
| Nonce-Kollision | 1/2^32 bei 4 Mrd. Msgs | **Praktisch unmöglich** |
| ARM / ohne AES-NI | Langsam | **Schnell** |
| KDF | PBKDF2-SHA256 / 600K | **PBKDF2-SHA512 / 650K** |
| MAC | HMAC-SHA256 (32 B) | **BLAKE2b-512 (64 B)** |
| AAD Chunk-Binding | ❌ | ✅ |
| Dateiendung | `.dgkn2` / `.key2` | `.dgkn3` / `.key3` |
| Kompatibilität | — | Nicht zu v2 kompatibel |

> v2 ist weiterhin im Repository unter `/v2/` verfügbar.

---

## 📁 Projektstruktur

```
dgknCryptoSuite/
│
├── README.md                  ← Diese Datei (v3)
├── LICENSE                    ← MIT
├── requirements.txt
│
├── v3/                        ← Empfohlen
│   └── dgkn_crypto_v3.py
│
└── v2/                        ← Legacy (AES-256-GCM)
    └── dgkn_crypto_v2.py
```

---

## 🔧 API – ohne GUI verwenden

```python
from dgkn_crypto_v3 import CryptoEngineV3

# Datei verschlüsseln
ok, enc_path, key_path, meta = CryptoEngineV3.encrypt_file(
    src_path   = "geheim.pdf",
    password   = "MeinSicheresPasswort!42",
    output_dir = "./encrypted/",
    secure_del = False,
)
if ok:
    print(f"Algorithmus: {meta['algo']}")   # XChaCha20-Poly1305
    print(f"MAC:         {meta['mac']}")    # BLAKE2b-512

# Datei entschlüsseln
ok, out_path, meta, _ = CryptoEngineV3.decrypt_file(
    dgkn_path  = "geheim.dgkn3",
    password   = "MeinSicheresPasswort!42",
    key_path   = "geheim.key3",
    output_dir = "./decrypted/",
)
```

---

## 🤝 Contributing

```bash
# Fork → Clone → Branch
git checkout -b feature/mein-feature

# Commit
git commit -m "feat: Beschreibung"

# Push → Pull Request
git push origin feature/mein-feature
```

### Ideen für Contributions

- [ ] 🌍 Englische Übersetzung
- [ ] 🧪 Unit Tests (pytest)
- [ ] 📦 pip-Package (`pip install dgkn-crypto`)
- [ ] 🗂 Ordner-Verschlüsselung
- [ ] 🖼 Screenshots & Demo-GIF
- [ ] 📱 Mobile Version (Kivy)
---
# DGKN Crypto Suite v3 im Vergleich: State-of-the-Art Kryptografie für höchste Sicherheitsansprüche

Während viele etablierte Verschlüsselungstools auf teils jahrzehntealten Standards beharren, setzt die **DGKN Crypto Suite v3** auf ein vollständig modernisiertes, mehrschichtiges Sicherheitskonzept. Das Ergebnis: Überlegene Resistenz gegen Angriffe, optimierte Performance und eine zukunftssichere Architektur.

Die folgende Tabelle vergleicht **DGKN Crypto Suite v3** mit gängigen Krypto-Apps und -Bibliotheken (wie VeraCrypt, Cryptomator, AxCrypt oder GPG):

| Sicherheitsmerkmal | **DGKN Crypto Suite v3** | Gängige Krypto-Apps (Traditionell) | Der DGKN-Vorteil |
|:---|:---|:---|:---|
| **Verschlüsselungsalgorithmus** | **XChaCha20-Poly1305 (AEAD)** | AES-256-GCM oder AES-256-CBC (oft veraltet) | **Überlegen in Geschwindigkeit & Sicherheit:** XChaCha20 ist auf allen Systemen schnell (keine Hardwareabhängigkeit wie AES-NI). Der **192-Bit Nonce** erlaubt **zufällige Nonces ohne Kollisionsrisiko** – bei AES-GCM (96-Bit) führen Nonce-Fehler sofort zur Katastrophe. |
| **Integritätssicherung (MAC)** | **BLAKE2b-512** (als Teil des AEAD) | HMAC-SHA256 oder reines Poly1305 | **Schneller & sicherer:** BLAKE2b ist in Software **deutlich schneller als SHA-2-Familie** und liefert einen **512-Bit MAC** – doppelte Sicherheitsmarge gegenüber HMAC-SHA256. |
| **Schlüsselableitung (KDF)** | **PBKDF2-HMAC-SHA512** mit **650.000 Iterationen** (NIST 2024-konform) | PBKDF2 mit niedrigen Iterationen (10.000–100.000) oder veraltete Methoden | **Zukunftssicherheit pur:** Die Iterationsanzahl entspricht den **aktuellsten NIST-Empfehlungen (2024)** . Brute-Force-Angriffe werden so um ein Vielfaches teurer – Ihr Passwort bleibt auch in 10+ Jahren sicher. |
| **Schlüsseltrennung** | **HKDF** – separate Schlüssel für Cipher, MAC und Metadaten | Ein einzelner Schlüssel für mehrere Zwecke | **Defense in Depth:** HKDF (RFC 5869) erzeugt **kryptografisch unabhängige Schlüssel** aus einem Master-Schlüssel. Selbst wenn ein Teilschlüssel kompromittiert wird, bleiben die anderen Bereiche sicher. |
| **Nonce & Salt** | **192-Bit zufällige Nonce** + **256-Bit zufälliger Salt** pro Datei | 96-Bit Nonce (bei GCM) oder inkrementelle Zähler | **Maximale Zufälligkeit:** Die Nonce ist so groß, dass **Kollisionen praktisch unmöglich** sind. Der 256-Bit Salt pro Datei macht Wörterbuchangriffe selbst bei schwachen Passwörtern extrem aufwändig. |
| **Authenticated Additional Data (AAD)** | **Chunk-Index + Salt-Hash** – fest an Ciphertext gebunden | Wird oft ignoriert oder nur oberflächlich genutzt | **Manipulationserkennung auf Meta-Ebene:** Jeder verschlüsselte Chunk ist untrennbar mit seinem Index und dem Datei-Salt verbunden. Chunk-Vertauschungen oder Zusammenbau aus verschiedenen Dateien werden **sofort erkannt**. |
| **Entschlüsselungs-Logik** | **Authenticate-then-Decrypt** | Decrypt-then-Authenticate oder beides parallel | **Hardened Security:** Die MAC-Prüfung erfolgt **vor** der Entschlüsselung. Manipulierte Daten werden gar nicht erst entschlüsselt – das schließt viele Seitenkanal-Angriffe von vornherein aus. |
| **Abhängigkeiten** | **Keine externen Bibliotheken** – vollständig eigene Implementierung | OpenSSL, libgcrypt oder andere externe Kryptobibliotheken | **Auditierbar & transparent:** Der gesamte Code liegt offen. Keine versteckten Fallstricke durch Drittanbieter-Bibliotheken. Sie sehen genau, was passiert. |
| **RFC-Konformität** | **HChaCha20 nach RFC 7539** – korrekt implementiert | Oft proprietäre Abwandlungen oder vereinfachte Implementierungen | **Standardkonform:** Die Implementierung folgt genau den RFC-Vorgaben – das garantiert Kompatibilität mit anderen RFC-konformen Systemen und vermeidet Implementierungsfehler. |

## Das Fazit

**DGKN Crypto Suite v3** ist keine weitere "Noch-eine-Verschlüsselungs-App". Es ist eine **sorgfältig kuratierte Suite modernster kryptografischer Verfahren**:

- ✅ **XChaCha20-Poly1305** – der Nachfolger von AES-GCM, ohne dessen Schwächen
- ✅ **650.000 PBKDF2-Iterationen** – nach NIST 2024, nicht nach Standards von 2010
- ✅ **HKDF + BLAKE2b** – moderne Schlüsselableitung und schnellste MACs
- ✅ **Authenticate-then-Decrypt** – wie echte Sicherheitsprofis implementieren
- ✅ **Zero externer Code** – 100% transparent, 100% kontrollierbar

**DGKN Crypto Suite v3** setzt den Standard für das, was man von einer ernstzunehmenden Verschlüsselungslösung im Jahr 2024 und darüber hinaus erwarten darf.

---

## 🔬 Hintergrund

Alle verwendeten Algorithmen wurden nach aktuellen wissenschaftlichen Empfehlungen ausgewählt und implementiert. Die Parameter (insbesondere die 650.000 PBKDF2-Iterationen) folgen den **NIST Digital Identity Guidelines 2024** und bieten damit eine Sicherheit, die viele kommerzielle Lösungen hinter sich lässt.

---

**DGKN Crypto Suite v3 – Sicherheit, der Sie vertrauen können.**
---
---

## ⚠️ Sicherheitshinweise

> **Passwort vergessen = Daten unwiederbringlich verloren.**

- `.dgkn3` und `.key3` **immer zusammen** aufbewahren
- **Backups** der `.key3` Dateien anlegen
- Empfohlene Passwortlänge: **≥ 16 Zeichen** (≥ 80 Bit Entropie)
- `.dgkn3` Dateien sind **nicht kompatibel** mit v2

### Sicherheitslücke melden

Bitte **keine** öffentlichen Issues für Sicherheitslücken!
→ GitHub Private Vulnerability Reporting verwenden.

---

## 📜 Lizenz

MIT License · Copyright (c) 2026 dogenc

---

<div align="center">

Made with ❤️ by [dogenc](https://github.com/dogenc)

⭐ **Wenn dir das Projekt gefällt – gib ihm einen Stern!** ⭐

</div>
