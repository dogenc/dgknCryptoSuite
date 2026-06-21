<div align="center">

```
                                                                                         
▄▄▄▄▄▄    ▄▄▄▄▄▄▄  ▄▄▄   ▄▄▄ ▄▄▄    ▄▄▄   ▄███████▄ ▄▄▄        ▄▄▄▄   ▄▄▄▄▄▄▄    ▄▄▄▄▄▄▄ 
███▀▀██▄ ███▀▀▀▀▀  ███ ▄███▀ ████▄  ███  ██     ▀█▄ ███      ▄██▀▀██▄ ███▀▀███▄ █████▀▀▀ 
███  ███ ███       ███████   ███▀██▄███ ██  ▄█▀▀▀██ ███      ███  ███ ███▄▄███▀  ▀████▄  
███  ███ ███  ███▀ ███▀███▄  ███  ▀████ ██  ██   ██ ███      ███▀▀███ ███  ███▄    ▀████ 
██████▀  ▀██████▀  ███  ▀███ ███    ███  ██▄ ▀▀▀▀▀▀ ████████ ███  ███ ████████▀ ███████▀ 
                                          ▀▀██████▀▀                                     
                                                                                         
```

# DGKN@Labs · Crypto Suite v7

**🌐 Language:** **English** · [Deutsch](README.de.md)

**Local. Offline. Uncompromising. — Native C++ Edition**

<img src="docs/img/splash.png" alt="DGKN@Labs Crypto Suite — Secure Crypto Terminal splash screen" width="560">


[![C++](https://img.shields.io/badge/C%2B%2B-20-00599C?style=flat-square&logo=cplusplus&logoColor=white)](https://isocpp.org)
[![Qt](https://img.shields.io/badge/GUI-Qt%206-41CD52?style=flat-square&logo=qt&logoColor=white)](https://qt.io)
[![License](https://img.shields.io/badge/License-GPLv3-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat-square&logo=windows&logoColor=white)](https://microsoft.com/windows)
[![Crypto](https://img.shields.io/badge/Cipher-XChaCha20--Poly1305-green?style=flat-square)](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
[![KDF](https://img.shields.io/badge/KDF-Argon2id%20%2B%20HKDF-orange?style=flat-square)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()

</div>

---

## Overview

DGKN Crypto Suite is a local, security-focused **encrypted volume manager** for Windows, written entirely in **native C++** with a **Qt 6** GUI. Files are stored inside encrypted containers that can only be opened with the correct password plus the bound 2FA secret. (Optional TPM / device binding is implemented in the core but **not yet exposed in the v7 GUI** — see *Security Architecture*.)

> **No cloud. No telemetry. No backdoors. Your data stays yours.**

<p align="center">
  <img src="docs/img/dashboard.png" alt="DGKN@Labs Crypto Suite — Operations Dashboard showing the crypto config (XChaCha20-Poly1305 · Argon2id · TOTP 2FA · TPM) and live system metrics" width="820">
  <br>
  <em>The Operations Dashboard — crypto configuration tiles plus live system metrics.</em>
</p>

### Why native C++ (and not Python anymore)

The earlier Python implementation could **not reliably erase key material from RAM** — Python strings are immutable, the garbage collector copies objects freely, and there is no guaranteed in-place wipe. Key bytes could linger in memory long after use.

The C++ edition fixes this at the root:

- Master/sector keys live in `sodium_mlock`ed buffers (excluded from the page file / no swap to disk) and are `sodium_munlock`ed — which zeroes them — the moment a volume is unmounted. Derived keys and decrypted plaintext are wiped with `sodium_memzero` (never elided by the optimizer) after use.
- A `SecureBuffer` helper (`VirtualLock` + guaranteed zero-on-destruction) is provided in `core/SecureMemory` for callers that want a RAII buffer; the live container/file paths use the `sodium_mlock`/`sodium_memzero` approach directly.
- No interpreter heap, no GC, no hidden copies of plaintext passwords (best-effort — see the Qt input caveat in `SECURITY.md`).

### Hardening

| Layer | Measure |
|---|---|
| **KDF** | Argon2id with **256 MiB** memory cost (memory-hard, GPU/ASIC-resistant) |
| **Memory** | `VirtualLock`/`sodium_mlock` on keys, `sodium_memzero` wipe on free |
| **Timing** | Constant-time comparisons (`sodium_memcmp`) for the header sentinel and journal HMAC |
| **AEAD** | XChaCha20-Poly1305 everywhere; tampered ciphertext/AAD is rejected by the Poly1305 tag |
| **Virtual drive** | Decrypted data lives **only in RAM** via a WinFsp filesystem — no plaintext temp folder on disk |
| **Path safety** | Archive entries are validated against traversal (`..`, absolute paths, drive letters); unpack is sandboxed to the target dir |
| **Anti-debug** | `IsDebuggerPresent` + `CheckRemoteDebuggerPresent` → self-defense (emergency wipe + abort). *Defense-in-depth/obscurity only — trivially bypassable by a determined attacker; the real protection is the cryptography, not this check.* |
| **Compiler** | `/GS` `/guard:cf` `/sdl` `/Qspectre` |
| **Linker** | ASLR (`/DYNAMICBASE` `/HIGHENTROPYVA`), DEP (`/NXCOMPAT`), Control Flow Guard, CET shadow stack (`/CETCOMPAT`) |
| **Journal** | HMAC-SHA256 (derived key) crash-recovery; partial writes are detected and refused at mount |
| **Input bounds** | AEAD key/nonce lengths validated; short ciphertext rejected (no `size_t` underflow); header plaintext length-checked before parsing (no OOB read) |
| **Integer safety** | Overflow-safe region checks (`offset + size` can't wrap past `fsize`); allocations bounded by file size (no attacker-controlled `bad_alloc`) |
| **Guaranteed wipe** | `SecureBuffer::zero()` uses `sodium_memzero` (never elided by the optimizer, unlike `memset`) |
| **Password policy** | Strength enforced at container creation (≥16 chars, 3 char classes, no trivial patterns) |
| **2FA secret (2nd key factor)** | The TOTP secret is mixed into the key derivation for **both containers and standalone files** — without the exact same secret, decryption fails even with the right password. The 6-digit RFC-6238 code is additionally verified at container create/open/change (own audited SHA-1/HMAC-SHA1, constant-time, ±1 window; scannable QR via libqrencode). **Note:** for offline data the secret acts as a second *key factor* (like a memorized keyfile), not as server-checked online 2FA. |
| **Persistent lockout** | Brute-force lockout is HMAC-persisted per identity → survives app restarts (online attacker can't reset it by relaunching) |
| **Duress password** | A separate emergency password is rejected exactly like a wrong one (no tell) and can optionally sanitize all headers — anti-coercion |
| **Live security bar** | The GUI shows a system-status bar (debugger attached, real-time AV active, admin/elevation) — an honest posture indicator, *not* a malware scanner |
| **TPM 2.0 detection + machine-bound sealing** | Real TBS availability check (genuine TPM 2.0 detection). Sealing itself uses **DPAPI `CRYPTPROTECT_LOCAL_MACHINE`** (the PCR string is passed as DPAPI entropy, *not* a real TPM PCR policy) — the sealed blob is bound to this machine and not portable to another PC. Honest scope: this is machine-bound DPAPI sealing, not TPM command-level PCR sealing. |
| **Auto-lock** | After 10 min of inactivity all mounts are closed and keys wiped automatically |
| **Clipboard auto-clear** | Copied 2FA secrets are removed from the clipboard after 15 s (only if still ours) |
| **Tamper-evident audit log** | HMAC-SHA256 hash-chain: every line signs the previous one; any edit/insert/delete breaks the chain and is flagged on startup. Stored under per-user `%APPDATA%` (not world-readable `%TEMP%`) |
| **No plaintext secrets on disk** | The App-Login 2FA secret is persisted **only encrypted** (XChaCha20-Poly1305, key via Argon2id from a separate master password) in `%LOCALAPPDATA%\DGKN\security\2fa.json`; per-operation container secrets are entered each time and wiped from RAM. The legacy clear-text secret file was removed and git-ignored |
| **Persistent App-Login 2FA** | The TOTP secret is set up once and stored encrypted (see above), restricted to the current user via Windows ACL and written atomically — re-opening Settings unlocks the *same* secret with the master password instead of regenerating it. Quantum-resistant by construction (XChaCha20 256-bit + Argon2id); no PQC theater |
| **Recovery codes** | 10 one-time codes generated at setup, stored **only** as per-code Argon2id hashes (plaintext shown once, never persisted). A code substitutes once for the TOTP code at login; reuse is rejected; verification is constant-time |
| **Process manifest** | Embedded manifest: `SegmentHeap` (hardened heap), per-monitor DPI, `asInvoker` (no silent elevation) |
| **CI pipeline** | GitHub Actions builds (hardened), runs the full Catch2 suite + 50k fuzz iterations + BinSkim mitigation check on every push |
| **Reproducible + verifiable** | `/Brepro` build, pinned `vcpkg.json` baseline, Authenticode-signed release binaries |

---

## Comparison with other tools

How DGKN Crypto Suite compares to common full-/file-level encryption tools. *(✅ yes · ⚠️ partial/optional · ❌ no)*

| | **DGKN v7** | VeraCrypt | BitLocker | Cryptomator |
|---|:---:|:---:|:---:|:---:|
| **Cipher** | XChaCha20-Poly1305 (AEAD) | AES/Serpent/Twofish (XTS, no AEAD) | AES-XTS | AES-GCM / scrypt |
| **Authenticated encryption** (tamper detection) | ✅ Poly1305 on header + container payload (one tag over the archive); standalone files are tagged per 4 KiB sector | ❌ XTS has no MAC | ❌ XTS has no MAC | ✅ GCM |
| **KDF** | Argon2id 256 MiB (memory-hard) | PBKDF2 (not memory-hard) | — (TPM/PIN) | scrypt |
| **2FA secret (2nd key factor)** | ✅ key-binding for containers *and* files + RFC-6238 code check (containers) | ❌ | ⚠️ TPM/PIN | ❌ |
| **TPM 2.0 binding** | ⚠️ TPM *detection* (TBS) + machine-bound **DPAPI** sealing — not real TPM PCR sealing; *core only, no v7 GUI toggle* | ❌ | ✅ (true TPM) | ❌ |
| **Device binding** (MachineGuid) | ⚠️ in core, *not yet GUI-exposed in v7* | ❌ | ✅ | ❌ |
| **Hidden volume** (plausible deniability) | ✅ key-salted HMAC offsets | ✅ fixed layout | ❌ | ❌ |
| **Full header encryption** (no plaintext magic) | ✅ indistinguishable from random | ⚠️ | ❌ | ❌ |
| **Keys locked in RAM** (no swap) | ✅ `sodium_mlock` (wraps `VirtualLock`) + `sodium_memzero` wipe | ⚠️ | n/a (kernel) | ❌ (JVM/GC) |
| **No plaintext on disk while mounted** | ✅ in-RAM WinFsp FS | ✅ kernel driver | ✅ | ❌ writes to a folder |
| **Crash-safe write journal** (HMAC-verified) | ✅ | ⚠️ | ✅ | ⚠️ |
| **Constant-time secret comparisons** | ✅ `sodium_memcmp` | ✅ | ✅ | ✅ |
| **Anti-debug / self-defense wipe** | ⚠️ obscurity only (trivially bypassable; not real protection) | ❌ | ❌ | ❌ |
| **Binary mitigations** (ASLR/DEP/CFG/CET) | ✅ all enabled | ⚠️ | ✅ | n/a (JVM) |
| **Source available / auditable** | ✅ open source (GPLv3) | ✅ open source | ❌ closed | ✅ open source |
| **Per-file encryption** (vs whole volume) | ✅ container *and* standalone files | ❌ volume only | ❌ volume only | ✅ |
| **Cross-platform** | ❌ Windows only | ✅ | ❌ Windows | ✅ |
| **Maturity / audit status** | 🟡 new, self-audited | 🟢 widely audited | 🟢 | 🟢 audited |

**Where DGKN aims higher:** authenticated encryption on every layer (XTS-based tools can't detect tampering at all), a memory-hard KDF (Argon2id 256 MiB vs PBKDF2), a second key factor (mandatory for containers, optional for files), and a fully encrypted header that looks like random noise. *(The anti-debug check is cosmetic defense-in-depth, not a real advantage.)*

**Honest trade-offs:** DGKN is **Windows-only**, **new and not yet independently audited**, and its real virtual-drive mount needs the WinFsp driver (no admin required). VeraCrypt and BitLocker are battle-tested over many years — for high-stakes use, prefer audited tools until DGKN has had external review.

---

## Features

| Feature | Details |
|---|---|
| 🔐 **Encryption** | XChaCha20-Poly1305 (container + payload layer) |
| 🔑 **Key Derivation** | Argon2id (memory-hard) + HKDF-SHA256 — GPU/ASIC-resistant |
| 🫥 **Plausible Deniability** | Hidden volumes with key-salted HMAC scan offsets |
| 🛡️ **Full Header Encryption** | No plaintext magic bytes — headers are indistinguishable from random |
| 🔒 **Multi-Factor Binding** | Containers: password + 2FA secret. *(TPM 2.0 + Device-ID binding are implemented in the core derivation pipeline but **not yet exposed in the v7 GUI**.)* Single-file encryption additionally supports an **optional keyfile** (any file type) as a second key factor, selectable in the GUI. |
| 💾 **Transaction Journal** | HMAC-verified journal for crash-safe unmount/write recovery |
| 🧠 **Secure Memory** | `VirtualLock` + `sodium_memzero` for all key material (native, no GC) |
| ⏱️ **Brute-Force Protection** | Auth lockout + exponential backoff |
| 🆘 **Emergency Mode** | Instant unmount + optional header sanitization |
| 🖥️ **Native GUI** | Qt 6 Widgets, dark theme, zero web/Electron overhead |

---

## Security Architecture

The key-derivation pipeline below is the **cryptographic core**; it can mix in a keyfile,
2FA secret, TPM secret and device binding. **Where each factor is actually entered in the
app, though, differs:**

- **Containers** (create / mount / change-password / integrity) bind **password + 2FA
  secret**. They do **not** offer a keyfile field — a long, strong passphrase plus the
  mandatory 2FA factor is the intended protection. *(TPM and device binding are part of the
  derivation pipeline below and fully implemented in the core, but the v7 GUI does not yet
  expose a toggle for them, so in v7 containers are bound by password + 2FA only.)*
- **Single-file encryption** (Encrypt / decrypt single files) binds **password + optional
  keyfile + 2FA secret**. This is the only place the keyfile is entered in the GUI.

So the keyfile in the diagram applies to **single-file encryption**; for containers, read
the same pipeline with the keyfile input empty.

```
Password + [Keyfile — single-file encryption only] + 2FA Secret + [TPM Secret + Device-ID — core only, no v7 GUI toggle]
                          │
                    SHA-256 binding digest
                          │
              ┌───────────▼───────────┐
              │   Argon2id KDF (v7)   │  memory-hard
              │   HKDF (SHA-256)      │  info: "DGKN7-NORM" / "DGKN7-HIDE"
              └───────────┬───────────┘
                          │  master_key (256-bit)
              ┌───────────▼───────────┐
              │  XChaCha20-Poly1305   │  Header encryption
              │  (salt + nonce + tag) │
              └───────────┬───────────┘
                          │
              ┌───────────▼───────────┐
              │   Sector-KDF (HKDF)   │  sector_key per volume
              └───────────┬───────────┘
                          │
              ┌───────────▼───────────┐
              │  SectorCrypto (AEAD)  │  Each sector: nonce(key, idx, epoch)
              │  AAD = sector index   │  + 16-byte Poly1305 tag
              └───────────────────────┘
```

---

## Threat Model

### ✅ Protected Against

- Offline attacks on stolen container files
- Forensic metadata analysis of headers (full header encryption, no plaintext identifiers)
- Password guessing via repeated online attempts (lockout + backoff)
- Data corruption from crashes during write operations (HMAC-verified journal recovery)
- RAM analysis of idle key material — keys are held in `sodium_mlock`ed pages (which uses `VirtualLock` on Windows; excluded from swap) and zeroized with `sodium_memzero` on unmount; no GC copies as in the former Python build
- Hidden volume detection via deterministic scanning (key-salted HMAC scan offsets since v7)
- Weak emergency passwords (Argon2id-hashed with app-specific salt)
- Journal metadata leaks (HMAC-protected payload integrity since v7)

### ❌ Out of Scope

- Fully compromised operating systems (kernel malware, live memory dumps with root privileges)
- Hardware / side-channel attacks at the physical layer
- Loss of 2FA secret or keyfile without backup (App-Login 2FA additionally offers one-time recovery codes, but a forgotten master password is not recoverable)
- Social engineering attacks

---

## Installation (end users)

> **🧪 This is an evaluation preview.** DGKN is offered for you to **try out and give
> feedback** — it is new and not yet independently audited, so please don't trust it with
> data of real value yet. Found a bug, a rough edge, or have an idea? Open an issue or get
> in touch (see *Project* below). Feedback is exactly what this release is for. Usage terms
> are in **[LICENSE](LICENSE)** (free software under the GPLv3).

Ship a single **`DGKN-Setup.exe`** — no separate DLLs to copy. It is a self-extracting
(7-Zip SFX) package built from the `dist/` folder; it bundles `dgkn_gui.exe` plus all
runtime DLLs and Qt plugins and the license texts.

```powershell
# After building (see "Build" below) and deploying the Qt runtime:
powershell -ExecutionPolicy Bypass -File installer\make_dist.ps1   # -> clean dist\
powershell -ExecutionPolicy Bypass -File installer\make_sfx.ps1    # -> DGKN-Setup.exe on the Desktop
```

> An Inno Setup script (`installer/dgkn_setup.iss`) is also included as an alternative if you
> prefer a classic wizard installer; it needs Inno Setup installed. The released
> `DGKN-Setup.exe` is the self-extracting SFX build.

**To install:** double-click `DGKN-Setup.exe`. It extracts to
`%LOCALAPPDATA%\DGKN@Labs\Crypto Suite` (no admin required) and launches the app.

### ⚠️ Virtual drive needs WinFsp (no admin required)

File encryption/decryption and container management work with normal user rights.
**Mounting a container as a real drive letter** requires one thing:

- The **WinFsp** driver installed — it is a kernel-mode filesystem driver and is *not*
  bundled in the installer (drivers can't be shipped this way).

**Admin rights are *not* required to mount.** WinFsp attaches the drive letter in your own
user session; the app waits until the drive is actually visible before reporting success,
and retries across several free letters (Z: → F:) if the first attempt doesn't come up. If
WinFsp is missing or no drive letter is free, the container is still authenticated and held
in RAM only (no drive letter — expected, not an error).

> **ℹ️ WinFsp version compatibility — Windows 11 Insider / Dev Channel builds**
>
> Mounting has been verified working with **WinFsp 2.1** (SxS driver model) on Windows 11
> Insider / Dev Channel build **26220** (25H2). Earlier Insider builds in the 26xxx range
> showed a transient incompatibility where the SxS driver mounted internally but the drive
> letter never appeared in Explorer or `GetLogicalDrives()`; this was resolved by a later
> Windows cumulative update (and/or a clean WinFsp re-install).
>
> If you hit that symptom on an older Insider build, either update Windows to the latest
> cumulative update, or install **WinFsp 2.0** (`winfsp-2.0.23075.msi`) from
> <https://github.com/winfsp/winfsp/releases/tag/v2.0>, which does not use the SxS driver
> mechanism. After (re)installing WinFsp, reboot once so the kernel driver loads.

> **ℹ️ Reported drive capacity is slightly below the container size**
>
> A 500 MB container mounts as a drive with roughly **~449 MB usable**, a 50 MB hidden
> volume as **~49 MB**, and so on. This is expected: the in-RAM volume is presented to
> Windows as an **NTFS** filesystem, and NTFS reserves space for its own metadata (MFT,
> bitmap, log). The difference is filesystem overhead, exactly as on any real NTFS
> partition — no data is lost and the container file itself is unaffected.

> One thing *does* benefit from elevation, unrelated to mounting: the live **CPU-temperature**
> reading (WMI `MSAcpi_ThermalZoneTemperature`) needs admin and otherwise shows
> `n/a (Admin nötig)`. Everything else — crypto, containers, mounting — works as a normal user.

*(A portable self-extracting build is also available via `installer\make_sfx.ps1` if you
prefer no installer.)*

---

## Project structure

```
.
├── core/             # Crypto core (no Qt): container/file format, KDF, AEAD, TOTP, audit log
│   ├── Manager.*         container create/mount/unmount, header & payload, journal
│   ├── CryptoUtils.*     Argon2id + HKDF KDF, XChaCha20-Poly1305, sector crypto
│   ├── Crypto.*          hidden-volume offset helpers (test-only — see note in header)
│   ├── Archive.*         in-RAM archive pack/unpack (path-traversal hardened)
│   ├── Totp.*            RFC-6238 TOTP (own test-vector-verified SHA-1/HMAC)
│   ├── TwoFactorStore.*  persistent encrypted App-Login 2FA secret + recovery codes
│   ├── TPMUtils.*        TPM 2.0 detection + machine-bound DPAPI sealing
│   ├── AuditLog.*        tamper-evident HMAC hash-chain log
│   ├── SecureMemory.*    VirtualLock/zeroizing RAII buffer
│   └── VirtualVolume.*   WinFsp in-RAM virtual drive
├── gui/              # Qt 6 desktop app (MainWindow, Splash, theme, widgets, icon, manifest)
├── utils/            # FsHelpers (secure file/dir wipe)
├── tests/            # Catch2 suite + fuzz-stress target
├── installer/        # SFX packaging (PowerShell) + optional Inno Setup script
├── resources/icons/  # SVG design sources for the app icon
├── .github/workflows # CI (build + tests + fuzz + BinSkim)
├── Config.hpp        # central crypto/format constants
├── CMakeLists.txt · vcpkg.json   # build + pinned dependencies
├── main.cpp          # CLI entry (dgkn_crypto)
├── README.md · SECURITY.md · LICENSE
```

---

## Build

### Prerequisites

- Windows 10/11 (x64)
- **MSVC 2022** (Visual Studio Build Tools / VS 18+) with C++20
- **CMake ≥ 3.20** and **Ninja**
- **vcpkg** for dependencies (`libsodium`, `argon2`, `nlohmann-json`, `catch2`, `libqrencode`)
- **Qt 6** (msvc2022_64) — modules **Widgets, OpenGL, OpenGLWidgets** (GUI + 3D globe)
- **WinFsp** (optional, for the virtual-drive mount feature)

### Setup

```powershell
# 1. Clone
git clone https://github.com/dogenc/dgknCryptoSuite.git
cd dgknCryptoSuite

# 2. Dependencies via vcpkg
vcpkg install libsodium:x64-windows argon2:x64-windows `
              nlohmann-json:x64-windows catch2:x64-windows libqrencode:x64-windows

# 3. Configure (Release; point CMAKE_PREFIX_PATH at your Qt kit)
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release `
      -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake `
      -DVCPKG_TARGET_TRIPLET=x64-windows `
      -DCMAKE_PREFIX_PATH="C:/Qt/6.x/msvc2022_64"

# 4. Build everything (core lib, CLI, GUI, tests)
cmake --build build

# 5. Deploy Qt runtime next to the GUI exe
& "C:/Qt/6.x/msvc2022_64/bin/windeployqt.exe" build/dgkn_gui.exe
```

Targets produced in `build/`:

| Target | Description |
|---|---|
| `dgkn_gui.exe` | Qt 6 desktop application (main entry point) |
| `dgkn_crypto.exe` | minimal CLI (file encrypt/decrypt) |
| `dgkn_tests.exe` | Catch2 test suite |

> If your antivirus flags the freshly built, unsigned binaries (common false-positive for crypto tools using memory-locking / secure-wipe), add the `build/` folder to its exclusions during development. Production releases should be code-signed.

---

## Usage

The GUI uses a dark, high-contrast **"agency" theme**: a Bloomberg-style header with a
live date/time readout and a real **rotating 3D globe** (OpenGL), a live system-status bar
(`● SECURE` / `▲ ADVISORY` / `■ ALERT`), an operations sidebar, and a status-tile dashboard.
The dashboard shows the crypto config (cipher · KDF · 2FA · TPM) **plus live system
metrics** — CPU load, CPU temperature, RAM usage, and system-disk free/used — refreshed every
2 s with green/amber/red thresholds. A count of *active mounts* is deliberately **not**
displayed: such a counter would reveal that a hidden volume is currently mounted and thereby
undermine its plausible deniability.

For the same reason, the **Unmount** dialog never shows container names or the
`normal`/`hidden` mode. Mounted volumes are listed by a neutral *“Volume N”* plus the drive
letter only — so opening the dialog reveals nothing about *which* container (or whether a
hidden volume) is currently open. The unmount success/error messages are likewise generic.

The active antivirus product is **detected dynamically** via Windows Security Center (WMI
`AntiVirusProduct`) — nothing is hard-coded; the real product name and real-time-protection
state are read live.

Launch **`dgkn_gui.exe`**. From the sidebar you can:

- **Set up 2FA / TOTP** — generate a secret, scan the QR into an authenticator app, then secure it with a master password. On later opens the *same* secret is unlocked with that password (no regeneration). Recovery codes are shown once — save them. If the stored secret file (`%LOCALAPPDATA%\DGKN\security\2fa.json`) is ever damaged or in an old format, the app detects this on unlock and offers to discard it and re-enrol (instead of locking you out) — confirming this invalidates the previous binding and old recovery codes.
- **Create a container** (size, password, optional hidden volume). The mandatory 2FA key factor is taken **automatically from your stored App-Login secret** — you no longer paste a secret by hand; you just enter the current TOTP code once. The same stored secret is reused (unlocked once per session with the master password) for *change password* and *integrity check*, so a container made in v7 always opens with the same secret.
- **Open a container (mount)** — pick the `.dgkn`, choose the volume mode (normal/hidden) and enter the password; the stored App-Login secret + a TOTP code are used automatically. With **WinFsp installed**, the container is attached as a real drive letter (contents live only in RAM). Admin rights are **not** required — WinFsp mounts in your own user session. If no free drive letter can be assigned or WinFsp is missing, the container is still authenticated and loaded into RAM **without** a drive letter (expected, not an error).
- **Unmount** — pick an active mount and close it securely; the in-RAM archive is re-encrypted and written back via the HMAC-verified journal.
- **Encrypt / decrypt single files** — alongside the password you can pick an **optional keyfile** (any file — image, PDF, anything): its BLAKE2b hash becomes a second key factor, so the **exact same file** must be selected again to decrypt. Lose it or alter its contents and the file can no longer be opened — back the keyfile up separately. Like containers, the 2FA key factor is taken **automatically from your stored App-Login secret** (no pasting) and a TOTP code is requested as an identity check. Note: the secret *bytes* bind the file's key, so the **same stored secret** is required to decrypt — a TOTP code (which rotates every 30 s) cannot replace it. When decrypting, the app tries the stored secret first; if that fails (e.g. a file encrypted before v7 with a manually entered secret, or none), it offers to **enter the secret manually**. After a successful encrypt, the app asks whether to **securely delete the plaintext original** (multi-pass overwrite + delete). On SSDs, wear-leveling limits the effect of overwriting in place — full-disk encryption is the more reliable protection there. **⚠️ When decrypting, you choose the output path yourself — and the original file extension is *not* stored inside the encrypted file. So give the output the correct extension again (e.g. `report` → `report.pdf`, `photo` → `photo.jpg`), exactly as it was before encrypting; otherwise Windows won't know which program opens it. Tip: keep the original name minus the `.dgkn` (e.g. `report.pdf.dgkn` → `report.pdf`).**
- **Change a container password**
- **Check integrity** of a container
- **Back up the header**
- **Emergency wipe** (close all mounts, optional header sanitization)

> **For the virtual drive:** install **WinFsp** (<https://winfsp.dev>). Admin rights are
> **not** needed — WinFsp mounts the drive letter in your own user session. If WinFsp is
> missing (or no drive letter is free), file/container crypto still works, but a container
> is then held in RAM only — no drive letter is mounted. See *Installation* above.

### Where things are stored

| What | Location | Notes |
|------|----------|-------|
| **App-Login 2FA secret** | `%LOCALAPPDATA%\DGKN\security\2fa.json` | Encrypted (XChaCha20-Poly1305, key via Argon2id from the master password). Created the first time you save a 2FA secret. Restricted to the current user via a Windows ACL and written atomically. Holds the recovery codes **only as Argon2id hashes** — never in clear text. |
| **Audit log** | `%APPDATA%\…\dgkn_audit.log` (Qt `AppDataLocation`; falls back to `%TEMP%` if unavailable) | Tamper-evident append-only log. Kept out of world-readable `%TEMP%`. A manipulated log is detected and warned about on startup (no hard stop). |
| **Containers** | Wherever you save them (e.g. `vault.dgkn`) | You choose the path in the *Create container* / *Encrypt file* dialogs. Encrypted file output uses the `.dgkn` extension. |
| **Encrypted file output** | `<original>.dgkn` next to the source, unless you pick another path | After a successful encrypt the app offers to securely shred the plaintext original. |

> `%LOCALAPPDATA%` and `%APPDATA%` are standard Windows environment variables that Windows expands to your own per-user profile folder — the app never hard-codes a user path. The 2FA secret uses the **Local** profile (`%LOCALAPPDATA%`, device-bound, not roamed); the audit log uses Qt's `AppDataLocation`. Resolve the real folder yourself any time with `echo %LOCALAPPDATA%` in a terminal.

The public C++ API (`dgkn::core::ContainerManager`) mirrors these operations and returns
`OpResult { bool ok; std::string message; }` (on a successful mount, `message` is the mount id):

```cpp
#include "Manager.hpp"
using dgkn::core::ContainerManager;

ContainerManager m;
auto r = m.create_container("vault.dgkn", /*size_mb=*/100, "YourStr0ng#Passphrase!",
                            /*keyfile_a=*/"", /*pw_b=*/"", /*keyfile_b=*/"",
                            /*hidden_mb=*/0, /*twofa_secret=*/"YOUR_TOTP_BASE32");
if (!r.ok) /* handle r.message */;

auto mnt = m.mount_volume("vault.dgkn", "YourStr0ng#Passphrase!", "", "normal", "YOUR_TOTP_BASE32");
if (mnt.ok) m.unmount(mnt.message);
```

---

## Testing

```powershell
cmake --build build
ctest --test-dir build --output-on-failure
# or run directly:
build/dgkn_tests.exe
```

The Catch2 suite covers:

- XChaCha20 and per-sector AEAD round-trips (incl. AAD tamper rejection)
- Argon2id + HKDF key-derivation determinism
- Container create → mount → unmount round-trip
- Header encryption, tamper rejection, and integrity verification
- Hidden-volume create + mount
- Password change and authentication checks
- HMAC-verified journal crash recovery

---

## v7 Changelog

| Area | Change |
|---|---|
| **Full rewrite** | **Ported from Python to native C++20 — keys live in `sodium_mlock`ed (`VirtualLock`-backed), `sodium_memzero`'d buffers** |
| **GUI** | Tkinter → **Qt 6 Widgets** (native, dark theme) |
| **KDF** | Argon2id (memory-hard) + HKDF-SHA256 |
| Hidden Volume | Key-salted HMAC scan offsets; create now places the hidden header on a scan-reachable offset (the Python layout was never discoverable) |
| Journal Integrity | HMAC-SHA-256 with derived key — crash-safe write recovery |
| Sector Nonces | Deterministic per-sector nonce (HKDF over key/index/epoch) — no nonce reuse |
| Header | Fully encrypted, random sentinel padding — indistinguishable from random |

---

## Security Notes

> ⚠️ Use a strong, unique passphrase — minimum 16 characters, multiple character classes.

> ⚠️ Back up your 2FA secret and keyfile separately. Loss without backup = permanent data loss. For the App-Login 2FA, also keep your master password and the one-time recovery codes (shown once at setup) somewhere safe — a recovery code substitutes for the TOTP code if your authenticator is lost, but it does **not** recover a forgotten master password.

> ⚠️ **The original file extension is not stored when you encrypt a single file.** When you decrypt, re-enter the correct extension on the output file (e.g. `.pdf`, `.jpg`, `.docx`) exactly as it was — otherwise the decrypted file is byte-for-byte correct but Windows can't tell which app opens it. Keeping the original name and just removing the trailing `.dgkn` is the easy way to get this right.

> ⚠️ Security guarantees require a non-compromised operating system.

> ⚠️ *If/when TPM or device binding is enabled* (core only in v7 — not GUI-exposed): migration or hardware changes without a proper backup/recovery concept can lock you out permanently.

---

## Security & Auditing

A full multi-perspective security review (reverse engineering, red-team, DevOps,
forensics) and a step-by-step **self-audit playbook** live in **[SECURITY.md](SECURITY.md)**.

> **Honest stance:** the cryptographic design is strong and hardened, but DGKN is
> **Windows-only, new, and not yet independently audited**. "Military/forensic grade" is a
> goal to be *earned through external validation* (Common Criteria / FIPS 140-3), not a
> self-declared property. For high-stakes data today, prefer audited tools until DGKN has
> had an external review. See SECURITY.md for the realistic threat model.

### How this was built (full transparency)

I want to be completely upfront, especially with security researchers reviewing this code:

- **I am early in my coding journey.** I'm still learning, and I built this project to learn
  by doing — picking up C++, cryptography concepts, and secure-software practices as I went.
- **This was built with the help of various AI models.** I used AI assistants to write,
  explain, and review code, and I'm gradually internalizing it rather than just copy-pasting —
  understanding *why* each piece works the way it does is the whole point for me.
- **I'm aware of how serious a project like this is.** Encryption software is exactly the kind
  of thing where subtle mistakes have real consequences, and I do *not* claim this is
  battle-tested. That honesty is why it ships as an **evaluation preview**, not a finished
  product you should trust with valuable data yet.
- **Inspiration:** the project was inspired by **TrueCrypt / VeraCrypt** — their idea of strong,
  local, no-cloud encrypted volumes is what set me down this path. DGKN is my own independent
  C++ implementation and shares no code with them.

If you're a security researcher: **please be critical.** Bug reports, design critiques, and
"this is wrong because…" feedback are genuinely welcome — that's exactly what helps me learn
and what makes the project better. See **[SECURITY.md](SECURITY.md)** for the threat model and
a self-audit playbook.

---

## License

DGKN Crypto Suite is **free software**, released under the **GNU General Public License
v3.0 (GPLv3)** — see **[LICENSE](LICENSE)**. In short: you're free to **use, study,
share, and modify** it, including for commercial use. If you distribute the program or a
modified version, you must pass on the **same GPLv3 freedoms** and make the corresponding
**source code** available. The Software comes with **NO WARRANTY**.

### Third-party open-source licenses

DGKN's GPLv3 covers **only DGKN's own code**. The Software is built on
third-party open-source libraries, each under its own license — these keep their own
terms and you retain all rights those licenses grant you. The full
attribution and license texts are in **[THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt)**
(with the LGPL/GPL full texts in `LGPL-3.0.txt`, `GPL-3.0.txt`, `LGPL-2.1.txt`). In short:

- **libsodium** (ISC), **nlohmann/json** (MIT), **argon2** (CC0/Apache-2.0) — permissive;
  attribution only.
- **Qt 6** and **libqrencode** — **LGPL**; shipped as separate, dynamically-linked DLLs so
  you may replace them with your own build, as the LGPL requires.
- **WinFsp** — GPLv3; **not bundled** — installed separately by the user from winfsp.dev
  and only loaded at runtime, so it does not affect DGKN's licensing.

These notices ship with the installer.

---

## Acknowledgements

Heartfelt thanks to everyone who takes the time to **try this out and share feedback** —
your bug reports, ideas, and honest criticism are what move the project forward. 🙏

Built on the shoulders of excellent open-source work:

- **[libsodium](https://libsodium.org)** — XChaCha20-Poly1305, BLAKE2b, HKDF, secure memory
- **[argon2](https://github.com/P-H-C/phc-winner-argon2)** — the Argon2id memory-hard KDF
- **[Qt 6](https://www.qt.io)** — the native desktop GUI
- **[WinFsp](https://winfsp.dev)** — the virtual-drive (FUSE-for-Windows) layer
- **[libqrencode](https://fukuchi.org/works/qrencode/)** — TOTP QR codes
- **[nlohmann/json](https://github.com/nlohmann/json)** — JSON handling
- **[Catch2](https://github.com/catchorg/Catch2)** — the test suite
- **[7-Zip](https://www.7-zip.org)** — self-extracting (SFX) installer packaging
- **[Inno Setup](https://jrsoftware.org/isinfo.php)** — optional alternative wizard installer
- **[vcpkg](https://vcpkg.io)** — dependency management

---

## Project

**DGKN@Labs**  · [GitHub @dogenc](https://github.com/dogenc)

<div align="center">
<sub>Built with paranoia. Tested with purpose.</sub>
</div>
