# DGKN@Labs Crypto Suite v7.0.0 — Evaluation Preview

> ⚠️ **This is an evaluation preview — a learning project, not audited software.**
> Built in native C++ with the help of various AI models as I learn to code. The
> cryptographic design is strong and hardened, but DGKN is **Windows-only, new, and not
> yet independently audited**. **Please don't trust it with data of real value yet.**
> Inspired by TrueCrypt / VeraCrypt; this is my own independent C++ implementation.

## What it is

A local, offline **encrypted volume manager** for Windows — no cloud, no telemetry, no
backdoors. Files live inside encrypted containers (or as standalone encrypted files) that
only open with the correct password plus a bound 2FA key factor.

## Highlights

- **XChaCha20-Poly1305** authenticated encryption on every layer (tamper-detecting)
- **Argon2id** memory-hard KDF (256 MiB) + HKDF-SHA256 — GPU/ASIC-resistant
- **2FA secret as a second key factor** for containers *and* single files
- **In-RAM virtual drive** via WinFsp — no plaintext on disk while mounted
- **Fully encrypted headers** — indistinguishable from random
- **Hardened binary** — ASLR, DEP, CFG, CET shadow stack, `/Qspectre`
- **Keys locked in RAM** (`sodium_mlock`) and zeroized on unmount
- Hidden volumes, tamper-evident audit log, brute-force lockout, duress password

See the [README](../README.md) for the full feature list and the honest threat model.

## Install

**Easiest:** download `DGKN-Setup.exe` below and run it. Installs to
`%ProgramFiles%\DGKN@Labs\Crypto Suite` (or per-user without admin).

- **Virtual drive (mount as a drive letter)** additionally needs the **WinFsp** driver,
  installed separately from <https://winfsp.dev> (no admin required to mount). File and
  container crypto work without it.
- If your antivirus flags the binary, it's a common false-positive for crypto tools using
  memory-locking.

### ⚠️ Windows SmartScreen warning is expected (self-signed)

This is a **free, open-source (GPLv3) project signed with my own self-signed
certificate** — not a paid CA certificate. So when you run `DGKN-Setup.exe`, Windows
SmartScreen will show **"Windows protected your PC / unknown publisher"**. That is normal
and expected here; it does **not** mean the file is malware — it only means the publisher
isn't validated by a commercial Certificate Authority.

**To run it anyway:** click **More info → Run anyway**.

**To verify it's really my build (recommended):**

1. Check the digital signature matches the fingerprint published below:
   right-click `DGKN-Setup.exe` → *Properties* → *Digital Signatures* → *Details*.
2. Check the SHA-256 hash against `SHA256SUMS.txt` (attached to this release):
   ```powershell
   Get-FileHash DGKN-Setup.exe -Algorithm SHA256
   ```

> **Certificate fingerprint (SHA-1):** `31D05A0D71F417F325EF8F263E72070D7F66D509`
> Subject `CN=Code Signing CA, C=DE`, valid 2026-06-14 → 2036-06-14.
> Compare the *Thumbprint* shown in the signature details against this value.

## Build from source

Fully supported and now path-independent — Qt is auto-detected:

```powershell
git clone https://github.com/dogenc/dgknCryptoSuite.git
cd dgknCryptoSuite
vcpkg install libsodium:x64-windows argon2:x64-windows nlohmann-json:x64-windows catch2:x64-windows libqrencode:x64-windows
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build
```

(Need Qt elsewhere? Pass `-DCMAKE_PREFIX_PATH="C:/Qt/6.x/msvc2022_64"`.)

## For security researchers

**Please be critical.** Bug reports, design critiques, and "this is wrong because…"
feedback are exactly what this preview is for. See [SECURITY.md](../SECURITY.md) for the
threat model and a self-audit playbook.

## Licensing

DGKN's own code is free software under the [GNU General Public License v3.0
(GPLv3)](../LICENSE). Third-party open-source components keep their own licenses — see
[THIRD-PARTY-NOTICES.txt](../THIRD-PARTY-NOTICES.txt).

## Verifying the download

See **"Windows SmartScreen warning is expected"** above for full verification steps
(digital-signature fingerprint + `SHA256SUMS.txt` hash check).
