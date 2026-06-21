# Security Analysis — DGKN@Labs Crypto Suite v7

> Multi-perspective review (reverse engineering, offensive/red-team, DevOps, forensics)
> and a practical self-audit playbook. **Honest assessment, not marketing.**

---

## Reporting a Vulnerability

**Please report security vulnerabilities privately — do not open a public issue or pull
request for a security bug.**

Use **GitHub Security Advisories**: go to the
[Security tab](https://github.com/dogenc/dgknCryptoSuite/security/advisories) → **"Report a
vulnerability"**. This opens a private channel between you and the maintainer for coordinated
disclosure; details stay confidential until a fix is ready.

When reporting, please include:

- the affected version / commit,
- a description of the issue and its impact,
- steps to reproduce (proof-of-concept if possible),
- any suggested fix or mitigation.

**What to expect:** DGKN is a single-author **evaluation/learning project**, so there is no
formal SLA. The maintainer aims to acknowledge a report within a few days and will work with
you on a fix and coordinated disclosure. Please allow reasonable time to address an issue
before any public disclosure. There is currently **no bug-bounty program** — reports are
handled on a best-effort, good-faith basis, and credit is gladly given in the advisory.

### Supported versions

| Version | Supported |
|---------|-----------|
| 7.x     | ✅ (current evaluation preview) |
| < 7.0   | ❌ |

---

## TL;DR — Is it "unhackable"?

**No software is unhackable, and any tool that claims to be is lying.** What can be
said honestly:

- The **cryptographic core is well-designed**: authenticated encryption on every layer
  (XChaCha20-Poly1305), a memory-hard KDF (Argon2id, 256 MiB), real RFC-6238 2FA, full
  header encryption, and constant-time secret comparisons. The math is sound and built on
  libsodium (audited) plus a small, test-vector-verified SHA-1/HMAC for TOTP.
- The **implementation is hardened**: bounds/overflow checks, guaranteed key wipe,
  RAM locking, ASLR/DEP/CFG/CET binary mitigations, anti-debug self-defense.
- **But**: it is **Windows-only, new, single-author, and has not had an independent
  external audit**. "Military/forensic grade" is an *aspiration* here, not a certification.
  Real military/government use requires formal evaluation (e.g. Common Criteria, FIPS 140-3
  validated crypto modules) — DGKN does not have these.

**Threat model where DGKN is strong:** a stolen container file / lost laptop (data at rest).
**Threat model where ANY user-space tool is weak:** a fully compromised, running OS
(kernel malware, a live RAM capture while mounted, a hardware keylogger). No user-space
encryption tool defends against an attacker who already owns the running machine.

---

## 1. Reverse-Engineering perspective

**What an RE analyst sees:**

| Aspect | Status | Note |
|---|---|---|
| Symbols / function names | ⚠️ present in unstripped build | RE-friendly. Mitigation: strip symbols / build with `/Brepro`, ship release PDB-less. |
| Strings (error messages) | ⚠️ readable ("Falsches Passwort…") | Reveal program logic but no secrets. Acceptable; could be obfuscated. |
| Crypto constants | ✅ standard | XChaCha20/Argon2 params visible — by design (Kerckhoffs: security must not rely on hiding the algorithm). |
| Container format | ✅ no plaintext magic | Header is indistinguishable from random; an RE can't tell a `.dgkn` from random data without the key. |
| Anti-debug | ✅ present | `IsDebuggerPresent` + `CheckRemoteDebuggerPresent` → wipe+abort. Defeatable by a determined RE (patch the check), but raises the bar. |

**Verdict:** The *format* and *crypto* resist RE well (no key material or plaintext is
recoverable from the binary). The *logic* is readable — which is fine, because security
comes from the keys, not from secrecy of the code. **Hardening opportunity:** strip
release symbols; consider control-flow obfuscation only if you have a specific threat that
warrants it (usually not worth the maintenance cost).

## 2. Offensive / Red-Team perspective

**Attack paths and how DGKN fares:**

| Attack | Result |
|---|---|
| Brute-force the password offline | 🟢 Hard — Argon2id 256 MiB makes each guess expensive; GPU/ASIC-resistant. Strong-password policy enforced. |
| Tamper with a container (flip bytes) | 🟢 Detected — every byte flip in the header is rejected (Poly1305 + sentinel). Tested. |
| Feed a malformed/huge container to crash the app | 🟢 Handled — bounds checks, overflow-safe region math, allocation caps. Tested with fuzz/garbage inputs. |
| Path-traversal via a crafted archive (`../../`) | 🟢 Blocked — archive entries validated, unpack sandboxed to target dir. Tested. |
| Online brute-force / repeated mount attempts | 🟢 Backoff + lockout, now **persisted** (HMAC-protected file per identity) — survives app restarts. Verified by test. |
| Timing side-channel on password/code | 🟢 Constant-time compares (`sodium_memcmp`) for sentinel, HMAC, TOTP. |
| Duress / coercion ("give me the password") | 🟢 Hidden volume for plausible deniability **+ real duress password**: entering it is rejected exactly like a wrong password (no tell), and can optionally sanitize all headers (Argon2id-hashed, constant-time compare). Verified by test. |
| Malicious WinFsp mount interaction | 🟡 Mount runs in user context; review FUSE op bounds (done in code) — but a hostile process on the same desktop could read the mounted drive while open. Same limitation as VeraCrypt. |

**Verdict:** Strong against *offline* and *malformed-input* attacks. The realistic gaps are
**operational**: lockout doesn't survive restart, no real duress password, and (like all such
tools) zero protection once the volume is *mounted* on a compromised host.

## 3. DevOps / Supply-chain perspective

| Aspect | Status | Hardening |
|---|---|---|
| Dependencies | libsodium, argon2, nlohmann-json, Qt6, WinFsp (all via vcpkg/official) | Pin exact versions; verify hashes; commit a `vcpkg.json` manifest with a baseline. |
| Reproducible build | 🟢 `/Brepro` enabled (compiler + linker) — strips timestamps from PE headers. | Combined with the pinned vcpkg baseline (`vcpkg.json`), identical source + toolchain produce bit-identical binaries. |
| Dependency pinning | 🟢 `vcpkg.json` with `builtin-baseline` SHA | Exact, reproducible dependency versions. |
| Code signing | 🟡 the released installer is Authenticode-signed with a **self-signed** cert (RFC-3161 timestamped); the signature proves integrity but the cert root is not publicly trusted, so other machines still show "Unknown Publisher". | Use a CA-issued (ideally EV) code-signing certificate for SmartScreen reputation on third-party machines. |
| CI / automated tests | 🟢 GitHub Actions (Windows) | The 68-test / 301-assertion Catch2 suite + 50k-input fuzz-stress + BinSkim run on every push (`.github/workflows/ci.yml`). |
| Secrets in repo | ✅ none | Runtime secret artifacts (`dgkn_2fa_local.json`, `2fa.json`, `**/security/2fa.json`) are git-ignored and were never committed — verified absent from the tree and from the full git history. |
| SBOM | ❌ | Generate a Software Bill of Materials for auditability. |

**Verdict:** The build is solid but not yet *verifiable by others*. For "high-assurance",
reproducible builds + code signing + CI are the missing pillars.

## 4. Forensic perspective (anti-forensics quality)

| Aspect | Status |
|---|---|
| Data at rest | 🟢 Full-container AEAD; header looks random; no plaintext magic to fingerprint. **Measured Shannon entropy across a 500 MB container ≈ 7.999 bits/byte everywhere (8.0 = perfect random)** — ciphertext and random padding are statistically indistinguishable from random, so a hidden volume's existence cannot be proven. |
| Keys in RAM | 🟢 `VirtualLock` (no swap) + `sodium_memzero` on unmount. |
| Plaintext on disk while mounted | 🟢 WinFsp in-RAM filesystem — **no plaintext temp folder** (unlike the old Python build / Cryptomator). |
| Password lifetime in RAM | 🟢 KDF input copies and our own `std::string` copies are wiped via `secure_wipe_string` (`sodium_memzero`); `QLineEdit` is cleared after use. *Residual:* Qt/`QString` may keep internal copies we can't reach — a custom secure widget would be needed for 100% coverage. |
| `.txn` journal files | 🟢 HMAC-protected, no plaintext payload; cleaned after commit. |
| Crash residue | 🟡 If the process crashes while mounted, RAM contents (incl. keys) could be captured from a memory dump or hibernation file. *Mitigation: disable crash dumps for the process; this is an OS-level concern.* |

**Verdict:** Excellent for *data at rest*. The residual forensic risks are the classic ones
for any running encryption tool: live RAM and the OS itself.

---

## How to audit & verify it yourself (self-audit playbook)

A pragmatic order for a single author to gain confidence — cheap/fast first:

### Tier 0 — Already in place (re-run before every release)
```powershell
# 1. All tests must pass (use the Argon2 test-override for speed)
$env:DGKN_ARGON2_TEST_KIB="64"
cmake --build build-rel; ctest --test-dir build-rel --output-on-failure
# 2. Crypto correctness is anchored to RFC test vectors (TOTP) and round-trip tests.
```

### Tier 1 — Static analysis (free, high value)
- **MSVC `/analyze`** (built-in static analyzer): add `--analyze` to a CI build, fix warnings.
- **clang-tidy** with `bugprone-*`, `cert-*`, `clang-analyzer-*` checks.
- **PVS-Studio** (free for open source) — catches integer/pointer/lifetime bugs.
- **CodeQL** (free on GitHub) — query for crypto misuse and taint flows.

### Tier 2 — Dynamic analysis (free)
- **Address/UB Sanitizer** build (clang on Windows or a Linux core-only build): run the test
  suite under ASan+UBSan to catch memory/overflow bugs the fuzz tests don't.
- **libFuzzer/AFL++** on the parsers: feed random bytes to `decrypt_and_verify_header`,
  `Archive::parse_structure`, and the payload parser. These are your highest-risk attack
  surface (attacker-controlled input).
- **Application Verifier** (Windows) on `dgkn_gui.exe` to catch heap/handle misuse.

### Tier 3 — Crypto-specific verification
- **Test vectors**: you already verify TOTP against RFC 6238. Add known-answer tests (KAT)
  for XChaCha20-Poly1305 and Argon2id against the libsodium/RFC vectors.
- **Nonce-uniqueness proof**: assert (already tested) that sector nonces never repeat across
  index × epoch.
- **`dieharder` / `ent`** on raw container bytes to confirm ciphertext is statistically random.

### Tier 4 — Binary & supply chain
- **BinSkim** (Microsoft) — verifies ASLR/DEP/CFG/CET are actually set in the binary
  (you've confirmed this manually with `dumpbin`; BinSkim automates it in CI).
- **`dumpbin /headers /loadconfig`** — spot-check mitigations per release.
- Pin and hash-verify all vcpkg dependencies; aim for a **reproducible build**.

### Tier 5 — Independent review (the real bar for "high assurance")
- Have a **second cryptographer/security engineer** read the format + KDF + nonce design.
- For genuine military/government acceptance: formal evaluation (Common Criteria EAL,
  FIPS 140-3 validated crypto). This is a months-long, paid process — set expectations.

---

## Roadmap to "high assurance" (status)

1. ✅ **Reproducible build** (`/Brepro`) + **dependency pinning** (`vcpkg.json` baseline) + **Authenticode-signed release binaries**. *Remaining: external audit for "high assurance".*
2. ✅ **Password wiping** — `secure_wipe_string` on all our copies + KDF inputs; `QLineEdit` cleared. *(Residual: Qt-internal copies — see note above.)*
3. ✅ **Persistent lockout** — HMAC-protected, survives restarts. Tested.
4. ✅ **Real duress/emergency password** — silent rejection + optional header sanitization. Tested.
5. ✅ **Fuzz/stress harness** — `dgkn_fuzz` runs 50k random inputs through the parsers with zero crashes; a clang/libFuzzer path is documented. **Now wired into CI** (`.github/workflows/ci.yml`).
6. ✅ **Optional TPM 2.0 binding** — real TBS availability check (`Tbsi_GetDeviceInfo`, tpmVersion==2) + machine-bound sealing via DPAPI/LocalMachine with PCR-policy entropy. Sealed secrets don't transfer to another machine. Tested. **GUI scope note (v7):** the TPM-sealed-secret and device-binding parameters are fully implemented in `ContainerManager` (`binding_digest`, `derive_volume_key`) and exercised by `tests/test_tpm.cpp`, but the v7 GUI calls `create_container`/`mount_volume` **without** these arguments — so the defaults (`tpm_sealed_secret = ""`, `bind_to_device = false`) apply and **containers created via the GUI are bound by password + 2FA only.** The TPM/device factors are wired in the core but not yet exposed as a GUI toggle.
7. ⬜ **Independent external audit** — the only thing that justifies "high-assurance" claims. *(Cannot be done in-house — requires a third party.)*

### Continuous integration
`.github/workflows/ci.yml` runs on every push: hardened build → full Catch2 suite →
50k-input fuzz stress → BinSkim mitigation verification. This gives continuous,
reproducible assurance.

### Note on the TPM approach
Rather than hand-crafting raw TPM 2.0 command byte-streams (hundreds of error-prone lines,
untestable without a physical TPM), DGKN binds secrets to the machine via DPAPI with the
`LOCAL_MACHINE` scope. On TPM-equipped systems Windows backs the DPAPI master-key chain with
hardware-bound keys, so the sealed blob is effectively device-bound. The presence of a real
TPM 2.0 is reported separately (`is_tpm_native_available`). For a future hardware-only seal
(no DPAPI), raw TBS command sealing would be the next step.

### Operational safeguards (in-app)
- **Auto-lock** (10 min idle): a global event filter tracks input; on timeout the app calls
  `emergency_wipe` — mounts closed, keys zeroed. Defends a walked-away-from session.
- **Clipboard auto-clear**: copied TOTP secrets are wiped from the clipboard after 15 s
  (only if the clipboard still holds our value), limiting clipboard-sniffing exposure.
- **Tamper-evident audit log** (`core::AuditLog`): HMAC-SHA256 hash-chain. Each entry signs
  the previous one, so any modification, insertion or deletion breaks the chain. `verify()`
  reports the first broken line; the GUI warns on startup if the log was tampered with.
  Tested (edit/delete detection).
  - **Key derivation (hardened, F-D 2026-06-01):** the HMAC key is
    `SHA256(constant ‖ MachineGuid ‖ per-install-random-secret)`. The 32-byte random secret
    is generated on first use and stored ACL-restricted in `<logpath>.key` (current user +
    SYSTEM + Admins). Previously the key was derivable from the binary + MachineGuid alone;
    now an attacker must additionally **read the protected `.key` file** to forge the log.
  - **Honest limit:** this remains tamper-*evident*, not tamper-*proof*. An attacker who can
    read both the binary **and** the `.key` file on the same machine (e.g. with the user's
    own privileges or root) can recompute the chain. Real tamper-*proofing* would need a
    TPM/HSM-sealed key or remote log shipping (out of scope for a local, offline tool). The
    log defends against accidental edits and casual after-the-fact tampering — not against a
    fully privileged on-host attacker.

### Storage & process hardening
- **No plaintext secrets on disk**: the legacy `dgkn_2fa_local.json` (which stored a TOTP
  secret in clear text) has been removed and git-ignored. The App-Login 2FA secret is now
  persisted **only encrypted** (XChaCha20-Poly1305, key via Argon2id from a separate master
  password) in `%LOCALAPPDATA%\DGKN\security\2fa.json`; per-operation container secrets are
  still entered each time and wiped from RAM after use. See "2FA secret store" below.
- **Audit log location**: moved from world-readable `%TEMP%` to the per-user
  `%APPDATA%\DGKN@Labs\DGKN Crypto Suite\` (not auto-cleaned, user-scoped ACL).
- **App manifest** (`gui/dgkn.manifest`, embedded): `heapType=SegmentHeap` (hardened heap
  backend), per-monitor-v2 DPI awareness, `asInvoker` execution level (no silent elevation;
  run elevated only when TPM/CPU-temp readout is desired). Verified embedded via `mt.exe`.

### 2FA secret store (App-Login) & RAM hygiene
The App-Login TOTP secret is stored in `%LOCALAPPDATA%\DGKN\security\2fa.json`, encrypted
with XChaCha20-Poly1305; the key is derived via Argon2id (256 MiB, hardened) from a separate
master password (≥16 chars, ≥3 character classes — enforced via `validate_password_strength`).
This combination is **quantum-resistant**: XChaCha20 (256-bit) and Argon2id remain practical
under Grover. A dedicated post-quantum layer (ML-KEM/Kyber) would add no real benefit here —
there is no asymmetric key exchange — and is deliberately omitted. The file is restricted via
a Windows ACL to the current user (+SYSTEM/Admins) and written atomically (temp + replace).

**Recovery codes**: 10 one-time codes are generated at setup. Each is stored **only** as an
Argon2id hash with its own 16-byte salt — the plaintext codes leave the app exactly once (the
one-time display) and are never persisted. A code substitutes once for the TOTP code at login;
used codes are marked and rejected on reuse. Verification runs in constant time (`sodium_memcmp`,
no early exit). `verify_password` / `regenerate_recovery_codes` confirm the master password
without ever materialising the decrypted secret to the caller.

**Known residual weakness (GUI input)**: passwords and secrets are entered through Qt widgets
(`QLineEdit`/`QString`). Active buffers are best-effort overwritten immediately after use
(`wipeQString`, `secure_wipe_string`, `sodium_mlock` for derived keys). Qt can nonetheless leave
copies at old heap addresses via implicit sharing / reallocations that we cannot reliably reach.
Full control would require a non-Qt input path (not implemented). This is stated honestly rather
than hidden.

### Self-audit code review — 2026-06-01 (findings & fixes)
A full white-box read of the security-critical modules (CryptoUtils, Crypto, Manager, Archive,
Totp, TwoFactorStore, TPMUtils, AuditLog, SecureMemory, FsHelpers, VirtualVolume). No
cryptographic break and no memory-corruption/RCE bug found. Findings and their resolution:

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| **F-A** | info | `Totp::code` dynamic-truncation offset `dig[off..off+3]` — confirmed always in-bounds (`off ≤ 15`, buffer 20 B). | No change needed (verified safe). |
| **F-B** | 🟠 medium | `change_password`: if the re-encrypted payload didn't fit the data area, the write was **silently skipped** but the header was still rewritten with the new key → silent data loss. (In practice unreachable: XChaCha20 is length-preserving, so the re-encrypted payload is the same size — but it was an unhandled path.) | **Fixed:** now returns an error and leaves the container unchanged (still openable with the old password) instead of continuing. |
| **F-C** | 🟡 low | `dgkn::crypto::{derive_hidden_seed,choose_hidden_offset,layout_hidden_volume}` is **dead in production** (the live hidden-volume path is `ContainerManager::scan_hidden`); only tests call it. Risk: a future reader could mistake it for the real path. | **Fixed (documented):** explicit "NOT the production path" notes added in `core/Crypto.hpp` and the test. |
| **F-D** | 🟡 low | Audit-log HMAC key was derivable from binary + MachineGuid (forgeable by an on-host attacker). | **Hardened:** per-install random secret in an ACL-restricted `.key` file (see "Tamper-evident audit log" above); honest limit documented. |
| **F-E** | 🟡 low | `Totp::is_valid_secret` decoded before the cheap length check. | **Fixed:** length checked first. |

All fixes are covered by the existing Catch2 suite (round-trip + tamper tests).

### Live security posture (in-app)
The GUI shows a top status bar (via `core::SystemStatus`): debugger attached,
real-time AV active, admin/elevation. It is an **honest posture indicator, not a malware
scanner** — a green bar does **not** mean the machine is malware-free.

> **Bottom line:** DGKN@Labs Crypto Suite v7 has a genuinely strong, hardened design that
> matches or exceeds common tools on several axes. Calling it "military/forensic grade"
> is a goal to *earn through external validation*, not a property you can self-declare.
