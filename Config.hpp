// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <string_view>
#include <cstdint>

namespace dgkn::config {
    // Application & Formats
    constexpr std::string_view APP_VER = "7.1";
    constexpr int FORMAT_VER = 7;

    // Krypto & Memory Parameter
    constexpr size_t SECTOR_SIZE = 4096;
    constexpr size_t SECTOR_CT_SIZE = SECTOR_SIZE + 16;

    // Argon2id — gehärtete Parameter. MEMORY_COST ist in KiB (Einheit der argon2-C-Lib),
    // um Einheiten-Bugs zu vermeiden. 262144 KiB = 256 MiB (deutlich über OWASP-Minimum
    // von 19 MiB; GPU/ASIC-resistent). TIME_COST = Iterationen über den Speicher.
    constexpr size_t ARGON2_MEMORY_KIB = 256u * 1024u; // 256 MiB
    constexpr size_t ARGON2_TIME_COST = 4;
    constexpr size_t ARGON2_PARALLELISM = 4;

    // Schlüsselgrößen & Header
    constexpr size_t SALT_SIZE = 32;
    constexpr size_t KEY_SIZE = 32;
    constexpr size_t NONCE_SIZE = 24;
    constexpr size_t HDR_TOTAL = 128; 

    // Byte Marker (in C++ als string_view abbildbar)
    constexpr std::string_view EMERGENCY_SALT = "DGKN7-EMERGENCY-SALT-20260520-00";
    constexpr std::string_view HIDDEN_SEED_INFO = "DGKN7-HIDDEN-SEED-INFO-20240723-00";
    constexpr std::string_view JOURNAL_HMAC_KEY = "DGKN7-JOURNAL-HMAC-KEY-20260520-0";
    constexpr std::string_view SENTINEL_PLAIN = "DGKN_AUTH_OK_V5";
    constexpr std::string_view PAYLOAD_MAGIC = "D5AR";
    constexpr std::string_view FILE_STREAM_MARKER = "DG2S";
    constexpr std::string_view FILE_KDF_V6_MARKER = "K6DF";
    constexpr std::string_view FILE_KDF_V6_2FA_MARKER = "K6F2";
    // H-2: authentifizierter Header der Einzeldatei-Verschlüsselung (v7).
    constexpr std::string_view FILE_AUTH_HDR_MARKER = "F7AH";       // Marker im Header-Padding
    constexpr std::string_view FILE_SENTINEL_PLAIN  = "DGKN_FILE_OK_V7"; // 15 B, im Header-AEAD
    constexpr std::string_view MOUNT_DIR_PREFIX = "DGKN7_";

    // Timeouts & Security Limits
    constexpr size_t AUTO_UNMOUNT_SECS = 5 * 60;
    constexpr size_t AUTH_WINDOW_SECS = 5 * 60;
    constexpr size_t AUTH_MAX_TRIES = 5;
    constexpr double AUTH_BASE_DELAY = 0.75;
    constexpr double AUTH_MAX_DELAY = 8.0;
    constexpr size_t AUTH_LOCKOUT_TRIES = 8;
    constexpr size_t AUTH_LOCKOUT_SECS = 15 * 60;
    constexpr size_t STALE_MOUNT_MAX_AGE = 12 * 60 * 60;

    // Größenlimits (Verwendung von uint64_t / unsigned long long für große Zahlen)
    constexpr size_t MAX_ARCHIVE_NAME_LEN = 4096;
    constexpr size_t MAX_ARCHIVE_FILE_SIZE = 512 * 1024 * 1024;
    constexpr uint64_t MAX_ARCHIVE_TOTAL_SIZE = 4ULL * 1024 * 1024 * 1024; // 4 GB

    // Passwort & 2FA
    constexpr size_t MIN_PASSWORD_LEN = 16;
    constexpr size_t PASSWORD_REQUIRED_CLASSES = 3;
    constexpr size_t TWOFA_DIGITS = 6;
    constexpr size_t TWOFA_PERIOD = 30;
    constexpr size_t TWOFA_WINDOW = 1;
    constexpr size_t TWOFA_TRUST_SECS = 5 * 60;
    constexpr size_t TWOFA_CFG_VER = 2;
    // AAD-String, der den 2FA-Secret-Ciphertext an seinen Zweck bindet (KEIN DPAPI —
    // der Name wurde von "TWOFA_DPAPI_PURPOSE" zu "TWOFA_AAD_PURPOSE" korrigiert, H-7).
    // Der String-WERT bleibt unverändert, sonst wären bereits gespeicherte 2fa.json
    // nicht mehr entschlüsselbar (AAD-Mismatch -> Poly1305-Fehler).
    constexpr std::string_view TWOFA_AAD_PURPOSE = "DGKN-2FA-SECRET-v1";
    constexpr size_t UNMOUNT_TXN_VER = 1;

    // UI Theme
    struct Colors {
        static constexpr std::string_view bg = "#090f1a";
        static constexpr std::string_view bg2 = "#101a2a";
        // ... fügen Sie hier bei Bedarf die restlichen Farbwerte analog ein
        static constexpr std::string_view acc = "#18d8a8";
        static constexpr std::string_view panic = "#ff2c55";
    };
}