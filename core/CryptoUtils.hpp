// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace dgkn::crypto_utils {

    // Struktur für Verschlüsselungsergebnisse
    struct CipherResult {
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> ciphertext;
    };

    // ═══════════════════════════════════════════════════════════════
    // XChaCha20-Poly1305 Wrapper
    // ═══════════════════════════════════════════════════════════════
    class XChaCha20 {
    public:
        static CipherResult encrypt(std::span<const uint8_t> key, std::span<const uint8_t> plaintext, std::span<const uint8_t> aad = {});
        static std::vector<uint8_t> decrypt(std::span<const uint8_t> key, std::span<const uint8_t> nonce, std::span<const uint8_t> ct, std::span<const uint8_t> aad = {});
        
        // Generiert den deterministischen Nonce pro Sektor via HKDF
        static std::vector<uint8_t> sector_nonce(std::span<const uint8_t> sector_key, uint64_t sector_idx, uint64_t write_epoch = 0);
    };

    // ═══════════════════════════════════════════════════════════════
    // Key Derivation Function (KDF)
    // ═══════════════════════════════════════════════════════════════
    class KDF {
    public:
        // Erzeugt den BLAKE2b Hash eines Keyfiles
        static std::vector<uint8_t> hash_keyfile(const std::string& path);

        // Moderne Argon2id + HKDF Ableitung (V6/V7)
        static std::vector<uint8_t> derive_hardened(
            std::string_view password, 
            std::span<const uint8_t> keyfile_hash, 
            std::span<const uint8_t> salt, 
            std::span<const uint8_t> info
        );

        // Ableitung des sektorspezifischen Schlüssels
        static std::vector<uint8_t> derive_sector_key(
            std::span<const uint8_t> master_key,
            std::span<const uint8_t> salt
        );

        // HKDF-SHA256 (Extract & Expand) — auch von XChaCha20::sector_nonce genutzt
        static std::vector<uint8_t> hkdf_sha256(std::span<const uint8_t> salt, std::span<const uint8_t> ikm, std::span<const uint8_t> info, size_t out_len);
    };

    // ═══════════════════════════════════════════════════════════════
    // Sektorweise Verschlüsselung
    // ═══════════════════════════════════════════════════════════════
    class SectorCrypto {
    public:
        static std::vector<uint8_t> encrypt_sector(
            std::span<const uint8_t> sector_key, 
            uint64_t sector_idx, 
            std::span<const uint8_t> data, 
            uint64_t write_epoch = 0
        );

        static std::vector<uint8_t> decrypt_sector(
            std::span<const uint8_t> sector_key, 
            uint64_t sector_idx, 
            std::span<const uint8_t> ct, 
            uint64_t write_epoch = 0
        );
    };

    std::pair<bool, std::string> validate_password_strength(std::string_view password);

    // Überschreibt den Inhalt eines std::string sicher im RAM (sodium_memzero auf
    // den zugrunde liegenden Puffer) und leert ihn. Für Passwörter nach Gebrauch.
    // Hinweis: kann GC-/SSO-Kopien des Strings nicht erfassen — best effort, aber
    // schließt die offensichtliche Lücke (das aktive Zeichenpuffer-Objekt).
    void secure_wipe_string(std::string& s);
}