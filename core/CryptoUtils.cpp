// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "CryptoUtils.hpp"
#include "../Config.hpp"
#include <sodium.h>
#include <argon2.h>
#include <fstream>
#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <cctype>

#if defined(_WIN32)
#include <windows.h>
#endif

// Byte-Konvertierung für den Maschinen-Endianness Support
static inline void store64_be(uint8_t* dst, uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        dst[i] = static_cast<uint8_t>(val & 0xFF);
        val >>= 8;
    }
}

namespace dgkn::crypto_utils {

    // ═══════════════════════════════════════════════════════════════
    // XChaCha20-Poly1305 Implementierung
    // ═══════════════════════════════════════════════════════════════
    CipherResult XChaCha20::encrypt(std::span<const uint8_t> key, std::span<const uint8_t> plaintext, std::span<const uint8_t> aad) {
        if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
            throw std::invalid_argument("XChaCha20: ungueltige Schluessellaenge");

        CipherResult result;
        result.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        randombytes_buf(result.nonce.data(), result.nonce.size());

        result.ciphertext.resize(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long ct_len = 0;

        crypto_aead_xchacha20poly1305_ietf_encrypt(
            result.ciphertext.data(), &ct_len,
            plaintext.data(), plaintext.size(),
            aad.empty() ? nullptr : aad.data(), aad.size(),
            nullptr, result.nonce.data(), key.data()
        );
        result.ciphertext.resize(ct_len);
        return result;
    }

    std::vector<uint8_t> XChaCha20::decrypt(std::span<const uint8_t> key, std::span<const uint8_t> nonce, std::span<const uint8_t> ct, std::span<const uint8_t> aad) {
        // Schlüssel-/Nonce-Größe validieren (verhindert OOB-Reads in libsodium).
        if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
            throw std::invalid_argument("XChaCha20: ungueltige Schluessellaenge");
        if (nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
            throw std::invalid_argument("XChaCha20: ungueltige Nonce-Laenge");
        // Ciphertext muss mindestens den 16-Byte-Poly1305-Tag enthalten.
        // (Ohne diese Prüfung würde ct.size() - ABYTES als size_t unterlaufen.)
        if (ct.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
            throw std::runtime_error("Entschluesselung fehlgeschlagen: Ciphertext zu kurz");

        std::vector<uint8_t> pt(ct.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long pt_len = 0;

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                pt.data(), &pt_len,
                nullptr,
                ct.data(), ct.size(),
                aad.empty() ? nullptr : aad.data(), aad.size(),
                nonce.data(), key.data()) != 0) {
            throw std::runtime_error("Entschlüsselung fehlgeschlagen: Invalid Tag (Daten manipuliert)");
        }
        pt.resize(pt_len);
        return pt;
    }

    std::vector<uint8_t> XChaCha20::sector_nonce(std::span<const uint8_t> sector_key, uint64_t sector_idx, uint64_t write_epoch) {
        uint8_t idx_b[8];
        uint8_t epoch_b[8];
        store64_be(idx_b, sector_idx);
        store64_be(epoch_b, write_epoch);

        std::vector<uint8_t> info;
        std::string_view info_prefix = "DGKN5-SECTOR";
        info.insert(info.end(), info_prefix.begin(), info_prefix.end());
        info.insert(info.end(), std::begin(epoch_b), std::end(epoch_b));

        return KDF::hkdf_sha256(idx_b, sector_key, info, dgkn::config::NONCE_SIZE);
    }

    // ═══════════════════════════════════════════════════════════════
    // KDF & HKDF Implementierung
    // ═══════════════════════════════════════════════════════════════
    std::vector<uint8_t> KDF::hkdf_sha256(std::span<const uint8_t> salt, std::span<const uint8_t> ikm, std::span<const uint8_t> info, size_t out_len) {
        // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
        std::vector<uint8_t> prk(crypto_auth_hmacsha256_BYTES);
        crypto_auth_hmacsha256_state state;
        
        // Falls Salt leer ist, nutzt HMAC standardmäßig Nullen, Libsodium erfordert aber einen gültigen Pointer
        const uint8_t* salt_ptr = salt.empty() ? reinterpret_cast<const uint8_t*>("") : salt.data();
        size_t salt_len = salt.empty() ? 0 : salt.size();

        crypto_auth_hmacsha256_init(&state, salt_ptr, salt_len);
        crypto_auth_hmacsha256_update(&state, ikm.data(), ikm.size());
        crypto_auth_hmacsha256_final(&state, prk.data());

        // HKDF-Expand: T1 = HMAC-SHA256(PRK, info | 0x01) (Hier nur für <= 32 Bytes implementiert)
        if (out_len > crypto_auth_hmacsha256_BYTES) {
            throw std::invalid_argument("HKDF-Expand in dieser Version nur bis 32 Bytes unterstützt.");
        }

        crypto_auth_hmacsha256_init(&state, prk.data(), prk.size());
        if (!info.empty()) {
            crypto_auth_hmacsha256_update(&state, info.data(), info.size());
        }
        uint8_t counter = 1;
        crypto_auth_hmacsha256_update(&state, &counter, 1);

        std::vector<uint8_t> t1(crypto_auth_hmacsha256_BYTES);
        crypto_auth_hmacsha256_final(&state, t1.data());
        
        // RAM bereinigen
        sodium_memzero(prk.data(), prk.size());

        std::vector<uint8_t> out(t1.begin(), t1.begin() + out_len);
        sodium_memzero(t1.data(), t1.size());
        return out;
    }

    std::vector<uint8_t> KDF::hash_keyfile(const std::string& path) {
        if (path.empty()) return {};
        
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return {};

        crypto_generichash_state state;
        crypto_generichash_init(&state, nullptr, 0, crypto_generichash_BYTES);

        std::vector<char> buffer(1024 * 1024); // Heap statt Stack (MSVC-Default-Stack = 1 MB)
        while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
            crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(buffer.data()), file.gcount());
        }

        std::vector<uint8_t> out(crypto_generichash_BYTES);
        crypto_generichash_final(&state, out.data(), out.size());
        return out;
    }

    std::vector<uint8_t> KDF::derive_hardened(std::string_view password, std::span<const uint8_t> keyfile_hash, std::span<const uint8_t> salt, std::span<const uint8_t> info) {
        std::vector<uint8_t> raw_secret(password.begin(), password.end());
        raw_secret.insert(raw_secret.end(), keyfile_hash.begin(), keyfile_hash.end());

        std::vector<uint8_t> mk(64); // Intermediate Master Key

        // Argon2id raw Aufruf. MEMORY_KIB ist bereits in KiB (Einheit der C-Lib).
        // ACHTUNG: Diese Parameter sind FORMATBESTIMMEND — Container, die mit anderen
        // Parametern erstellt wurden, sind nicht entschlüsselbar. Der folgende
        // Test-Override (Umgebungsvariable DGKN_ARGON2_TEST_KIB) dient AUSSCHLIESSLICH
        // dem Test-Speedup und darf in Produktion NICHT gesetzt sein. GUI/CLI setzen
        // die Variable nie -> volle 256 MiB.
        uint32_t mem_kib = static_cast<uint32_t>(config::ARGON2_MEMORY_KIB);
        uint32_t time_cost = static_cast<uint32_t>(config::ARGON2_TIME_COST);
#if defined(_WIN32)
        {
            char buf[16]; DWORD n = GetEnvironmentVariableA("DGKN_ARGON2_TEST_KIB", buf, sizeof(buf));
            if (n > 0 && n < sizeof(buf)) {
                unsigned long v = std::strtoul(buf, nullptr, 10);
                // Argon2 verlangt mindestens 8*parallelism KiB.
                uint32_t min_kib = 8u * static_cast<uint32_t>(config::ARGON2_PARALLELISM);
                if (v >= min_kib) { mem_kib = static_cast<uint32_t>(v); time_cost = 1; }
            }
        }
#endif
        int res = argon2id_hash_raw(
            time_cost, mem_kib,
            static_cast<uint32_t>(config::ARGON2_PARALLELISM),
            raw_secret.data(), raw_secret.size(),
            salt.data(), salt.size(),
            mk.data(), mk.size()
        );

        // Sensible Eingangsdaten sicher im RAM löschen
        sodium_memzero(raw_secret.data(), raw_secret.size());

        if (res != ARGON2_OK) {
            throw std::runtime_error("Argon2id hashing fehlgeschlagen");
        }

        // HKDF zur finalen Schlüsselableitung
        std::vector<uint8_t> final_key = hkdf_sha256(salt, mk, info, config::KEY_SIZE);
        sodium_memzero(mk.data(), mk.size());

        return final_key;
    }

    std::vector<uint8_t> KDF::derive_sector_key(std::span<const uint8_t> master_key, std::span<const uint8_t> salt) {
        std::string_view info = "DGKN5-SECTORKEY";
        return hkdf_sha256(salt, master_key, {reinterpret_cast<const uint8_t*>(info.data()), info.size()}, config::KEY_SIZE);
    }

    // ═══════════════════════════════════════════════════════════════
    // SectorCrypto Implementierung
    // ═══════════════════════════════════════════════════════════════
    std::vector<uint8_t> SectorCrypto::encrypt_sector(std::span<const uint8_t> sector_key, uint64_t sector_idx, std::span<const uint8_t> data, uint64_t write_epoch) {
        if (data.size() != config::SECTOR_SIZE) {
            throw std::invalid_argument("Sektor muss exakt SECTOR_SIZE entsprechen");
        }
        auto n24 = XChaCha20::sector_nonce(sector_key, sector_idx, write_epoch);
        uint8_t aad[8];
        store64_be(aad, sector_idx);

        // Mit dem deterministischen Sektor-Nonce verschlüsseln (NICHT zufällig),
        // damit decrypt_sector denselben Nonce rekonstruieren kann.
        std::vector<uint8_t> ciphertext(data.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long ct_len = 0;
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ct_len,
            data.data(), data.size(),
            aad, sizeof(aad),
            nullptr, n24.data(), sector_key.data()
        );
        ciphertext.resize(ct_len);
        return ciphertext;
    }

    std::vector<uint8_t> SectorCrypto::decrypt_sector(std::span<const uint8_t> sector_key, uint64_t sector_idx, std::span<const uint8_t> ct, uint64_t write_epoch) {
        if (ct.size() != config::SECTOR_CT_SIZE) {
            throw std::invalid_argument("Ciphertext entspricht nicht der SECTOR_CT_SIZE");
        }
        auto n24 = XChaCha20::sector_nonce(sector_key, sector_idx, write_epoch);
        uint8_t aad[8];
        store64_be(aad, sector_idx);

        return XChaCha20::decrypt(sector_key, n24, ct, aad);
    }

    // Entspricht core/crypto_utils.py::validate_password_strength
    std::pair<bool, std::string> validate_password_strength(std::string_view password) {
        if (password.size() < dgkn::config::MIN_PASSWORD_LEN) {
            return {false, "Passwort zu kurz: mindestens "
                + std::to_string(dgkn::config::MIN_PASSWORD_LEN) + " Zeichen erforderlich"};
        }

        int classes = 0;
        bool has_lower = false, has_upper = false, has_digit = false, has_special = false;
        for (unsigned char ch : password) {
            if (std::islower(ch)) has_lower = true;
            else if (std::isupper(ch)) has_upper = true;
            else if (std::isdigit(ch)) has_digit = true;
            else if (!std::isalnum(ch)) has_special = true;
        }
        classes = has_lower + has_upper + has_digit + has_special;
        if (classes < static_cast<int>(dgkn::config::PASSWORD_REQUIRED_CLASSES)) {
            return {false, "Passwort zu schwach: nutze mindestens 3 Zeichengruppen (klein/gross/Ziffer/Sonderzeichen)"};
        }

        static const char* bad_patterns[] = {
            "1234", "password", "passwort", "qwerty", "asdf", "admin", "secret", "dgkn"
        };
        std::string lowered(password);
        for (auto& c : lowered) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (const char* p : bad_patterns) {
            if (lowered.find(p) != std::string::npos) {
                return {false, "Passwort zu schwach: triviale Muster/Woerter nicht erlaubt"};
            }
        }

        int max_run = 1, cur_run = 1;
        for (size_t i = 1; i < password.size(); ++i) {
            if (password[i] == password[i - 1]) {
                cur_run += 1;
                if (cur_run > max_run) max_run = cur_run;
            } else {
                cur_run = 1;
            }
        }
        if (max_run >= 4) {
            secure_wipe_string(lowered);
            return {false, "Passwort zu schwach: zu viele gleiche Zeichen in Folge"};
        }

        secure_wipe_string(lowered);
        return {true, ""};
    }

    void secure_wipe_string(std::string& s) {
        if (!s.empty()) {
            sodium_memzero(&s[0], s.size());
        }
        s.clear();
        s.shrink_to_fit();
    }

} // namespace dgkn::crypto_utils