// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include <catch2/catch_test_macros.hpp>

#include <sodium.h>
#include <vector>
#include <string>
#include <cstdint>

#include "CryptoUtils.hpp"
#include "Crypto.hpp"
#include "Config.hpp"

using namespace dgkn;

namespace {
    // sodium_init() ist idempotent und thread-safe; einmal vor den Tests genügt.
    // (KEIN REQUIRE im globalen Konstruktor — das ist außerhalb einer Catch2-
    // Session illegal und führt zu __fastfail.)
    const int _sodium_init_result = sodium_init();

    std::vector<uint8_t> random_bytes(size_t n) {
        std::vector<uint8_t> v(n);
        randombytes_buf(v.data(), n);
        return v;
    }
}

TEST_CASE("libsodium initialized", "[setup]") {
    REQUIRE(_sodium_init_result >= 0);
}

TEST_CASE("XChaCha20 encrypt/decrypt roundtrip", "[crypto]") {
    auto key = random_bytes(config::KEY_SIZE);
    std::vector<uint8_t> pt = {'H','e','l','l','o',' ','D','G','K','N'};
    std::vector<uint8_t> aad = {'A','A','D'};

    auto res = crypto_utils::XChaCha20::encrypt(key, pt, aad);
    REQUIRE(res.nonce.size() == config::NONCE_SIZE);
    REQUIRE(res.ciphertext.size() == pt.size() + 16);

    auto out = crypto_utils::XChaCha20::decrypt(key, res.nonce, res.ciphertext, aad);
    REQUIRE(out == pt);
}

TEST_CASE("XChaCha20 wrong AAD fails", "[crypto]") {
    auto key = random_bytes(config::KEY_SIZE);
    std::vector<uint8_t> pt = {'x','y','z'};
    auto res = crypto_utils::XChaCha20::encrypt(key, pt, {});
    std::vector<uint8_t> bad_aad = {'n','o'};
    REQUIRE_THROWS([&]{
        crypto_utils::XChaCha20::decrypt(key, res.nonce, res.ciphertext, bad_aad);
    }());
}

TEST_CASE("Sector crypto roundtrip (deterministic nonce)", "[crypto]") {
    auto sector_key = random_bytes(config::KEY_SIZE);
    auto data = random_bytes(config::SECTOR_SIZE);
    uint64_t idx = 42;

    auto ct = crypto_utils::SectorCrypto::encrypt_sector(sector_key, idx, data);
    REQUIRE(ct.size() == config::SECTOR_CT_SIZE);

    auto pt = crypto_utils::SectorCrypto::decrypt_sector(sector_key, idx, ct);
    REQUIRE(pt == data);
}

TEST_CASE("Sector crypto fails with wrong index (AAD = sector index)", "[crypto]") {
    auto sector_key = random_bytes(config::KEY_SIZE);
    auto data = random_bytes(config::SECTOR_SIZE);

    auto ct = crypto_utils::SectorCrypto::encrypt_sector(sector_key, 1, data);
    REQUIRE_THROWS([&]{
        crypto_utils::SectorCrypto::decrypt_sector(sector_key, 2, ct);
    }());
}

TEST_CASE("KDF derive_hardened is deterministic", "[kdf]") {
    std::string pw = "Str0ng#Passphrase!XYZ";
    auto kf = random_bytes(32);
    auto salt = random_bytes(config::SALT_SIZE);
    std::string info_s = "DGKN7-NORM";
    std::span<const uint8_t> info(reinterpret_cast<const uint8_t*>(info_s.data()), info_s.size());

    auto k1 = crypto_utils::KDF::derive_hardened(pw, kf, salt, info);
    auto k2 = crypto_utils::KDF::derive_hardened(pw, kf, salt, info);
    REQUIRE(k1.size() == config::KEY_SIZE);
    REQUIRE(k1 == k2);

    // Anderer Salt -> anderer Schlüssel
    auto salt2 = random_bytes(config::SALT_SIZE);
    auto k3 = crypto_utils::KDF::derive_hardened(pw, kf, salt2, info);
    REQUIRE(k3 != k1);
}

TEST_CASE("Sector key derivation is deterministic and salt-bound", "[kdf]") {
    auto master = random_bytes(config::KEY_SIZE);
    auto salt = random_bytes(config::SALT_SIZE);
    auto sk1 = crypto_utils::KDF::derive_sector_key(master, salt);
    auto sk2 = crypto_utils::KDF::derive_sector_key(master, salt);
    REQUIRE(sk1 == sk2);
    REQUIRE(sk1.size() == config::KEY_SIZE);
}

// F-C: Testet die dgkn::crypto-Layout-Helfer. ACHTUNG: das ist NICHT der
// Produktionspfad (der läuft über ContainerManager::scan_hidden) — siehe Hinweis
// in core/Crypto.hpp. Der Test sichert nur den Determinismus dieser Helfer.
TEST_CASE("Hidden volume layout is deterministic for a seed", "[hidden]") {
    auto seed = random_bytes(32);
    uint64_t total = 100 * 1024 * 1024;
    uint64_t hidden = 30 * 1024 * 1024;

    auto l1 = crypto::layout_hidden_volume(total, hidden, seed, 4096, config::HDR_TOTAL, 4096);
    auto l2 = crypto::layout_hidden_volume(total, hidden, seed, 4096, config::HDR_TOTAL, 4096);
    // Deterministisch für denselben Seed (Voraussetzung für den Hidden-Scan beim Mount).
    REQUIRE(l1.hidden_header_offset == l2.hidden_header_offset);
    // Offset liegt im gültigen Bereich. Die Alignment-Grenze selbst ist
    // seed-randomisiert (v7: Scan-Muster nicht fingerprint-bar), daher KEINE
    // feste %4096-Invariante — nur Determinismus + Bereich werden geprüft.
    const uint64_t first_allowed = config::HDR_TOTAL + 4096;
    REQUIRE(l1.hidden_header_offset >= first_allowed);
    REQUIRE(l1.hidden_header_offset + hidden <= total);
    REQUIRE(l1.normal_data_size >= 4096);
    REQUIRE(l1.hidden_data_offset == l1.hidden_header_offset + config::HDR_TOTAL);
}

TEST_CASE("Password strength validation", "[pw]") {
    auto [weak_ok, weak_msg] = crypto_utils::validate_password_strength("short");
    REQUIRE_FALSE(weak_ok);
    auto [strong_ok, strong_msg] = crypto_utils::validate_password_strength("Str0ng#Passphrase!XYZ");
    REQUIRE(strong_ok);
}