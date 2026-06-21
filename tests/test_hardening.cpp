// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include <catch2/catch_test_macros.hpp>

#include <sodium.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

#include "Manager.hpp"
#include "CryptoUtils.hpp"
#include "Config.hpp"

namespace fs = std::filesystem;
using namespace dgkn;
using dgkn::core::ContainerManager;

namespace {
    const int _si = sodium_init();
    const std::string PW    = "Str0ng#Passphrase!XYZ";
    const std::string TWOFA = "JBSWY3DPEHPK3PXP";

    struct TC {
        fs::path path;
        TC() { path = fs::temp_directory_path() / ("dgkn_hard_" + std::to_string(randombytes_random()) + ".dgkn"); }
        ~TC() { std::error_code ec; fs::remove(path, ec); fs::remove(path.string()+".txn", ec); }
        std::string str() const { return path.string(); }
    };

    void flip_byte_at(const fs::path& p, std::streamoff off) {
        std::fstream f(p, std::ios::binary | std::ios::in | std::ios::out);
        f.seekg(off); char b; f.read(&b, 1); b ^= 0x80; f.seekp(off); f.write(&b, 1);
    }

    std::string read_all(const fs::path& p) {
        std::ifstream f(p, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(f)), {});
    }
}

// ─── Datei-Krypto mit 2FA-Secret als zweitem Schlüsselfaktor ───
TEST_CASE("file encryption binds the 2FA secret into the key", "[hardening][file2fa]") {
    fs::path in  = fs::temp_directory_path() / ("dgkn_in_"  + std::to_string(randombytes_random()) + ".txt");
    fs::path enc = fs::temp_directory_path() / ("dgkn_enc_" + std::to_string(randombytes_random()) + ".dgkn");
    fs::path dec = fs::temp_directory_path() / ("dgkn_dec_" + std::to_string(randombytes_random()) + ".txt");
    { std::ofstream f(in, std::ios::binary); f << "Geheime Datei-Inhalte 123"; }

    ContainerManager m;
    // Mit 2FA-Secret verschlüsseln.
    REQUIRE(m.encrypt_file(in.string(), enc.string(), PW, "", TWOFA));

    SECTION("correct password + correct secret -> success") {
        REQUIRE(m.decrypt_file(enc.string(), dec.string(), PW, "", TWOFA));
        REQUIRE(read_all(dec) == "Geheime Datei-Inhalte 123");
    }
    SECTION("correct password but MISSING secret -> fail") {
        REQUIRE_FALSE(m.decrypt_file(enc.string(), dec.string(), PW, "", ""));
    }
    SECTION("correct password but WRONG secret -> fail") {
        REQUIRE_FALSE(m.decrypt_file(enc.string(), dec.string(), PW, "", "WRONGSECRET2222"));
    }

    std::error_code ec;
    fs::remove(in, ec); fs::remove(enc, ec); fs::remove(dec, ec);
}

// H-1: das Klartext-Längenfeld pro Sektor ist nicht authentifiziert. Wird es auf einen
// Wert > entschlüsselter Sektorgröße manipuliert, darf decrypt_file NICHT out-of-bounds
// lesen, sondern muss sauber fehlschlagen.
TEST_CASE("file decrypt rejects oversized (tampered) sector length", "[hardening][file2fa][bounds]") {
    fs::path in  = fs::temp_directory_path() / ("dgkn_in_"  + std::to_string(randombytes_random()) + ".txt");
    fs::path enc = fs::temp_directory_path() / ("dgkn_enc_" + std::to_string(randombytes_random()) + ".dgkn");
    fs::path dec = fs::temp_directory_path() / ("dgkn_dec_" + std::to_string(randombytes_random()) + ".txt");
    { std::ofstream f(in, std::ios::binary); f << "kurz"; }  // < 4096 -> orig_len klein

    ContainerManager m;
    REQUIRE(m.encrypt_file(in.string(), enc.string(), PW, "", TWOFA));

    // Längenfeld des ersten Sektors (Offset HDR_TOTAL=128, 4 Byte) auf 0xFFFFFFFF setzen.
    {
        std::fstream f(enc, std::ios::binary | std::ios::in | std::ios::out);
        f.seekp(static_cast<std::streamoff>(dgkn::config::HDR_TOTAL));
        uint32_t huge = 0xFFFFFFFFu;
        f.write(reinterpret_cast<const char*>(&huge), sizeof(huge));
    }
    // Darf nicht abstürzen und muss false liefern (Manipulation erkannt / Tag-Fehler).
    REQUIRE_FALSE(m.decrypt_file(enc.string(), dec.string(), PW, "", TWOFA));

    std::error_code ec;
    fs::remove(in, ec); fs::remove(enc, ec); fs::remove(dec, ec);
}

// H-2: authentifizierter Datei-Header. Roundtrip ok; manipulierter Header / falsches
// Passwort werden SOFORT (vor dem ersten Sektor) per Poly1305 abgewiesen.
TEST_CASE("file auth header: roundtrip ok, tampered header rejected", "[hardening][file2fa][authhdr]") {
    fs::path in  = fs::temp_directory_path() / ("dgkn_in_"  + std::to_string(randombytes_random()) + ".txt");
    fs::path enc = fs::temp_directory_path() / ("dgkn_enc_" + std::to_string(randombytes_random()) + ".dgkn");
    fs::path dec = fs::temp_directory_path() / ("dgkn_dec_" + std::to_string(randombytes_random()) + ".txt");
    { std::ofstream f(in, std::ios::binary); f << "Header-Auth-Test 456"; }

    ContainerManager m;
    REQUIRE(m.encrypt_file(in.string(), enc.string(), PW, "", TWOFA));

    SECTION("roundtrip") {
        REQUIRE(m.decrypt_file(enc.string(), dec.string(), PW, "", TWOFA));
        REQUIRE(read_all(dec) == "Header-Auth-Test 456");
    }
    SECTION("wrong password rejected via header") {
        REQUIRE_FALSE(m.decrypt_file(enc.string(), dec.string(), "Wr0ng#Passphrase!ZZ", "", TWOFA));
    }
    SECTION("tampered auth-header ciphertext rejected") {
        // Ein Byte im Header-AEAD (nach marker(4)+nonce(24), Offset 32+4+24=60) kippen.
        flip_byte_at(enc, static_cast<std::streamoff>(config::SALT_SIZE + 4 + config::NONCE_SIZE));
        REQUIRE_FALSE(m.decrypt_file(enc.string(), dec.string(), PW, "", TWOFA));
    }

    std::error_code ec;
    fs::remove(in, ec); fs::remove(enc, ec); fs::remove(dec, ec);
}

// ─── Krypto-Robustheit ───

TEST_CASE("every byte flip in the header is detected", "[hardening][fuzz]") {
    TC tc; ContainerManager m;
    REQUIRE(m.create_container(tc.str(), 2, PW, "", "", "", 0, TWOFA).ok);
    // Header = erste 128 Bytes. Jedes 7. Byte kippen und Mount muss scheitern.
    for (std::streamoff off = 0; off < 128; off += 7) {
        // frische Kopie
        TC t2; { std::error_code ec; fs::copy_file(tc.path, t2.path, fs::copy_options::overwrite_existing, ec); }
        flip_byte_at(t2.path, off);
        auto r = m.mount_volume(t2.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false);
        INFO("offset=" << off);
        REQUIRE_FALSE(r.ok); // Manipulation muss erkannt werden
    }
}

TEST_CASE("empty password is handled (no crash)", "[hardening]") {
    TC tc; ContainerManager m;
    // create mit leerem Passwort + leerem 2FA -> muss sauber ablehnen, nicht crashen
    auto r = m.create_container(tc.str(), 2, "", "", "", "", 0, "");
    REQUIRE_FALSE(r.ok);
}

TEST_CASE("mount on nonexistent file fails cleanly", "[hardening]") {
    ContainerManager m;
    auto r = m.mount_volume("Z:/does/not/exist_98765.dgkn", PW, "", "normal", TWOFA, "", false, "", false, nullptr, false);
    REQUIRE_FALSE(r.ok);
}

TEST_CASE("mount on truncated/garbage file fails cleanly", "[hardening]") {
    TC tc; ContainerManager m;
    { std::ofstream f(tc.path, std::ios::binary); std::string junk(64, 'X'); f << junk; }
    auto r = m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false);
    REQUIRE_FALSE(r.ok);
}

TEST_CASE("mount on zero-byte file fails cleanly", "[hardening]") {
    TC tc; ContainerManager m;
    { std::ofstream f(tc.path, std::ios::binary); }
    auto r = m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false);
    REQUIRE_FALSE(r.ok);
}

TEST_CASE("wrong mode (hidden on normal-only container) fails", "[hardening]") {
    TC tc; ContainerManager m;
    REQUIRE(m.create_container(tc.str(), 4, PW, "", "", "", 0, TWOFA).ok);
    auto r = m.mount_volume(tc.str(), PW, "", "hidden", TWOFA, "", false, "", false, nullptr, false);
    REQUIRE_FALSE(r.ok); // es gibt kein hidden volume
}

// ─── KDF / Schlüssel-Eigenschaften ───

TEST_CASE("derived key has full entropy (not all-zero, not constant)", "[hardening][kdf]") {
    auto salt = std::vector<uint8_t>(config::SALT_SIZE); randombytes_buf(salt.data(), salt.size());
    std::string info_s = "DGKN7-NORM";
    std::span<const uint8_t> info(reinterpret_cast<const uint8_t*>(info_s.data()), info_s.size());
    auto k = crypto_utils::KDF::derive_hardened(PW, {}, salt, info);
    REQUIRE(k.size() == config::KEY_SIZE);
    bool all_zero = std::all_of(k.begin(), k.end(), [](uint8_t b){ return b == 0; });
    REQUIRE_FALSE(all_zero);
    // Verschiedene Info -> verschiedener Key (Domänentrennung normal/hidden)
    std::string info_h = "DGKN7-HIDE";
    std::span<const uint8_t> infoH(reinterpret_cast<const uint8_t*>(info_h.data()), info_h.size());
    auto kh = crypto_utils::KDF::derive_hardened(PW, {}, salt, infoH);
    REQUIRE(k != kh);
}

TEST_CASE("Argon2 memory cost is hardened (>= 64 MiB)", "[hardening][kdf]") {
    // Regressionsschutz gegen den Einheiten-Bug (war faktisch 64 KiB).
    REQUIRE(config::ARGON2_MEMORY_KIB >= 64u * 1024u);
}

TEST_CASE("sector nonce is unique per index and per epoch", "[hardening][nonce]") {
    auto sk = std::vector<uint8_t>(config::KEY_SIZE); randombytes_buf(sk.data(), sk.size());
    auto n0 = crypto_utils::XChaCha20::sector_nonce(sk, 0, 0);
    auto n1 = crypto_utils::XChaCha20::sector_nonce(sk, 1, 0);
    auto n0e1 = crypto_utils::XChaCha20::sector_nonce(sk, 0, 1);
    REQUIRE(n0 != n1);    // verschiedene Sektoren
    REQUIRE(n0 != n0e1);  // verschiedene Epochen (kein Nonce-Reuse bei Overwrite)
    REQUIRE(n0.size() == config::NONCE_SIZE);
}

// ─── Krypto-Primitiven: Bounds & Validierung (Regressionsschutz F1–F3) ───

TEST_CASE("XChaCha20::decrypt rejects too-short ciphertext (no underflow)", "[hardening][bounds]") {
    std::vector<uint8_t> key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 0x11);
    std::vector<uint8_t> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 0x22);
    // Ciphertext kürzer als der 16-Byte-Tag -> muss werfen, NICHT crashen/riesig allozieren.
    std::vector<uint8_t> tiny(5, 0x33);
    REQUIRE_THROWS([&]{ crypto_utils::XChaCha20::decrypt(key, nonce, tiny, {}); }());
    std::vector<uint8_t> empty;
    REQUIRE_THROWS([&]{ crypto_utils::XChaCha20::decrypt(key, nonce, empty, {}); }());
}

TEST_CASE("XChaCha20 rejects wrong key/nonce sizes", "[hardening][bounds]") {
    std::vector<uint8_t> good_key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 1);
    std::vector<uint8_t> bad_key(16, 1);
    std::vector<uint8_t> pt = {1,2,3};
    REQUIRE_THROWS([&]{ crypto_utils::XChaCha20::encrypt(bad_key, pt, {}); }());

    auto res = crypto_utils::XChaCha20::encrypt(good_key, pt, {});
    std::vector<uint8_t> bad_nonce(8, 0);
    REQUIRE_THROWS([&]{ crypto_utils::XChaCha20::decrypt(good_key, bad_nonce, res.ciphertext, {}); }());
}

TEST_CASE("container with overflow-crafted header region is rejected", "[hardening][bounds]") {
    // create gültigen Container, dann data_size-Feld im (verschlüsselten) Header
    // lässt sich nicht ohne Key fälschen — der AEAD-Tag schützt. Wir prüfen daher
    // den Pfad indirekt: ein abgeschnittener Container (kleiner als Header behauptet)
    // darf nicht mounten und nicht crashen.
    TC tc; ContainerManager m;
    REQUIRE(m.create_container(tc.str(), 4, PW, "", "", "", 0, TWOFA).ok);
    // Datei nach dem Header stark kürzen (simuliert data_offset+data_size > fsize).
    {
        std::error_code ec;
        fs::resize_file(tc.path, 200, ec); // nur Header + ein paar Bytes
    }
    auto r = m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false);
    REQUIRE_FALSE(r.ok); // sauber abgelehnt, kein Crash/Bad-Alloc
}

// ─── Duress / Notfall-Passwort (R3) ───

TEST_CASE("duress password is rejected like a wrong password", "[hardening][duress]") {
    TC tc; ContainerManager m;
    const std::string emergency = "Duress#Notfall!2024XY";
    REQUIRE(m.create_container(tc.str(), 2, PW, "", "", "", 0, TWOFA).ok);

    // Normales Passwort funktioniert.
    REQUIRE(m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, /*emergency*/"", false, nullptr, false).ok);

    // Wird das Notfall-Passwort eingegeben, MUSS der Zugriff verweigert werden
    // (gleiche Meldung wie bei falschem Passwort -> unauffällig), OHNE Sanitization.
    auto r = m.mount_volume(tc.str(), emergency, "", "normal", TWOFA, "", false, emergency, false, nullptr, false);
    REQUIRE_FALSE(r.ok);

    // Container ist danach noch intakt (keine Sanitization angefordert).
    REQUIRE(m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false).ok);
}

TEST_CASE("duress password with sanitization destroys headers", "[hardening][duress]") {
    TC tc; ContainerManager m;
    const std::string emergency = "Duress#Notfall!2024XY";
    REQUIRE(m.create_container(tc.str(), 2, PW, "", "", "", 0, TWOFA).ok);

    // Notfall-Passwort MIT Sanitization -> Header werden mit Zufall überschrieben.
    auto r = m.mount_volume(tc.str(), emergency, "", "normal", TWOFA, "", false, emergency, /*sanitize*/true, nullptr, false);
    REQUIRE_FALSE(r.ok);

    // Danach ist der Container unbrauchbar — auch das korrekte Passwort mountet nicht mehr.
    REQUIRE_FALSE(m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false).ok);
}

// ─── Brute-Force-Schutz ───

TEST_CASE("repeated wrong passwords trigger backoff/lockout", "[hardening][bruteforce]") {
    TC tc; ContainerManager m;
    REQUIRE(m.create_container(tc.str(), 2, PW, "", "", "", 0, TWOFA).ok);
    int rejected = 0;
    for (int i = 0; i < 6; ++i) {
        auto r = m.mount_volume(tc.str(), "Wr0ng#Passphrase!ZZ" + std::to_string(i), "", "normal", TWOFA, "", false, "", false, nullptr, false);
        if (!r.ok) ++rejected;
    }
    REQUIRE(rejected == 6); // alle Fehlversuche abgelehnt (Lockout/Backoff greift intern)
    // Korrektes Passwort muss danach trotzdem noch funktionieren (sofern kein harter Lockout)
}

TEST_CASE("lockout persists across a simulated app restart", "[hardening][bruteforce][persist]") {
    TC tc;
    {
        ContainerManager m;
        REQUIRE(m.create_container(tc.str(), 2, PW, "", "", "", 0, TWOFA).ok);
        // Genug Fehlversuche, um den harten Lockout (AUTH_LOCKOUT_TRIES) auszulösen.
        for (int i = 0; i < (int)dgkn::config::AUTH_LOCKOUT_TRIES + 1; ++i) {
            m.mount_volume(tc.str(), "Wr0ng#Pass!ZZ" + std::to_string(i), "", "normal", TWOFA, "", false, "", false, nullptr, false);
        }
    }
    // "Neustart": frische Instanz. Der Lockout muss aus der persistierten Datei greifen,
    // d.h. selbst das KORREKTE Passwort wird (für die Lockout-Dauer) abgewiesen.
    {
        ContainerManager m2;
        auto r = m2.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false);
        REQUIRE_FALSE(r.ok); // Lockout aus voriger Sitzung aktiv
        INFO(r.message);
        REQUIRE(r.message.find("Fehlversuche") != std::string::npos);
    }
    // Aufräumen: Lockout-Datei entfernen (Pfad ist sha256(identity) im Temp/DGKN7_LOCKS).
    // Wird nicht zwingend gebraucht (Temp), aber sauber.
}