// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>
#include <windows.h>
#include <string>
#include <fstream>
#include <filesystem>
#include <cctype>
#include <nlohmann/json.hpp>

#include "TwoFactorStore.hpp"

namespace { const int _si = sodium_init(); }
using dgkn::core::TwoFactorStore;

// Argon2-Speedup über DIESELBE API, die derive_hardened liest (Win32, nicht CRT).
static void set_argon2_test_kib() { SetEnvironmentVariableA("DGKN_ARGON2_TEST_KIB", "1024"); }

static std::string tmp_2fa_path() {
    auto dir = std::filesystem::temp_directory_path() / "dgkn_2fa_test";
    std::filesystem::create_directories(dir);
    static int ctr = 0;
    auto p = dir / ("2fa_" + std::to_string(++ctr) + ".json");
    std::error_code ec; std::filesystem::remove(p, ec);
    return p.string();
}

TEST_CASE("path() liefert expliziten Pfad, exists() false bei fehlender Datei", "[twofa]") {
    auto p = tmp_2fa_path();
    TwoFactorStore store(p);
    REQUIRE(store.path() == p);
    REQUIRE_FALSE(store.exists());
}

TEST_CASE("save/load Roundtrip liefert dasselbe Secret", "[twofa]") {
    set_argon2_test_kib();
    auto p = tmp_2fa_path();
    TwoFactorStore store(p);
    const std::string secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const std::string pw = "Korrekt-Pferd-Batterie-7!";
    std::vector<std::string> codes; std::string err;
    REQUIRE(store.save(secret, pw, codes, err));
    REQUIRE(err.empty());
    REQUIRE(store.exists());

    TwoFactorStore reopened(p);
    std::string lerr;
    auto loaded = reopened.load(pw, lerr);
    REQUIRE(loaded.has_value());
    REQUIRE(*loaded == secret);
}

TEST_CASE("load/verify_password mit falschem Passwort schlaegt fehl", "[twofa]") {
    set_argon2_test_kib();
    auto p = tmp_2fa_path();
    TwoFactorStore store(p);
    std::vector<std::string> codes; std::string err;
    REQUIRE(store.save("GEZDGNBVGY3TQOJQ", "Richtiges-PW-12345!", codes, err));

    std::string lerr;
    REQUIRE_FALSE(store.load("Falsches-PW-99999!", lerr).has_value());
    REQUIRE_FALSE(lerr.empty());
    REQUIRE(store.verify_password("Richtiges-PW-12345!"));
    REQUIRE_FALSE(store.verify_password("Falsches-PW-99999!"));
}

TEST_CASE("Manipulierter Ciphertext wird abgewiesen", "[twofa]") {
    set_argon2_test_kib();
    auto p = tmp_2fa_path();
    TwoFactorStore store(p);
    std::vector<std::string> codes; std::string err;
    REQUIRE(store.save("GEZDGNBVGY3TQOJQ", "Gutes-PW-2026!!", codes, err));
    nlohmann::json j; { std::ifstream f(p); f >> j; }
    std::string ct = j["secret_enc_b64"]; ct[0] = (ct[0] == 'A' ? 'B' : 'A'); j["secret_enc_b64"] = ct;
    { std::ofstream f(p); f << j.dump(2); }
    std::string lerr;
    REQUIRE_FALSE(store.load("Gutes-PW-2026!!", lerr).has_value());
    REQUIRE_FALSE(lerr.empty());
}

TEST_CASE("Fehlende Datei: load nullopt, exists false", "[twofa]") {
    auto p = tmp_2fa_path();
    TwoFactorStore store(p);
    REQUIRE_FALSE(store.exists());
    std::string lerr;
    REQUIRE_FALSE(store.load("egal", lerr).has_value());
}

TEST_CASE("save erzeugt 10 Recovery-Codes, Klartext nicht in Datei", "[twofa][recovery]") {
    set_argon2_test_kib();
    auto p = tmp_2fa_path();
    TwoFactorStore store(p);
    std::vector<std::string> codes; std::string err;
    REQUIRE(store.save("GEZDGNBVGY3TQOJQ", "Recovery-PW-2026!", codes, err));
    REQUIRE(codes.size() == 10);
    for (const auto& c : codes) { REQUIRE(c.size() == 11); REQUIRE(c.find('-') == 5); }
    REQUIRE(store.remaining_recovery_codes() == 10);
    std::ifstream f(p); std::string content((std::istreambuf_iterator<char>(f)), {});
    for (const auto& c : codes) {
        std::string raw = c.substr(0, 5) + c.substr(6);
        INFO("code=" << c);
        REQUIRE(content.find(c) == std::string::npos);
        REQUIRE(content.find(raw) == std::string::npos);
    }
}

TEST_CASE("Recovery-Code: einmal gueltig, dann verbraucht, normalisiert", "[twofa][recovery]") {
    set_argon2_test_kib();
    auto p = tmp_2fa_path(); TwoFactorStore store(p);
    std::vector<std::string> codes; std::string err;
    REQUIRE(store.save("GEZDGNBVGY3TQOJQ", "PW-Consume-2026!", codes, err));
    std::string cerr;
    REQUIRE(store.consume_recovery_code(codes[0], cerr));
    REQUIRE(store.remaining_recovery_codes() == 9);
    REQUIRE_FALSE(store.consume_recovery_code(codes[0], cerr));      // verbraucht
    REQUIRE(store.remaining_recovery_codes() == 9);
    REQUIRE_FALSE(store.consume_recovery_code("AAAAA-AAAAA", cerr)); // unbekannt
    REQUIRE(store.remaining_recovery_codes() == 9);
    std::string c1 = codes[1];
    for (auto& ch : c1) ch = static_cast<char>(std::tolower((unsigned char)ch));
    REQUIRE(store.consume_recovery_code(" " + c1 + " ", cerr));      // lower+spaces
    REQUIRE(store.remaining_recovery_codes() == 8);
}

TEST_CASE("status() klassifiziert fehlend/brauchbar/beschaedigt", "[twofa][status]") {
    set_argon2_test_kib();
    auto p = tmp_2fa_path();
    TwoFactorStore store(p);

    // Keine Datei → Missing.
    REQUIRE(store.status() == TwoFactorStore::Status::Missing);

    // Nach save → brauchbar.
    std::vector<std::string> codes; std::string err;
    REQUIRE(store.save("GEZDGNBVGY3TQOJQ", "Status-PW-2026!", codes, err));
    REQUIRE(store.status() == TwoFactorStore::Status::Usable);

    // Alt-Format ohne 'salt_b64' (genau der Bug aus dem Screenshot) → Corrupt.
    nlohmann::json j; { std::ifstream f(p); f >> j; }
    j.erase("salt_b64");
    { std::ofstream f(p); f << j.dump(2); }
    REQUIRE(store.status() == TwoFactorStore::Status::Corrupt);

    // Unparsebarer Müll → Corrupt.
    { std::ofstream f(p); f << "kein json {{{"; }
    REQUIRE(store.status() == TwoFactorStore::Status::Corrupt);
}

TEST_CASE("reset() entfernt beschaedigte Datei, danach Einrichtung moeglich", "[twofa][status]") {
    set_argon2_test_kib();
    auto p = tmp_2fa_path();
    TwoFactorStore store(p);

    // reset ohne Datei ist erfolgreich (idempotent).
    std::string rerr;
    REQUIRE(store.reset(rerr));

    // Beschädigte Datei anlegen, dann zurücksetzen.
    { std::ofstream f(p); f << "{ \"version\": 1 }"; }
    REQUIRE(store.status() == TwoFactorStore::Status::Corrupt);
    REQUIRE(store.reset(rerr));
    REQUIRE(store.status() == TwoFactorStore::Status::Missing);
    REQUIRE_FALSE(store.exists());

    // Frische Einrichtung danach klappt.
    std::vector<std::string> codes; std::string err;
    REQUIRE(store.save("GEZDGNBVGY3TQOJQ", "Nach-Reset-2026!", codes, err));
    REQUIRE(store.status() == TwoFactorStore::Status::Usable);
}

TEST_CASE("regenerate ersetzt Satz, verlangt korrektes PW", "[twofa][recovery]") {
    set_argon2_test_kib();
    auto p = tmp_2fa_path(); TwoFactorStore store(p);
    std::vector<std::string> codes; std::string err;
    REQUIRE(store.save("GEZDGNBVGY3TQOJQ", "PW-Regen-2026!", codes, err));
    std::string rerr;
    auto fresh = store.regenerate_recovery_codes("PW-Regen-2026!", rerr);
    REQUIRE(fresh.has_value()); REQUIRE(fresh->size() == 10);
    REQUIRE(store.remaining_recovery_codes() == 10);
    std::string cerr;
    REQUIRE_FALSE(store.consume_recovery_code(codes[0], cerr));   // alt ungueltig
    REQUIRE(store.consume_recovery_code((*fresh)[0], cerr));      // neu gueltig
    std::string rerr2;
    REQUIRE_FALSE(store.regenerate_recovery_codes("Falsch-PW-12345!", rerr2).has_value());
}