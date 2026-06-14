// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include <catch2/catch_test_macros.hpp>

#include <sodium.h>
#include <filesystem>
#include <fstream>
#include <string>

#include "Manager.hpp"
#include "Config.hpp"

namespace fs = std::filesystem;
using namespace dgkn;
using dgkn::core::ContainerManager;

namespace {
    const int _si = sodium_init();

    struct TempContainer {
        fs::path path;
        TempContainer() {
            path = fs::temp_directory_path() / ("dgkn_test_" + std::to_string(randombytes_random()) + ".dgkn");
        }
        ~TempContainer() {
            std::error_code ec;
            fs::remove(path, ec);
            fs::remove(path.string() + ".txn", ec);
        }
        std::string str() const { return path.string(); }
    };

    const std::string PW   = "Str0ng#Passphrase!XYZ";
    const std::string PW2  = "An0ther#Passphrase!ABC";
    const std::string TWOFA = "JBSWY3DPEHPK3PXP"; // Test-2FA-Secret (Base32)
}

TEST_CASE("create_container produces a valid NORM header", "[manager]") {
    REQUIRE(_si >= 0);
    TempContainer tc;
    ContainerManager m;

    auto r = m.create_container(tc.str(), /*size_mb=*/2, PW, "", "", "", 0, TWOFA);
    INFO(r.message);
    REQUIRE(r.ok);
    REQUIRE(fs::exists(tc.path));
    REQUIRE(fs::file_size(tc.path) == 2ull * 1024 * 1024);
}

TEST_CASE("create_container requires 2FA secret (v7)", "[manager]") {
    TempContainer tc;
    ContainerManager m;
    auto r = m.create_container(tc.str(), 2, PW, "", "", "", 0, /*twofa=*/"");
    REQUIRE_FALSE(r.ok);
}

TEST_CASE("mount with correct password succeeds, wrong fails", "[manager]") {
    TempContainer tc;
    ContainerManager m;
    REQUIRE(m.create_container(tc.str(), 2, PW, "", "", "", 0, TWOFA).ok);

    SECTION("correct password") {
        auto r = m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false);
        INFO(r.message);
        REQUIRE(r.ok);
        // message ist die mount_id
        REQUIRE_FALSE(r.message.empty());
        auto u = m.unmount(r.message);
        INFO(u.message);
        REQUIRE(u.ok);
    }
    SECTION("wrong password") {
        auto r = m.mount_volume(tc.str(), "Wr0ng#Passphrase!ZZZ", "", "normal", TWOFA, "", false, "", false, nullptr, false);
        REQUIRE_FALSE(r.ok);
    }
    SECTION("wrong 2FA") {
        auto r = m.mount_volume(tc.str(), PW, "", "normal", "WRONGSECRET12345", "", false, "", false, nullptr, false);
        REQUIRE_FALSE(r.ok);
    }
}

TEST_CASE("tampered header is rejected", "[manager]") {
    TempContainer tc;
    ContainerManager m;
    REQUIRE(m.create_container(tc.str(), 2, PW, "", "", "", 0, TWOFA).ok);

    // Ein Byte im verschlüsselten Header-Block kippen (nach salt+nonce = offset 56).
    {
        std::fstream f(tc.path, std::ios::binary | std::ios::in | std::ios::out);
        f.seekg(70);
        char b; f.read(&b, 1);
        b ^= 0x01;
        f.seekp(70);
        f.write(&b, 1);
    }
    auto r = m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false);
    REQUIRE_FALSE(r.ok);
}

TEST_CASE("change_password: old fails, new works after change", "[manager]") {
    TempContainer tc;
    ContainerManager m;
    REQUIRE(m.create_container(tc.str(), 2, PW, "", "", "", 0, TWOFA).ok);

    auto c = m.change_password(tc.str(), PW, "", PW2, "", "normal", TWOFA);
    INFO(c.message);
    REQUIRE(c.ok);

    // Altes Passwort darf nicht mehr funktionieren
    REQUIRE_FALSE(m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false).ok);
    // Neues Passwort funktioniert
    auto r = m.mount_volume(tc.str(), PW2, "", "normal", TWOFA, "", false, "", false, nullptr, false);
    INFO(r.message);
    REQUIRE(r.ok);
}

TEST_CASE("check_integrity passes on fresh container", "[manager]") {
    TempContainer tc;
    ContainerManager m;
    REQUIRE(m.create_container(tc.str(), 2, PW, "", "", "", 0, TWOFA).ok);

    auto r = m.check_integrity(tc.str(), PW, "", "normal", TWOFA);
    INFO(r.message);
    REQUIRE(r.ok);
}

TEST_CASE("header backup and restore roundtrip", "[manager]") {
    TempContainer tc;
    ContainerManager m;
    REQUIRE(m.create_container(tc.str(), 2, PW, "", "", "", 0, TWOFA).ok);

    auto bak = (fs::temp_directory_path() / ("dgkn_bak_" + std::to_string(randombytes_random()) + ".json")).string();
    REQUIRE(m.backup_header(tc.str(), bak).ok);

    // Header zerstören
    {
        std::fstream f(tc.path, std::ios::binary | std::ios::in | std::ios::out);
        std::vector<char> junk(128, 0);
        f.seekp(0); f.write(junk.data(), junk.size());
    }
    REQUIRE_FALSE(m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false).ok);

    // Restaurieren -> Mount geht wieder
    REQUIRE(m.restore_header(tc.str(), bak).ok);
    auto r = m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false);
    INFO(r.message);
    REQUIRE(r.ok);

    std::error_code ec; fs::remove(bak, ec);
}

TEST_CASE("journal: uncommitted (prepare) transaction blocks mount", "[manager][journal]") {
    TempContainer tc;
    ContainerManager m;
    REQUIRE(m.create_container(tc.str(), 2, PW, "", "", "", 0, TWOFA).ok);

    // Simuliere einen abgebrochenen Schreibvorgang: ein .txn im 'prepare'-Zustand.
    {
        std::ofstream f(tc.path.string() + ".txn", std::ios::binary | std::ios::trunc);
        f << R"({"version":1,"op":"unmount","state":"prepare","data_offset":128,"data_size":1024,"payload_len":1024,"payload_hmac":"deadbeef"})";
    }
    // Mount muss die unvollständige Transaktion erkennen und verweigern.
    auto r = m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false);
    INFO(r.message);
    REQUIRE_FALSE(r.ok);
}

TEST_CASE("hidden volume create + mount", "[manager][hidden]") {
    TempContainer tc;
    ContainerManager m;
    // 8 MB Container mit 2 MB hidden volume
    auto cr = m.create_container(tc.str(), 8, PW, "", PW2, "", 2, TWOFA);
    INFO(cr.message);
    REQUIRE(cr.ok);

    SECTION("normal volume mounts with pw_a") {
        auto r = m.mount_volume(tc.str(), PW, "", "normal", TWOFA, "", false, "", false, nullptr, false);
        INFO(r.message);
        REQUIRE(r.ok);
    }
    SECTION("hidden volume mounts with pw_b") {
        auto r = m.mount_volume(tc.str(), PW2, "", "hidden", TWOFA, "", false, "", false, nullptr, false);
        INFO(r.message);
        REQUIRE(r.ok);
    }
}