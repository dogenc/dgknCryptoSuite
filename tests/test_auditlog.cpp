// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include <catch2/catch_test_macros.hpp>

#include <sodium.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include "AuditLog.hpp"

namespace fs = std::filesystem;
using dgkn::core::AuditLog;

namespace {
    const int _si = sodium_init();
    struct TmpLog {
        fs::path p;
        TmpLog() { p = fs::temp_directory_path() / ("dgkn_audit_" + std::to_string(randombytes_random()) + ".log"); }
        ~TmpLog() { std::error_code ec; fs::remove(p, ec); }
        std::string str() const { return p.string(); }
    };
}

TEST_CASE("audit log: intact chain verifies", "[audit]") {
    TmpLog t;
    {
        AuditLog log(t.str());
        log.append("App gestartet");
        log.append("Container erstellt: vault.dgkn");
        log.append("Mount normal");
        log.append("Unmount");
    }
    AuditLog reload(t.str());
    size_t bad = 0;
    REQUIRE(reload.verify(&bad));
    REQUIRE(bad == 0);
}

TEST_CASE("audit log: tampering a line is detected", "[audit][security]") {
    TmpLog t;
    {
        AuditLog log(t.str());
        log.append("Eintrag A");
        log.append("Eintrag B");
        log.append("Eintrag C");
    }
    // Mittlere Zeile bösartig verändern (Message-Feld).
    {
        std::ifstream in(t.str());
        std::vector<std::string> lines; std::string l;
        while (std::getline(in, l)) lines.push_back(l);
        in.close();
        REQUIRE(lines.size() == 3);
        // In Zeile 2 die Message ersetzen (HMAC bleibt alt -> Kette bricht).
        auto& mid = lines[1];
        size_t p2 = mid.find('\t', mid.find('\t') + 1);
        size_t p3 = mid.rfind('\t');
        mid = mid.substr(0, p2 + 1) + "GEFAELSCHT" + mid.substr(p3);
        std::ofstream out(t.str(), std::ios::trunc);
        for (auto& x : lines) out << x << "\n";
    }
    AuditLog reload(t.str());
    size_t bad = 0;
    REQUIRE_FALSE(reload.verify(&bad));
    REQUIRE(bad == 2); // genau die manipulierte Zeile
}

TEST_CASE("audit log: deleting a line is detected", "[audit][security]") {
    TmpLog t;
    {
        AuditLog log(t.str());
        log.append("eins"); log.append("zwei"); log.append("drei");
    }
    // Mittlere Zeile löschen -> seq-Lücke + Kettenbruch.
    {
        std::ifstream in(t.str());
        std::vector<std::string> lines; std::string l;
        while (std::getline(in, l)) lines.push_back(l);
        in.close();
        std::ofstream out(t.str(), std::ios::trunc);
        out << lines[0] << "\n" << lines[2] << "\n"; // Zeile 2 entfernt
    }
    AuditLog reload(t.str());
    REQUIRE_FALSE(reload.verify(nullptr));
}

TEST_CASE("audit log: appending continues the chain", "[audit]") {
    TmpLog t;
    { AuditLog log(t.str()); log.append("session1-a"); log.append("session1-b"); }
    { AuditLog log(t.str()); log.append("session2-a"); } // neue Instanz = "Neustart"
    AuditLog reload(t.str());
    REQUIRE(reload.verify(nullptr));
}