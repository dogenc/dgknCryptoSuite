// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include <catch2/catch_test_macros.hpp>

#include <sodium.h>
#include <string>

#include "Totp.hpp"
#include "Config.hpp"

using dgkn::core::Totp;

namespace {
    const int _si = sodium_init();
    // RFC 6238 Test-Secret: ASCII "12345678901234567890" (20 Bytes) als Base32.
    // base32("12345678901234567890") = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    const std::string RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
}

TEST_CASE("TOTP matches RFC 6238 SHA1 test vectors", "[totp][rfc]") {
    // Aus RFC 6238 Appendix B (SHA1, 8 Stellen). Wir nutzen 6 Stellen (Config),
    // daher die letzten 6 Ziffern der bekannten 8-stelligen Werte.
    // T=59       -> 94287082 -> 6-stellig 287082
    // T=1111111109 -> 07081804 -> 081804
    // T=1234567890 -> 89005924 -> 005924
    // T=2000000000 -> 69279037 -> 279037
    struct V { int64_t t; const char* code6; };
    V vectors[] = {
        {59,         "287082"},
        {1111111109, "081804"},
        {1234567890, "005924"},
        {2000000000, "279037"},
    };
    REQUIRE(dgkn::config::TWOFA_DIGITS == 6);
    REQUIRE(dgkn::config::TWOFA_PERIOD == 30);
    for (auto& v : vectors) {
        auto c = Totp::code(RFC_SECRET, v.t);
        REQUIRE(c.has_value());
        INFO("t=" << v.t << " got=" << *c << " want=" << v.code6);
        REQUIRE(*c == v.code6);
    }
}

TEST_CASE("TOTP verify accepts current code, rejects wrong", "[totp]") {
    auto secret = Totp::generate_secret();
    int64_t now = 1700000000;
    auto c = Totp::code(secret, now);
    REQUIRE(c.has_value());

    REQUIRE(Totp::verify(secret, *c, now));            // korrekt
    REQUIRE(Totp::verify(secret, " " + *c + " ", now)); // mit Whitespace
    REQUIRE_FALSE(Totp::verify(secret, "000000", now)); // falsch (sehr wahrscheinlich)
    REQUIRE_FALSE(Totp::verify(secret, "12345", now));  // falsche Länge
    REQUIRE_FALSE(Totp::verify(secret, "abcdef", now)); // keine Ziffern
    REQUIRE_FALSE(Totp::verify("", *c, now));           // kein Secret
}

TEST_CASE("TOTP window tolerates +/- one period", "[totp][window]") {
    auto secret = Totp::generate_secret();
    int64_t now = 1700000000;
    // Code aus der vorigen Periode muss innerhalb des Fensters (±1) noch akzeptiert werden.
    auto prev = Totp::code(secret, now - dgkn::config::TWOFA_PERIOD);
    auto next = Totp::code(secret, now + dgkn::config::TWOFA_PERIOD);
    REQUIRE(prev.has_value()); REQUIRE(next.has_value());
    REQUIRE(Totp::verify(secret, *prev, now));
    REQUIRE(Totp::verify(secret, *next, now));
    // Zwei Perioden entfernt -> außerhalb des Fensters -> abgelehnt.
    auto far = Totp::code(secret, now - 3*dgkn::config::TWOFA_PERIOD);
    REQUIRE(far.has_value());
    // (kann theoretisch zufällig kollidieren; bei 6 Stellen ~1e-6, vernachlässigbar)
    REQUIRE_FALSE(Totp::verify(secret, *far, now));
}

TEST_CASE("generate_secret yields valid, distinct secrets", "[totp]") {
    auto s1 = Totp::generate_secret();
    auto s2 = Totp::generate_secret();
    REQUIRE(Totp::is_valid_secret(s1));
    REQUIRE(s1.size() >= 16);
    REQUIRE(s1 != s2);
    REQUIRE_FALSE(Totp::is_valid_secret("not base32 !!!"));
}

TEST_CASE("otpauth URI is well-formed", "[totp]") {
    auto uri = Totp::otpauth_uri("GEZDGNBVGY3TQOJQ", "DGKN", "alice");
    REQUIRE(uri.rfind("otpauth://totp/", 0) == 0);
    REQUIRE(uri.find("secret=GEZDGNBVGY3TQOJQ") != std::string::npos);
    REQUIRE(uri.find("algorithm=SHA1") != std::string::npos);
    REQUIRE(uri.find("digits=6") != std::string::npos);
    REQUIRE(uri.find("period=30") != std::string::npos);
}