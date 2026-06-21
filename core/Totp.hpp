// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <string>
#include <cstdint>
#include <optional>

namespace dgkn::core {

    // RFC 6238 TOTP (Time-based One-Time Password), HMAC-SHA1, 6 Stellen, 30s Periode.
    // Parameter stammen aus Config.hpp (TWOFA_DIGITS / TWOFA_PERIOD / TWOFA_WINDOW).
    class Totp {
    public:
        // Erzeugt ein neues zufälliges Base32-Secret (20 Bytes Entropie, ohne Padding).
        static std::string generate_secret();

        // Berechnet den TOTP-Code für ein Base32-Secret zum Zeitpunkt unix_time
        // (Default: jetzt). Gibt einen nullopt zurück, wenn das Secret ungültig ist.
        static std::optional<std::string> code(const std::string& base32_secret,
                                               int64_t unix_time = -1);

        // Verifiziert einen vom Nutzer eingegebenen Code gegen das Secret, mit
        // Toleranzfenster (±TWOFA_WINDOW Perioden). Konstanter-Zeit-Vergleich.
        static bool verify(const std::string& base32_secret, const std::string& user_code,
                           int64_t unix_time = -1);

        // Baut eine otpauth://-URI (für QR-Code / Authenticator-App-Import).
        static std::string otpauth_uri(const std::string& base32_secret,
                                       const std::string& issuer = "DGKN Crypto Suite",
                                       const std::string& account = "user");

        // Validiert grob, ob ein String ein plausibles Base32-Secret ist.
        static bool is_valid_secret(const std::string& base32_secret);
    };

}