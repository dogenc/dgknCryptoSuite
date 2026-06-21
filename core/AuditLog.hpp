// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace dgkn::core {

    // Tamper-evidentes Audit-Log: jede Zeile wird per HMAC-SHA256 an die vorherige
    // gekettet (Hash-Chain). Eine nachträgliche Änderung, Einfügung oder Löschung
    // einer Zeile bricht die Kette und ist über verify() erkennbar.
    //
    // Format pro Zeile (eine JSON-freie, leicht parsebare Form):
    //   <seq>\t<iso8601>\t<message>\t<hmac_hex>
    // wobei hmac = HMAC-SHA256(key, prev_hmac_hex + "|" + seq + "|" + iso + "|" + message)
    //
    // Der Schlüssel wird aus einem app-/maschinenspezifischen Geheimnis abgeleitet,
    // sodass das Log nicht trivial neu signiert werden kann.
    class AuditLog {
    public:
        // path: Zieldatei (wird angehängt). Lädt den letzten HMAC, um die Kette
        // bei Programmstart fortzusetzen.
        explicit AuditLog(const std::string& path);

        // Hängt einen Eintrag an (thread-safe genug für GUI-Single-Thread-Nutzung).
        void append(const std::string& message);

        // Prüft die gesamte Kette. Gibt true zurück, wenn unverändert; bei Bruch
        // wird in bad_line die 1-basierte Zeilennummer des ersten Fehlers gesetzt.
        bool verify(size_t* bad_line = nullptr) const;

    private:
        std::string compute_line_hmac(const std::string& prev_hmac, uint64_t seq,
                                      const std::string& iso, const std::string& message) const;
        std::vector<uint8_t> log_key() const;
        std::vector<uint8_t> install_secret() const;   // F-D: Pro-Installations-Zufallsgeheimnis

        std::string path_;
        std::string last_hmac_;
        uint64_t seq_ = 0;
    };

}