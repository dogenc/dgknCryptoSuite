// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <string>

namespace dgkn::core {

    // Liefert eine ehrliche Momentaufnahme der System-Sicherheitslage.
    // ACHTUNG: Dies ist KEIN Malware-Scanner. Es prüft nur Indikatoren, die für
    // eine Krypto-App relevant und seriös feststellbar sind. Eine "sauber"-Anzeige
    // bedeutet NICHT, dass das System frei von Malware ist.
    struct SystemStatus {
        bool debugger_present = false;   // Debugger an diesem Prozess?
        bool av_active = false;          // Ein Echtzeit-AV (Defender/3rd-party) aktiv?
        std::string av_name;             // Name des AV-Produkts (falls bekannt)
        bool elevated = false;           // Läuft mit Administrator-Rechten?
        bool self_integrity_ok = true;   // Eigene EXE seit Start unverändert (Best-effort)

        // Erfasst den aktuellen Status (Windows-APIs; auf anderen Plattformen Defaults).
        static SystemStatus capture();

        // Grobe Gesamtbewertung für die Ampel-Anzeige: 0=gut, 1=Achtung, 2=Warnung.
        int risk_level() const;
        // Kurzer, menschenlesbarer Statustext (eine Zeile).
        std::string summary() const;
    };

}