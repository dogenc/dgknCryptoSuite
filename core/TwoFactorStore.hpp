// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <string>
#include <vector>
#include <optional>

namespace dgkn::core {

    // Persistente, verschlüsselte Speicherung des App-Login-TOTP-Secrets.
    // Secret: XChaCha20-Poly1305; Schlüssel via Argon2id aus Master-Passwort.
    // Recovery-Codes: NUR Argon2id-Hash, Einmal-Nutzung.
    // Datei: %LOCALAPPDATA%\DGKN\security\2fa.json. Kennt kein Qt.
    class TwoFactorStore {
    public:
        // Zustand der Sicherungsdatei aus Sicht der GUI:
        //  Missing  – keine Datei → Einrichtungsmodus.
        //  Usable   – Datei vorhanden, parsebar und vollständig → Master-PW abfragen.
        //  Corrupt  – Datei vorhanden, aber unlesbar/Alt-Format/Pflichtfelder fehlen
        //             → Reset anbieten (verwerfen + neu einrichten), NICHT stillschweigend
        //             ein neues Secret erzeugen.
        enum class Status { Missing, Usable, Corrupt };

        explicit TwoFactorStore(std::string explicit_path = "");

        bool exists() const;
        std::string path() const;

        // Klassifiziert die Datei ohne Master-PW (siehe Status). Erlaubt der GUI,
        // eine beschädigte/veraltete Datei zu erkennen, statt am Entschlüsseln zu
        // scheitern und den Nutzer auszusperren.
        Status status() const;

        // Löscht die Sicherungsdatei (für den Reset-Pfad bei Corrupt). Überschreibt
        // sie vorher mehrfach, da sie verschlüsseltes Material enthält. true bei Erfolg
        // oder wenn keine Datei existierte.
        bool reset(std::string& err);

        // Speichert Secret (Master-PW-geschützt) + erzeugt 10 Recovery-Codes (out_codes).
        // Atomar + ACL-eingeschränkt. false + err bei Fehler.
        bool save(const std::string& secret, const std::string& master_pw,
                  std::vector<std::string>& out_codes, std::string& err);

        // Entschlüsseltes Secret oder nullopt (falsches PW / Korruption / fehlt).
        std::optional<std::string> load(const std::string& master_pw, std::string& err) const;

        // Prüft NUR das Master-PW (kein Secret-Leak nach außen).
        bool verify_password(const std::string& master_pw) const;

        // Erzeugt 10 neue Recovery-Codes (ersetzt alte). Verlangt korrektes Master-PW.
        std::optional<std::vector<std::string>> regenerate_recovery_codes(
            const std::string& master_pw, std::string& err);

        // Prüft Recovery-Code; bei Treffer used=true + persistiert. Einmal-Nutzung.
        bool consume_recovery_code(const std::string& code, std::string& err);

        int remaining_recovery_codes() const;

    private:
        std::string path_;
    };

}