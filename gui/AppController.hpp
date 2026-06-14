// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <string>
#include <vector>
#include <tuple>
#include <optional>
#include "Manager.hpp"
#include "Totp.hpp"
#include "TwoFactorStore.hpp"

namespace dgkn::gui {

    // Dünne Controller-Schicht zwischen Qt-View und core::ContainerManager.
    // Entspricht controllers/app_controller.py.
    class AppController {
    public:
        core::ContainerManager& manager() { return manager_; }

        // ── 2FA / TOTP (echte Code-Verifikation, RFC 6238) ──
        // Verifiziert den vom Nutzer eingegebenen 6-stelligen Code gegen das Secret.
        bool verify_totp(const std::string& secret, const std::string& user_code) const {
            return core::Totp::verify(secret, user_code);
        }
        // Erzeugt ein neues Base32-Secret für die Einrichtung.
        std::string new_totp_secret() const { return core::Totp::generate_secret(); }
        // otpauth://-URI zum Import in eine Authenticator-App (Google Authenticator etc.).
        std::string totp_uri(const std::string& secret, const std::string& account = "user") const {
            return core::Totp::otpauth_uri(secret, "DGKN Crypto Suite", account);
        }
        bool totp_secret_valid(const std::string& secret) const {
            return core::Totp::is_valid_secret(secret);
        }

        // ── Persistente 2FA-Sicherung (App-Login, XChaCha20+Argon2id) ──
        bool twofa_store_exists() const { return store_.exists(); }
        std::string twofa_store_path() const { return store_.path(); }
        core::TwoFactorStore::Status twofa_store_status() const { return store_.status(); }
        bool twofa_reset(std::string& err) { return store_.reset(err); }
        bool twofa_save(const std::string& secret, const std::string& master_pw,
                        std::vector<std::string>& out_codes, std::string& err) {
            return store_.save(secret, master_pw, out_codes, err);
        }
        std::optional<std::string> twofa_load(const std::string& master_pw, std::string& err) const {
            return store_.load(master_pw, err);
        }
        bool twofa_verify_password(const std::string& master_pw) const {
            return store_.verify_password(master_pw);
        }
        std::optional<std::vector<std::string>> twofa_regenerate_codes(
            const std::string& master_pw, std::string& err) {
            return store_.regenerate_recovery_codes(master_pw, err);
        }
        bool twofa_consume_code(const std::string& code, std::string& err) {
            return store_.consume_recovery_code(code, err);
        }
        int twofa_remaining_codes() const { return store_.remaining_recovery_codes(); }

        // Mountet ein oder (im protected-Modus) zwei Volumes.
        // Rückgabe: (ok, Liste der mount_ids ODER Fehlermeldung als erstes Element).
        std::pair<bool, std::vector<std::string>> mount_volumes(
            const std::string& container_path,
            const std::string& mode,
            const std::string& password_a,
            const std::string& keyfile_a,
            const std::string& password_b,
            const std::string& keyfile_b,
            const std::string& twofa_secret,
            const std::string& tpm_sealed_secret = "",
            bool bind_to_device = false);

    private:
        core::ContainerManager manager_;
        core::TwoFactorStore store_;
    };

}