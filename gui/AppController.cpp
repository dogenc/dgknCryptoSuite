// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "AppController.hpp"

namespace dgkn::gui {

    std::pair<bool, std::vector<std::string>> AppController::mount_volumes(
        const std::string& container_path, const std::string& mode,
        const std::string& password_a, const std::string& keyfile_a,
        const std::string& password_b, const std::string& keyfile_b,
        const std::string& twofa_secret, const std::string& tpm_sealed_secret,
        bool bind_to_device
    ) {
        if (mode == "protected") {
            if (password_b.empty()) return {false, {"Passwort B fehlt"}};

            auto r1 = manager_.mount_volume(container_path, password_a, keyfile_a, "normal",
                                            twofa_secret, tpm_sealed_secret, bind_to_device);
            if (!r1.ok) return {false, {"Normal: " + r1.message}};

            auto r2 = manager_.mount_volume(container_path, password_b, keyfile_b, "hidden",
                                            twofa_secret, tpm_sealed_secret, bind_to_device);
            if (!r2.ok) {
                manager_.unmount(r1.message);
                return {false, {"Hidden: " + r2.message}};
            }
            return {true, {r1.message, r2.message}};
        }

        auto r = manager_.mount_volume(container_path, password_a, keyfile_a, mode,
                                       twofa_secret, tpm_sealed_secret, bind_to_device);
        if (!r.ok) return {false, {r.message}};
        return {true, {r.message}};
    }

}