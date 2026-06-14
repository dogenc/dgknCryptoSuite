// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <string>
#include <optional>

namespace dgkn::core {

    struct TPMSealConfig {
        bool enabled = false;
        std::string pcrs = "sha256:0,2,4,7";
        std::string key_path = "/HS/SRK/dgkn/2fa-secret";
    };

    class TPMUtils {
    public:
        // Prüft, ob ein TPM-Chip über FAPI erreichbar ist
        static bool is_tpm_native_available();

        // Versiegelt ein Secret an spezifische PCR-Zustände (JSON Base64 Output)
        static std::optional<std::string> seal_secret(const std::string& secret_text, const TPMSealConfig& config);

        // Entsiegelt den Base64 Payload wieder zum Klartext-Secret
        static std::optional<std::string> unseal_secret(const std::string& blob_b64, const TPMSealConfig& config);

        // Validiert einen PCR-String wie "sha256:0,2,4,7" (Algorithmus:Indizes).
        static bool validate_pcrs(const std::string& pcrs);

    private:
        static std::string normalize_path(const std::string& path);
    };

} // namespace dgkn::core