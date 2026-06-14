// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include <catch2/catch_test_macros.hpp>

#include <string>
#include "TPMUtils.hpp"

using dgkn::core::TPMUtils;
using dgkn::core::TPMSealConfig;

TEST_CASE("TPM availability query does not crash", "[tpm]") {
    // Darf auf JEDEM System sicher aufrufbar sein (mit/ohne TPM, ohne Admin).
    bool avail = TPMUtils::is_tpm_native_available();
    INFO("TPM 2.0 verfuegbar: " << (avail ? "ja" : "nein"));
    REQUIRE((avail == true || avail == false)); // nur: kein Crash
}

TEST_CASE("PCR string validation", "[tpm]") {
    REQUIRE(TPMUtils::validate_pcrs("sha256:0,2,4,7"));
    REQUIRE(TPMUtils::validate_pcrs("sha1:7"));
    REQUIRE_FALSE(TPMUtils::validate_pcrs("sha256:"));
    REQUIRE_FALSE(TPMUtils::validate_pcrs("0,2,4"));        // kein Algorithmus
    REQUIRE_FALSE(TPMUtils::validate_pcrs("sha256:a,b"));   // keine Ziffern
    REQUIRE_FALSE(TPMUtils::validate_pcrs(""));
}

TEST_CASE("seal/unseal roundtrip (machine-bound via DPAPI)", "[tpm]") {
    TPMSealConfig cfg{true};
    const std::string secret = "MeinGeheimes2FA-Secret-XYZ";

    auto sealed = TPMUtils::seal_secret(secret, cfg);
#ifdef _WIN32
    // Auf Windows muss DPAPI(LocalMachine) immer funktionieren.
    REQUIRE(sealed.has_value());
    REQUIRE_FALSE(sealed->empty());
    REQUIRE(*sealed != secret); // verschlüsselt, nicht Klartext

    auto unsealed = TPMUtils::unseal_secret(*sealed, cfg);
    REQUIRE(unsealed.has_value());
    REQUIRE(*unsealed == secret);
#else
    REQUIRE_FALSE(sealed.has_value()); // Nicht-Windows: Stub
#endif
}

TEST_CASE("unseal of garbage fails cleanly", "[tpm]") {
    TPMSealConfig cfg{true};
    auto r = TPMUtils::unseal_secret("not-a-valid-base64-blob!!!", cfg);
    REQUIRE_FALSE(r.has_value());
    auto r2 = TPMUtils::unseal_secret("", cfg);
    REQUIRE_FALSE(r2.has_value());
}

TEST_CASE("disabled config seals nothing", "[tpm]") {
    TPMSealConfig cfg{false};
    REQUIRE_FALSE(TPMUtils::seal_secret("x", cfg).has_value());
    REQUIRE_FALSE(TPMUtils::unseal_secret("x", cfg).has_value());
}

TEST_CASE("sealed blob is bound to its PCR policy (entropy)", "[tpm]") {
#ifdef _WIN32
    TPMSealConfig cfg_a{true}; cfg_a.pcrs = "sha256:0,2,4,7";
    TPMSealConfig cfg_b{true}; cfg_b.pcrs = "sha256:1,3";
    auto sealed = TPMUtils::seal_secret("geheim", cfg_a);
    REQUIRE(sealed.has_value());
    // Mit anderer PCR-Policy (entropy) darf nicht entsiegelt werden.
    auto wrong = TPMUtils::unseal_secret(*sealed, cfg_b);
    REQUIRE_FALSE(wrong.has_value());
    // Mit derselben Policy schon.
    auto ok = TPMUtils::unseal_secret(*sealed, cfg_a);
    REQUIRE(ok.has_value());
#endif
}