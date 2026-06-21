// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string_view>

namespace dgkn::crypto {

    // ─────────────────────────────────────────────────────────────────────────
    // F-C HINWEIS (Security-Review 2026-06-01): Die folgenden Hidden-Volume-
    // Funktionen sind NICHT der Produktionspfad. Der echte Hidden-Scan beim
    // Erstellen/Mounten läuft über ContainerManager::hidden_scan_seed +
    // ContainerManager::scan_hidden (siehe core/Manager.cpp). Diese
    // dgkn::crypto-Routinen sind eine eigenständige, deterministische
    // Offset-Berechnung aus der Python-Portierung und werden derzeit NUR von
    // tests/test_crypto.cpp verwendet. Nicht hier ändern in der Annahme, damit
    // den Live-Pfad zu beeinflussen — er liegt in Manager.cpp.
    // ─────────────────────────────────────────────────────────────────────────

    constexpr std::string_view HIDDEN_SEED_INFO = "DGKN7-HIDDEN-VOLUME-SEED";
    constexpr std::string_view HIDDEN_OFFSET_INFO = "DGKN7-HIDDEN-OFFSET";

    struct HiddenVolumeLayout {
        uint64_t normal_data_size;
        uint64_t hidden_header_offset;
        uint64_t hidden_data_offset;
        uint64_t hidden_size;
    };

    // Leitet einen deterministischen, key-gebundenen Seed für versteckte Volumes ab.
    std::vector<uint8_t> derive_hidden_seed(
        std::span<const uint8_t> password_bytes,
        std::span<const uint8_t> keyfile_hash,
        std::span<const uint8_t> bind_digest = {}
    );

    // Wählt einen key-abhängigen Offset für das versteckte Volume.
    uint64_t choose_hidden_offset(
        uint64_t total_size,
        uint64_t hidden_size,
        std::span<const uint8_t> seed,
        uint64_t min_offset,
        uint64_t alignment = 4096
    );

    // Berechnet die sichtbare/verborgene Aufteilung für ein verstecktes Volume.
    HiddenVolumeLayout layout_hidden_volume(
        uint64_t total_size,
        uint64_t hidden_size,
        std::span<const uint8_t> seed,
        uint64_t min_normal_data = 4096,
        uint64_t header_size = 128,
        uint64_t alignment = 4096
    );

} // namespace dgkn::crypto