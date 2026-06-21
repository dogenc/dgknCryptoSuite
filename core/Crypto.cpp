// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "Crypto.hpp"
#include <sodium.h>
#include <stdexcept>
#include <initializer_list>

namespace dgkn::crypto {

    // Hilfsfunktion: Emuliert exakt Pythons Floor Division (//)
    static int64_t python_floordiv(int64_t a, int64_t b) {
        int64_t res = a / b;
        int64_t rem = a % b;
        if (rem != 0 && ((a < 0) ^ (b < 0))) {
            res -= 1;
        }
        return res;
    }

    // Hilfsfunktion: Emuliert exakt Pythons Modulo (%)
    static int64_t python_mod(int64_t a, int64_t b) {
        int64_t rem = a % b;
        if (rem != 0 && ((a < 0) ^ (b < 0))) {
            rem += b;
        }
        return rem;
    }

    // Hilfsfunktion für SHA256 über mehrere Puffersegmente
    static std::vector<uint8_t> sha256_concat(std::initializer_list<std::span<const uint8_t>> parts) {
        crypto_hash_sha256_state state;
        crypto_hash_sha256_init(&state);
        for (auto part : parts) {
            if (!part.empty()) {
                crypto_hash_sha256_update(&state, part.data(), part.size());
            }
        }
        std::vector<uint8_t> out(crypto_hash_sha256_BYTES);
        crypto_hash_sha256_final(&state, out.data());
        return out;
    }

    std::vector<uint8_t> derive_hidden_seed(
        std::span<const uint8_t> password_bytes,
        std::span<const uint8_t> keyfile_hash,
        std::span<const uint8_t> bind_digest
    ) {
        std::vector<uint8_t> out_seed(crypto_auth_hmacsha256_BYTES);
        crypto_auth_hmacsha256_state state;

        // Fallback auf leeren Schlüssel falls keyfile_hash nicht übergeben wurde
        const uint8_t* key_data = keyfile_hash.empty() ? reinterpret_cast<const uint8_t*>("") : keyfile_hash.data();
        size_t key_len = keyfile_hash.empty() ? 0 : keyfile_hash.size();

        crypto_auth_hmacsha256_init(&state, key_data, key_len);
        crypto_auth_hmacsha256_update(&state, password_bytes.data(), password_bytes.size());

        if (!bind_digest.empty()) {
            crypto_auth_hmacsha256_update(&state, bind_digest.data(), bind_digest.size());
        }

        crypto_auth_hmacsha256_update(&state,
            reinterpret_cast<const uint8_t*>(HIDDEN_SEED_INFO.data()),
            HIDDEN_SEED_INFO.size());

        crypto_auth_hmacsha256_final(&state, out_seed.data());

        return out_seed;
    }

    uint64_t choose_hidden_offset(
        uint64_t total_size,
        uint64_t hidden_size,
        std::span<const uint8_t> seed,
        uint64_t min_offset,
        uint64_t alignment
    ) {
        if (total_size <= 0 || hidden_size <= 0) throw std::invalid_argument("Größen müssen positiv sein");
        if (alignment <= 0) throw std::invalid_argument("Alignment muss positiv sein");

        int64_t first_allowed = min_offset;
        int64_t last_allowed = total_size - hidden_size;
        
        if (last_allowed < first_allowed) {
            throw std::runtime_error("Hidden volume passt nicht in den gewünschten Container-Platz");
        }

        std::vector<uint8_t> offset_info(HIDDEN_OFFSET_INFO.begin(), HIDDEN_OFFSET_INFO.end());
        offset_info.push_back(static_cast<uint8_t>((alignment >> 8) & 0xFF));
        offset_info.push_back(static_cast<uint8_t>(alignment & 0xFF));

        auto hash1 = sha256_concat({seed, offset_info});
        
        // Konvertiere die ersten 8 Bytes des SHA256-Hash in uint64_t (Big Endian)
        uint64_t residue_u = 0;
        for (int i = 0; i < 8; ++i) residue_u = (residue_u << 8) | hash1[i];
        
        int64_t residue = residue_u % alignment;
        int64_t align_i = alignment;

        // Python Logik-Aquivalent: aligned_start = first_allowed + ((residue - first_allowed) % alignment)
        int64_t aligned_start = first_allowed + python_mod(residue - first_allowed, align_i);

        if (aligned_start > last_allowed) {
            int64_t steps = python_floordiv(aligned_start - last_allowed + align_i - 1, align_i);
            aligned_start -= steps * align_i;
        }

        if (aligned_start < first_allowed) {
            int64_t steps = python_floordiv(aligned_start - first_allowed + align_i - 1, align_i);
            aligned_start = first_allowed + steps * align_i;
        }

        int64_t slot_count = python_floordiv(last_allowed - aligned_start, align_i) + 1;
        if (slot_count <= 0) {
            return aligned_start;
        }

        std::string_view index_str = "INDEX";
        std::span<const uint8_t> index_bytes(reinterpret_cast<const uint8_t*>(index_str.data()), index_str.size());
        auto hash2 = sha256_concat({seed, offset_info, index_bytes});
        
        uint64_t index_u = 0;
        for (int i = 0; i < 8; ++i) index_u = (index_u << 8) | hash2[i];
        
        int64_t index = index_u % slot_count;

        return aligned_start + index * align_i;
    }

    HiddenVolumeLayout layout_hidden_volume(
        uint64_t total_size,
        uint64_t hidden_size,
        std::span<const uint8_t> seed,
        uint64_t min_normal_data,
        uint64_t header_size,
        uint64_t alignment
    ) {
        if (hidden_size <= 0 || total_size <= 0 || header_size <= 0) {
            throw std::invalid_argument("Größenparameter müssen positiv sein");
        }

        uint64_t min_offset = header_size;
        uint64_t last_header_offset = total_size - hidden_size;
        if (last_header_offset < min_offset + min_normal_data) {
            throw std::runtime_error("Container zu klein für verstecktes Volume");
        }

        uint64_t hide_hdr_off = choose_hidden_offset(
            total_size,
            hidden_size,
            seed,
            min_offset + min_normal_data,
            alignment
        );

        uint64_t normal_data_size = hide_hdr_off - min_offset;
        if (normal_data_size < min_normal_data) {
            throw std::runtime_error("Normaler Datenbereich wäre zu klein");
        }

        return HiddenVolumeLayout{
            normal_data_size,
            hide_hdr_off,
            hide_hdr_off + header_size,
            hidden_size
        };
    }

} // namespace dgkn::crypto