// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string_view>

namespace dgkn::core {

    class SecureBuffer {
    public:
        explicit SecureBuffer(size_t size);
        ~SecureBuffer();

        // Verhindert versehentliches Kopieren
        SecureBuffer(const SecureBuffer&) = delete;
        SecureBuffer& operator=(const SecureBuffer&) = delete;

        // Move erlaubt (überträgt Besitz des gesperrten Speichers)
        SecureBuffer(SecureBuffer&& other) noexcept;
        SecureBuffer& operator=(SecureBuffer&& other) noexcept;

        static SecureBuffer from_bytes(std::span<const uint8_t> data);
        static SecureBuffer from_text(std::string_view text);

        void write(std::span<const uint8_t> data);
        void zero();
        std::span<uint8_t> get_view();
        size_t size() const { return size_; }

    private:
        // Gibt den gesperrten Speicher frei (zero + unlock + free) und setzt ptr_=nullptr.
        // Wird von Destruktor und Move-Zuweisung geteilt — vermeidet einen fragilen
        // expliziten Destruktoraufruf.
        void release() noexcept;

        size_t size_;
        uint8_t* ptr_;
    };
}