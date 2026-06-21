// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "SecureMemory.hpp"
#include <stdexcept>
#include <cstring>
#include <sodium.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace dgkn::core {

    SecureBuffer::SecureBuffer(size_t size) : size_(size), ptr_(nullptr) {
        if (size == 0) throw std::invalid_argument("SecureBuffer size must be > 0");

#ifdef _WIN32
        ptr_ = static_cast<uint8_t*>(VirtualAlloc(nullptr, size_, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!ptr_) throw std::bad_alloc();
        // VirtualLock kann am Working-Set-Limit scheitern; das ist nicht fatal
        // (die Seite bleibt nutzbar, nur evtl. swap-bar). Bewusst best-effort.
        (void)VirtualLock(ptr_, size_);
#else
        ptr_ = new uint8_t[size_]();
        (void)mlock(ptr_, size_);
#endif
    }

    void SecureBuffer::release() noexcept {
        if (!ptr_) return;
        // RtlSecureZeroMemory/sodium-äquivalent: garantiert nicht wegoptimiert.
        zero();
#ifdef _WIN32
        VirtualUnlock(ptr_, size_);
        VirtualFree(ptr_, 0, MEM_RELEASE);
#else
        munlock(ptr_, size_);
        delete[] ptr_;
#endif
        ptr_ = nullptr;
        size_ = 0;
    }

    SecureBuffer::~SecureBuffer() {
        release();
    }

    SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
        : size_(other.size_), ptr_(other.ptr_) {
        other.ptr_ = nullptr;
        other.size_ = 0;
    }

    SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            release();              // eigenen Speicher sicher freigeben (kein Dtor-Aufruf)
            size_ = other.size_;
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    SecureBuffer SecureBuffer::from_bytes(std::span<const uint8_t> data) {
        SecureBuffer buf(data.empty() ? 1 : data.size());
        buf.write(data);
        return buf;
    }

    SecureBuffer SecureBuffer::from_text(std::string_view text) {
        return from_bytes({reinterpret_cast<const uint8_t*>(text.data()), text.size()});
    }

    void SecureBuffer::write(std::span<const uint8_t> data) {
        if (!ptr_) throw std::logic_error("SecureBuffer: write nach release/move");
        if (data.size() > size_) throw std::out_of_range("SecureBuffer overflow");
        if (!data.empty()) std::memcpy(ptr_, data.data(), data.size());
    }

    void SecureBuffer::zero() {
        // sodium_memzero statt memset: garantiert NICHT vom Compiler wegoptimiert
        // (memset auf einen gleich freigegebenen Puffer wird sonst eliminiert).
        if (ptr_ && size_) sodium_memzero(ptr_, size_);
    }

    std::span<uint8_t> SecureBuffer::get_view() { return {ptr_, size_}; }
}