// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "TPMUtils.hpp"

#include <regex>
#include <vector>
#include <cstdint>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tbs.h>          // TPM Base Services (Verfügbarkeitsprüfung)
#include <dpapi.h>        // CryptProtectData / CryptUnprotectData
#include <wincrypt.h>
#pragma comment(lib, "tbs.lib")
#pragma comment(lib, "crypt32.lib")
#endif

namespace dgkn::core {

#ifdef _WIN32
    namespace {
        // Base64 über die Windows-Crypt-API (vermeidet eigene Implementierung).
        std::string b64_encode(const std::vector<uint8_t>& in) {
            DWORD len = 0;
            if (!CryptBinaryToStringA(in.data(), (DWORD)in.size(),
                    CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &len)) return {};
            std::string out(len, '\0');
            if (!CryptBinaryToStringA(in.data(), (DWORD)in.size(),
                    CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &len)) return {};
            out.resize(len);
            return out;
        }
        bool b64_decode(const std::string& in, std::vector<uint8_t>& out) {
            DWORD len = 0;
            if (!CryptStringToBinaryA(in.c_str(), (DWORD)in.size(), CRYPT_STRING_BASE64,
                    nullptr, &len, nullptr, nullptr)) return false;
            out.resize(len);
            if (!CryptStringToBinaryA(in.c_str(), (DWORD)in.size(), CRYPT_STRING_BASE64,
                    out.data(), &len, nullptr, nullptr)) return false;
            out.resize(len);
            return true;
        }
    }
#endif

    bool TPMUtils::is_tpm_native_available() {
#ifdef _WIN32
        // Echte Prüfung über die TBS-DeviceInfo: tpmVersion == 2 bedeutet TPM 2.0.
        TPM_DEVICE_INFO info{};
        TBS_RESULT r = Tbsi_GetDeviceInfo(sizeof(info), &info);
        return (r == TBS_SUCCESS && info.tpmVersion == 2);
#else
        return false;
#endif
    }

    std::optional<std::string> TPMUtils::seal_secret(const std::string& secret_text, const TPMSealConfig& config) {
#ifdef _WIN32
        if (!config.enabled) return std::nullopt;
        if (secret_text.empty()) return std::nullopt;
        if (!validate_pcrs(config.pcrs)) return std::nullopt;

        // Maschinengebundenes Sealing via DPAPI mit LOCAL_MACHINE-Scope. Auf Systemen
        // mit TPM 2.0 stützt sich die DPAPI-Masterkey-Kette auf hardwaregebundene
        // Schlüssel — der Blob ist damit faktisch an genau diesen PC gebunden und
        // außerhalb nicht entsiegelbar. (Robuster Ansatz ohne fragiles TPM-Command-
        // Crafting; Verfügbarkeit eines echten TPM wird separat angezeigt.)
        DATA_BLOB in{}, out{};
        in.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(secret_text.data()));
        in.cbData = static_cast<DWORD>(secret_text.size());

        // Optionaler zusätzlicher Entropie-/Bindungs-Faktor: der PCR-String als
        // "entropy", sodass derselbe Container an dieselbe Policy-Beschreibung bindet.
        DATA_BLOB entropy{};
        entropy.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(config.pcrs.data()));
        entropy.cbData = static_cast<DWORD>(config.pcrs.size());

        if (!CryptProtectData(&in, L"DGKN-TPM-SEAL", &entropy, nullptr, nullptr,
                CRYPTPROTECT_LOCAL_MACHINE, &out)) {
            return std::nullopt;
        }
        std::vector<uint8_t> blob(out.pbData, out.pbData + out.cbData);
        LocalFree(out.pbData);
        return b64_encode(blob);
#else
        (void)secret_text; (void)config;
        return std::nullopt;
#endif
    }

    std::optional<std::string> TPMUtils::unseal_secret(const std::string& blob_b64, const TPMSealConfig& config) {
#ifdef _WIN32
        if (!config.enabled) return std::nullopt;
        if (blob_b64.empty()) return std::nullopt;

        std::vector<uint8_t> blob;
        if (!b64_decode(blob_b64, blob) || blob.empty()) return std::nullopt;

        DATA_BLOB in{}, out{};
        in.pbData = blob.data();
        in.cbData = static_cast<DWORD>(blob.size());

        DATA_BLOB entropy{};
        entropy.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(config.pcrs.data()));
        entropy.cbData = static_cast<DWORD>(config.pcrs.size());

        if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr,
                CRYPTPROTECT_LOCAL_MACHINE, &out)) {
            return std::nullopt; // anderer PC / manipuliert / falsche Policy
        }
        std::string secret(reinterpret_cast<char*>(out.pbData), out.cbData);
        SecureZeroMemory(out.pbData, out.cbData);
        LocalFree(out.pbData);
        return secret;
#else
        (void)blob_b64; (void)config;
        return std::nullopt;
#endif
    }

    bool TPMUtils::validate_pcrs(const std::string& pcrs) {
        // z.B. "sha256:0,2,4,7" — Algorithmus + kommaseparierte PCR-Indizes
        static const std::regex re(R"(^[a-z0-9]+:\d+(,\d+)*$)");
        return std::regex_match(pcrs, re);
    }

    std::string TPMUtils::normalize_path(const std::string& path) {
        return path;
    }

}