// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "AuditLog.hpp"
#include "../Config.hpp"

#include <sodium.h>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstdio>

#include <filesystem>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#endif

namespace fs = std::filesystem;

namespace dgkn::core {

    namespace {
        // F-D: Datei nur fuer aktuellen Nutzer + SYSTEM + Admins lesbar (wie 2fa.json).
        void restrict_acl([[maybe_unused]] const std::string& path) {
#if defined(_WIN32)
            const char* sddl = "D:(A;;FA;;;CU)(A;;FA;;;SY)(A;;FA;;;BA)";
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &sd, nullptr)) {
                BOOL present = FALSE, defaulted = FALSE; PACL dacl = nullptr;
                if (GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present)
                    SetNamedSecurityInfoA(const_cast<char*>(path.c_str()), SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
                LocalFree(sd);
            }
#endif
        }

        std::string to_hex(const unsigned char* p, size_t n) {
            static const char* h = "0123456789abcdef";
            std::string s; s.reserve(n * 2);
            for (size_t i = 0; i < n; ++i) { s.push_back(h[p[i] >> 4]); s.push_back(h[p[i] & 0xF]); }
            return s;
        }
        std::string iso_now() {
            std::time_t t = std::time(nullptr);
            std::tm tm{};
#ifdef _WIN32
            localtime_s(&tm, &t);
#else
            localtime_r(&t, &tm);
#endif
            char buf[32];
            std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
            return buf;
        }
        // Felder werden durch TAB getrennt; in der Message TABs/Newlines neutralisieren.
        std::string sanitize(const std::string& in) {
            std::string out; out.reserve(in.size());
            for (char c : in) out.push_back((c == '\t' || c == '\n' || c == '\r') ? ' ' : c);
            return out;
        }
    }

    // F-D: Lädt das zufällige Pro-Installations-Geheimnis (32 B) aus <logpath>.key
    // oder erzeugt es beim ersten Mal. Dieses Geheimnis ist NICHT aus dem Binary
    // ableitbar — ein Angreifer muss zusätzlich diese (ACL-geschützte) Datei lesen,
    // um das Log neu signieren zu können. Schlägt das Lesen/Erzeugen fehl, fällt der
    // Schlüssel auf die reine Konstanten+MachineGuid-Ableitung zurück (best effort).
    std::vector<uint8_t> AuditLog::install_secret() const {
        std::vector<uint8_t> secret;
        std::string key_path = path_ + ".key";
        std::error_code ec;
        if (fs::exists(key_path, ec)) {
            std::ifstream f(key_path, std::ios::binary);
            std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), {});
            if (buf.size() == 32) return buf;
        }
        // Neu erzeugen + ACL-geschützt schreiben.
        secret.resize(32);
        randombytes_buf(secret.data(), secret.size());
        std::string tmp = key_path + ".tmp";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (f) f.write(reinterpret_cast<const char*>(secret.data()), secret.size());
        }
        fs::rename(tmp, key_path, ec);
        if (ec) { fs::remove(tmp, ec); return secret; } // Schreiben fehlgeschlagen: nur im RAM
        restrict_acl(key_path);
        return secret;
    }

    std::vector<uint8_t> AuditLog::log_key() const {
        // Schlüssel = SHA256(Tag + JOURNAL_HMAC_KEY-Konstante + MachineGuid +
        // Pro-Installations-Zufallsgeheimnis). Das Zufallsgeheimnis (F-D) hebt den
        // Schutz von "tamper-evident gegen Reverse-Engineering" auf "Angreifer muss
        // zusätzlich die ACL-geschützte .key-Datei lesen".
        crypto_hash_sha256_state st;
        crypto_hash_sha256_init(&st);
        static const char* tag = "DGKN7-AUDIT-LOG-CHAIN";
        crypto_hash_sha256_update(&st, reinterpret_cast<const uint8_t*>(tag), std::char_traits<char>::length(tag));
        crypto_hash_sha256_update(&st,
            reinterpret_cast<const uint8_t*>(config::JOURNAL_HMAC_KEY.data()), config::JOURNAL_HMAC_KEY.size());
#ifdef _WIN32
        // Maschinenbindung über MachineGuid.
        HKEY k;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0,
                          KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
            char buf[128]; DWORD len = sizeof(buf), type = 0;
            if (RegQueryValueExA(k, "MachineGuid", nullptr, &type,
                    reinterpret_cast<LPBYTE>(buf), &len) == ERROR_SUCCESS && type == REG_SZ)
                crypto_hash_sha256_update(&st, reinterpret_cast<const uint8_t*>(buf), len);
            RegCloseKey(k);
        }
#endif
        auto secret = install_secret();
        crypto_hash_sha256_update(&st, secret.data(), secret.size());
        sodium_memzero(secret.data(), secret.size());

        std::vector<uint8_t> key(crypto_hash_sha256_BYTES);
        crypto_hash_sha256_final(&st, key.data());
        return key;
    }

    std::string AuditLog::compute_line_hmac(const std::string& prev_hmac, uint64_t seq,
                                            const std::string& iso, const std::string& message) const {
        auto key = log_key();
        std::ostringstream msg;
        msg << prev_hmac << "|" << seq << "|" << iso << "|" << message;
        std::string m = msg.str();
        unsigned char mac[crypto_auth_hmacsha256_BYTES];
        crypto_auth_hmacsha256(mac, reinterpret_cast<const uint8_t*>(m.data()), m.size(), key.data());
        return to_hex(mac, sizeof(mac));
    }

    AuditLog::AuditLog(const std::string& path) : path_(path) {
        // Letzten HMAC + seq aus einer evtl. vorhandenen Datei laden (Kette fortsetzen).
        std::ifstream f(path_);
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty()) continue;
            // Felder: seq, iso, message, hmac (3 TABs).
            size_t p1 = line.find('\t');
            size_t p4 = line.rfind('\t');
            if (p1 == std::string::npos || p4 == std::string::npos || p4 <= p1) continue;
            try { seq_ = std::stoull(line.substr(0, p1)); } catch (...) {}
            last_hmac_ = line.substr(p4 + 1);
        }
    }

    void AuditLog::append(const std::string& message) {
        uint64_t seq = ++seq_;
        std::string iso = iso_now();
        std::string msg = sanitize(message);
        std::string mac = compute_line_hmac(last_hmac_, seq, iso, msg);
        std::ofstream f(path_, std::ios::app);
        f << seq << '\t' << iso << '\t' << msg << '\t' << mac << '\n';
        last_hmac_ = mac;
    }

    bool AuditLog::verify(size_t* bad_line) const {
        std::ifstream f(path_);
        std::string line, prev_hmac;
        size_t lineno = 0;
        uint64_t expect_seq = 0;
        while (std::getline(f, line)) {
            ++lineno;
            if (line.empty()) continue;
            // Zerlege in seq \t iso \t message \t hmac (message kann keine TABs haben — sanitisiert).
            size_t p1 = line.find('\t');
            size_t p2 = line.find('\t', p1 + 1);
            size_t p3 = line.rfind('\t');
            if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos || p3 <= p2) {
                if (bad_line) *bad_line = lineno; return false;
            }
            uint64_t seq = 0;
            try { seq = std::stoull(line.substr(0, p1)); } catch (...) { if (bad_line) *bad_line = lineno; return false; }
            std::string iso = line.substr(p1 + 1, p2 - p1 - 1);
            std::string msg = line.substr(p2 + 1, p3 - p2 - 1);
            std::string mac = line.substr(p3 + 1);

            ++expect_seq;
            if (seq != expect_seq) { if (bad_line) *bad_line = lineno; return false; }
            std::string want = compute_line_hmac(prev_hmac, seq, iso, msg);
            if (want.size() != mac.size() ||
                sodium_memcmp(want.data(), mac.data(), want.size()) != 0) {
                if (bad_line) *bad_line = lineno; return false;
            }
            prev_hmac = mac;
        }
        return true;
    }

}