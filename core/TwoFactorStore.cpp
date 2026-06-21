// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "TwoFactorStore.hpp"
#include "../Config.hpp"
#include "CryptoUtils.hpp"
#include "FsHelpers.hpp"

#include <sodium.h>
#include <argon2.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <cctype>
#include <string_view>

#if defined(_WIN32)
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#endif

namespace fs = std::filesystem;

namespace dgkn::core {

    namespace {
        using nlohmann::json;

        std::string env_var(const char* name) {
#if defined(_WIN32)
            char buf[1024];
            DWORD n = GetEnvironmentVariableA(name, buf, sizeof(buf));
            if (n > 0 && n < sizeof(buf)) return std::string(buf, n);
#endif
            return std::string();
        }

        std::string default_path() {
            std::string base = env_var("LOCALAPPDATA");
            if (base.empty()) base = env_var("APPDATA");
            if (base.empty()) base = env_var("USERPROFILE");
            fs::path dir = base.empty() ? fs::current_path() : fs::path(base);
            dir /= "DGKN"; dir /= "security";
            return (dir / "2fa.json").string();
        }

        std::string b64(const std::vector<uint8_t>& v) {
            if (v.empty()) return std::string();
            std::vector<char> out(sodium_base64_ENCODED_LEN(v.size(), sodium_base64_VARIANT_ORIGINAL));
            sodium_bin2base64(out.data(), out.size(), v.data(), v.size(), sodium_base64_VARIANT_ORIGINAL);
            return std::string(out.data());
        }
        std::vector<uint8_t> unb64(const std::string& s) {
            if (s.empty()) return {};
            std::vector<uint8_t> out(s.size()); size_t out_len = 0;
            if (sodium_base642bin(out.data(), out.size(), s.c_str(), s.size(),
                                  nullptr, &out_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) return {};
            out.resize(out_len); return out;
        }
        std::vector<uint8_t> aad_bytes() {
            auto sv = dgkn::config::TWOFA_AAD_PURPOSE;
            return std::vector<uint8_t>(sv.begin(), sv.end());
        }

        // Windows-ACL: Datei nur für Owner + SYSTEM. Defensiv: Fehler werden geschluckt
        // (die Datei ist ohnehin verschlüsselt).
        void restrict_acl([[maybe_unused]] const std::string& path) {
#if defined(_WIN32)
            // DACL: Vollzugriff nur fuer den AKTUELLEN Nutzer (CU) + SYSTEM (SY) + Admins (BA).
            // CU = aktueller Nutzer-SID (nicht "OW"/Owner-Rights, das ist ein anderer Prinzipal
            // und kann dem Token das Loeschen verwehren -> "Access is denied" beim Ersetzen).
            // NICHT protected: vererbte Rechte des Profilordners bleiben, damit Ersetzen klappt.
            const char* sddl = "D:(A;;FA;;;CU)(A;;FA;;;SY)(A;;FA;;;BA)";
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &sd, nullptr)) {
                BOOL present = FALSE, defaulted = FALSE; PACL dacl = nullptr;
                if (GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present) {
                    SetNamedSecurityInfoA(const_cast<char*>(path.c_str()), SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
                }
                LocalFree(sd);
            }
#endif
        }

        // Liest JSON und schliesst das Handle SOFORT (offener Lese-Handle wuerde sonst
        // unter Windows das spaetere atomare Ersetzen blockieren -> "Access is denied").
        bool read_json(const std::string& path, json& out, std::string& err) {
            std::ifstream f(path, std::ios::binary);
            if (!f) { err = "2FA-Datei nicht gefunden"; return false; }
            try { f >> out; } catch (const std::exception& e) {
                err = std::string("2FA-Datei beschaedigt: ") + e.what(); return false;
            }
            return true;
        }

        bool write_atomic(const std::string& path, const std::string& content, std::string& err) {
            try {
                fs::path target(path); fs::create_directories(target.parent_path());
                fs::path tmp = target; tmp += ".tmp";
                {
                    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
                    if (!f) { err = "Kann temporaere Datei nicht schreiben: " + tmp.string(); return false; }
                    f.write(content.data(), (std::streamsize)content.size());
                    if (!f) { err = "Schreibfehler: " + tmp.string(); return false; }
                }
                // Vorhandenes Ziel zuerst entfernen (der Owner darf das trotz PROTECTED-DACL),
                // dann verschieben. So scheitert das atomare Ersetzen nicht an der restriktiven
                // ACL der bereits vorhandenen verschlüsselten Datei.
                std::error_code ec;
                if (fs::exists(target, ec)) fs::remove(target, ec);
                fs::rename(tmp, target, ec);
                if (ec) {
                    std::error_code rmec; fs::remove(tmp, rmec);
                    err = "Verschieben fehlgeschlagen: " + ec.message();
                    return false;
                }
                restrict_acl(target.string());
                return true;
            } catch (const std::exception& e) {
                err = std::string("Schreiben fehlgeschlagen: ") + e.what();
                return false;
            }
        }

        // ── Recovery-Codes ──
        constexpr char RC_ALPHABET[] = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // ohne 0/1/8/O/I/L

        std::string make_recovery_code() {
            std::string s;
            for (int i = 0; i < 10; ++i) {
                if (i == 5) s += '-';
                s += RC_ALPHABET[randombytes_uniform(sizeof(RC_ALPHABET) - 1)];
            }
            return s;
        }
        std::string normalize_code(const std::string& in) {
            std::string out;
            for (char c : in) {
                char u = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                if (std::string_view(RC_ALPHABET).find(u) != std::string_view::npos) out += u;
            }
            return out;
        }
        // Liest DGKN_ARGON2_TEST_KIB über DIESELBE Win32-API wie derive_hardened.
        std::vector<uint8_t> hash_code(const std::string& norm, const std::vector<uint8_t>& salt) {
            uint32_t mem_kib = static_cast<uint32_t>(dgkn::config::ARGON2_MEMORY_KIB);
            uint32_t t_cost  = static_cast<uint32_t>(dgkn::config::ARGON2_TIME_COST);
#if defined(_WIN32)
            char buf[16]; DWORD n = GetEnvironmentVariableA("DGKN_ARGON2_TEST_KIB", buf, sizeof(buf));
            if (n > 0 && n < sizeof(buf)) {
                unsigned long v = std::strtoul(buf, nullptr, 10);
                uint32_t min_kib = 8u * static_cast<uint32_t>(dgkn::config::ARGON2_PARALLELISM);
                if (v >= min_kib) { mem_kib = static_cast<uint32_t>(v); t_cost = 1; }
            }
#endif
            std::vector<uint8_t> out(32);
            argon2id_hash_raw(t_cost, mem_kib, static_cast<uint32_t>(dgkn::config::ARGON2_PARALLELISM),
                              norm.data(), norm.size(), salt.data(), salt.size(), out.data(), out.size());
            return out;
        }
        json build_recovery_array(const std::vector<std::string>& codes) {
            json arr = json::array();
            for (const auto& c : codes) {
                std::string norm = normalize_code(c);
                std::vector<uint8_t> salt(16);
                randombytes_buf(salt.data(), salt.size());
                auto h = hash_code(norm, salt);
                arr.push_back({ {"salt_b64", b64(salt)}, {"hash_b64", b64(h)}, {"used", false} });
            }
            return arr;
        }

        // Liest Salt/Nonce/CT, leitet Key ab und entschlüsselt. out_secret nur bei != nullptr.
        // Rückgabe: true wenn PW korrekt (Poly1305-Verify ok). Konstante Argon2-Kosten.
        bool decrypt_secret(const std::string& path, const std::string& pw,
                            std::string* out_secret, std::string& err) {
            using namespace dgkn::crypto_utils;
            std::ifstream f(path, std::ios::binary);
            if (!f) { err = "2FA-Datei nicht gefunden"; return false; }
            json j;
            try { f >> j; } catch (const std::exception& e) {
                err = std::string("2FA-Datei beschaedigt: ") + e.what(); return false;
            }
            std::vector<uint8_t> salt, nonce, ct;
            try {
                salt  = unb64(j.at("salt_b64").get<std::string>());
                nonce = unb64(j.at("nonce_b64").get<std::string>());
                ct    = unb64(j.at("secret_enc_b64").get<std::string>());
            } catch (const std::exception& e) {
                err = std::string("2FA-Datei beschaedigt: ") + e.what(); return false;
            }
            if (salt.empty() || nonce.empty() || ct.empty()) { err = "2FA-Datei unvollstaendig"; return false; }

            auto aad = aad_bytes();
            std::vector<uint8_t> key = KDF::derive_hardened(pw, {}, salt, aad);
            sodium_mlock(key.data(), key.size());
            std::vector<uint8_t> pt; bool ok = true;
            try { pt = XChaCha20::decrypt(key, nonce, ct, aad); }
            catch (const std::exception&) { ok = false; }
            sodium_munlock(key.data(), key.size());
            if (!ok) { err = "Falsches Passwort oder Datei manipuliert"; return false; }
            if (out_secret) out_secret->assign(pt.begin(), pt.end());
            if (!pt.empty()) sodium_memzero(pt.data(), pt.size());
            return true;
        }
    }

    TwoFactorStore::TwoFactorStore(std::string explicit_path)
        : path_(explicit_path.empty() ? default_path() : std::move(explicit_path)) {}

    bool TwoFactorStore::exists() const { std::error_code ec; return fs::exists(path_, ec); }
    std::string TwoFactorStore::path() const { return path_; }

    TwoFactorStore::Status TwoFactorStore::status() const {
        std::error_code ec;
        if (!fs::exists(path_, ec)) return Status::Missing;
        std::ifstream f(path_, std::ios::binary);
        if (!f) return Status::Corrupt;
        json j;
        try { f >> j; } catch (const std::exception&) { return Status::Corrupt; }
        // Pflichtfelder für die Entschlüsselung (vgl. decrypt_secret). Fehlt eines —
        // z. B. bei einer Alt-Format-Datei ohne 'salt_b64' —, ist die Datei aus
        // unserer Sicht unbrauchbar.
        for (const char* key : {"salt_b64", "nonce_b64", "secret_enc_b64"}) {
            if (!j.contains(key) || !j[key].is_string() || j[key].get<std::string>().empty())
                return Status::Corrupt;
        }
        return Status::Usable;
    }

    bool TwoFactorStore::reset(std::string& err) {
        std::error_code ec;
        if (!fs::exists(path_, ec)) return true;
        // Verschlüsseltes Material vor dem Löschen überschreiben.
        dgkn::utils::secure_wipe_file(path_, 3);
        if (fs::exists(path_, ec)) {
            err = "Beschädigte 2FA-Datei konnte nicht entfernt werden: " + path_;
            return false;
        }
        return true;
    }

    bool TwoFactorStore::save(const std::string& secret, const std::string& master_pw,
                              std::vector<std::string>& out_codes, std::string& err) {
        using namespace dgkn::crypto_utils;
        if (secret.empty()) { err = "Leeres Secret"; return false; }
        if (master_pw.empty()) { err = "Leeres Master-Passwort"; return false; }

        std::vector<uint8_t> salt(dgkn::config::SALT_SIZE);
        randombytes_buf(salt.data(), salt.size());
        auto aad = aad_bytes();
        std::vector<uint8_t> key = KDF::derive_hardened(master_pw, {}, salt, aad);
        sodium_mlock(key.data(), key.size());
        std::vector<uint8_t> pt(secret.begin(), secret.end());
        CipherResult enc = XChaCha20::encrypt(key, pt, aad);
        sodium_memzero(pt.data(), pt.size());
        sodium_munlock(key.data(), key.size());

        json j;
        j["version"]        = dgkn::config::TWOFA_CFG_VER;
        j["issuer"]         = "DGKN Crypto Suite";
        j["enabled"]        = true;
        j["kdf"]            = "argon2id";
        j["salt_b64"]       = b64(salt);
        j["nonce_b64"]      = b64(enc.nonce);
        j["secret_enc_b64"] = b64(enc.ciphertext);

        out_codes.clear();
        for (int i = 0; i < 10; ++i) out_codes.push_back(make_recovery_code());
        j["recovery"] = build_recovery_array(out_codes);

        if (!write_atomic(path_, j.dump(2), err)) { out_codes.clear(); return false; }
        return true;
    }

    std::optional<std::string> TwoFactorStore::load(const std::string& master_pw, std::string& err) const {
        std::string secret;
        if (!decrypt_secret(path_, master_pw, &secret, err)) return std::nullopt;
        return secret;
    }

    bool TwoFactorStore::verify_password(const std::string& master_pw) const {
        std::string err;
        return decrypt_secret(path_, master_pw, nullptr, err);
    }

    std::optional<std::vector<std::string>> TwoFactorStore::regenerate_recovery_codes(
        const std::string& master_pw, std::string& err) {
        if (!verify_password(master_pw)) { err = "Falsches Master-Passwort"; return std::nullopt; }
        json j;
        if (!read_json(path_, j, err)) return std::nullopt;
        std::vector<std::string> codes;
        for (int i = 0; i < 10; ++i) codes.push_back(make_recovery_code());
        j["recovery"] = build_recovery_array(codes);
        if (!write_atomic(path_, j.dump(2), err)) return std::nullopt;
        return codes;
    }

    bool TwoFactorStore::consume_recovery_code(const std::string& code, std::string& err) {
        std::string norm = normalize_code(code);
        if (norm.size() != 10) { err = "Ungueltiges Code-Format"; return false; }
        json j;
        if (!read_json(path_, j, err)) return false;
        if (!j.contains("recovery") || !j["recovery"].is_array()) { err = "Keine Recovery-Codes"; return false; }

        int match = -1;
        auto& arr = j["recovery"];
        for (int i = 0; i < static_cast<int>(arr.size()); ++i) {
            if (arr[i].value("used", false)) continue;
            auto salt = unb64(arr[i].value("salt_b64", std::string{}));
            auto want = unb64(arr[i].value("hash_b64", std::string{}));
            if (salt.empty() || want.size() != 32) continue;
            auto got = hash_code(norm, salt);
            if (sodium_memcmp(got.data(), want.data(), 32) == 0) match = i;  // kein break: konstante Zeit
        }
        if (match < 0) { err = "Unbekannter oder bereits verbrauchter Code"; return false; }
        arr[match]["used"] = true;
        return write_atomic(path_, j.dump(2), err);
    }

    int TwoFactorStore::remaining_recovery_codes() const {
        std::ifstream f(path_, std::ios::binary);
        if (!f) return 0;
        try {
            json j; f >> j;
            int n = 0;
            for (const auto& e : j.value("recovery", json::array()))
                if (!e.value("used", false)) ++n;
            return n;
        } catch (...) { return 0; }
    }

}