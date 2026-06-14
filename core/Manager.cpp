// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "Manager.hpp"
#include "CryptoUtils.hpp"
#include "TPMUtils.hpp"
#include "Crypto.hpp"
#include "Archive.hpp"
#include "VirtualVolume.hpp"
#include "../Config.hpp"
#include <sodium.h>
#include <argon2.h>
#include <array>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <algorithm>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <chrono>

#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#include <cstdlib>
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace dgkn::core {

    // Portable Big-Endian-Konvertierung. Linux-Funktionen wie htobe32/be32toh
    // existieren auf MSVC nicht; x86/x64 ist little-endian, daher Byteswap.
    namespace {
        inline uint32_t to_be32(uint32_t v) {
#ifdef _WIN32
            return _byteswap_ulong(v);
#else
            return __builtin_bswap32(v);
#endif
        }
        inline uint32_t from_be32(uint32_t v) { return to_be32(v); }
        inline uint64_t to_be64(uint64_t v) {
#ifdef _WIN32
            return _byteswap_uint64(v);
#else
            return __builtin_bswap64(v);
#endif
        }
        inline uint64_t from_be64(uint64_t v) { return to_be64(v); }

        // Overflow-sichere Prüfung: liegt [offset, offset+size) vollständig in [0, fsize)?
        // Verhindert, dass ein Integer-Overflow (offset+size) den Bounds-Check umgeht.
        inline bool region_within(uint64_t offset, uint64_t size, uint64_t fsize) {
            if (offset > fsize) return false;
            if (size > fsize - offset) return false; // kein Overflow: fsize-offset >= 0
            return true;
        }
    }

    // Sicheres Löschen der Schlüssel im RAM, sobald der Container ausgehängt wird.
    MountInfo::~MountInfo() {
        // sodium_munlock nullt den Speicher UND hebt den Swap-Schutz auf.
        if (!master_key.empty()) sodium_munlock(master_key.data(), master_key.size());
        if (!sector_key.empty()) sodium_munlock(sector_key.data(), sector_key.size());
        if (!archive_data.empty()) sodium_memzero(archive_data.data(), archive_data.size());
    }

    ContainerManager::ContainerManager() {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium konnte nicht initialisiert werden!");
        }
    }

    void ContainerManager::runtime_integrity_check() {
        // H-5 (ehrliche Einordnung): Diese Anti-Debug-Prüfung ist bewusst nur
        // Defense-in-Depth / Obscurity — KEINE echte Schutzschicht. IsDebuggerPresent /
        // CheckRemoteDebuggerPresent sind von einem ernsthaften Angreifer trivial zu
        // umgehen (PEB-Patch, Hardware-Breakpoints, Hypervisor-Debugging). Der reale
        // Schutz der Daten ist ausschließlich die Kryptografie (Argon2id + XChaCha20-
        // Poly1305), nicht dieser Check. Er erhöht nur die Hürde für Gelegenheits-Tampering
        // und darf nicht als Sicherheitsgarantie verstanden werden.
        if (!tamper_detection_enabled_) return;

#ifdef _WIN32
        if (IsDebuggerPresent()) {
            trigger_self_defense("Debugger erkannt (IsDebuggerPresent)");
        }
        BOOL isRemoteDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebugger);
        if (isRemoteDebugger) {
            trigger_self_defense("Remote-Debugger erkannt");
        }
#endif
    }

    void ContainerManager::trigger_self_defense(const std::string& reason) {
        std::cerr << "[PANIC] Self-Defense aktiviert: " << reason << "\n";
        emergency_wipe(false);
        
        std::lock_guard<std::mutex> lock(auth_lock_);
        auth_failures_.clear();
        auth_lockouts_.clear();
        
        std::exit(EXIT_FAILURE);
    }

    // ─── Anti-Brute-Force & Lockouts ───

    std::string ContainerManager::pre_auth_guard(const std::string& identity) {
        auto now = std::chrono::system_clock::now();
        std::lock_guard<std::mutex> lock(auth_lock_);

        // Persistierten Lockout (von einer früheren App-Sitzung) berücksichtigen.
        if (!auth_lockouts_.contains(identity)) {
            auto persisted = load_persisted_lockout(identity);
            if (persisted > now) auth_lockouts_[identity] = persisted;
        }

        if (auth_lockouts_.contains(identity)) {
            auto lock_until = auth_lockouts_[identity];
            if (lock_until > now) {
                auto remain = std::chrono::duration_cast<std::chrono::seconds>(lock_until - now).count();
                return "Zu viele Fehlversuche. Erneut versuchen in " + std::to_string(remain) + "s";
            }
            auth_lockouts_.erase(identity);
        }

        auto& hist = auth_failures_[identity];
        // Alte Einträge entfernen
        hist.erase(std::remove_if(hist.begin(), hist.end(), [&now](const auto& t) {
            return std::chrono::duration_cast<std::chrono::seconds>(now - t).count() > config::AUTH_WINDOW_SECS;
        }), hist.end());

        if (hist.size() >= config::AUTH_MAX_TRIES) {
            // In C++ verzögern wir den Thread, genau wie in Python
            double delay = std::min(config::AUTH_MAX_DELAY, config::AUTH_BASE_DELAY * (1 << (hist.size() - config::AUTH_MAX_TRIES + 1)));
            std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(delay * 1000)));
        }
        return "";
    }

    void ContainerManager::auth_failed(const std::string& identity) {
        auto now = std::chrono::system_clock::now();
        std::lock_guard<std::mutex> lock(auth_lock_);
        
        auto& hist = auth_failures_[identity];
        hist.push_back(now);
        
        if (hist.size() >= config::AUTH_LOCKOUT_TRIES) {
            auto until = now + std::chrono::seconds(config::AUTH_LOCKOUT_SECS);
            auth_lockouts_[identity] = until;
            persist_lockout(identity, until); // überlebt App-Neustart
        }
    }

    void ContainerManager::auth_success(const std::string& identity) {
        std::lock_guard<std::mutex> lock(auth_lock_);
        auth_failures_.erase(identity);
        auth_lockouts_.erase(identity);
        clear_persisted_lockout(identity);
    }

    // ─── Persistenter Lockout (überlebt Neustarts) ───

    std::string ContainerManager::lockout_file_for(const std::string& identity) {
        // Dateiname = sha256(identity) hex, im Lockout-Verzeichnis (Temp/DGKN7_LOCKS).
        uint8_t h[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(h, reinterpret_cast<const uint8_t*>(identity.data()), identity.size());
        static const char* hx = "0123456789abcdef";
        std::string name; for (auto b : h) { name.push_back(hx[b>>4]); name.push_back(hx[b&0xF]); }
        auto dir = fs::temp_directory_path() / "DGKN7_LOCKS";
        std::error_code ec; fs::create_directories(dir, ec);
        return (dir / (name + ".lock")).string();
    }

    std::chrono::system_clock::time_point ContainerManager::load_persisted_lockout(const std::string& identity) {
        std::string path = lockout_file_for(identity);
        std::error_code ec;
        if (!fs::exists(path, ec)) return std::chrono::system_clock::time_point{};
        try {
            std::ifstream f(path, std::ios::binary);
            std::string line; std::getline(f, line);
            // Format: "<until_unix>|<hmac_hex>"
            auto bar = line.find('|');
            if (bar == std::string::npos) return {};
            std::string until_s = line.substr(0, bar);
            std::string mac = line.substr(bar + 1);
            // HMAC über identity + "|" + until_s mit journal_key(identity) prüfen.
            std::string msg = identity + "|" + until_s;
            std::string expect = journal_hmac(identity,
                {reinterpret_cast<const uint8_t*>(msg.data()), msg.size()});
            if (mac.size() != expect.size() ||
                sodium_memcmp(mac.data(), expect.data(), mac.size()) != 0) {
                // Manipuliert -> ignorieren (kein Lockout erzwingbar durch Fälschung,
                // aber auch nicht umgehbar in die andere Richtung relevant).
                return {};
            }
            long long until = std::stoll(until_s);
            return std::chrono::system_clock::time_point{std::chrono::seconds{until}};
        } catch (...) { return {}; }
    }

    void ContainerManager::persist_lockout(const std::string& identity, std::chrono::system_clock::time_point until) {
        long long until_unix = std::chrono::duration_cast<std::chrono::seconds>(until.time_since_epoch()).count();
        std::string until_s = std::to_string(until_unix);
        std::string msg = identity + "|" + until_s;
        std::string mac = journal_hmac(identity, {reinterpret_cast<const uint8_t*>(msg.data()), msg.size()});
        std::ofstream f(lockout_file_for(identity), std::ios::binary | std::ios::trunc);
        f << until_s << "|" << mac;
    }

    void ContainerManager::clear_persisted_lockout(const std::string& identity) {
        std::error_code ec; fs::remove(lockout_file_for(identity), ec);
    }

    // ─── Duress / Notfall-Passwort ───

    bool ContainerManager::is_emergency_password(const std::string& password, const std::string& emergency_password) {
        if (emergency_password.empty()) return false;
        // Beide Passwörter mit Argon2id (fester app-spezifischer Salt) hashen und
        // konstant-zeit vergleichen (entspricht core/manager.py::_is_emergency_password).
        auto hash = [](const std::string& pw, std::array<uint8_t,32>& out) -> bool {
            return argon2id_hash_raw(
                4, 65536, 1,
                pw.data(), pw.size(),
                config::EMERGENCY_SALT.data(), config::EMERGENCY_SALT.size(),
                out.data(), out.size()) == ARGON2_OK;
        };
        std::array<uint8_t,32> a{}, b{};
        bool ok = hash(password, a) && hash(emergency_password, b);
        bool match = ok && sodium_memcmp(a.data(), b.data(), a.size()) == 0;
        sodium_memzero(a.data(), a.size());
        sodium_memzero(b.data(), b.size());
        return match;
    }

    void ContainerManager::sanitize_headers(const std::string& container_path) {
        std::error_code ec;
        uint64_t fsize = fs::file_size(container_path, ec);
        if (ec) return;
        std::vector<uint64_t> offsets = {0};
        for (auto off : scan_hidden(fsize, {})) offsets.push_back(off);

        std::fstream f(container_path, std::ios::binary | std::ios::in | std::ios::out);
        if (!f) return;
        std::vector<uint8_t> rnd(config::HDR_TOTAL);
        std::vector<uint64_t> seen;
        for (auto off : offsets) {
            bool dup = false; for (auto s : seen) if (s == off) { dup = true; break; }
            if (dup) continue; seen.push_back(off);
            if (off + config::HDR_TOTAL > fsize) continue;
            randombytes_buf(rnd.data(), rnd.size());
            f.seekp(static_cast<std::streamoff>(off));
            f.write(reinterpret_cast<const char*>(rnd.data()), rnd.size());
        }
        f.flush();
    }

    // ─── Kryptografische Schlüsselableitung ───

    std::string ContainerManager::device_binding_id() {
#ifdef _WIN32
        // MachineGuid aus der Registry (entspricht core/manager.py::_device_binding_id)
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography",
                          0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            char buf[256];
            DWORD len = sizeof(buf);
            DWORD type = 0;
            LONG r = RegQueryValueExA(hKey, "MachineGuid", nullptr, &type,
                                      reinterpret_cast<LPBYTE>(buf), &len);
            RegCloseKey(hKey);
            if (r == ERROR_SUCCESS && type == REG_SZ && len > 1) {
                std::string guid(buf, (buf[len - 1] == '\0') ? len - 1 : len);
                // trim
                while (!guid.empty() && (guid.back() == '\0' || guid.back() == ' ')) guid.pop_back();
                if (!guid.empty()) return guid;
            }
        }
        // Fallback: COMPUTERNAME über die Win32-API (sicher, kein deprecated getenv).
        char namebuf[256];
        DWORD n = GetEnvironmentVariableA("COMPUTERNAME", namebuf, sizeof(namebuf));
        if (n > 0 && n < sizeof(namebuf)) return std::string("host:") + namebuf;
        return "host:unknown-host";
#else
        if (const char* host = std::getenv("HOSTNAME")) {
            if (host[0]) return std::string("host:") + host;
        }
        return "host:unknown-host";
#endif
    }

    std::vector<uint8_t> ContainerManager::binding_digest(const std::string& twofa_secret, const std::string& tpm_sealed_secret, bool bind_to_device) {
        crypto_hash_sha256_state state;
        crypto_hash_sha256_init(&state);
        bool has_data = false;

        auto update_part = [&](const std::string& part) {
            if (part.empty()) return;
            uint32_t len = to_be32(static_cast<uint32_t>(part.size())); // Big Endian Length
            crypto_hash_sha256_update(&state, reinterpret_cast<const uint8_t*>(&len), sizeof(len));
            crypto_hash_sha256_update(&state, reinterpret_cast<const uint8_t*>(part.data()), part.size());
            has_data = true;
        };

        update_part(twofa_secret);

        // TPM-Bindung: tpm_sealed_secret entsiegeln und einfließen lassen.
        if (!tpm_sealed_secret.empty()) {
            auto tpm_secret = TPMUtils::unseal_secret(tpm_sealed_secret, TPMSealConfig{true});
            if (tpm_secret && !tpm_secret->empty()) {
                update_part(*tpm_secret);
            } else if (tpm_require_unseal_) {
                throw std::runtime_error("TPM-Bindung aktiv, aber Secret konnte nicht entsiegelt werden");
            }
        }

        if (bind_to_device) {
            update_part(device_binding_id());
        }

        if (!has_data) return {};
        
        std::vector<uint8_t> out(crypto_hash_sha256_BYTES);
        crypto_hash_sha256_final(&state, out.data());
        return out;
    }

    std::vector<uint8_t> ContainerManager::derive_volume_key(
        const std::string& password, std::span<const uint8_t> keyfile_hash, std::span<const uint8_t> salt,
        const std::string& mode, const std::string& twofa_secret,
        const std::string& tpm_sealed_secret, bool bind_to_device
    ) {
        auto bd = binding_digest(twofa_secret, tpm_sealed_secret, bind_to_device);

        // kf_eff = sha256(keyfile_hash + bind_digest) — IMMER, auch bei leerem
        // bind_digest (entspricht core/manager.py::_derive_volume_key). Andernfalls
        // entstehen inkompatible Container.
        std::vector<uint8_t> kf_eff(crypto_hash_sha256_BYTES);
        {
            crypto_hash_sha256_state state;
            crypto_hash_sha256_init(&state);
            if (!keyfile_hash.empty()) crypto_hash_sha256_update(&state, keyfile_hash.data(), keyfile_hash.size());
            if (!bd.empty()) crypto_hash_sha256_update(&state, bd.data(), bd.size());
            crypto_hash_sha256_final(&state, kf_eff.data());
        }

        std::string info_str = (mode == "normal") ? "DGKN7-NORM" : "DGKN7-HIDE";
        std::span<const uint8_t> info(reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size());

        return crypto_utils::KDF::derive_hardened(password, kf_eff, salt, info);
    }

    // ─── Header Lesen & Validieren ───

    bool ContainerManager::read_header_raw(std::istream& f, uint64_t offset, RawHeader& out_header) {
        f.clear();
        f.seekg(static_cast<std::streamoff>(offset));
        std::vector<uint8_t> buffer(config::HDR_TOTAL);
        f.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        if (static_cast<size_t>(f.gcount()) < config::HDR_TOTAL) return false;

        out_header.salt.assign(buffer.begin(), buffer.begin() + 32);
        out_header.nonce.assign(buffer.begin() + 32, buffer.begin() + 32 + 24);
        out_header.encrypted_block.assign(buffer.begin() + 56, buffer.end());
        return true;
    }

    std::pair<bool, HeaderData> ContainerManager::decrypt_and_verify_header(const RawHeader& raw, std::span<const uint8_t> master_key) {
        try {
            auto pt = crypto_utils::XChaCha20::decrypt(master_key, raw.nonce, raw.encrypted_block);
            
            // Der Header-Plaintext muss vollständig sein: 32 (Sentinel) + 4 (vol_type)
            // + 4 (Version) + 8 (data_offset) + 8 (data_size) = 56 Bytes. Diese Prüfung
            // VOR dem Lesen verhindert Out-of-Bounds-Zugriffe bei verkürzten Blöcken.
            constexpr size_t HDR_PLAINTEXT_MIN = 56;
            if (pt.size() < HDR_PLAINTEXT_MIN) return {false, {}};

            // Sentinel in konstanter Zeit prüfen (sodium_memcmp) — kein Timing-Leak.
            if (sodium_memcmp(pt.data(), config::SENTINEL_PLAIN.data(), config::SENTINEL_PLAIN.size()) != 0) {
                return {false, {}};
            }

            HeaderData data;
            data.salt = raw.salt;

            size_t p = 32; // Nach dem 32-Byte Sentinel
            
            data.vol_type = std::string(reinterpret_cast<char*>(pt.data() + p), 4);
            p += 4;
            
            // Read Big Endian Integers
            auto read_u32 = [&]() { uint32_t v; memcpy(&v, pt.data() + p, 4); p += 4; return from_be32(v); };
            auto read_u64 = [&]() { uint64_t v; memcpy(&v, pt.data() + p, 8); p += 8; return from_be64(v); };

            data.fmt_ver = read_u32();
            data.data_offset = read_u64();
            data.data_size = read_u64();

            uint32_t fmt = data.fmt_ver;
            // H-4: Header-Plaintext (Sentinel/Offsets/Größen) nach dem Auslesen
            // zeroisieren. Keine Keys, aber Metadaten gehören nicht länger als nötig
            // in den RAM — konsistent mit der übrigen Hygiene.
            sodium_memzero(pt.data(), pt.size());

            if (fmt < 7) return {false, {}}; // Alte Formate in V7 abgelehnt

            return {true, data};

        } catch (const std::exception&) {
            return {false, {}};
        }
    }

    // ─── Header schreiben ───

    void ContainerManager::write_header(std::ostream& f, uint64_t offset, const std::string& vol_type,
                                        std::span<const uint8_t> master_key,
                                        uint64_t data_offset, uint64_t data_size,
                                        std::span<const uint8_t> salt) {
        std::vector<uint8_t> nonce(config::NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        // sentinel(32) = SENTINEL_PLAIN + random padding
        std::vector<uint8_t> plaintext;
        plaintext.insert(plaintext.end(), config::SENTINEL_PLAIN.begin(), config::SENTINEL_PLAIN.end());
        size_t pad = 32 - config::SENTINEL_PLAIN.size();
        size_t pad_start = plaintext.size();
        plaintext.resize(plaintext.size() + pad);
        randombytes_buf(plaintext.data() + pad_start, pad);

        // vol_type[:4].ljust(4, '\0')
        std::string vt = vol_type.substr(0, 4);
        vt.resize(4, '\0');
        plaintext.insert(plaintext.end(), vt.begin(), vt.end());

        // struct.pack('>I', FORMAT_VER) + '>Q' data_offset + '>Q' data_size
        auto push_be32 = [&](uint32_t v) { uint32_t b = to_be32(v); auto* p = reinterpret_cast<uint8_t*>(&b); plaintext.insert(plaintext.end(), p, p + 4); };
        auto push_be64 = [&](uint64_t v) { uint64_t b = to_be64(v); auto* p = reinterpret_cast<uint8_t*>(&b); plaintext.insert(plaintext.end(), p, p + 8); };
        push_be32(static_cast<uint32_t>(config::FORMAT_VER));
        push_be64(data_offset);
        push_be64(data_size);

        // Mit dem festen (zufälligen) nonce verschlüsseln — derselbe nonce wird im
        // Klartext-Header gespeichert, damit decrypt_and_verify_header ihn nutzt.
        std::vector<uint8_t> encrypted_block(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long ct_len = 0;
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            encrypted_block.data(), &ct_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0, nullptr, nonce.data(), master_key.data());
        encrypted_block.resize(ct_len);

        f.seekp(static_cast<std::streamoff>(offset));
        f.write(reinterpret_cast<const char*>(salt.data()), salt.size());
        f.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
        f.write(reinterpret_cast<const char*>(encrypted_block.data()), encrypted_block.size());

        sodium_memzero(plaintext.data(), plaintext.size());
    }

    // ─── Hidden-Volume Scan ───

    std::vector<uint8_t> ContainerManager::hidden_scan_seed(
        const std::string& password, std::span<const uint8_t> keyfile_hash,
        const std::string& twofa_secret, const std::string& tpm_sealed_secret, bool bind_to_device
    ) {
        crypto_hash_sha256_state st;
        crypto_hash_sha256_init(&st);
        crypto_hash_sha256_update(&st, reinterpret_cast<const uint8_t*>(password.data()), password.size());
        if (!keyfile_hash.empty()) crypto_hash_sha256_update(&st, keyfile_hash.data(), keyfile_hash.size());
        auto bd = binding_digest(twofa_secret, tpm_sealed_secret, bind_to_device);
        if (!bd.empty()) crypto_hash_sha256_update(&st, bd.data(), bd.size());
        std::vector<uint8_t> out(crypto_hash_sha256_BYTES);
        crypto_hash_sha256_final(&st, out.data());
        return out;
    }

    std::vector<uint64_t> ContainerManager::scan_hidden(uint64_t fsize, std::span<const uint8_t> seed) {
        std::vector<uint64_t> offsets;
        offsets.reserve(64);
        auto add = [&](uint64_t o) {
            if (o > config::HDR_TOTAL) {
                for (auto e : offsets) if (e == o) return;
                offsets.push_back(o);
            }
        };

        std::vector<uint8_t> seed_h;
        if (!seed.empty()) {
            seed_h.resize(crypto_hash_sha256_BYTES);
            crypto_hash_sha256(seed_h.data(), seed.data(), seed.size());
        }

        const uint64_t steps[] = {1048576, 65536, 4096};
        for (uint32_t step_index = 0; step_index < 3; ++step_index) {
            uint64_t step = steps[step_index];
            uint64_t shift = 0;
            if (!seed_h.empty()) {
                // info = struct.pack('>I', step_index) + step.to_bytes(8,'big')
                uint8_t info[12];
                uint32_t si = to_be32(step_index);
                std::memcpy(info, &si, 4);
                uint64_t sb = to_be64(step);
                std::memcpy(info + 4, &sb, 8);
                uint8_t mac[crypto_auth_hmacsha256_BYTES];
                crypto_auth_hmacsha256(mac, info, sizeof(info), seed_h.data()); // key = seed_h (32B)
                uint64_t v = 0;
                for (int i = 0; i < 8; ++i) v = (v << 8) | mac[i];
                shift = v % step;
            }
            uint64_t off = std::max<uint64_t>(config::HDR_TOTAL + 1,
                (fsize > step + shift) ? fsize - step - shift : config::HDR_TOTAL + 1);
            while (off > config::HDR_TOTAL) {
                add(off);
                if (off < step) break;
                off -= step;
                if (offsets.size() > 512) break;
            }
        }
        return offsets;
    }

    // ─── Journal (.txn) ───

    std::string ContainerManager::txn_path(const std::string& container_path) {
        return container_path + ".txn";
    }

    std::vector<uint8_t> ContainerManager::journal_key(const std::string& container_path) {
        crypto_hash_sha256_state st;
        crypto_hash_sha256_init(&st);
        crypto_hash_sha256_update(&st,
            reinterpret_cast<const uint8_t*>(config::JOURNAL_HMAC_KEY.data()), config::JOURNAL_HMAC_KEY.size());
        crypto_hash_sha256_update(&st,
            reinterpret_cast<const uint8_t*>(container_path.data()), container_path.size());
        std::vector<uint8_t> out(crypto_hash_sha256_BYTES);
        crypto_hash_sha256_final(&st, out.data());
        return out;
    }

    std::string ContainerManager::journal_hmac(const std::string& container_path, std::span<const uint8_t> payload) {
        auto key = journal_key(container_path);
        uint8_t mac[crypto_auth_hmacsha256_BYTES];
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, key.data(), key.size());
        crypto_auth_hmacsha256_update(&st, payload.data(), payload.size());
        crypto_auth_hmacsha256_final(&st, mac);
        static const char* hexd = "0123456789abcdef";
        std::string hex;
        hex.reserve(sizeof(mac) * 2);
        for (auto b : mac) { hex.push_back(hexd[b >> 4]); hex.push_back(hexd[b & 0xF]); }
        return hex;
    }

    void ContainerManager::write_unmount_txn(const std::string& container_path, const std::string& json_text) {
        std::string path = txn_path(container_path);
        std::string tmp = path + ".tmp";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            f.write(json_text.data(), json_text.size());
            f.flush();
        }
        std::error_code ec;
        fs::rename(tmp, path, ec);
        if (ec) { fs::remove(path, ec); fs::rename(tmp, path, ec); }
    }

    void ContainerManager::clear_unmount_txn(const std::string& container_path) {
        std::error_code ec;
        fs::remove(txn_path(container_path), ec);
    }

    OpResult ContainerManager::recover_unmount_txn(const std::string& container_path) {
        std::string path = txn_path(container_path);
        std::error_code ec;
        if (!fs::exists(path, ec)) return {true, ""};
        try {
            std::ifstream f(path, std::ios::binary);
            json tx; f >> tx;
            if (tx.value("version", 0) != static_cast<int>(config::UNMOUNT_TXN_VER))
                return {false, "Unbekannte Journal-Version (Unmount-Transaktion)"};
            std::string state = tx.value("state", "prepare");
            std::string op = tx.value("op", "unmount");
            if (state != "prepare" && state != "commit")
                return {false, "Ungueltiger Journal-Status (" + state + ")"};
            if (state != "commit")
                return {false, "Abgebrochene " + op + "-Transaktion erkannt (nicht committed)"};
            uint64_t data_off = tx.value("data_offset", (uint64_t)0);
            uint64_t data_size = tx.value("data_size", (uint64_t)0);
            uint64_t payload_len = tx.value("payload_len", (uint64_t)0);
            std::string payload_hmac = tx.value("payload_hmac", std::string());
            uint64_t csize = fs::file_size(container_path, ec);
            if (!region_within(data_off, data_size, csize)) return {false, "Unmount-Journal ungueltig (Datenbereich ausserhalb)"};
            if (payload_len == 0 || payload_len > data_size) return {false, "Unmount-Journal ungueltig (Payload-Laenge)"};
            std::vector<uint8_t> payload(payload_len);
            { std::ifstream cf(container_path, std::ios::binary);
              cf.seekg(static_cast<std::streamoff>(data_off));
              cf.read(reinterpret_cast<char*>(payload.data()), payload_len);
              if (static_cast<uint64_t>(cf.gcount()) != payload_len)
                  return {false, "Unvollstaendiger Container-Schreibvorgang erkannt"}; }
            if (!payload_hmac.empty()) {
                std::string actual = journal_hmac(container_path, payload);
                // Konstanter-Zeit-Vergleich (gleiche Länge -> sodium_memcmp).
                bool ok = (actual.size() == payload_hmac.size()) &&
                          sodium_memcmp(actual.data(), payload_hmac.data(), actual.size()) == 0;
                if (!ok) return {false, "Abgebrochener Schreibvorgang (Payload-HMAC ungueltig)"};
            } else {
                return {false, "Unmount-Journal ungueltig (keine Pruefwerte)"};
            }
            clear_unmount_txn(container_path);
            return {true, "Recovery erfolgreich (committed-Zustand bestaetigt)"};
        } catch (const std::exception& e) {
            return {false, std::string("Journal-Lesefehler: ") + e.what()};
        }
    }

    // ─── Mount-Verzeichnisse ───

    std::string ContainerManager::mount_root_dir() {
        auto base = fs::temp_directory_path() / "DGKN7_MOUNTS";
        std::error_code ec; fs::create_directories(base, ec);
        return base.string();
    }

    std::string ContainerManager::create_mount_dir(const std::string& mode) {
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        auto dir = fs::path(mount_root_dir()) /
            (std::string(config::MOUNT_DIR_PREFIX) + mode + "_" + std::to_string(now));
        std::error_code ec; fs::create_directories(dir, ec);
        return dir.string();
    }

    std::string ContainerManager::find_free_drive_letter() {
#ifdef _WIN32
        DWORD used = GetLogicalDrives(); // Bit 0 = A:, Bit 25 = Z:
        // Von Z: abwärts bis F: suchen (A-E meist Systemlaufwerke).
        for (int i = 25; i >= 5; --i) {
            if ((used & (1u << i)) == 0) {
                std::string d; d += static_cast<char>('A' + i); d += ":";
                return d;
            }
        }
#endif
        return "";
    }

    // ─── Container erstellen ───

    OpResult ContainerManager::create_container(
        const std::string& path, uint64_t size_mb, const std::string& pw_a,
        const std::string& keyfile_a, const std::string& pw_b, const std::string& keyfile_b,
        uint64_t hidden_mb, const std::string& twofa_secret, const std::string& tpm_sealed_secret,
        bool bind_to_device, CreateCb callback
    ) {
        try {
            runtime_integrity_check();

            // Passwort-Stärke ERZWINGEN (mind. 16 Zeichen, 3 Zeichengruppen, keine
            // trivialen Muster). Verhindert, dass ein Container mit schwachem Passwort
            // angelegt wird — die KDF kann ein schwaches Passwort nicht retten.
            {
                auto [ok_a, msg_a] = crypto_utils::validate_password_strength(pw_a);
                if (!ok_a) return {false, std::string("Passwort A: ") + msg_a};
                if (!pw_b.empty()) {
                    auto [ok_b, msg_b] = crypto_utils::validate_password_strength(pw_b);
                    if (!ok_b) return {false, std::string("Passwort B: ") + msg_b};
                }
            }

            uint64_t total = size_mb * 1024 * 1024;
            uint64_t hidden = (!pw_b.empty() && hidden_mb > 0) ? hidden_mb * 1024 * 1024 : 0;

            uint64_t norm_data_sz, hide_hdr_off = 0, hide_data_sz = 0;
            bool has_hidden = hidden > 0;
            if (has_hidden) {
                // Der versteckte Header MUSS an einem Offset liegen, den scan_hidden
                // beim Mount tatsächlich produziert. Daher wählen wir hier denselben
                // scan_seed wie mount_volume (hidden) und nehmen den ersten Scan-Offset,
                // der genug Platz für normales Volume davor und das Hidden-Volume
                // dahinter lässt. (Das Original nutzte zwei inkompatible Seed-Verfahren,
                // wodurch der Hidden-Header nie gefunden werden konnte.)
                auto kh_b = crypto_utils::KDF::hash_keyfile(keyfile_b);
                auto scan_seed = hidden_scan_seed(pw_b, kh_b, twofa_secret, tpm_sealed_secret, bind_to_device);
                uint64_t min_normal = config::HDR_TOTAL + 4096; // Header + min. Daten davor
                bool placed = false;
                for (auto off : scan_hidden(total, scan_seed)) {
                    if (off >= min_normal && off + hidden <= total) {
                        hide_hdr_off = off;
                        placed = true;
                        break;
                    }
                }
                if (!placed) return {false, "Kein geeigneter Offset fuer verstecktes Volume gefunden"};
                norm_data_sz = hide_hdr_off - config::HDR_TOTAL;
                hide_data_sz = hidden - config::HDR_TOTAL;
            } else {
                norm_data_sz = total - config::HDR_TOTAL;
            }
            if (norm_data_sz < 4096) return {false, "Container zu klein"};
            if (twofa_secret.empty()) return {false, "2FA-Secret erforderlich (Containerformat v7)"};

            if (callback) callback("status", "Fuelle Container mit Zufallsdaten...", 0);
            {
                std::ofstream f(path, std::ios::binary | std::ios::trunc);
                if (!f) return {false, "Kann Container nicht anlegen"};
                std::vector<uint8_t> buf(65536);
                uint64_t written = 0;
                while (written < total) {
                    size_t chunk = static_cast<size_t>(std::min<uint64_t>(buf.size(), total - written));
                    randombytes_buf(buf.data(), chunk);
                    f.write(reinterpret_cast<const char*>(buf.data()), chunk);
                    written += chunk;
                    if (callback && (written % 1048576 == 0))
                        callback("progress", "", static_cast<int>((double)written / total * 40));
                }
            }

            if (callback) callback("status", "Erstelle normales Volume...", 50);
            auto kh_a = crypto_utils::KDF::hash_keyfile(keyfile_a);
            std::vector<uint8_t> salt_a(config::SALT_SIZE);
            randombytes_buf(salt_a.data(), salt_a.size());
            auto key_a = derive_volume_key(pw_a, kh_a, salt_a, "normal", twofa_secret, tpm_sealed_secret, bind_to_device);
            {
                std::fstream f(path, std::ios::binary | std::ios::in | std::ios::out);
                write_header(f, 0, "NORM", key_a, config::HDR_TOTAL, norm_data_sz, salt_a);
            }
            sodium_memzero(key_a.data(), key_a.size());
            if (callback) callback("progress", "", 60);

            if (has_hidden) {
                if (callback) callback("status", "Erstelle verstecktes Volume...", 70);
                auto kh_b = crypto_utils::KDF::hash_keyfile(keyfile_b);
                std::vector<uint8_t> salt_b(config::SALT_SIZE);
                randombytes_buf(salt_b.data(), salt_b.size());
                auto key_b = derive_volume_key(pw_b, kh_b, salt_b, "hidden", twofa_secret, tpm_sealed_secret, bind_to_device);
                {
                    std::fstream f(path, std::ios::binary | std::ios::in | std::ios::out);
                    write_header(f, hide_hdr_off, "HIDE", key_b, hide_hdr_off + config::HDR_TOTAL, hide_data_sz, salt_b);
                }
                sodium_memzero(key_b.data(), key_b.size());
            }
            if (callback) callback("progress", "", 100);
            return {true, "Container erstellt: " + fs::path(path).filename().string()};
        } catch (const std::exception& e) {
            return {false, std::string("Fehler: ") + e.what()};
        }
    }

    // ─── Mount (Auth + Header-Verifikation; WinFsp folgt in Etappe 5) ───

    OpResult ContainerManager::mount_volume(
        const std::string& container_path, const std::string& password,
        const std::string& keyfile_path, const std::string& mode,
        const std::string& twofa_secret, const std::string& tpm_sealed_secret,
        bool bind_to_device, const std::string& emergency_password,
        bool allow_emergency_sanitization, ProgressCb progress_cb,
        bool attach_drive
    ) {
        try {
            runtime_integrity_check();
            std::error_code ec;
            if (!fs::exists(container_path, ec)) return {false, "Container nicht gefunden"};

            auto rec = recover_unmount_txn(container_path);
            if (!rec.ok) return {false, rec.message.empty() ? "Unvollstaendiger Schreibvorgang erkannt" : rec.message};

            std::string canon = fs::absolute(container_path, ec).string();
            std::string auth_id = "mount:" + canon + ":" + mode;
            auto blocked = pre_auth_guard(auth_id);
            if (!blocked.empty()) return {false, blocked};

            // Duress/Notfall-Passwort: Wenn das eingegebene Passwort dem hinterlegten
            // Notfall-Passwort entspricht, Zugriff unauffällig verweigern (gleiche
            // Meldung wie bei falschem Passwort) — optional Header sanitisieren.
            if (is_emergency_password(password, emergency_password)) {
                if (allow_emergency_sanitization) sanitize_headers(container_path);
                auth_failed(auth_id);
                return {false, "Falsches Passwort, Keyfile oder Volume nicht vorhanden"};
            }

            auto kh = crypto_utils::KDF::hash_keyfile(keyfile_path);
            uint64_t fsize = fs::file_size(container_path, ec);

            bool found = false;
            HeaderData hdr;
            std::vector<uint8_t> master_key;

            std::ifstream f(container_path, std::ios::binary);
            if (mode == "normal") {
                RawHeader raw;
                if (read_header_raw(f, 0, raw)) {
                    auto k = derive_volume_key(password, kh, raw.salt, "normal", twofa_secret, tpm_sealed_secret, bind_to_device);
                    auto [ok, hd] = decrypt_and_verify_header(raw, k);
                    if (ok && hd.vol_type.substr(0,4) == "NORM") { found = true; hdr = hd; master_key = k; }
                    else sodium_memzero(k.data(), k.size());
                }
            } else {
                auto scan_seed = hidden_scan_seed(password, kh, twofa_secret, tpm_sealed_secret, bind_to_device);
                for (auto off : scan_hidden(fsize, scan_seed)) {
                    RawHeader raw;
                    if (!read_header_raw(f, off, raw)) continue;
                    auto k = derive_volume_key(password, kh, raw.salt, "hidden", twofa_secret, tpm_sealed_secret, bind_to_device);
                    auto [ok, hd] = decrypt_and_verify_header(raw, k);
                    if (ok && hd.vol_type.substr(0,4) == "HIDE") { found = true; hdr = hd; master_key = k; break; }
                    sodium_memzero(k.data(), k.size());
                }
            }

            if (!found || master_key.empty()) {
                auth_failed(auth_id);
                return {false, "Falsches Passwort, Keyfile oder Volume nicht vorhanden"};
            }
            auth_success(auth_id);

            // Overflow-sichere Bereichsprüfung (data_offset+data_size kann überlaufen).
            if (!region_within(hdr.data_offset, hdr.data_size, fsize)) {
                auth_failed(auth_id);
                sodium_memzero(master_key.data(), master_key.size());
                return {false, "Container-Header ungueltig oder manipuliert"};
            }

            auto sector_key = crypto_utils::KDF::derive_sector_key(master_key, hdr.salt);

            // Payload (Archiv) entschlüsseln, falls vorhanden.
            // data_size ist durch region_within bereits <= fsize begrenzt (kein Bad-Alloc).
            std::vector<uint8_t> enc(static_cast<size_t>(hdr.data_size));
            f.seekg(static_cast<std::streamoff>(hdr.data_offset));
            f.read(reinterpret_cast<char*>(enc.data()), enc.size());
            enc.resize(static_cast<size_t>(f.gcount()));

            std::vector<uint8_t> archive_data;
            std::string aad = "DGKN5-ARCHIVE";
            std::span<const uint8_t> aad_s(reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
            const size_t min_payload = config::PAYLOAD_MAGIC.size() + 4 + config::NONCE_SIZE + 16;
            if (enc.size() > min_payload &&
                std::equal(config::PAYLOAD_MAGIC.begin(), config::PAYLOAD_MAGIC.end(), enc.begin())) {
                size_t p = config::PAYLOAD_MAGIC.size();
                uint32_t arc_len; std::memcpy(&arc_len, enc.data() + p, 4); arc_len = from_be32(arc_len); p += 4;
                size_t max_ct = enc.size() - p - config::NONCE_SIZE;
                if (arc_len > 16 && arc_len <= max_ct) {
                    std::span<const uint8_t> n24(enc.data() + p, config::NONCE_SIZE); p += config::NONCE_SIZE;
                    std::span<const uint8_t> ct(enc.data() + p, arc_len);
                    if (progress_cb) progress_cb(0.3);
                    try {
                        archive_data = crypto_utils::XChaCha20::decrypt(master_key, n24, ct, aad_s);
                        if (progress_cb) progress_cb(1.0);
                    } catch (...) {
                        sodium_memzero(master_key.data(), master_key.size());
                        sodium_memzero(sector_key.data(), sector_key.size());
                        return {false, "Payload-Authentifizierung fehlgeschlagen (Daten beschaedigt/manipuliert)"};
                    }
                }
            }

            std::string mount_point = create_mount_dir(mode);
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            std::string mid = mode + "_" + std::to_string(now);

            auto info = std::make_shared<MountInfo>();
            info->path = container_path;
            info->mode = mode;
            info->master_key = master_key;
            info->sector_key = sector_key;
            info->archive_data = archive_data;
            // Schlüssel gegen Auslagern in die Swap-Datei sperren (Anti-Forensik).
            if (!info->master_key.empty()) sodium_mlock(info->master_key.data(), info->master_key.size());
            if (!info->sector_key.empty()) sodium_mlock(info->sector_key.data(), info->sector_key.size());
            info->data_offset = hdr.data_offset;
            info->data_size = hdr.data_size;
            info->label = (mode == "normal" ? "NORMAL" : "HIDDEN");
            info->label += " - " + fs::path(container_path).filename().string();
            info->last_activity = std::chrono::system_clock::now();
            info->container_size = fsize;

            // Virtuelles Laufwerk (WinFsp) erstellen und best-effort mounten.
            // Wenn kein Treiber/keine Adminrechte verfügbar sind, bleibt das Volume
            // dennoch registriert (Daten im RAM) — nur ohne Laufwerksbuchstabe.
            std::vector<uint8_t> blob = archive_data.empty() ? Archive::empty_archive() : archive_data;
            // Echte Containerkapazitaet (Datenbereich) durchreichen, damit das Laufwerk
            // im Explorer die korrekte Groesse zeigt statt der frueheren hartcodierten 4 GiB.
            info->volume = std::make_shared<VirtualVolume>(blob, info->label, info->data_size);
            if (attach_drive) {
                // Robustheit gegen intermittierende Mount-Fehler: mehrere freie
                // Laufwerksbuchstaben der Reihe nach probieren. Ein einzelner Versuch
                // kann scheitern, wenn WinFsp einen Buchstaben noch halb-reserviert haelt
                // (Geister-Mount eines vorherigen Laufs) oder der Treiber gerade "kalt"
                // ist. Ein zweiter Buchstabe/Versuch umgeht das, ohne dass der Nutzer
                // die App neu starten muss.
                info->mount_point = "";
#ifdef _WIN32
                DWORD used = GetLogicalDrives();
                int attempts = 0;
                for (int i = 25; i >= 5 && attempts < 5; --i) {       // Z: -> F:
                    if (used & (1u << i)) continue;                   // belegt
                    std::string drive; drive += static_cast<char>('A' + i); drive += ":";
                    ++attempts;
                    if (info->volume->mount(drive)) { info->mount_point = drive; break; }
                    // Fehlversuch: kurz warten, damit WinFsp den Buchstaben freigibt,
                    // bevor der naechste Kandidat probiert wird.
                    std::this_thread::sleep_for(std::chrono::milliseconds(300));
                }
#else
                std::string drive = find_free_drive_letter();
                if (!drive.empty() && info->volume->mount(drive)) info->mount_point = drive;
#endif
            } else {
                info->mount_point = ""; // bewusst kein Laufwerk (headless/Test)
            }
            sodium_memzero(blob.data(), blob.size());

            {
                std::lock_guard<std::mutex> lock(lock_);
                mounted_[mid] = info;
            }
            // master_key/sector_key sind kopiert in MountInfo; lokale Kopien wipen.
            sodium_memzero(master_key.data(), master_key.size());
            sodium_memzero(sector_key.data(), sector_key.size());
            return {true, mid};
        } catch (const std::exception& e) {
            return {false, std::string("Fehler: ") + e.what()};
        }
    }

    OpResult ContainerManager::unmount(const std::string& mount_id, bool secure_delete) {
        std::shared_ptr<MountInfo> info;
        {
            std::lock_guard<std::mutex> lock(lock_);
            auto it = mounted_.find(mount_id);
            if (it == mounted_.end()) return {false, "Volume nicht gefunden"};
            info = it->second;
        }
        try {
            // Falls ein virtuelles Laufwerk läuft: aktuellen Stand serialisieren und
            // das Laufwerk aushängen. serialize() liefert den (ggf. veränderten) Archiv-Blob.
            std::vector<uint8_t> current_archive;
            if (info->volume) {
                info->volume->unmount();
                current_archive = info->volume->serialize();
            } else {
                current_archive = info->archive_data;
            }

            // Archiv (im RAM) zurück in den Container schreiben (verschlüsselt).
            std::string aad = "DGKN5-ARCHIVE";
            std::span<const uint8_t> aad_s(reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
            auto res = crypto_utils::XChaCha20::encrypt(info->master_key, current_archive, aad_s);
            sodium_memzero(current_archive.data(), current_archive.size());

            std::vector<uint8_t> payload;
            payload.insert(payload.end(), config::PAYLOAD_MAGIC.begin(), config::PAYLOAD_MAGIC.end());
            uint32_t ctlen = to_be32(static_cast<uint32_t>(res.ciphertext.size()));
            auto* lp = reinterpret_cast<uint8_t*>(&ctlen); payload.insert(payload.end(), lp, lp + 4);
            payload.insert(payload.end(), res.nonce.begin(), res.nonce.end());
            payload.insert(payload.end(), res.ciphertext.begin(), res.ciphertext.end());

            uint64_t max_sz = info->data_size;
            if (payload.size() > max_sz)
                return {false, "Daten zu gross fuer den Datenbereich"};
            std::vector<uint8_t> padded = payload;
            size_t pad_start = padded.size();
            padded.resize(max_sz);
            if (max_sz > pad_start) randombytes_buf(padded.data() + pad_start, max_sz - pad_start);

            // Journal: prepare -> write -> commit -> clear
            json tx;
            tx["version"] = config::UNMOUNT_TXN_VER;
            tx["op"] = "unmount";
            tx["state"] = "prepare";
            tx["data_offset"] = info->data_offset;
            tx["data_size"] = max_sz;
            tx["payload_len"] = padded.size();
            tx["payload_hmac"] = journal_hmac(info->path, padded);
            write_unmount_txn(info->path, tx.dump(2));

            {
                std::fstream f(info->path, std::ios::binary | std::ios::in | std::ios::out);
                f.seekp(static_cast<std::streamoff>(info->data_offset));
                f.write(reinterpret_cast<const char*>(padded.data()), padded.size());
                f.flush();
            }
            tx["state"] = "commit";
            write_unmount_txn(info->path, tx.dump(2));
            clear_unmount_txn(info->path);

            // Bei virtuellem Laufwerk gibt es keinen Klartext-Temp-Ordner zu löschen.
            // (info->mount_point ist dann ein Laufwerksbuchstabe.)
            {
                std::lock_guard<std::mutex> lock(lock_);
                mounted_.erase(mount_id);
            }
            return {true, "Volume gespeichert & sicher geloescht"};
        } catch (const std::exception& e) {
            return {false, std::string("Fehler beim Speichern: ") + e.what()};
        }
    }

    std::vector<ContainerManager::MountView> ContainerManager::list_mounts() {
        std::vector<MountView> out;
        std::lock_guard<std::mutex> lock(lock_);
        for (auto& kv : mounted_) {
            const auto& m = kv.second;
            out.push_back(MountView{ kv.first, m->label, m->mount_point, m->mode, m->path });
        }
        return out;
    }

    std::vector<std::tuple<std::string, bool, std::string>> ContainerManager::unmount_all(bool secure_delete) {
        std::vector<std::tuple<std::string, bool, std::string>> results;
        std::vector<std::string> ids;
        { std::lock_guard<std::mutex> lock(lock_); for (auto& kv : mounted_) ids.push_back(kv.first); }
        for (auto& id : ids) {
            auto r = unmount(id, secure_delete);
            results.emplace_back(id, r.ok, r.message);
        }
        return results;
    }

    OpResult ContainerManager::backup_header(const std::string& container_path, const std::string& backup_path) {
        try {
            std::error_code ec;
            uint64_t fsize = fs::file_size(container_path, ec);
            std::ifstream f(container_path, std::ios::binary);
            std::vector<uint8_t> norm_hdr(config::HDR_TOTAL);
            f.read(reinterpret_cast<char*>(norm_hdr.data()), norm_hdr.size());

            std::vector<uint8_t> hide_hdr(config::HDR_TOTAL, 0);
            long long hide_off = -1;
            for (auto off : scan_hidden(fsize, {})) {
                f.clear(); f.seekg(static_cast<std::streamoff>(off));
                std::vector<uint8_t> cand(config::HDR_TOTAL);
                f.read(reinterpret_cast<char*>(cand.data()), cand.size());
                if (static_cast<size_t>(f.gcount()) == config::HDR_TOTAL) { hide_hdr = cand; hide_off = (long long)off; break; }
            }
            auto to_hex = [](const std::vector<uint8_t>& v) {
                static const char* h = "0123456789abcdef"; std::string s; s.reserve(v.size()*2);
                for (auto b : v) { s.push_back(h[b>>4]); s.push_back(h[b&0xF]); } return s;
            };
            json bak;
            bak["version"] = config::FORMAT_VER;
            bak["file"] = fs::path(container_path).filename().string();
            bak["file_size"] = fsize;
            bak["norm_hdr"] = to_hex(norm_hdr);
            bak["hide_hdr"] = to_hex(hide_hdr);
            if (hide_off >= 0) bak["hide_off"] = (uint64_t)hide_off; else bak["hide_off"] = nullptr;
            std::ofstream of(backup_path, std::ios::binary | std::ios::trunc);
            std::string txt = bak.dump(2); of.write(txt.data(), txt.size());
            return {true, "Header-Backup gespeichert: " + fs::path(backup_path).filename().string()};
        } catch (const std::exception& e) { return {false, std::string("Backup-Fehler: ") + e.what()}; }
    }

    OpResult ContainerManager::restore_header(const std::string& container_path, const std::string& backup_path) {
        try {
            std::ifstream bf(backup_path, std::ios::binary);
            json bak; bf >> bak;
            auto from_hex = [](const std::string& s) {
                std::vector<uint8_t> v; v.reserve(s.size()/2);
                auto hv = [](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return 0; };
                for (size_t i=0;i+1<s.size();i+=2) v.push_back((uint8_t)((hv(s[i])<<4)|hv(s[i+1])));
                return v;
            };
            auto norm_hdr = from_hex(bak.at("norm_hdr").get<std::string>());
            auto hide_hdr = from_hex(bak.at("hide_hdr").get<std::string>());
            std::fstream f(container_path, std::ios::binary | std::ios::in | std::ios::out);
            f.seekp(0);
            f.write(reinterpret_cast<const char*>(norm_hdr.data()), norm_hdr.size());
            if (!bak.at("hide_off").is_null()) {
                uint64_t hide_off = bak.at("hide_off").get<uint64_t>();
                bool any_nonzero = std::any_of(hide_hdr.begin(), hide_hdr.end(), [](uint8_t b){ return b != 0; });
                if (hide_off && any_nonzero) {
                    f.seekp(static_cast<std::streamoff>(hide_off));
                    f.write(reinterpret_cast<const char*>(hide_hdr.data()), hide_hdr.size());
                }
            }
            f.flush();
            return {true, "Header wiederhergestellt"};
        } catch (const std::exception& e) { return {false, std::string("Restore-Fehler: ") + e.what()}; }
    }

    OpResult ContainerManager::change_password(
        const std::string& container_path, const std::string& old_pw, const std::string& old_keyfile,
        const std::string& new_pw, const std::string& new_keyfile, const std::string& mode,
        const std::string& twofa_secret, const std::string& tpm_sealed_secret, bool bind_to_device
    ) {
        try {
            runtime_integrity_check();
            std::error_code ec;
            std::string canon = fs::absolute(container_path, ec).string();
            std::string auth_id = "changepw:" + canon + ":" + mode;
            auto blocked = pre_auth_guard(auth_id);
            if (!blocked.empty()) return {false, blocked};

            auto kh_old = crypto_utils::KDF::hash_keyfile(old_keyfile);
            uint64_t fsize = fs::file_size(container_path, ec);
            bool found = false; HeaderData hdr; std::vector<uint8_t> old_key; uint64_t hdr_off = 0;

            { std::ifstream f(container_path, std::ios::binary);
              if (mode == "normal") {
                  RawHeader raw;
                  if (read_header_raw(f, 0, raw)) {
                      auto k = derive_volume_key(old_pw, kh_old, raw.salt, "normal", twofa_secret, tpm_sealed_secret, bind_to_device);
                      auto [ok, hd] = decrypt_and_verify_header(raw, k);
                      if (ok && hd.vol_type.substr(0,4) == "NORM") { found=true; hdr=hd; old_key=k; hdr_off=0; }
                      else sodium_memzero(k.data(), k.size());
                  }
              } else {
                  auto scan_seed = hidden_scan_seed(old_pw, kh_old, twofa_secret, tpm_sealed_secret, bind_to_device);
                  for (auto off : scan_hidden(fsize, scan_seed)) {
                      RawHeader raw; if (!read_header_raw(f, off, raw)) continue;
                      auto k = derive_volume_key(old_pw, kh_old, raw.salt, "hidden", twofa_secret, tpm_sealed_secret, bind_to_device);
                      auto [ok, hd] = decrypt_and_verify_header(raw, k);
                      if (ok && hd.vol_type.substr(0,4) == "HIDE") { found=true; hdr=hd; old_key=k; hdr_off=off; break; }
                      sodium_memzero(k.data(), k.size());
                  }
              }
            }
            if (!found || old_key.empty()) { auth_failed(auth_id); return {false, "Falsches Passwort, Keyfile oder Volume nicht vorhanden"}; }
            auth_success(auth_id);

            auto kh_new = crypto_utils::KDF::hash_keyfile(new_keyfile);
            std::vector<uint8_t> new_salt(config::SALT_SIZE); randombytes_buf(new_salt.data(), new_salt.size());
            auto new_key = derive_volume_key(new_pw, kh_new, new_salt, mode, twofa_secret, tpm_sealed_secret, bind_to_device);

            if (!region_within(hdr.data_offset, hdr.data_size, fsize)) {
                sodium_memzero(old_key.data(), old_key.size());
                sodium_memzero(new_key.data(), new_key.size());
                return {false, "Container-Header ungueltig oder manipuliert"};
            }
            std::vector<uint8_t> enc(static_cast<size_t>(hdr.data_size));
            { std::ifstream f(container_path, std::ios::binary);
              f.seekg(static_cast<std::streamoff>(hdr.data_offset));
              f.read(reinterpret_cast<char*>(enc.data()), enc.size());
              enc.resize(static_cast<size_t>(f.gcount())); }

            std::string aad = "DGKN5-ARCHIVE";
            std::span<const uint8_t> aad_s(reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
            std::vector<uint8_t> padded(hdr.data_size);
            randombytes_buf(padded.data(), padded.size());

            const size_t min_payload = config::PAYLOAD_MAGIC.size() + 4 + config::NONCE_SIZE + 16;
            bool has_payload = enc.size() > min_payload &&
                std::equal(config::PAYLOAD_MAGIC.begin(), config::PAYLOAD_MAGIC.end(), enc.begin());
            if (has_payload) {
                size_t p = config::PAYLOAD_MAGIC.size();
                uint32_t ct_len; std::memcpy(&ct_len, enc.data()+p, 4); ct_len = from_be32(ct_len); p += 4;
                size_t max_ct = enc.size() - p - config::NONCE_SIZE;
                if (ct_len > 16 && ct_len <= max_ct) {
                    std::span<const uint8_t> n24(enc.data()+p, config::NONCE_SIZE); p += config::NONCE_SIZE;
                    std::span<const uint8_t> ct(enc.data()+p, ct_len);
                    auto arc = crypto_utils::XChaCha20::decrypt(old_key, n24, ct, aad_s);
                    auto re = crypto_utils::XChaCha20::encrypt(new_key, arc, aad_s);
                    std::vector<uint8_t> np;
                    np.insert(np.end(), config::PAYLOAD_MAGIC.begin(), config::PAYLOAD_MAGIC.end());
                    uint32_t nl = to_be32(static_cast<uint32_t>(re.ciphertext.size()));
                    auto* lp = reinterpret_cast<uint8_t*>(&nl); np.insert(np.end(), lp, lp+4);
                    np.insert(np.end(), re.nonce.begin(), re.nonce.end());
                    np.insert(np.end(), re.ciphertext.begin(), re.ciphertext.end());
                    // F-B: Passt das neu verschlüsselte Payload NICHT in den Datenbereich,
                    // dürfen wir NICHT still weiterlaufen und den Header mit dem neuen Key
                    // schreiben — sonst läge danach Zufall statt Daten im Container
                    // (stiller Datenverlust, Passwortänderung "erfolgreich"). Stattdessen
                    // sauber abbrechen; der Container bleibt mit dem ALTEN Passwort intakt.
                    if (np.size() > padded.size()) {
                        sodium_memzero(arc.data(), arc.size());
                        sodium_memzero(old_key.data(), old_key.size());
                        sodium_memzero(new_key.data(), new_key.size());
                        return {false, "Passwortaenderung abgebrochen: Daten passen nicht mehr "
                                       "in den Datenbereich (Container unveraendert)"};
                    }
                    std::copy(np.begin(), np.end(), padded.begin());
                    // Rest bleibt random (schon gefüllt)
                    sodium_memzero(arc.data(), arc.size());
                }
            }

            json tx;
            tx["version"] = config::UNMOUNT_TXN_VER; tx["op"] = "changepw"; tx["state"] = "prepare";
            tx["data_offset"] = hdr.data_offset; tx["data_size"] = hdr.data_size;
            tx["payload_len"] = padded.size(); tx["payload_hmac"] = journal_hmac(container_path, padded);
            write_unmount_txn(container_path, tx.dump(2));

            { std::fstream f(container_path, std::ios::binary | std::ios::in | std::ios::out);
              f.seekp(static_cast<std::streamoff>(hdr.data_offset));
              f.write(reinterpret_cast<const char*>(padded.data()), padded.size());
              f.flush();
              write_header(f, hdr_off, (mode=="normal"?"NORM":"HIDE"), new_key, hdr.data_offset, hdr.data_size, new_salt);
              f.flush(); }

            tx["state"] = "commit"; write_unmount_txn(container_path, tx.dump(2));
            clear_unmount_txn(container_path);
            sodium_memzero(old_key.data(), old_key.size());
            sodium_memzero(new_key.data(), new_key.size());
            return {true, "Passwort erfolgreich geaendert"};
        } catch (const std::exception& e) { return {false, std::string("Fehler: ") + e.what()}; }
    }

    OpResult ContainerManager::check_integrity(
        const std::string& container_path, const std::string& password, const std::string& keyfile,
        const std::string& mode, const std::string& twofa_secret, const std::string& tpm_sealed_secret,
        bool bind_to_device, ProgressCb progress_cb
    ) {
        try {
            runtime_integrity_check();
            auto rec = recover_unmount_txn(container_path);
            if (!rec.ok) return {false, rec.message.empty() ? "Unvollstaendiger Schreibvorgang erkannt" : rec.message};
            std::error_code ec;
            std::string canon = fs::absolute(container_path, ec).string();
            std::string auth_id = "integrity:" + canon + ":" + mode;
            auto blocked = pre_auth_guard(auth_id);
            if (!blocked.empty()) return {false, blocked};

            auto kh = crypto_utils::KDF::hash_keyfile(keyfile);
            uint64_t fsize = fs::file_size(container_path, ec);
            bool found = false; HeaderData hdr; std::vector<uint8_t> key;

            { std::ifstream f(container_path, std::ios::binary);
              if (mode == "normal") {
                  RawHeader raw;
                  if (read_header_raw(f, 0, raw)) {
                      auto k = derive_volume_key(password, kh, raw.salt, "normal", twofa_secret, tpm_sealed_secret, bind_to_device);
                      auto [ok, hd] = decrypt_and_verify_header(raw, k);
                      if (ok && hd.vol_type.substr(0,4) == "NORM") { found=true; hdr=hd; key=k; }
                      else sodium_memzero(k.data(), k.size());
                  }
              } else {
                  auto scan_seed = hidden_scan_seed(password, kh, twofa_secret, tpm_sealed_secret, bind_to_device);
                  for (auto off : scan_hidden(fsize, scan_seed)) {
                      RawHeader raw; if (!read_header_raw(f, off, raw)) continue;
                      auto k = derive_volume_key(password, kh, raw.salt, "hidden", twofa_secret, tpm_sealed_secret, bind_to_device);
                      auto [ok, hd] = decrypt_and_verify_header(raw, k);
                      if (ok && hd.vol_type.substr(0,4) == "HIDE") { found=true; hdr=hd; key=k; break; }
                      sodium_memzero(k.data(), k.size());
                  }
              } }
            if (!found || key.empty()) { auth_failed(auth_id); return {false, "Falsches Passwort, Keyfile oder Volume nicht vorhanden"}; }
            auth_success(auth_id);

            if (!region_within(hdr.data_offset, hdr.data_size, fsize)) {
                sodium_memzero(key.data(), key.size());
                return {false, "Container-Header ungueltig oder manipuliert"};
            }
            // Payload-Integrität prüfen (Poly1305-Tag über XChaCha20).
            std::vector<uint8_t> enc(static_cast<size_t>(hdr.data_size));
            { std::ifstream f(container_path, std::ios::binary);
              f.seekg(static_cast<std::streamoff>(hdr.data_offset));
              f.read(reinterpret_cast<char*>(enc.data()), enc.size());
              enc.resize(static_cast<size_t>(f.gcount())); }

            std::string aad = "DGKN5-ARCHIVE";
            std::span<const uint8_t> aad_s(reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
            const size_t min_payload = config::PAYLOAD_MAGIC.size() + 4 + config::NONCE_SIZE + 16;
            std::string result_msg = "Header gueltig. Kein Payload-Archiv vorhanden.";
            if (enc.size() > min_payload &&
                std::equal(config::PAYLOAD_MAGIC.begin(), config::PAYLOAD_MAGIC.end(), enc.begin())) {
                size_t p = config::PAYLOAD_MAGIC.size();
                uint32_t ct_len; std::memcpy(&ct_len, enc.data()+p, 4); ct_len = from_be32(ct_len); p += 4;
                size_t max_ct = enc.size() - p - config::NONCE_SIZE;
                if (ct_len > 16 && ct_len <= max_ct) {
                    std::span<const uint8_t> n24(enc.data()+p, config::NONCE_SIZE); p += config::NONCE_SIZE;
                    std::span<const uint8_t> ct(enc.data()+p, ct_len);
                    if (progress_cb) progress_cb(0.5);
                    try {
                        auto arc = crypto_utils::XChaCha20::decrypt(key, n24, ct, aad_s);
                        sodium_memzero(arc.data(), arc.size());
                        result_msg = "Integritaet OK: Header + Payload authentifiziert.";
                    } catch (...) {
                        sodium_memzero(key.data(), key.size());
                        return {false, "Integritaet FEHLGESCHLAGEN: Payload manipuliert/beschaedigt."};
                    }
                    if (progress_cb) progress_cb(1.0);
                }
            }
            sodium_memzero(key.data(), key.size());
            return {true, result_msg};
        } catch (const std::exception& e) { return {false, std::string("Fehler: ") + e.what()}; }
    }

    void ContainerManager::emergency_wipe(bool wipe_headers) {
        std::vector<std::shared_ptr<MountInfo>> mounts;
        { std::lock_guard<std::mutex> lock(lock_);
          for (auto& kv : mounted_) mounts.push_back(kv.second); }
        for (auto& info : mounts) {
            try {
                if (wipe_headers) {
                    std::fstream f(info->path, std::ios::binary | std::ios::in | std::ios::out);
                    std::vector<uint8_t> rnd(config::HDR_TOTAL);
                    randombytes_buf(rnd.data(), rnd.size());
                    f.seekp(0); f.write(reinterpret_cast<const char*>(rnd.data()), rnd.size()); f.flush();
                }
                std::error_code ec; fs::remove_all(info->mount_point, ec);
            } catch (...) {}
        }
        std::lock_guard<std::mutex> lock(lock_);
        mounted_.clear();
    }

    // ─── Einzeldateien Ver- und Entschlüsselung (Standalone) ───

    bool ContainerManager::encrypt_file(
        const std::string& input_path, const std::string& output_path,
        const std::string& password, const std::string& keyfile_path, const std::string& twofa_secret
    ) {
        std::ifstream in(input_path, std::ios::binary);
        std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
        if (!in.is_open() || !out.is_open()) return false;

        // 1. Keys generieren
        std::vector<uint8_t> salt(config::SALT_SIZE);
        randombytes_buf(salt.data(), salt.size());
        
        auto kf_hash = crypto_utils::KDF::hash_keyfile(keyfile_path);
        auto master_key = derive_volume_key(password, kf_hash, salt, "normal", twofa_secret, "", false);
        auto sector_key = crypto_utils::KDF::derive_sector_key(master_key, salt);

        // 2. Authentifizierter Header (H-2): Layout bleibt HDR_TOTAL(128) groß, damit die
        //    Sektor-Daten weiterhin bei Offset 128 beginnen. In den bislang genullten
        //    Padding-Bereich legen wir einen AEAD-Block, der ein festes Sentinel
        //    verschlüsselt. Beim Entschlüsseln verifiziert dessen Poly1305-Tag das
        //    Passwort + 2FA-Secret SOFORT (statt erst am ersten Sektor) und macht die
        //    Datei manipulationsfest. Aufbau des 96-Byte-Padding-Bereichs:
        //      marker(4) "F7AH" ‖ nonce(24) ‖ AEAD(master_key, SENTINEL, AAD="DGKN-FILE-HDR")
        //    Rest mit Zufall aufgefüllt. Alte Dateien haben hier 0x00 -> Marker fehlt ->
        //    decrypt_file faellt automatisch auf das Legacy-Format zurueck.
        out.write(reinterpret_cast<const char*>(salt.data()), salt.size());
        {
            std::vector<uint8_t> hdr(config::HDR_TOTAL - config::SALT_SIZE); // 96 B
            randombytes_buf(hdr.data(), hdr.size()); // Default: Zufall (getarnt)
            size_t p = 0;
            std::memcpy(hdr.data() + p, config::FILE_AUTH_HDR_MARKER.data(), 4); p += 4;
            std::vector<uint8_t> nonce(config::NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());
            std::memcpy(hdr.data() + p, nonce.data(), nonce.size()); p += nonce.size();
            std::string aad = "DGKN-FILE-HDR";
            std::span<const uint8_t> aad_s(reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
            std::vector<uint8_t> sentinel(config::FILE_SENTINEL_PLAIN.begin(), config::FILE_SENTINEL_PLAIN.end());
            // Mit unserem festen (im Header gespeicherten) Nonce verschlüsseln.
            std::vector<uint8_t> ct(sentinel.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
            unsigned long long ctlen = 0;
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                ct.data(), &ctlen, sentinel.data(), sentinel.size(),
                aad_s.data(), aad_s.size(), nullptr, nonce.data(), master_key.data());
            // ct passt in den Header: 4(marker)+24(nonce)+31(ct) = 59 <= 96.
            std::memcpy(hdr.data() + p, ct.data(), static_cast<size_t>(ctlen));
            out.write(reinterpret_cast<const char*>(hdr.data()), hdr.size());
        }

        // 3. Sektorweise einlesen und verschlüsseln
        std::vector<uint8_t> buffer(config::SECTOR_SIZE);
        uint64_t sector_idx = 0;

        while (in) {
            in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            size_t bytes_read = in.gcount();
            if (bytes_read == 0) break;

            // Auffüllen (Padding) falls der letzte Sektor nicht voll ist
            if (bytes_read < config::SECTOR_SIZE) {
                std::fill(buffer.begin() + bytes_read, buffer.end(), 0);
            }

            auto ct = crypto_utils::SectorCrypto::encrypt_sector(sector_key, sector_idx, buffer);
            
            // Echte Länge speichern (4 Bytes) und dann Ciphertext schreiben
            uint32_t len = static_cast<uint32_t>(bytes_read);
            out.write(reinterpret_cast<const char*>(&len), sizeof(len));
            out.write(reinterpret_cast<const char*>(ct.data()), ct.size());
            sector_idx++;
        }
        // H-3: abgeleitete Schlüssel nach Gebrauch sicher aus dem RAM entfernen.
        sodium_memzero(master_key.data(), master_key.size());
        sodium_memzero(sector_key.data(), sector_key.size());
        return true;
    }

    bool ContainerManager::decrypt_file(
        const std::string& input_path, const std::string& output_path,
        const std::string& password, const std::string& keyfile_path, const std::string& twofa_secret
    ) {
        std::ifstream in(input_path, std::ios::binary);
        std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
        if (!in.is_open() || !out.is_open()) return false;

        std::vector<uint8_t> salt(config::SALT_SIZE);
        if (!in.read(reinterpret_cast<char*>(salt.data()), salt.size())) return false;
        // Restlichen Header-Bereich (96 B) lesen, um den Auth-Header (H-2) zu prüfen.
        std::vector<uint8_t> hdr(config::HDR_TOTAL - config::SALT_SIZE);
        bool have_hdr = static_cast<bool>(in.read(reinterpret_cast<char*>(hdr.data()), hdr.size()));
        in.seekg(config::HDR_TOTAL); // Sektordaten beginnen bei Offset 128

        auto kf_hash = crypto_utils::KDF::hash_keyfile(keyfile_path);
        auto master_key = derive_volume_key(password, kf_hash, salt, "normal", twofa_secret, "", false);
        auto sector_key = crypto_utils::KDF::derive_sector_key(master_key, salt);

        // H-2 / F-3: Wenn der Auth-Header-Marker vorhanden ist, Passwort+2FA SOFORT
        // verifizieren (Poly1305). Bei Fehler sauberer Abbruch, ohne Sektoren zu lesen.
        // Fehlt der Marker, ist es eine Legacy-Datei -> ohne Vorabprüfung weiter (der
        // erste Sektor-Tag erkennt ein falsches Passwort dann ebenfalls).
        if (have_hdr &&
            std::equal(config::FILE_AUTH_HDR_MARKER.begin(), config::FILE_AUTH_HDR_MARKER.end(), hdr.begin())) {
            size_t p = 4;
            std::span<const uint8_t> nonce(hdr.data() + p, config::NONCE_SIZE); p += config::NONCE_SIZE;
            size_t ct_len = config::FILE_SENTINEL_PLAIN.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
            std::string aad = "DGKN-FILE-HDR";
            std::span<const uint8_t> aad_s(reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
            std::span<const uint8_t> ct(hdr.data() + p, ct_len);
            try {
                auto pt = crypto_utils::XChaCha20::decrypt(master_key, nonce, ct, aad_s);
                bool ok = pt.size() == config::FILE_SENTINEL_PLAIN.size() &&
                          sodium_memcmp(pt.data(), config::FILE_SENTINEL_PLAIN.data(), pt.size()) == 0;
                sodium_memzero(pt.data(), pt.size());
                if (!ok) { sodium_memzero(master_key.data(), master_key.size());
                           sodium_memzero(sector_key.data(), sector_key.size()); return false; }
            } catch (...) {
                sodium_memzero(master_key.data(), master_key.size());
                sodium_memzero(sector_key.data(), sector_key.size());
                return false; // falsches Passwort/Secret oder manipulierter Header
            }
        }

        std::vector<uint8_t> ct_buffer(config::SECTOR_CT_SIZE);
        uint64_t sector_idx = 0;

        while (in) {
            uint32_t original_len = 0;
            if (!in.read(reinterpret_cast<char*>(&original_len), sizeof(original_len))) break;
            in.read(reinterpret_cast<char*>(ct_buffer.data()), ct_buffer.size());
            if (in.gcount() != static_cast<std::streamsize>(ct_buffer.size())) break;

            try {
                auto pt = crypto_utils::SectorCrypto::decrypt_sector(sector_key, sector_idx, ct_buffer);
                // H-1: original_len stammt aus der (nicht authentifizierten) Datei und
                // darf NIEMALS größer als der entschlüsselte Klartext sein — sonst läse
                // out.write() über pt hinaus (Out-of-bounds). Hart abweisen.
                if (original_len > pt.size()) {
                    sodium_memzero(pt.data(), pt.size());
                    sodium_memzero(master_key.data(), master_key.size());
                    sodium_memzero(sector_key.data(), sector_key.size());
                    return false;
                }
                out.write(reinterpret_cast<const char*>(pt.data()), original_len);
                sodium_memzero(pt.data(), pt.size());
            } catch (...) {
                sodium_memzero(master_key.data(), master_key.size());
                sodium_memzero(sector_key.data(), sector_key.size());
                return false;
            } // Manipulation oder falsches Passwort erkannt
            sector_idx++;
        }
        // H-3: abgeleitete Schlüssel nach Gebrauch sicher aus dem RAM entfernen.
        sodium_memzero(master_key.data(), master_key.size());
        sodium_memzero(sector_key.data(), sector_key.size());
        return true;
    }

} // namespace dgkn::core