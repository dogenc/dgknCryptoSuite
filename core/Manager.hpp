// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <filesystem>
#include <memory>
#include <chrono>
#include <span>
#include <functional>
#include <cstdint>

namespace dgkn::core { class VirtualVolume; }

namespace dgkn::core {

    // Repräsentiert die entschlüsselten Metadaten eines Container-Headers
    struct HeaderData {
        std::string vol_type;
        uint32_t fmt_ver;
        uint64_t data_offset;
        uint64_t data_size;
        std::vector<uint8_t> salt;
    };

    // Repräsentiert einen aktiv eingehängten Container
    struct MountInfo {
        std::string path;
        std::string mode;
        std::vector<uint8_t> master_key; // Wird beim Zerstören sicher mit sodium_memzero gelöscht
        std::vector<uint8_t> sector_key; // Wird beim Zerstören sicher mit sodium_memzero gelöscht
        std::vector<uint8_t> archive_data; // entschlüsselte Payload (im RAM); wird sicher gewiped
        uint64_t data_offset = 0;
        uint64_t data_size = 0;
        std::string mount_point;            // Laufwerksbuchstabe/Verzeichnis (falls virtuell gemountet)
        std::string label;
        std::chrono::system_clock::time_point last_activity;
        uint64_t container_size = 0;
        std::shared_ptr<VirtualVolume> volume; // virtuelles Laufwerk (WinFsp), optional

        ~MountInfo(); // Destruktor für sicheres Wiping
    };

    // Ergebnis-Typ für Operationen, die eine Meldung zurückgeben (entspricht
    // den (bool, str)-Tupeln der Python-Referenz).
    struct OpResult {
        bool ok;
        std::string message; // bei mount: bei Erfolg die mount_id
    };

    using ProgressCb = std::function<void(double)>;
    using CreateCb = std::function<void(const std::string& kind, const std::string& text, int progress)>;

    class ContainerManager {
    public:
        ContainerManager();
        ~ContainerManager() = default;

        // ─── Container-Lebenszyklus ───

        // Erstellt einen neuen Container (optional mit verstecktem Volume).
        OpResult create_container(
            const std::string& path,
            uint64_t size_mb,
            const std::string& pw_a,
            const std::string& keyfile_a = "",
            const std::string& pw_b = "",
            const std::string& keyfile_b = "",
            uint64_t hidden_mb = 0,
            const std::string& twofa_secret = "",
            const std::string& tpm_sealed_secret = "",
            bool bind_to_device = false,
            CreateCb callback = nullptr
        );

        // Authentifiziert und verifiziert den Header. Bei Erfolg ist message die
        // mount_id und der Mount-Eintrag (inkl. entschlüsselten Schlüsseln im
        // SecureBuffer-Sinn) ist registriert. Das eigentliche virtuelle Laufwerk
        // (WinFsp) wird in einer späteren Etappe angebunden.
        OpResult mount_volume(
            const std::string& container_path,
            const std::string& password,
            const std::string& keyfile_path = "",
            const std::string& mode = "normal",
            const std::string& twofa_secret = "",
            const std::string& tpm_sealed_secret = "",
            bool bind_to_device = false,
            const std::string& emergency_password = "",
            bool allow_emergency_sanitization = false,
            ProgressCb progress_cb = nullptr,
            // attach_drive=false: nur authentifizieren + Payload in den RAM laden,
            // KEIN WinFsp-Laufwerksbuchstabe (für Tests/headless/CLI ohne Admin).
            bool attach_drive = true
        );

        OpResult unmount(const std::string& mount_id, bool secure_delete = true);
        std::vector<std::tuple<std::string, bool, std::string>> unmount_all(bool secure_delete = true);
        void emergency_wipe(bool wipe_headers = false);

        // Read-only-Übersicht der aktiven Mounts für die GUI (keine Schlüssel exponiert).
        struct MountView {
            std::string mount_id;     // ID für unmount()
            std::string label;        // "NORMAL - vault.dgkn"
            std::string mount_point;  // Laufwerksbuchstabe ("X:") oder "" wenn RAM-only
            std::string mode;         // "normal" | "hidden"
            std::string path;         // Container-Pfad
        };
        std::vector<MountView> list_mounts();

        // ─── Wartung & Integrität ───

        OpResult change_password(
            const std::string& container_path,
            const std::string& old_pw, const std::string& old_keyfile,
            const std::string& new_pw, const std::string& new_keyfile,
            const std::string& mode = "normal",
            const std::string& twofa_secret = "",
            const std::string& tpm_sealed_secret = "",
            bool bind_to_device = false
        );

        OpResult check_integrity(
            const std::string& container_path,
            const std::string& password,
            const std::string& keyfile = "",
            const std::string& mode = "normal",
            const std::string& twofa_secret = "",
            const std::string& tpm_sealed_secret = "",
            bool bind_to_device = false,
            ProgressCb progress_cb = nullptr
        );

        OpResult backup_header(const std::string& container_path, const std::string& backup_path);
        OpResult restore_header(const std::string& container_path, const std::string& backup_path);

        // Einzeldateien Ver- und Entschlüsseln (Standalone CLI-Modus)
        bool encrypt_file(
            const std::string& input_path,
            const std::string& output_path,
            const std::string& password,
            const std::string& keyfile_path = "",
            const std::string& twofa_secret = ""
        );

        bool decrypt_file(
            const std::string& input_path,
            const std::string& output_path,
            const std::string& password,
            const std::string& keyfile_path = "",
            const std::string& twofa_secret = ""
        );

    private:
        // Thread-sichere Container-Verwaltung
        std::unordered_map<std::string, std::shared_ptr<MountInfo>> mounted_;
        std::mutex lock_;

        // Anti-Brute-Force & Lockout System
        std::mutex auth_lock_;
        std::unordered_map<std::string, std::vector<std::chrono::system_clock::time_point>> auth_failures_;
        std::unordered_map<std::string, std::chrono::system_clock::time_point> auth_lockouts_;

        bool tamper_detection_enabled_ = true;
        bool tpm_require_unseal_ = false;

        std::string device_binding_id();

        // ─── Interne Sicherheits- und Hilfsfunktionen ───
        
        void runtime_integrity_check();
        void trigger_self_defense(const std::string& reason);
        
        std::string pre_auth_guard(const std::string& identity);
        void auth_failed(const std::string& identity);
        void auth_success(const std::string& identity);

        // Duress/Notfall-Passwort: prüft konstant-zeit, ob das eingegebene Passwort
        // dem hinterlegten Notfall-Passwort entspricht (Argon2id mit festem Salt).
        bool is_emergency_password(const std::string& password, const std::string& emergency_password);
        // Überschreibt alle Header-Bereiche (normal + mögliche hidden-Offsets) mit Zufall.
        void sanitize_headers(const std::string& container_path);

        // Persistenter Lockout: überlebt App-Neustarts (gegen Online-Brute-Force, bei
        // dem der Angreifer die App immer wieder neu startet). Gespeichert als kleine
        // Datei pro identity; HMAC-geschützt gegen triviale Manipulation.
        std::string lockout_file_for(const std::string& identity);
        std::chrono::system_clock::time_point load_persisted_lockout(const std::string& identity);
        void persist_lockout(const std::string& identity, std::chrono::system_clock::time_point until);
        void clear_persisted_lockout(const std::string& identity);

        std::vector<uint8_t> binding_digest(
            const std::string& twofa_secret,
            const std::string& tpm_sealed_secret,
            bool bind_to_device
        );

        std::vector<uint8_t> derive_volume_key(
            const std::string& password,
            std::span<const uint8_t> keyfile_hash,
            std::span<const uint8_t> salt,
            const std::string& mode,
            const std::string& twofa_secret,
            const std::string& tpm_sealed_secret,
            bool bind_to_device
        );

        std::vector<uint8_t> hidden_scan_seed(
            const std::string& password,
            std::span<const uint8_t> keyfile_hash,
            const std::string& twofa_secret,
            const std::string& tpm_sealed_secret,
            bool bind_to_device
        );

        // ─── Header I/O ───

        struct RawHeader {
            std::vector<uint8_t> salt;
            std::vector<uint8_t> nonce;
            std::vector<uint8_t> encrypted_block;
        };

        bool read_header_raw(std::istream& f, uint64_t offset, RawHeader& out_header);

        std::pair<bool, HeaderData> decrypt_and_verify_header(
            const RawHeader& raw,
            std::span<const uint8_t> master_key
        );

        // Schreibt einen vollständig verschlüsselten Header an offset.
        void write_header(std::ostream& f, uint64_t offset, const std::string& vol_type,
                          std::span<const uint8_t> master_key,
                          uint64_t data_offset, uint64_t data_size,
                          std::span<const uint8_t> salt);

        std::vector<uint64_t> scan_hidden(uint64_t fsize, std::span<const uint8_t> seed = {});

        // ─── Journal (.txn) ───
        std::string txn_path(const std::string& container_path);
        std::vector<uint8_t> journal_key(const std::string& container_path);
        std::string journal_hmac(const std::string& container_path, std::span<const uint8_t> payload);
        void write_unmount_txn(const std::string& container_path, const std::string& json_text);
        void clear_unmount_txn(const std::string& container_path);
        OpResult recover_unmount_txn(const std::string& container_path);

        // ─── Mount-Verzeichnisse ───
        std::string mount_root_dir();
        std::string create_mount_dir(const std::string& mode);

        // Findet einen freien Laufwerksbuchstaben ("Z:" → "Y:" ...), oder "" wenn keiner frei.
        std::string find_free_drive_letter();
    };

} // namespace dgkn::core