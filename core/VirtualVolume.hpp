// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <vector>
#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <cstdint>

// FUSE-Typen global vorwaerts deklarieren, damit die Op-Signaturen exakt zu den
// (globalen) WinFsp-Typen passen — NICHT im dgkn::core-Namespace.
struct fuse_stat;
struct fuse_statvfs;
struct fuse_file_info;
struct fuse_conn_info;

namespace dgkn::core {

    // VirtualVolume praesentiert ein entschluesseltes Archiv-Blob als echtes
    // Windows-Laufwerk (WinFsp/FUSE). Alle Dateiinhalte leben ausschliesslich im
    // RAM — es landet kein Klartext auf der Platte. Schreibzugriffe mutieren nur
    // den In-RAM-Zustand; serialize() packt diesen wieder ins Archive-Format,
    // damit der Aufrufer ihn verschluesselt zurueckschreiben kann.
    class VirtualVolume {
    public:
        // archive_blob: entschluesseltes Archiv (DGKN5ARC-Format).
        // label: Volume-Bezeichnung (z.B. fuer Anzeige im Explorer).
        // capacity_bytes: angezeigte Gesamtkapazitaet des Laufwerks (statfs). 0 = Default
        //   (Fallback 4 GiB). Sollte dem echten Datenbereich des Containers entsprechen,
        //   damit der Explorer die korrekte Groesse zeigt.
        VirtualVolume(std::vector<uint8_t> archive_blob, std::string label,
                      uint64_t capacity_bytes = 0);
        ~VirtualVolume();

        VirtualVolume(const VirtualVolume&) = delete;
        VirtualVolume& operator=(const VirtualVolume&) = delete;

        // Mountet das In-RAM-FS in einem Hintergrund-Thread. mount_point kann ein
        // Laufwerksbuchstabe ("Z:") oder ein (leeres) Verzeichnis sein.
        // Rueckgabe: ob der Mount initiiert werden konnte.
        bool mount(const std::string& mount_point);

        // Beendet die FUSE-Loop sauber und joint den Hintergrund-Thread.
        void unmount();

        // Ist das FS aktuell gemountet (Loop laeuft)?
        bool is_mounted() const { return mounted_.load(); }

        // Packt den AKTUELLEN In-RAM-Zustand zurueck in ein Archive-Blob.
        std::vector<uint8_t> serialize();

    private:
        // Ein In-RAM-Knoten (Datei oder Verzeichnis).
        struct Node {
            bool is_dir = false;
            std::vector<uint8_t> data;   // nur fuer Dateien relevant
        };

        // FUSE-Operationen (statisch; greifen via fuse_get_context()->private_data
        // auf die Instanz zu).
        static int op_getattr(const char* path, ::fuse_stat* st);
        static int op_readdir(const char* path, void* buf, void* filler,
                              long long off, ::fuse_file_info* fi);
        static int op_open(const char* path, ::fuse_file_info* fi);
        static int op_create(const char* path, unsigned int mode, ::fuse_file_info* fi);
        static int op_read(const char* path, char* buf, size_t size, long long off,
                           ::fuse_file_info* fi);
        static int op_write(const char* path, const char* buf, size_t size, long long off,
                            ::fuse_file_info* fi);
        static int op_truncate(const char* path, long long size);
        static int op_unlink(const char* path);
        static int op_mkdir(const char* path, unsigned int mode);
        static int op_rmdir(const char* path);
        static int op_rename(const char* oldp, const char* newp);
        static int op_statfs(const char* path, ::fuse_statvfs* st);

        // Helfer (mit gehaltenem Lock aufrufen).
        static std::string normalize(const char* path);   // "/sub/x" -> "sub/x"
        bool node_exists(const std::string& key) const;
        bool dir_has_children(const std::string& key) const;

        std::map<std::string, Node> nodes_;   // Key: '/'-getrennter relativer Pfad ("" = root)
        std::string label_;
        std::string mount_point_;             // Laufwerksbuchstabe ("Z:"); fuer sauberen Abbau
        uint64_t capacity_bytes_ = 0;         // angezeigte Gesamtkapazitaet (statfs); 0 = Default
        mutable std::mutex mtx_;

        std::thread loop_thread_;
        std::atomic<bool> mounted_{false};
        std::atomic<bool> loop_done_{false};  // FUSE-Loop im Thread beendet
        void* fuse_handle_ = nullptr;         // struct fuse* (in init() gesetzt)
        std::mutex handle_mtx_;
    };

}