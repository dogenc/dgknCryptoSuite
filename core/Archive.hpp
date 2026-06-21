// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include <span>

namespace dgkn::core {

    // Ein Eintrag in der geparsten Archivstruktur. offset/size beziehen sich auf
    // den File-Datenbereich (nur für reguläre Dateien relevant).
    struct ArchiveNode {
        char type;        // 'F' Datei, 'D' Verzeichnis
        uint64_t offset;  // Offset der Dateidaten innerhalb der gepackten Daten
        uint64_t size;    // Größe der Dateidaten
    };

    // Archiv-Containerformat (im entschlüsselten Payload):
    //
    //   "DGKN5ARC" (8) | entry_count (u32 BE) | Entry*
    //   Entry: tag (1, 'F'|'D') | name_len (u16 BE) | name (UTF-8, '/'-getrennt)
    //          [ falls 'F': data_len (u32 BE) | data ]
    //
    // Sicherheitsmerkmale:
    //  - Pfadnamen werden gegen Traversal ('..', absolute Pfade, Laufwerksbuchstaben,
    //    NUL/Backslash) validiert; bösartige Einträge werden verworfen.
    //  - Größenlimits aus Config (MAX_ARCHIVE_NAME_LEN, MAX_ARCHIVE_FILE_SIZE,
    //    MAX_ARCHIVE_TOTAL_SIZE) werden durchgesetzt.
    class Archive {
    public:
        static constexpr char MAGIC[8] = {'D','G','K','N','5','A','R','C'};

        // Packt ein Verzeichnis rekursiv in ein Archiv-Blob.
        static std::vector<uint8_t> pack(const std::string& directory);

        // Entpackt ein Archiv-Blob in ein Zielverzeichnis (Traversal-sicher).
        static void unpack(std::span<const uint8_t> data, const std::string& directory);

        // Liest die Struktur (Namen -> Node) ohne Dateidaten zu kopieren.
        // map (sortiert) für deterministische Reihenfolge im virtuellen Laufwerk.
        static std::map<std::string, ArchiveNode> parse_structure(std::span<const uint8_t> data);

        // Erzeugt ein leeres, gültiges Archiv ("DGKN5ARC" + count=0).
        static std::vector<uint8_t> empty_archive();

        // Prüft, ob ein (relativer) Eintragsname sicher ist (kein Traversal).
        static bool is_safe_name(const std::string& name);
    };

}