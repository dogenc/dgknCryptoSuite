// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

// Fuzz-Harness für die Angreifer-kontrollierten Parser.
//
// Zwei Build-Modi:
//  1) libFuzzer (clang):   clang++ -fsanitize=fuzzer,address tests/fuzz_parsers.cpp core/Archive.cpp ...
//     -> definiert LLVMFuzzerTestOneInput; clang ruft es mit Mutations-Inputs auf.
//  2) Standalone (MSVC):   wird über DGKN_FUZZ_STANDALONE als deterministischer
//     Stress-Test gebaut (zufällige Inputs via libsodium randombytes), nutzbar in CI
//     auch ohne clang/libFuzzer. KEIN Catch2 — eigenständiges main().
//
// Ziel: keiner der Parser darf bei beliebigem Input crashen, OOB lesen oder
// unbounded allozieren. Korrektheit ist hier zweitrangig — es geht um Robustheit.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>

#include "Archive.hpp"

using namespace dgkn::core;

// Gemeinsamer Fuzz-Body: ruft alle robusten Parser auf. Darf NIE crashen.
static void fuzz_one(const uint8_t* data, size_t size) {
    std::vector<uint8_t> buf(data, data + size);

    // 1) Archive-Struktur parsen (Magic, count, Einträge, Längenfelder).
    try { (void)Archive::parse_structure(buf); } catch (...) {}

    // 2) Namens-Validierung (Traversal-Schutz) mit beliebigen Bytes als "Name".
    try {
        std::string name(reinterpret_cast<const char*>(buf.data()), buf.size());
        (void)Archive::is_safe_name(name);
    } catch (...) {}

    // 3) Entpacken in ein (nicht existierendes) Temp-Ziel — muss bounded bleiben
    //    und darf das Zielverzeichnis nie verlassen. Wir geben einen Pfad an, der
    //    sicher ist; bei korruptem Input darf nichts geschrieben/gecrasht werden.
    //    (Auskommentiert im Standalone-Modus, da es FS berührt; libFuzzer kann es
    //    aktivieren, indem DGKN_FUZZ_UNPACK gesetzt wird.)
#ifdef DGKN_FUZZ_UNPACK
    try { Archive::unpack(buf, "C:/Windows/Temp/dgkn_fuzz_out"); } catch (...) {}
#endif
}

#if defined(DGKN_FUZZ_LIBFUZZER)
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    fuzz_one(data, size);
    return 0;
}
#else
// Standalone-Stress: N zufällige Inputs verschiedener Größen.
#include <sodium.h>
#include <cstdio>
int main(int argc, char** argv) {
    if (sodium_init() < 0) return 1;
    int iters = (argc > 1) ? std::atoi(argv[1]) : 20000;
    std::vector<uint8_t> buf;
    for (int i = 0; i < iters; ++i) {
        size_t n = randombytes_uniform(4096);
        buf.resize(n);
        if (n) randombytes_buf(buf.data(), n);
        // Hin und wieder ein gültiges Archiv-Magic voranstellen, um tiefere Pfade zu treffen.
        if ((i & 7) == 0 && n >= 12) {
            std::memcpy(buf.data(), Archive::MAGIC, 8);
        }
        fuzz_one(buf.data(), buf.size());
    }
    std::printf("Fuzz-Stress OK: %d Iterationen ohne Crash.\n", iters);
    return 0;
}
#endif