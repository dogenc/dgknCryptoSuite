// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "FsHelpers.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace dgkn::utils {

namespace {
    constexpr size_t CHUNK = 65536;

    // Erzwingt das Schreiben der OS-Puffer auf den Datenträger.
    void flush_to_disk(std::FILE* fp) {
        std::fflush(fp);
#if defined(_WIN32)
        _commit(_fileno(fp));
#else
        ::fsync(::fileno(fp));
#endif
    }
}

void secure_wipe_file(const std::string& path, int passes) {
    std::error_code ec;

    if (fs::is_symlink(path, ec)) {
        fs::remove(path, ec);
        return;
    }

    const auto size = fs::file_size(path, ec);
    if (ec) {
        fs::remove(path, ec);
        return;
    }

    std::FILE* fp = nullptr;
#if defined(_WIN32)
    if (fopen_s(&fp, path.c_str(), "r+b") != 0) fp = nullptr;
#else
    fp = std::fopen(path.c_str(), "r+b");
#endif
    if (!fp) {
        fs::remove(path, ec);
        return;
    }

    std::array<uint8_t, CHUNK> buf{};
    for (int p = 0; p < passes; ++p) {
        if (std::fseek(fp, 0, SEEK_SET) != 0) break;
        uintmax_t written = 0;
        while (written < size) {
            const size_t chunk = static_cast<size_t>(
                std::min<uintmax_t>(CHUNK, size - written));
            randombytes_buf(buf.data(), chunk);
            if (std::fwrite(buf.data(), 1, chunk, fp) != chunk) {
                p = passes; // Abbruch der äußeren Schleife
                break;
            }
            written += chunk;
        }
        flush_to_disk(fp);
    }

    std::fclose(fp);
    fs::remove(path, ec);
}

void secure_wipe_dir(const std::string& path) {
    std::error_code ec;
    if (!fs::exists(path, ec)) return;

    // Bottom-up: erst Dateien überschreiben, dann leere Verzeichnisse entfernen.
    std::vector<fs::path> dirs;
    for (auto it = fs::recursive_directory_iterator(
             path, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        const auto& entry = *it;
        std::error_code st_ec;
        if (entry.is_directory(st_ec)) {
            dirs.push_back(entry.path());
        } else {
            secure_wipe_file(entry.path().string(), 1);
        }
    }

    for (auto rit = dirs.rbegin(); rit != dirs.rend(); ++rit) {
        fs::remove(*rit, ec);
    }
    fs::remove(path, ec);
}

}