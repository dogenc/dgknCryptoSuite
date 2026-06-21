// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "Archive.hpp"
#include "../Config.hpp"

#include <filesystem>
#include <fstream>
#include <cstring>
#include <algorithm>

namespace fs = std::filesystem;

namespace dgkn::core {

    namespace {
        void put_u16_be(std::vector<uint8_t>& v, uint16_t x) {
            v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
            v.push_back(static_cast<uint8_t>(x & 0xFF));
        }
        void put_u32_be(std::vector<uint8_t>& v, uint32_t x) {
            v.push_back(static_cast<uint8_t>((x >> 24) & 0xFF));
            v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
            v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
            v.push_back(static_cast<uint8_t>(x & 0xFF));
        }
        uint16_t get_u16_be(std::span<const uint8_t> d, size_t p) {
            return static_cast<uint16_t>((d[p] << 8) | d[p + 1]);
        }
        uint32_t get_u32_be(std::span<const uint8_t> d, size_t p) {
            return (static_cast<uint32_t>(d[p]) << 24) | (static_cast<uint32_t>(d[p + 1]) << 16)
                 | (static_cast<uint32_t>(d[p + 2]) << 8) | static_cast<uint32_t>(d[p + 3]);
        }
    }

    bool Archive::is_safe_name(const std::string& name) {
        if (name.empty() || name.size() > config::MAX_ARCHIVE_NAME_LEN) return false;
        if (name.find('\0') != std::string::npos) return false;
        if (name.find('\\') != std::string::npos) return false;   // nur '/' als Trenner
        if (name.front() == '/') return false;                    // kein absoluter Pfad
        if (name.size() >= 2 && name[1] == ':') return false;     // kein Laufwerksbuchstabe
        size_t start = 0;
        while (true) {
            size_t slash = name.find('/', start);
            std::string comp = (slash == std::string::npos)
                ? name.substr(start) : name.substr(start, slash - start);
            if (comp == ".." || comp == ".") return false;        // Traversal / leere Komponente
            if (slash == std::string::npos) break;
            start = slash + 1;
        }
        return true;
    }

    std::vector<uint8_t> Archive::empty_archive() {
        std::vector<uint8_t> out(MAGIC, MAGIC + 8);
        put_u32_be(out, 0);
        return out;
    }

    std::vector<uint8_t> Archive::pack(const std::string& directory) {
        fs::path base(directory);
        std::error_code ec;
        if (!fs::exists(base, ec) || !fs::is_directory(base, ec)) return empty_archive();

        std::vector<fs::directory_entry> entries;
        for (auto it = fs::recursive_directory_iterator(
                 base, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            entries.push_back(*it);
        }
        std::sort(entries.begin(), entries.end(),
                  [](const fs::directory_entry& a, const fs::directory_entry& b) {
                      return a.path().generic_string() < b.path().generic_string();
                  });

        std::vector<uint8_t> body;
        uint32_t count = 0;
        uint64_t total = 0;

        for (const auto& e : entries) {
            std::error_code st;
            fs::path rel = fs::relative(e.path(), base, st);
            if (st) continue;
            std::string name = rel.generic_string();
            if (!is_safe_name(name) || name.size() > 0xFFFF) continue;

            if (e.is_directory(st)) {
                body.push_back('D');
                put_u16_be(body, static_cast<uint16_t>(name.size()));
                body.insert(body.end(), name.begin(), name.end());
                ++count;
            } else if (e.is_regular_file(st)) {
                uintmax_t fsz = fs::file_size(e.path(), st);
                if (st || fsz > config::MAX_ARCHIVE_FILE_SIZE) continue;
                if (total + fsz > config::MAX_ARCHIVE_TOTAL_SIZE) break;

                std::ifstream f(e.path(), std::ios::binary);
                if (!f) continue;
                std::vector<uint8_t> fdata(static_cast<size_t>(fsz));
                if (fsz > 0) f.read(reinterpret_cast<char*>(fdata.data()), fsz);

                body.push_back('F');
                put_u16_be(body, static_cast<uint16_t>(name.size()));
                body.insert(body.end(), name.begin(), name.end());
                put_u32_be(body, static_cast<uint32_t>(fdata.size()));
                body.insert(body.end(), fdata.begin(), fdata.end());
                total += fsz;
                ++count;
            }
        }

        std::vector<uint8_t> out(MAGIC, MAGIC + 8);
        put_u32_be(out, count);
        out.insert(out.end(), body.begin(), body.end());
        return out;
    }

    std::map<std::string, ArchiveNode> Archive::parse_structure(std::span<const uint8_t> data) {
        std::map<std::string, ArchiveNode> structure;
        if (data.size() < 12 || std::memcmp(data.data(), MAGIC, 8) != 0) return structure;

        uint32_t count = get_u32_be(data, 8);
        size_t p = 12;
        uint32_t parsed = 0;

        while (p < data.size() && parsed < count) {
            char tag = static_cast<char>(data[p++]);
            if (p + 2 > data.size()) break;
            uint16_t name_len = get_u16_be(data, p); p += 2;
            if (name_len == 0 || p + name_len > data.size()) break;
            std::string name(reinterpret_cast<const char*>(&data[p]), name_len);
            p += name_len;

            if (tag == 'F') {
                if (p + 4 > data.size()) break;
                uint32_t data_len = get_u32_be(data, p); p += 4;
                if (p + data_len > data.size()) break;
                if (is_safe_name(name)) structure[name] = {'F', static_cast<uint64_t>(p), data_len};
                p += data_len;
            } else if (tag == 'D') {
                if (is_safe_name(name)) structure[name] = {'D', 0, 0};
            } else {
                break; // unbekanntes Tag -> Format korrupt
            }
            ++parsed;
        }
        return structure;
    }

    void Archive::unpack(std::span<const uint8_t> data, const std::string& directory) {
        if (data.size() < 12 || std::memcmp(data.data(), MAGIC, 8) != 0) return;
        fs::path base(directory);
        std::error_code ec;
        fs::create_directories(base, ec);
        fs::path base_norm = base.lexically_normal();

        uint32_t count = get_u32_be(data, 8);
        size_t p = 12;
        uint32_t parsed = 0;

        while (p < data.size() && parsed < count) {
            char tag = static_cast<char>(data[p++]);
            if (p + 2 > data.size()) break;
            uint16_t name_len = get_u16_be(data, p); p += 2;
            if (name_len == 0 || p + name_len > data.size()) break;
            std::string name(reinterpret_cast<const char*>(&data[p]), name_len);
            p += name_len;

            uint32_t data_len = 0;
            const uint8_t* fdata = nullptr;
            if (tag == 'F') {
                if (p + 4 > data.size()) break;
                data_len = get_u32_be(data, p); p += 4;
                if (p + data_len > data.size()) break;
                fdata = &data[p];
                p += data_len;
            } else if (tag != 'D') {
                break;
            }
            ++parsed;

            if (!is_safe_name(name)) continue;

            // Zielpfad absichern: muss innerhalb base bleiben (zweite Verteidigungslinie).
            fs::path dest_norm = (base / fs::path(name)).lexically_normal();
            auto mm = std::mismatch(base_norm.begin(), base_norm.end(), dest_norm.begin());
            if (mm.first != base_norm.end()) continue;

            if (tag == 'D') {
                fs::create_directories(dest_norm, ec);
            } else {
                fs::create_directories(dest_norm.parent_path(), ec);
                std::ofstream of(dest_norm, std::ios::binary | std::ios::trunc);
                if (of && data_len > 0) of.write(reinterpret_cast<const char*>(fdata), data_len);
            }
        }
    }

}