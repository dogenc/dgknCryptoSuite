// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>

#include "Archive.hpp"
#include "VirtualVolume.hpp"

namespace fs = std::filesystem;
using dgkn::core::Archive;
using dgkn::core::ArchiveNode;
using dgkn::core::VirtualVolume;

namespace {
    struct TempDir {
        fs::path p;
        TempDir() {
            p = fs::temp_directory_path() / ("dgkn_arc_" + std::to_string(std::rand()));
            fs::create_directories(p);
        }
        ~TempDir() { std::error_code ec; fs::remove_all(p, ec); }
    };

    void write_file(const fs::path& path, const std::string& content) {
        fs::create_directories(path.parent_path());
        std::ofstream f(path, std::ios::binary);
        f.write(content.data(), content.size());
    }
}

TEST_CASE("Archive pack -> parse_structure roundtrip", "[archive]") {
    TempDir src;
    write_file(src.p / "hello.txt", "Hallo Welt");
    write_file(src.p / "sub" / "data.bin", std::string("\x00\x01\x02\x03", 4));
    fs::create_directories(src.p / "leer");

    auto blob = Archive::pack(src.p.string());
    REQUIRE(blob.size() >= 12);
    REQUIRE(std::memcmp(blob.data(), Archive::MAGIC, 8) == 0);

    auto st = Archive::parse_structure(blob);
    REQUIRE(st.count("hello.txt") == 1);
    REQUIRE(st["hello.txt"].type == 'F');
    REQUIRE(st["hello.txt"].size == 10);
    REQUIRE(st.count("sub/data.bin") == 1);
    REQUIRE(st["sub/data.bin"].size == 4);
    REQUIRE(st.count("sub") == 1);
    REQUIRE(st["sub"].type == 'D');
    REQUIRE(st.count("leer") == 1);
}

TEST_CASE("Archive pack -> unpack roundtrip restores content", "[archive]") {
    TempDir src, dst;
    write_file(src.p / "a.txt", "AAA");
    write_file(src.p / "dir" / "b.txt", "BBBB");

    auto blob = Archive::pack(src.p.string());
    Archive::unpack(blob, dst.p.string());

    REQUIRE(fs::exists(dst.p / "a.txt"));
    REQUIRE(fs::exists(dst.p / "dir" / "b.txt"));
    std::ifstream f(dst.p / "dir" / "b.txt", std::ios::binary);
    std::string s((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(s == "BBBB");
}

TEST_CASE("is_safe_name rejects traversal and absolute paths", "[archive][security]") {
    REQUIRE(Archive::is_safe_name("ok/file.txt"));
    REQUIRE(Archive::is_safe_name("nested/deep/x"));
    REQUIRE_FALSE(Archive::is_safe_name("../escape"));
    REQUIRE_FALSE(Archive::is_safe_name("a/../../etc/passwd"));
    REQUIRE_FALSE(Archive::is_safe_name("/abs/path"));
    REQUIRE_FALSE(Archive::is_safe_name("C:/windows/system32"));
    REQUIRE_FALSE(Archive::is_safe_name("back\\slash"));
    REQUIRE_FALSE(Archive::is_safe_name(std::string("nul\0byte", 8)));
    REQUIRE_FALSE(Archive::is_safe_name(""));
}

TEST_CASE("unpack never escapes the destination directory", "[archive][security]") {
    TempDir dst;
    // Manuell ein bösartiges Archiv bauen: eine 'F'-Entry mit Traversal-Namen.
    std::vector<uint8_t> blob(Archive::MAGIC, Archive::MAGIC + 8);
    auto put32 = [&](uint32_t x){ blob.push_back(x>>24); blob.push_back(x>>16); blob.push_back(x>>8); blob.push_back(x); };
    auto put16 = [&](uint16_t x){ blob.push_back(x>>8); blob.push_back(x); };
    put32(1); // count
    std::string evil = "../../pwned.txt";
    blob.push_back('F');
    put16((uint16_t)evil.size());
    blob.insert(blob.end(), evil.begin(), evil.end());
    std::string content = "owned";
    put32((uint32_t)content.size());
    blob.insert(blob.end(), content.begin(), content.end());

    Archive::unpack(blob, dst.p.string());

    // Die Datei darf NICHT außerhalb von dst entstanden sein.
    fs::path escaped = dst.p.parent_path() / "pwned.txt";
    REQUIRE_FALSE(fs::exists(escaped));
}

TEST_CASE("VirtualVolume serialize roundtrip (no mount)", "[archive][virtualvolume]") {
    TempDir src;
    write_file(src.p / "hello.txt", "Hallo Welt");
    write_file(src.p / "sub" / "data.bin", std::string("\x00\x01\x02\x03", 4));
    fs::create_directories(src.p / "leer");

    // Blob packen, in VirtualVolume laden, ohne Mount wieder serialisieren.
    auto blob = Archive::pack(src.p.string());
    VirtualVolume v(blob, "TEST");
    auto out = v.serialize();

    // Ergebnis muss ein gueltiges Archive-Blob sein.
    REQUIRE(out.size() >= 12);
    REQUIRE(std::memcmp(out.data(), Archive::MAGIC, 8) == 0);

    // Inhalt muss erhalten bleiben (Struktur + Dateigroessen).
    auto st = Archive::parse_structure(out);
    REQUIRE(st.count("hello.txt") == 1);
    REQUIRE(st["hello.txt"].type == 'F');
    REQUIRE(st["hello.txt"].size == 10);
    REQUIRE(st.count("sub/data.bin") == 1);
    REQUIRE(st["sub/data.bin"].size == 4);
    REQUIRE(st.count("sub") == 1);
    REQUIRE(st["sub"].type == 'D');
    REQUIRE(st.count("leer") == 1);
    REQUIRE(st["leer"].type == 'D');

    // Datei-Bytes muessen via Offset im neuen Blob exakt wiederherstellbar sein.
    const auto& fn = st["hello.txt"];
    std::string content(reinterpret_cast<const char*>(out.data() + fn.offset), fn.size);
    REQUIRE(content == "Hallo Welt");
}

TEST_CASE("empty archive parses to nothing", "[archive]") {
    auto e = Archive::empty_archive();
    auto st = Archive::parse_structure(e);
    REQUIRE(st.empty());
}