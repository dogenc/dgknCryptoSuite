// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#define _CRT_SECURE_NO_WARNINGS

#include "VirtualVolume.hpp"
#include "Archive.hpp"

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <chrono>

namespace dgkn::core {

    // ── Helfer: Pfadnormalisierung (FUSE-Pfad "/a/b" -> Archive-Key "a/b") ──
    std::string VirtualVolume::normalize(const char* path) {
        if (!path) return "";
        std::string s(path);
        // Backslashes vereinheitlichen, fuehrenden Slash entfernen.
        std::replace(s.begin(), s.end(), '\\', '/');
        while (!s.empty() && s.front() == '/') s.erase(s.begin());
        while (!s.empty() && s.back() == '/') s.pop_back();
        return s;
    }

    bool VirtualVolume::node_exists(const std::string& key) const {
        return nodes_.find(key) != nodes_.end();
    }

    bool VirtualVolume::dir_has_children(const std::string& key) const {
        const std::string prefix = key.empty() ? "" : key + "/";
        for (const auto& [k, _] : nodes_) {
            if (k == key) continue;
            if (k.compare(0, prefix.size(), prefix) == 0) return true;
        }
        return false;
    }

    // ── Konstruktor: Blob in In-RAM-Struktur ueberfuehren ──
    VirtualVolume::VirtualVolume(std::vector<uint8_t> archive_blob, std::string label,
                                 uint64_t capacity_bytes)
        : label_(std::move(label)), capacity_bytes_(capacity_bytes) {
        // Root immer vorhanden.
        nodes_[""] = Node{true, {}};

        auto structure = Archive::parse_structure(archive_blob);
        for (const auto& [name, an] : structure) {
            Node n;
            if (an.type == 'D') {
                n.is_dir = true;
            } else {
                n.is_dir = false;
                // Dateidaten liegen bei [offset, offset+size) im Blob.
                if (an.offset + an.size <= archive_blob.size()) {
                    n.data.assign(archive_blob.begin() + static_cast<size_t>(an.offset),
                                  archive_blob.begin() + static_cast<size_t>(an.offset + an.size));
                }
            }
            // Eltern-Verzeichnisse implizit anlegen (falls nicht als 'D' vorhanden).
            std::string acc;
            size_t start = 0;
            while (true) {
                size_t slash = name.find('/', start);
                if (slash == std::string::npos) break;
                acc = name.substr(0, slash);
                if (!node_exists(acc)) nodes_[acc] = Node{true, {}};
                start = slash + 1;
            }
            nodes_[name] = std::move(n);
        }
    }

    VirtualVolume::~VirtualVolume() {
        unmount();
    }

    // ── serialize(): aktuellen In-RAM-Zustand zurueck ins Archive-Format ──
    // Wir bauen das DGKN5ARC-Format hier direkt, da Archive::pack ein echtes
    // Verzeichnis erwartet — wir wollen aber kein Klartext-Temp auf Disk.
    std::vector<uint8_t> VirtualVolume::serialize() {
        std::lock_guard<std::mutex> lk(mtx_);

        auto put_u16 = [](std::vector<uint8_t>& v, uint16_t x) {
            v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
            v.push_back(static_cast<uint8_t>(x & 0xFF));
        };
        auto put_u32 = [](std::vector<uint8_t>& v, uint32_t x) {
            v.push_back(static_cast<uint8_t>((x >> 24) & 0xFF));
            v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
            v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
            v.push_back(static_cast<uint8_t>(x & 0xFF));
        };

        std::vector<uint8_t> body;
        uint32_t count = 0;

        for (const auto& [name, node] : nodes_) {
            if (name.empty()) continue;                 // Root nicht serialisieren
            if (!Archive::is_safe_name(name)) continue;  // Defensive
            if (name.size() > 0xFFFF) continue;

            if (node.is_dir) {
                body.push_back('D');
                put_u16(body, static_cast<uint16_t>(name.size()));
                body.insert(body.end(), name.begin(), name.end());
                ++count;
            } else {
                body.push_back('F');
                put_u16(body, static_cast<uint16_t>(name.size()));
                body.insert(body.end(), name.begin(), name.end());
                put_u32(body, static_cast<uint32_t>(node.data.size()));
                body.insert(body.end(), node.data.begin(), node.data.end());
                ++count;
            }
        }

        std::vector<uint8_t> out(Archive::MAGIC, Archive::MAGIC + 8);
        put_u32(out, count);
        out.insert(out.end(), body.begin(), body.end());
        return out;
    }

}

#ifdef DGKN_HAVE_WINFSP

// ── FUSE / WinFsp-Integration ──
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>   // GetFileAttributesA für die Mount-Sichtbarkeitsprüfung
#endif
#include <fuse/fuse.h>
#include <sys/stat.h>
#include <errno.h>
#include <cstdarg>

namespace dgkn::core {

    // Mount-Diagnose-Log.
    //
    // SICHERHEIT: In der ausgelieferten App ist dieses Log DEAKTIVIERT (No-Op). Ein
    // dauerhaftes Klartext-Log in %TEMP% ist in einem Tool mit Hidden-Volumes gefaehrlich:
    // es wuerde Laufwerksbuchstaben UND Volume-Labels (z. B. "HIDDEN - vault.dgkn") auf die
    // Platte schreiben und damit die Existenz eines versteckten Volumes forensisch beweisen
    // — genau die plausible deniability, die GUI und Unmount-Dialog schuetzen, waere ueber
    // eine Logdatei ausgehebelt. Daher schreibt mlog() nichts, ausser ein Entwickler baut
    // explizit mit -DDGKN_MOUNT_DIAG. Selbst dann werden NIE Pfade, Laufwerksbuchstaben
    // oder Labels geloggt (die betroffenen Aufrufe wurden entsprechend entschaerft).
#if defined(_WIN32) && defined(DGKN_MOUNT_DIAG)
    static void mlog(const char* fmt, ...) {
        char path[MAX_PATH]; DWORD n = ::GetTempPathA(MAX_PATH, path);
        if (n == 0 || n > MAX_PATH) return;
        std::string fn = std::string(path) + "dgkn_mount.log";
        FILE* f = std::fopen(fn.c_str(), "a");
        if (!f) return;
        SYSTEMTIME st; ::GetLocalTime(&st);
        std::fprintf(f, "%02d:%02d:%02d.%03d  ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_list ap; va_start(ap, fmt); std::vfprintf(f, fmt, ap); va_end(ap);
        std::fprintf(f, "\n"); std::fclose(f);
    }
#else
    static void mlog(const char*, ...) {}
#endif

    namespace {
        // Zugriff auf die aktive Instanz aus den statischen Ops.
        VirtualVolume* self() {
            return static_cast<VirtualVolume*>(fuse_get_context()->private_data);
        }
    }

    int VirtualVolume::op_getattr(const char* path, ::fuse_stat* st) {
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);
        std::string key = normalize(path);
        auto it = v->nodes_.find(key);
        if (it == v->nodes_.end()) return -ENOENT;

        std::memset(st, 0, sizeof(*st));
        // Voll beschreibbare Rechte (0777/0666). WinFsp bildet die Unix-Mode-Bits auf
        // Windows-ACLs ab: mit 0755/0644 fehlt dem zugreifenden Nutzer das Schreibrecht,
        // wodurch der Explorer "Zugriff auf den Zielordner wurde verweigert" meldet.
        // Das Volume lebt ohnehin nur im RAM dieser Session — restriktive Mode-Bits
        // bringen hier keinen Schutz, verhindern aber das Befuellen.
        if (it->second.is_dir) {
            st->st_mode = S_IFDIR | 0777;
            st->st_nlink = 2;
        } else {
            st->st_mode = S_IFREG | 0666;
            st->st_nlink = 1;
            st->st_size = static_cast<fuse_off_t>(it->second.data.size());
        }
        return 0;
    }

    int VirtualVolume::op_readdir(const char* path, void* buf, void* filler_v,
                                  long long /*off*/, ::fuse_file_info* /*fi*/) {
        auto filler = reinterpret_cast<fuse_fill_dir_t>(filler_v);
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);
        std::string key = normalize(path);
        auto it = v->nodes_.find(key);
        if (it == v->nodes_.end() || !it->second.is_dir) return -ENOENT;

        filler(buf, ".", nullptr, 0);
        filler(buf, "..", nullptr, 0);

        const std::string prefix = key.empty() ? "" : key + "/";
        for (const auto& [k, node] : v->nodes_) {
            if (k.empty() || k == key) continue;
            if (k.compare(0, prefix.size(), prefix) != 0) continue;
            std::string rest = k.substr(prefix.size());
            if (rest.find('/') != std::string::npos) continue;  // nur direkte Kinder
            if (rest.empty()) continue;
            filler(buf, rest.c_str(), nullptr, 0);
        }
        return 0;
    }

    int VirtualVolume::op_open(const char* path, ::fuse_file_info* /*fi*/) {
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);
        auto it = v->nodes_.find(normalize(path));
        if (it == v->nodes_.end()) return -ENOENT;
        if (it->second.is_dir) return -EISDIR;
        return 0;
    }

    int VirtualVolume::op_create(const char* path, unsigned int /*mode*/,
                                 ::fuse_file_info* /*fi*/) {
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);
        std::string key = normalize(path);
        if (key.empty()) return -EEXIST;
        if (!Archive::is_safe_name(key)) return -EACCES;
        v->nodes_[key] = Node{false, {}};
        return 0;
    }

    int VirtualVolume::op_read(const char* path, char* buf, size_t size, long long off,
                               ::fuse_file_info* /*fi*/) {
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);
        auto it = v->nodes_.find(normalize(path));
        if (it == v->nodes_.end() || it->second.is_dir) return -ENOENT;

        const auto& d = it->second.data;
        if (off < 0 || static_cast<size_t>(off) >= d.size()) return 0;
        size_t avail = d.size() - static_cast<size_t>(off);
        size_t n = std::min(size, avail);
        std::memcpy(buf, d.data() + off, n);
        return static_cast<int>(n);
    }

    int VirtualVolume::op_write(const char* path, const char* buf, size_t size, long long off,
                                ::fuse_file_info* /*fi*/) {
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);
        auto it = v->nodes_.find(normalize(path));
        if (it == v->nodes_.end() || it->second.is_dir) return -ENOENT;
        if (off < 0) return -EINVAL;

        auto& d = it->second.data;
        size_t end = static_cast<size_t>(off) + size;
        if (end > d.size()) d.resize(end);
        std::memcpy(d.data() + off, buf, size);
        return static_cast<int>(size);
    }

    int VirtualVolume::op_truncate(const char* path, long long size) {
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);
        auto it = v->nodes_.find(normalize(path));
        if (it == v->nodes_.end() || it->second.is_dir) return -ENOENT;
        if (size < 0) return -EINVAL;
        it->second.data.resize(static_cast<size_t>(size));
        return 0;
    }

    int VirtualVolume::op_unlink(const char* path) {
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);
        auto it = v->nodes_.find(normalize(path));
        if (it == v->nodes_.end()) return -ENOENT;
        if (it->second.is_dir) return -EISDIR;
        v->nodes_.erase(it);
        return 0;
    }

    int VirtualVolume::op_mkdir(const char* path, unsigned int /*mode*/) {
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);
        std::string key = normalize(path);
        if (key.empty()) return -EEXIST;
        if (!Archive::is_safe_name(key)) return -EACCES;
        if (v->node_exists(key)) return -EEXIST;
        v->nodes_[key] = Node{true, {}};
        return 0;
    }

    int VirtualVolume::op_rmdir(const char* path) {
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);
        std::string key = normalize(path);
        auto it = v->nodes_.find(key);
        if (it == v->nodes_.end()) return -ENOENT;
        if (!it->second.is_dir) return -ENOTDIR;
        if (v->dir_has_children(key)) return -ENOTEMPTY;
        v->nodes_.erase(it);
        return 0;
    }

    int VirtualVolume::op_rename(const char* oldp, const char* newp) {
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);
        std::string okey = normalize(oldp);
        std::string nkey = normalize(newp);
        if (okey.empty() || nkey.empty()) return -EINVAL;
        if (!Archive::is_safe_name(nkey)) return -EACCES;
        auto it = v->nodes_.find(okey);
        if (it == v->nodes_.end()) return -ENOENT;

        const std::string oprefix = okey + "/";
        const std::string nprefix = nkey + "/";

        // Knoten + alle Nachfahren umbenennen (rekursiv bei Verzeichnis).
        std::map<std::string, Node> moved;
        for (auto i = v->nodes_.begin(); i != v->nodes_.end();) {
            if (i->first == okey) {
                moved[nkey] = std::move(i->second);
                i = v->nodes_.erase(i);
            } else if (i->first.compare(0, oprefix.size(), oprefix) == 0) {
                std::string sub = i->first.substr(oprefix.size());
                moved[nprefix + sub] = std::move(i->second);
                i = v->nodes_.erase(i);
            } else {
                ++i;
            }
        }
        for (auto& [k, n] : moved) v->nodes_[k] = std::move(n);
        return 0;
    }

    int VirtualVolume::op_statfs(const char* /*path*/, ::fuse_statvfs* st) {
        VirtualVolume* v = self();
        std::lock_guard<std::mutex> lk(v->mtx_);

        uint64_t used = 0, files = 0;
        for (const auto& [k, node] : v->nodes_) {
            if (k.empty()) continue;
            ++files;
            if (!node.is_dir) used += node.data.size();
        }

        std::memset(st, 0, sizeof(*st));
        const uint64_t bsize = 4096;
        // Echte Containerkapazitaet anzeigen, falls bekannt; sonst 4-GiB-Fallback.
        // Mindestens so gross wie die belegten Daten, damit free nicht negativ wird.
        uint64_t capacity = v->capacity_bytes_ ? v->capacity_bytes_ : (1ull << 32);
        if (capacity < used) capacity = used;
        st->f_bsize = bsize;
        st->f_frsize = bsize;
        st->f_blocks = capacity / bsize;
        uint64_t used_blocks = (used + bsize - 1) / bsize;
        uint64_t free_blocks = (st->f_blocks > used_blocks) ? (st->f_blocks - used_blocks) : 0;
        st->f_bfree = free_blocks;
        st->f_bavail = free_blocks;
        st->f_files = files;
        st->f_ffree = 1ull << 20;
        st->f_namemax = 255;
        return 0;
    }

#if defined(_WIN32)
    // Prueft, ob ein Laufwerksbuchstabe ("Z:" o.ae.) tatsaechlich im System sichtbar
    // ist. WinFsp ruft init() bereits auf, BEVOR der Mount-Manager den Buchstaben
    // verlaesslich registriert hat — init() allein ist daher KEIN Beweis, dass "Z:\"
    // im Explorer existiert. Erst wenn GetFileAttributes auf das Wurzelverzeichnis
    // gelingt, ist der Mount wirklich nutzbar. (Ohne diese Pruefung meldete mount()
    // faelschlich Erfolg und die GUI oeffnete ein nicht existentes "Z:\".)
    // Eine einzelne Sichtbarkeitspruefung: existiert "Z:\" und ist es ein Verzeichnis?
    // GetFileAttributes auf die Wurzel loest WinFsp-seitig nur op_getattr("/") aus — das
    // ist die LEICHTE, zuverlaessige Pruefung, die ein frisch gemountetes Volume sofort
    // bedienen kann. (Eine schwerere FindFirstFile-Enumeration auf "Z:\*" schlug bei
    // frisch gemounteten WinFsp-Volumes fehl und liess selbst funktionierende Mounts
    // faelschlich durchfallen — daher bewusst NUR GetFileAttributes.)
    // Prueft via GetLogicalDrives()-Bitmask, ob der Laufwerksbuchstabe systemweit
    // registriert ist. GetLogicalDrives() fragt den Windows-Kernel (MountManager)
    // direkt — zuverlaessiger als GetFileAttributesA, das nur den eigenen Prozessnamensraum
    // sieht, solange WinFsp den Mount noch nicht vollstaendig global eingetragen hat.
    static bool drive_letter_in_logical_drives(const std::string& mount_point) {
        if (mount_point.size() < 2) return false;
        char letter = static_cast<char>(std::toupper(static_cast<unsigned char>(mount_point[0])));
        if (letter < 'A' || letter > 'Z') return false;
        int bit = letter - 'A';
        DWORD mask = ::GetLogicalDrives();
        return (mask & (1u << bit)) != 0;
    }

    // Wartet (gepollt), bis der Laufwerksbuchstabe systemweit FREIGEGEBEN ist, d. h. nicht
    // mehr in der GetLogicalDrives()-Bitmask steht. Hintergrund: Nach fuse_exit()+join()
    // gibt WinFsp den Buchstaben nicht zwingend sofort frei; ein direkt folgender Mount-
    // Versuch auf den naechsten Buchstaben kann dann auf ein halb-abgebautes Volume treffen
    // und ein "Geister-Volume" ohne Buchstaben hinterlassen. Erst wenn der Buchstabe
    // nachweislich frei ist, gilt der Abbau als abgeschlossen.
    // Rueckgabe: true = freigegeben; false = Timeout (kein Deadlock, Aufrufer faehrt fort).
    static bool wait_drive_letter_released(const std::string& mount_point, int timeout_ms) {
        if (mount_point.size() < 2) return true; // kein echter Buchstabe -> nichts zu warten
        const int step_ms = 50;
        for (int waited = 0; waited <= timeout_ms; waited += step_ms) {
            if (!drive_letter_in_logical_drives(mount_point)) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(step_ms));
        }
        return !drive_letter_in_logical_drives(mount_point);
    }

    // GetFileAttributesA als zweite Bestaetigung: Laufwerk im Bitmask UND tatsaechlich
    // als Verzeichnis zugreifbar (verhindert Falsch-Positiv bei halbregistriertem Mount).
    static bool drive_root_probe_once(const std::string& root_bs) {
        UINT prev = ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
        DWORD attr = ::GetFileAttributesA(root_bs.c_str());
        ::SetErrorMode(prev);
        return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
    }

    // Sichtbar = Buchstabe im systemweiten Bitmask UND GetFileAttributes bestaetigt
    // den Ordner. Einmalige Pruefung genuegt (kein Retry-Loop mehr) — GetLogicalDrives
    // ist atomar und wird erst gesetzt, wenn der Mount Manager fertig registriert hat.
    static bool drive_root_visible(const std::string& mount_point) {
        if (mount_point.empty()) return false;
        std::string root = mount_point;
        if (root.back() != '\\' && root.back() != '/') root += '\\';
        if (!drive_letter_in_logical_drives(mount_point)) return false;
        return drive_root_probe_once(root);
    }
#endif

    bool VirtualVolume::mount(const std::string& mount_point) {
        if (mounted_.load()) return false;
        if (loop_thread_.joinable()) return false;

        // Mount-Punkt merken, damit unmount() den Buchstaben fuer den sauberen Abbau kennt.
        mount_point_ = mount_point;

        // Hinweis: WinFsp benoetigt KEINE Adminrechte, um ein Laufwerk einzuhaengen.
        // Ein normaler User-Prozess kann ueber den (per Installer registrierten) WinFsp-
        // Treiber mounten; das Laufwerk ist in der eigenen Session sofort im Explorer
        // sichtbar. Frueher brach mount() ohne Elevation hart ab — dadurch entstand fuer
        // normale Nutzer GAR kein Laufwerk ("RAM-only"). Diese Sperre ist entfernt; der
        // Erfolg wird unten am gesetzten fuse_handle_ UND an der echten Sichtbarkeit des
        // Laufwerks (GetFileAttributes) erkannt — init() allein genuegt nicht.

        mounted_.store(true);
        loop_done_.store(false);
        loop_thread_ = std::thread([this, mount_point]() {
            struct fuse_operations ops;
            std::memset(&ops, 0, sizeof(ops));
            ops.getattr  = &VirtualVolume::op_getattr;
            ops.readdir  = reinterpret_cast<decltype(ops.readdir)>(&VirtualVolume::op_readdir);
            ops.open     = &VirtualVolume::op_open;
            ops.create   = reinterpret_cast<decltype(ops.create)>(&VirtualVolume::op_create);
            ops.read     = reinterpret_cast<decltype(ops.read)>(&VirtualVolume::op_read);
            ops.write    = reinterpret_cast<decltype(ops.write)>(&VirtualVolume::op_write);
            ops.truncate = reinterpret_cast<decltype(ops.truncate)>(&VirtualVolume::op_truncate);
            ops.unlink   = &VirtualVolume::op_unlink;
            ops.mkdir    = reinterpret_cast<decltype(ops.mkdir)>(&VirtualVolume::op_mkdir);
            ops.rmdir    = &VirtualVolume::op_rmdir;
            ops.rename   = &VirtualVolume::op_rename;
            ops.statfs   = reinterpret_cast<decltype(ops.statfs)>(&VirtualVolume::op_statfs);
            // init: struct fuse* fuer ein sauberes fuse_exit() in unmount() abgreifen.
            ops.init = [](struct fuse_conn_info*) -> void* {
                struct fuse_context* ctx = fuse_get_context();
                VirtualVolume* v = static_cast<VirtualVolume*>(ctx->private_data);
                {
                    std::lock_guard<std::mutex> hl(v->handle_mtx_);
                    v->fuse_handle_ = ctx->fuse;
                }
                return v;  // bleibt private_data
            };

            // Argumente fuer fuse_main_real zusammenbauen.
            //
            // WICHTIG fuer globale Sichtbarkeit: WinFsp-FUSE braucht "-o uid=-1,gid=-1",
            // damit alle Dateien als dem AUFRUFENDEN Benutzer gehoerend praesentiert werden.
            // Ohne diese Option registriert WinFsp das Volume nur prozess-lokal: der
            // mountende Prozess sieht "Z:\", aber Explorer/andere Prozesse NICHT
            // ("Z:\ ist nicht verfuegbar"), und `fsptool lsvol` zeigt das Volume ohne
            // Laufwerksbuchstaben. Mit uid/gid=-1 erscheint der Buchstabe systemweit
            // (verifiziert gegen WinFsps memfs-Referenz + sshfs-Beispielkommandozeile).
            // Argumente einzeln aufgeloest, damit WinFsp-FUSE jede Option korrekt
            // parsen kann. uid=-1 und gid=-1 als SEPARATE -o-Argumente uebergeben,
            // da manche WinFsp-Versionen komma-separierte Werte in einem einzigen
            // -o-Token nicht zuverlaessig splitten.
            std::string volname_opt = "volname=" + label_;
            std::vector<std::string> args = {
                "dgkn_virtualvolume",
                mount_point,
                "-f",           // foreground (Loop laeuft im Thread)
                "-o", "uid=-1", // \  Zusammen sorgen uid/gid=-1 dafuer, dass WinFsp
                "-o", "gid=-1", // /  das Volume systemweit (global) sichtbar macht.
                "-o", volname_opt,
            };
            std::vector<char*> argv;
            for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));

            // Bewusst OHNE Laufwerksbuchstabe und OHNE Label/volname: diese wuerden den
            // Mount-Modus und Containernamen leaken (siehe Sicherheitshinweis bei mlog()).
            mlog("thread: fuse_main_real START");
            int rc = fuse_main_real(static_cast<int>(argv.size()), argv.data(),
                                    &ops, sizeof(ops), this);
#if defined(_WIN32)
            mlog("thread: fuse_main_real RETURNED rc=%d WinErr=%lu", rc, (unsigned long)::GetLastError());
#endif
            (void)rc;

            {
                std::lock_guard<std::mutex> hl(handle_mtx_);
                fuse_handle_ = nullptr;
            }
            mounted_.store(false);
            loop_done_.store(true);
        });

        // Auf erfolgreichen Mount warten. init() setzt fuse_handle_, aber das allein
        // beweist NICHT, dass das Laufwerk im Explorer existiert (WinFsp registriert den
        // Buchstaben verzoegert). Daher zusaetzlich auf echte Sichtbarkeit von "Z:\"
        // warten — erst dann ist mount() ein verlaessliches Erfolgssignal.
        // Timeout grosszuegig (bis ~15s): bei kaltem WinFsp-Treiber (erster Mount nach
        // Reboot) oder waehrend ein Virenscanner das neue Volume inspiziert, kann die
        // Registrierung des Buchstabens deutlich laenger als die frueheren 5s dauern.
        // Bewusst OHNE mount_point und OHNE label_ (Leak-Schutz, siehe mlog()).
        mlog("mount() ENTER");
        bool handle_seen = false;
        for (int i = 0; i < 150; ++i) { // bis ~15s
            bool handle_ready = false;
            {
                std::lock_guard<std::mutex> hl(handle_mtx_);
                handle_ready = (fuse_handle_ != nullptr);
            }
            if (handle_ready) {
                if (!handle_seen) { handle_seen = true; mlog("wait i=%d: init() done (handle set)", i); }
#if defined(_WIN32)
                if (drive_root_visible(mount_point)) {
                    mlog("wait i=%d: drive VISIBLE -> SUCCESS", i);
                    return true; // Laufwerk real da
                }
#else
                return true; // Nicht-Windows: init() genuegt als Erfolgssignal
#endif
            }
            if (loop_done_.load()) { mlog("wait i=%d: loop_done early -> FAIL", i); break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        mlog("mount() TIMEOUT/FAIL (handle_seen=%d) -> cleanup", handle_seen ? 1 : 0);
        // Kein erfolgreicher Mount: Thread sauber beenden.
        {
            std::lock_guard<std::mutex> hl(handle_mtx_);
            if (fuse_handle_) { fuse_exit(static_cast<struct fuse*>(fuse_handle_)); }
        }
        if (loop_thread_.joinable()) loop_thread_.join();
#if defined(_WIN32)
        // WICHTIG: Warten, bis WinFsp den Buchstaben wirklich freigegeben hat, BEVOR
        // mount() zurueckkehrt. Sonst probiert der aufrufende mount_volume() sofort den
        // naechsten Buchstaben, waehrend dieses Volume noch halb-registriert ist — genau
        // so entstehen die "Geister-Volumes" ohne Buchstaben, die spaeter "Z:\ nicht
        // verfuegbar" verursachen. Kein Deadlock: nach dem Timeout faehrt mount() fort.
        wait_drive_letter_released(mount_point, 1500);
#endif
        mounted_.store(false);
        mlog("mount() returned FALSE");
        return false;
    }

    void VirtualVolume::unmount() {
        if (loop_thread_.joinable()) {
            {
                std::lock_guard<std::mutex> hl(handle_mtx_);
                if (fuse_handle_) {
                    fuse_exit(static_cast<struct fuse*>(fuse_handle_));
                }
            }
            loop_thread_.join();
#if defined(_WIN32)
            // Symmetrisch zum mount()-Fehlerpfad: warten, bis der Buchstabe wirklich frei
            // ist, damit ein direkt folgender Re-Mount denselben Buchstaben sauber
            // wiederverwenden kann und kein halb-abgebautes Volume zuruecklaesst.
            wait_drive_letter_released(mount_point_, 1500);
#endif
        }
        mounted_.store(false);
    }

}

#else  // ── Stub ohne WinFsp: Mount nicht verfuegbar, Rest bleibt nutzbar ──

namespace dgkn::core {

    bool VirtualVolume::mount(const std::string&) { return false; }
    void VirtualVolume::unmount() {
        if (loop_thread_.joinable()) loop_thread_.join();
        mounted_.store(false);
    }

}

#endif  // DGKN_HAVE_WINFSP