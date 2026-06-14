// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <cstdint>
#include <string>

namespace dgkn::core {

    // Live-Systemmetriken für die Statusanzeige (CPU-Last, RAM, Disk, CPU-Temp).
    // Alle Werte best-effort; nicht ermittelbare Felder sind als "valid=false"
    // markiert bzw. -1.
    struct SystemMetrics {
        double cpu_percent = -1.0;     // CPU-Gesamtauslastung 0..100 (-1 = unbekannt)
        double cpu_temp_c = -1.0;      // CPU-Temperatur °C (-1 = nicht verfügbar)
        uint64_t ram_total = 0;        // Bytes
        uint64_t ram_used = 0;         // Bytes
        uint64_t disk_total = 0;       // Bytes (Systemlaufwerk)
        uint64_t disk_free = 0;        // Bytes

        double ram_percent() const {
            return ram_total ? (100.0 * double(ram_used) / double(ram_total)) : -1.0;
        }
        uint64_t disk_used() const { return disk_total > disk_free ? disk_total - disk_free : 0; }
        double disk_percent() const {
            return disk_total ? (100.0 * double(disk_used()) / double(disk_total)) : -1.0;
        }

        // Erfasst alle Metriken (CPU-Last über Delta seit letztem Aufruf — Instanz halten).
        static SystemMetrics capture();

        // Formatiert Bytes als "12.3 GB" / "850 MB".
        static std::string human_bytes(uint64_t bytes);
    };

}