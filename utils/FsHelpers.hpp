// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <string>

namespace dgkn::utils {

    // Überschreibt eine Datei mehrfach mit Zufallsdaten und löscht sie.
    // 3 Passes entsprechen DoD 5220.22-M (eingeschränkt). Bei SSDs ist die
    // Wirkung durch Wear Leveling begrenzt — dort ist Full-Disk-Encryption
    // vorzuziehen. Symlinks werden ohne Überschreiben direkt entfernt.
    void secure_wipe_file(const std::string& path, int passes = 3);

    // Löscht ein Verzeichnis rekursiv; enthaltene Dateien werden überschrieben
    // (1 Pass, ausreichend für Temporärdateien).
    void secure_wipe_dir(const std::string& path);

}