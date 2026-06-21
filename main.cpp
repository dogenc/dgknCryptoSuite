// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include <iostream>
#include <string>
#include "Config.hpp"
#include "core/Manager.hpp"

int main(int argc, char* argv[]) {
    std::cout << "=================================================\n";
    std::cout << " DGKN Crypto Suite v" << dgkn::config::APP_VER << " (Native C++ Edition)\n";
    std::cout << "=================================================\n\n";

    dgkn::core::ContainerManager manager;
    std::string mode, input, output, password;

    std::cout << "Modus waehlen (E = Encrypt / D = Decrypt): ";
    std::getline(std::cin, mode);

    if (mode != "E" && mode != "e" && mode != "D" && mode != "d") {
        std::cout << "Fehler: Ungueltiger Modus.\n";
        return 1;
    }

    std::cout << "Pfad zur Original-Datei : ";
    std::getline(std::cin, input);
    std::cout << "Pfad zur Ausgabe-Datei  : ";
    std::getline(std::cin, output);
    std::cout << "Passwort                : ";
    std::getline(std::cin, password);

    std::cout << "\nVerarbeite Kryptografie... Bitte warten.\n";

    bool success = false;
    try {
        if (mode == "E" || mode == "e") {
            success = manager.encrypt_file(input, output, password);
        } else {
            success = manager.decrypt_file(input, output, password);
        }
    } catch (const std::exception& e) {
        std::cout << "\n[EXCEPTION] " << e.what() << "\n";
        return 2;
    }

    if (success) std::cout << "\n[ERFOLG] Vorgang erfolgreich abgeschlossen!\n";
    else std::cout << "\n[FEHLER] Fehlgeschlagen! Falsches Passwort oder korrupte Datei?\n";

    return 0;
}