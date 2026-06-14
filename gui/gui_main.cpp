// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include <QApplication>
#include <QIcon>
#include <sodium.h>
#include "MainWindow.hpp"
#include "Theme.hpp"
#include "Splash.hpp"

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) return 1;

    QApplication app(argc, argv);
    app.setOrganizationName("DGKN@Labs");
    app.setApplicationName("DGKN Crypto Suite");
    app.setWindowIcon(QIcon(":/icon.png"));   // App-weites Fenster-/Taskbar-Icon
    app.setStyleSheet(dgkn::gui::stylesheet());

    // Hauptfenster vorab erstellen, aber noch nicht zeigen. Der Splashscreen läuft
    // 7 Sekunden und zeigt danach das Fenster (über den Callback).
    dgkn::gui::MainWindow w;

    auto* splash = new dgkn::gui::Splash([&w]() { w.show(); w.raise(); w.activateWindow(); },
                                         /*duration_ms=*/7000);
    splash->show();

    return app.exec();
}