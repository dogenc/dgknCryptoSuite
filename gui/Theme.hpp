// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <QString>

namespace dgkn::gui {

    // ── DGKN@Labs "Agency" Theme ──────────────────────────────────────────────
    // Nüchterner, hochkontrastiger Behörden-/Tactical-Look: tiefes Anthrazit-Navy,
    // kühles Stahlblau als Akzent, Bernstein für Warnungen, scharfe Kanten,
    // Uppercase-Labels mit Sperrung, Monospace für technische Felder.
    namespace color {
        constexpr const char* bg      = "#0a0e14";  // fast schwarz, leicht blaustichig
        constexpr const char* surface = "#10151f";  // Panels
        constexpr const char* surface2= "#161d2b";  // erhabene Flächen / Buttons
        constexpr const char* border  = "#27313f";  // kühle Stahllinie
        constexpr const char* fg      = "#dfe6ef";  // klares Hellgrau
        constexpr const char* fg_dim  = "#7e8aa0";  // gedämpft
        constexpr const char* acc     = "#5b8dd6";  // Stahlblau (Agency)
        constexpr const char* acc_dim = "#3c648f";
        constexpr const char* warn    = "#e0a31e";  // Bernstein
        constexpr const char* panic   = "#d83a3a";  // gedämpftes Rot
        constexpr const char* ok       = "#3fae6a"; // gedämpftes Grün
    }

    inline QString stylesheet() {
        return QStringLiteral(R"QSS(
        * {
            font-family: "Segoe UI", "Inter", sans-serif;
            font-size: 10pt;
            color: #dfe6ef;
        }
        QMainWindow, QDialog, QWidget#root { background: #0a0e14; }

        /* ── Classification-Banner (oben/unten) ── */
        QLabel#classbar {
            background: #161d2b; color: #9fb0c8;
            font-family: "Cascadia Code","Consolas",monospace;
            font-size: 8pt; font-weight: 700; letter-spacing: 2px;
            border-bottom: 1px solid #27313f; padding: 4px 0;
        }

        /* ── Sidebar / Operations-Menü ── */
        QFrame#sidebar { background: #10151f; border-right: 1px solid #27313f; }
        QLabel#logo {
            font-family: "Cascadia Code","Consolas",monospace;
            font-size: 15pt; font-weight: 700; color: #dfe6ef;
            letter-spacing: 1px; padding: 16px 14px 2px 14px;
        }
        QLabel#logosub {
            color: #5b8dd6; font-size: 8pt; font-weight: 700; letter-spacing: 3px;
            padding: 0 14px 14px 14px;
        }
        QLabel#sectionTitle {
            color: #5b8dd6; font-size: 8pt; font-weight: 700;
            letter-spacing: 2px; padding: 14px 14px 4px 14px;
        }

        /* ── Buttons: scharfe Kanten, klare Hover-Rahmen ── */
        QPushButton {
            background: #161d2b; border: 1px solid #27313f; border-radius: 2px;
            padding: 9px 14px; color: #dfe6ef; text-align: left;
            font-size: 9pt; letter-spacing: 0.5px;
        }
        QPushButton:hover { background: #1c2636; border-color: #5b8dd6; color: #ffffff; }
        QPushButton:pressed { background: #11161f; }
        QPushButton#primary {
            background: #21456e; border: 1px solid #5b8dd6;
            color: #eaf2ff; font-weight: 700; letter-spacing: 1px;
        }
        QPushButton#primary:hover { background: #2a5689; }
        QPushButton#danger {
            background: #3a1518; border: 1px solid #d83a3a; color: #ff9a9a;
            font-weight: 700; letter-spacing: 1px;
        }
        QPushButton#danger:hover { background: #5a1d22; color: #ffd0d0; }

        /* ── Eingabefelder: monospace, klare Fokuslinie ── */
        QLineEdit, QSpinBox, QComboBox {
            background: #0c1118; border: 1px solid #27313f; border-radius: 2px;
            padding: 8px 10px; color: #eaf2ff;
            font-family: "Cascadia Code","Consolas",monospace; font-size: 10pt;
            selection-background-color: #5b8dd6; selection-color: #0a0e14;
        }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border: 1px solid #5b8dd6; }
        QCheckBox { spacing: 8px; color: #dfe6ef; }
        QCheckBox::indicator {
            width: 15px; height: 15px; border: 1px solid #27313f;
            background: #0c1118; border-radius: 2px;
        }
        QCheckBox::indicator:checked { background: #5b8dd6; border-color: #5b8dd6; }

        /* ── Tabs ── */
        QTabWidget::pane { border: none; background: #0a0e14; }
        QTabBar::tab {
            background: transparent; color: #7e8aa0; padding: 10px 20px;
            border-bottom: 2px solid transparent;
            font-weight: 700; font-size: 8pt; letter-spacing: 2px;
        }
        QTabBar::tab:selected { color: #5b8dd6; border-bottom: 2px solid #5b8dd6; }
        QTabBar::tab:hover { color: #dfe6ef; }

        /* ── Typografie ── */
        QLabel#h1 { font-size: 17pt; font-weight: 700; color: #eaf2ff; letter-spacing: 1px; }
        QLabel#h2 {
            font-size: 10pt; font-weight: 700; color: #5b8dd6;
            letter-spacing: 2px;
        }
        QLabel#dim { color: #7e8aa0; }
        QLabel#acc { color: #5b8dd6; font-weight: 700; }

        /* ── Karten / Panels: scharfe Kanten + linker Akzentstreifen-Look ── */
        QFrame#card {
            background: #10151f; border: 1px solid #27313f;
            border-left: 2px solid #5b8dd6; border-radius: 2px;
        }

        /* ── Mono-Konsolen / Log ── */
        QTextEdit, QPlainTextEdit {
            background: #070a0f; border: 1px solid #27313f; border-radius: 2px;
            color: #9fd0a8;  /* terminal-grün für Logs */
            font-family: "Cascadia Code","Consolas",monospace; font-size: 9pt;
        }

        QProgressBar {
            background: #0c1118; border: 1px solid #27313f; border-radius: 2px;
            height: 6px; text-align: center; color: #dfe6ef;
        }
        QProgressBar::chunk { background: #5b8dd6; }

        QStatusBar {
            background: #10151f; color: #7e8aa0; border-top: 1px solid #27313f;
            font-family: "Cascadia Code","Consolas",monospace; font-size: 8pt;
        }
        QScrollBar:vertical { background: transparent; width: 10px; }
        QScrollBar::handle:vertical { background: #27313f; border-radius: 2px; min-height: 24px; }
        QScrollBar::handle:vertical:hover { background: #5b8dd6; }
        QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
        )QSS");
    }

}