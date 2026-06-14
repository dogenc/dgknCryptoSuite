// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <QMainWindow>
#include <QElapsedTimer>
#include <memory>
#include "AppController.hpp"
#include "AuditLog.hpp"

class QPlainTextEdit;
class QLabel;
class QTabWidget;
class QTimer;

namespace dgkn::gui {

    class MainWindow : public QMainWindow {
        Q_OBJECT
    public:
        explicit MainWindow(QWidget* parent = nullptr);

    protected:
        // Globaler Event-Filter: setzt den Inaktivitäts-Timer bei jeder Eingabe zurück.
        bool eventFilter(QObject* obj, QEvent* ev) override;

    private slots:
        void onCreateContainer();
        void onMountContainer();
        void onUnmountContainer();
        void onEncryptFile();
        void onDecryptFile();
        void onChangePassword();
        void onCheckIntegrity();
        void onBackupHeader();
        void onEmergencyWipe();
        void onSetup2FA();
        // Prüft Inaktivität; nach Ablauf der Frist -> Auto-Lock (Mounts schließen + Wipe).
        void checkInactivity();

    private:
        QWidget* buildSidebar();
        QWidget* buildDashboardTab();
        QWidget* buildLogTab();
        void log(const QString& msg);

        // Fragt den 6-stelligen TOTP-Code ab und verifiziert ihn gegen das Secret.
        // Gibt true zurück, wenn der Code korrekt ist (oder kein Secret gesetzt ist).
        // Bei leerem Secret (kein 2FA) wird true zurückgegeben (Verifikation entfällt).
        bool require2FA(const std::string& secret, const QString& reason);

        // Liefert das persistente App-Login-2FA-Secret für Container-Operationen.
        //  • Keine 2FA eingerichtet      → leerer String (kein zweiter Faktor).
        //  • Beschädigte Datei           → leerer String + Hinweis (Nutzer soll 2FA reparieren).
        //  • Eingerichtet, noch gesperrt → einmalig Master-PW abfragen, entsperren, cachen.
        //  • Bereits entsperrt           → gecachter Wert.
        // So nutzt JEDE Container-Operation dasselbe gespeicherte Secret — es wird nie
        // mehr „von alleine" ein neues erzeugt. ok=false nur bei Abbruch durch den Nutzer.
        bool unlockTwofaSecret(std::string& out_secret, bool& ok);

        // Löscht das gecachte Secret sicher aus dem RAM (Auto-Lock / Fenster schließen).
        void clearTwofaCache();

        // Zeigt frisch erzeugte Recovery-Codes EINMALIG an (notieren/kopieren).
        void showRecoveryCodes(const std::vector<std::string>& codes);

        // Baut die Security-Statusleiste (oben) und aktualisiert sie periodisch.
        QWidget* buildSecurityBar();
        void refreshSecurityStatus();
        // Bloomberg-Style Kopfleiste: Datum/Uhrzeit links, 3D-Erde rechts.
        QWidget* buildHeaderBar();
        void refreshClock();
        // Live-Systemmetriken (CPU/Temp/RAM/Disk) aktualisieren.
        void refreshMetrics();

        QLabel* mCpu_ = nullptr;
        QLabel* mTemp_ = nullptr;
        QLabel* mRam_ = nullptr;
        QLabel* mDisk_ = nullptr;
        bool elevated_ = false;   // läuft die App mit Admin-Rechten? (einmalig erfasst)

        AppController controller_;
        QTabWidget* tabs_ = nullptr;
        QPlainTextEdit* logView_ = nullptr;
        QLabel* statusLabel_ = nullptr;
        QLabel* secBar_ = nullptr;       // Security-Status oben
        QLabel* clockLabel_ = nullptr;   // Live-Uhr/Datum

        // Auto-Lock: Inaktivitäts-Tracking.
        QElapsedTimer idleClock_;        // Zeit seit letzter Eingabe
        bool locked_ = false;            // bereits gesperrt?
        static constexpr int kAutoLockMs = 10 * 60 * 1000; // 10 Minuten

        std::unique_ptr<core::AuditLog> audit_; // tamper-evidentes Audit-Log

        // Session-Cache des entsperrten App-Login-2FA-Secrets. Einmal pro Sitzung
        // per Master-PW entsperrt, danach für alle Container-Operationen wiederverwendet.
        // Bei Auto-Lock / Fenster-Schließen mit secure_wipe_string geleert.
        std::string twofaSecretCache_;
        bool twofaUnlocked_ = false;
    };

}