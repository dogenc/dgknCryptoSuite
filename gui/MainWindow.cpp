// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "MainWindow.hpp"
#include "Theme.hpp"
#include "CryptoUtils.hpp"
#include "FsHelpers.hpp"
#include <filesystem>
#include <system_error>
#include "SystemStatus.hpp"
#include "SystemMetrics.hpp"
#include "EarthWidget.hpp"
#include "QrWidget.hpp"
#include <QTimer>
#include <QEvent>
#include <QDir>
#include <QStandardPaths>

#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QFrame>
#include <QLabel>
#include <QPushButton>
#include <QTabWidget>
#include <QPlainTextEdit>
#include <QStatusBar>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QDesktopServices>
#include <QUrl>
#include <QLineEdit>
#include <QDateTime>
#include <QDialog>
#include <QFormLayout>
#include <QSpinBox>
#include <QCheckBox>
#include <QProgressBar>
#include <QApplication>
#include <QClipboard>

namespace dgkn::gui {

    namespace {
        QPushButton* makeBtn(const QString& text, const QString& objName = {}) {
            auto* b = new QPushButton(text);
            if (!objName.isEmpty()) b->setObjectName(objName);
            return b;
        }

        // Gestylter Dialog-Header (Agency-Look): Akzent-Titelzeile + dünne Trennlinie.
        QWidget* dialogHeader(const QString& title, const QString& subtitle = {}) {
            auto* head = new QWidget;
            auto* v = new QVBoxLayout(head);
            v->setContentsMargins(0, 0, 0, 8);
            v->setSpacing(2);
            auto* t = new QLabel(title);
            t->setObjectName("h2");                 // Stahlblau, Uppercase-Look
            v->addWidget(t);
            if (!subtitle.isEmpty()) {
                auto* s = new QLabel(subtitle);
                s->setObjectName("dim");
                s->setWordWrap(true);
                v->addWidget(s);
            }
            return head;
        }

        // Einheitliche Dialog-Grundeinrichtung (Titel, Mindestbreite, scharfer Rahmen).
        void styleDialog(QDialog& d, int minW = 440) {
            d.setMinimumWidth(minW);
            d.setStyleSheet("QDialog{background:#0a0e14;}");
        }

        // Best-effort: überschreibt die AKTUELLE QString-Allokation und leert sie.
        // EHRLICHE GRENZE: Qt kann durch Implicit-Sharing/Reallocs Kopien an alten
        // Heap-Adressen hinterlassen, die wir nicht erreichen. Reduziert Zahl/Lebensdauer
        // lebender Klartextkopien, ist aber KEINE Garantie. Siehe SECURITY.md.
        void wipeQString(QString& s) { for (QChar& c : s) c = QChar(u'\0'); s.clear(); }

        // Gestylter Ersatz für QInputDialog (Passwort / Text / 2FA-Code).
        // Gibt true + value zurück, wenn bestätigt.
        bool promptText(QWidget* parent, const QString& title, const QString& subtitle,
                        const QString& fieldLabel, bool password, QString& valueOut) {
            QDialog d(parent);
            d.setWindowTitle(title);
            styleDialog(d, 420);
            auto* v = new QVBoxLayout(&d);
            v->setContentsMargins(20, 18, 20, 18);
            v->setSpacing(10);
            v->addWidget(dialogHeader(title, subtitle));
            auto* lbl = new QLabel(fieldLabel);
            lbl->setObjectName("dim");
            v->addWidget(lbl);
            auto* edit = new QLineEdit;
            if (password) edit->setEchoMode(QLineEdit::Password);
            v->addWidget(edit);
            auto* row = new QHBoxLayout;
            auto* cancel = makeBtn("ABBRECHEN");
            auto* ok = makeBtn("BESTÄTIGEN", "primary");
            row->addStretch(1); row->addWidget(cancel); row->addWidget(ok);
            v->addLayout(row);
            QObject::connect(cancel, &QPushButton::clicked, &d, &QDialog::reject);
            QObject::connect(ok, &QPushButton::clicked, &d, &QDialog::accept);
            QObject::connect(edit, &QLineEdit::returnPressed, &d, &QDialog::accept);
            edit->setFocus();
            if (d.exec() != QDialog::Accepted) return false;
            valueOut = edit->text();
            // QLineEdit-Puffer best-effort ueberschreiben (Passwoerter/Secrets).
            edit->setText(QString(valueOut.size(), QChar(u'\0')));
            edit->clear();
            return true;
        }

        // promptText-Variante für Geheimnisse: liefert std::string, wischt QString-Reste.
        bool promptSecret(QWidget* parent, const QString& title, const QString& subtitle,
                          const QString& fieldLabel, std::string& valueOut) {
            QString q;
            bool ok = promptText(parent, title, subtitle, fieldLabel, /*password=*/true, q);
            if (ok) valueOut.assign(q.toStdString());
            wipeQString(q);
            return ok;
        }

        // Passwort + OPTIONALES Keyfile in einem Dialog abfragen (für Datei-Krypto).
        // Das Keyfile ist ein zusätzlicher Schlüsselfaktor: dieselbe Datei muss beim
        // Entschlüsseln wieder gewählt werden. Jede Dateiart ist erlaubt (Bild, PDF, …);
        // entscheidend ist nur der unveränderte Inhalt (BLAKE2b-Hash).
        // Gibt true bei Bestätigung; passwordOut/keyfileOut werden gesetzt.
        // keyfileOut ist "" wenn kein Keyfile gewählt wurde.
        bool promptPasswordAndKeyfile(QWidget* parent, const QString& title, const QString& subtitle,
                                      bool requirePassword, std::string& passwordOut,
                                      std::string& keyfileOut) {
            QDialog d(parent);
            d.setWindowTitle(title);
            styleDialog(d, 480);
            auto* v = new QVBoxLayout(&d);
            v->setContentsMargins(20, 18, 20, 18);
            v->setSpacing(10);
            v->addWidget(dialogHeader(title, subtitle));

            auto* form = new QFormLayout;
            form->setSpacing(8);
            auto* pw = new QLineEdit;
            pw->setEchoMode(QLineEdit::Password);
            form->addRow("Passwort:", pw);

            // Keyfile-Zeile: schreibgeschütztes Pfadfeld + "Wählen…"-/"Entfernen"-Knöpfe.
            auto* kfRow = new QHBoxLayout;
            auto* kfPath = new QLineEdit;
            kfPath->setReadOnly(true);
            kfPath->setPlaceholderText("(optional) keine Keyfile gewählt");
            auto* kfPick = makeBtn("Wählen…");
            auto* kfClear = makeBtn("Entfernen");
            kfClear->setEnabled(false);
            kfRow->addWidget(kfPath, 1);
            kfRow->addWidget(kfPick);
            kfRow->addWidget(kfClear);
            auto* kfWrap = new QWidget;
            kfWrap->setLayout(kfRow);
            kfRow->setContentsMargins(0, 0, 0, 0);
            form->addRow("Keyfile:", kfWrap);
            auto* kfHint = new QLabel(
                "Optionaler zweiter Schlüsselfaktor. Jede Dateiart ist möglich. "
                "Beim Entschlüsseln muss exakt dieselbe (unveränderte) Datei wieder gewählt "
                "werden — geht sie verloren oder ändert sich ihr Inhalt, ist die Datei "
                "nicht mehr entschlüsselbar.");
            kfHint->setObjectName("dim");
            kfHint->setWordWrap(true);
            form->addRow("", kfHint);
            v->addLayout(form);

            QObject::connect(kfPick, &QPushButton::clicked, &d, [&]() {
                QString f = QFileDialog::getOpenFileName(&d, "Keyfile wählen", "", "Alle Dateien (*)");
                if (f.isEmpty()) return;
                kfPath->setText(f);
                kfClear->setEnabled(true);
            });
            QObject::connect(kfClear, &QPushButton::clicked, &d, [&]() {
                kfPath->clear();
                kfClear->setEnabled(false);
            });

            auto* row = new QHBoxLayout;
            auto* cancel = makeBtn("ABBRECHEN");
            auto* ok = makeBtn("BESTÄTIGEN", "primary");
            row->addStretch(1); row->addWidget(cancel); row->addWidget(ok);
            v->addLayout(row);
            QObject::connect(cancel, &QPushButton::clicked, &d, &QDialog::reject);
            QObject::connect(ok, &QPushButton::clicked, &d, &QDialog::accept);
            pw->setFocus();

            if (d.exec() != QDialog::Accepted) return false;
            if (requirePassword && pw->text().isEmpty()) return false;
            passwordOut.assign(pw->text().toStdString());
            keyfileOut.assign(kfPath->text().toStdString());
            // QLineEdit-Passwortpuffer best-effort überschreiben.
            pw->setText(QString(pw->text().size(), QChar(u'\0')));
            pw->clear();
            return true;
        }
    }

    MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
        setWindowTitle("DGKN@Labs Crypto Suite v7 — Native C++ Edition");
        resize(1040, 700);

        // Admin-Status einmalig erfassen (ändert sich zur Laufzeit nicht) — für den
        // CPU-Temp-Hinweis ("Admin nötig"), ohne pro Tick eine WMI-Abfrage zu machen.
        elevated_ = core::SystemStatus::capture().elevated;

        // Tamper-evidentes Audit-Log in %LOCALAPPDATA%\DGKN (persistent + nutzergebunden,
        // nicht im weltlesbaren %TEMP%, das das OS aufräumt).
        {
            QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
            if (base.isEmpty()) base = QDir::tempPath();
            QDir().mkpath(base);
            QString logPath = base + "/dgkn_audit.log";
            audit_ = std::make_unique<core::AuditLog>(logPath.toStdString());
            size_t bad = 0;
            if (!audit_->verify(&bad) && bad > 0) {
                // Existierendes Log ist manipuliert -> sichtbar warnen (kein Abbruch).
                QMessageBox::warning(this, "Audit-Log",
                    QString("WARNUNG: Das Audit-Log wurde manipuliert (Bruch in Zeile %1).\n"
                            "Die Integritaetskette ist verletzt.").arg(bad));
            }
        }

        auto* root = new QWidget;
        root->setObjectName("root");
        auto* outer = new QVBoxLayout(root);
        outer->setContentsMargins(0, 0, 0, 0);
        outer->setSpacing(0);

        // Bloomberg-Style Kopfleiste (Datum/Uhrzeit links, 3D-Erde rechts).
        outer->addWidget(buildHeaderBar());

        // Security-Statusleiste darunter.
        outer->addWidget(buildSecurityBar());

        auto* body = new QWidget;
        auto* h = new QHBoxLayout(body);
        h->setContentsMargins(0, 0, 0, 0);
        h->setSpacing(0);
        h->addWidget(buildSidebar());

        tabs_ = new QTabWidget;
        tabs_->addTab(buildDashboardTab(), "  DASHBOARD  ");
        tabs_->addTab(buildLogTab(), "  AUDIT LOG  ");
        h->addWidget(tabs_, 1);
        outer->addWidget(body, 1);

        // Classification-Banner unten (symmetrisch, klassischer Agency-Look).
        auto* classBot = new QLabel("XCHACHA20-POLY1305 · ARGON2ID · TPM/2FA · DGKN@LABS");
        classBot->setObjectName("classbar");
        classBot->setAlignment(Qt::AlignCenter);
        outer->addWidget(classBot);

        setCentralWidget(root);

        statusLabel_ = new QLabel("READY.");
        statusBar()->addWidget(statusLabel_);

        // Security-Status initial erfassen + alle 5s aktualisieren.
        refreshSecurityStatus();
        auto* secTimer = new QTimer(this);
        connect(secTimer, &QTimer::timeout, this, &MainWindow::refreshSecurityStatus);
        secTimer->start(5000);

        // Live-Uhr (Bloomberg-Stil) im Sekundentakt.
        refreshClock();
        auto* clockTimer = new QTimer(this);
        connect(clockTimer, &QTimer::timeout, this, &MainWindow::refreshClock);
        clockTimer->start(1000);

        // Live-Systemmetriken alle 2 Sekunden (CPU-Last braucht Delta zwischen Aufrufen).
        auto* metricTimer = new QTimer(this);
        connect(metricTimer, &QTimer::timeout, this, &MainWindow::refreshMetrics);
        metricTimer->start(2000);

        // ── Auto-Lock: Inaktivität verfolgen und alle 15 s prüfen. ──
        idleClock_.start();
        qApp->installEventFilter(this); // jede Eingabe setzt den Timer zurück
        auto* idleTimer = new QTimer(this);
        connect(idleTimer, &QTimer::timeout, this, &MainWindow::checkInactivity);
        idleTimer->start(15000);

        log("DGKN@Labs Crypto Suite gestartet (native C++/Qt).");
        log("Auto-Lock aktiv: Sperre nach 10 Min Inaktivitaet.");
    }

    bool MainWindow::eventFilter(QObject* obj, QEvent* ev) {
        switch (ev->type()) {
            case QEvent::MouseMove:
            case QEvent::MouseButtonPress:
            case QEvent::KeyPress:
            case QEvent::Wheel:
            case QEvent::TouchBegin:
                idleClock_.restart();   // Aktivität -> Timer zurücksetzen
                break;
            default: break;
        }
        return QMainWindow::eventFilter(obj, ev);
    }

    void MainWindow::checkInactivity() {
        if (locked_) return;
        if (idleClock_.elapsed() < kAutoLockMs) return;

        locked_ = true;
        // Auto-Lock: alle gemounteten Volumes schließen + Schlüssel im RAM wipen.
        controller_.manager().emergency_wipe(false);
        clearTwofaCache();   // gecachtes 2FA-Secret ebenfalls aus dem RAM entfernen
        log("AUTO-LOCK: 10 Min Inaktivitaet — alle Volumes geschlossen, Schluessel geloescht.");
        QMessageBox::information(this, "Auto-Lock",
            "Wegen Inaktivität (10 Minuten) wurden alle Volumes automatisch geschlossen "
            "und die Schlüssel aus dem RAM gelöscht.\n\nBitte erneut anmelden.");
        idleClock_.restart();
        locked_ = false; // bereit für die nächste Sitzung
    }

    QWidget* MainWindow::buildHeaderBar() {
        auto* bar = new QFrame;
        bar->setObjectName("headerbar");
        bar->setFixedHeight(72);
        bar->setStyleSheet(
            "QFrame#headerbar{background:#0c111a;border-bottom:1px solid #27313f;}");
        auto* h = new QHBoxLayout(bar);
        h->setContentsMargins(18, 6, 12, 6);
        h->setSpacing(0);

        // Links: Markenzeile + Bloomberg-artige Datum/Uhrzeit (groß, monospace, tickend).
        auto* left = new QVBoxLayout;
        left->setSpacing(0);
        auto* brand = new QLabel("DGKN@LABS · CRYPTO TERMINAL");
        brand->setStyleSheet("color:#5b8dd6;font-family:'Cascadia Code','Consolas',monospace;"
                             "font-size:8pt;font-weight:700;letter-spacing:3px;");
        clockLabel_ = new QLabel("--:--:--");
        clockLabel_->setStyleSheet("color:#eaf2ff;font-family:'Cascadia Code','Consolas',monospace;"
                                   "font-size:20pt;font-weight:700;letter-spacing:2px;");
        left->addWidget(brand);
        left->addWidget(clockLabel_);
        h->addLayout(left);
        h->addStretch(1);

        // Rechts: echte 3D-rotierende Erde.
        auto* earth = new EarthWidget(bar);
        earth->setFixedSize(60, 60);
        h->addWidget(earth, 0, Qt::AlignVCenter);

        return bar;
    }

    void MainWindow::refreshClock() {
        if (!clockLabel_) return;
        QDateTime now = QDateTime::currentDateTime();
        // Bloomberg-Stil: Wochentag, Datum, Zeit + UTC-Offset, monospace.
        QString s = now.toString("ddd  dd MMM yyyy   HH:mm:ss");
        clockLabel_->setText(s.toUpper());
    }

    void MainWindow::refreshMetrics() {
        auto m = core::SystemMetrics::capture();
        auto colorFor = [](double pct) -> QString {
            if (pct < 0)  return "#7e8aa0";          // unbekannt
            if (pct < 70) return "#3fae6a";          // grün
            if (pct < 90) return "#e0a31e";          // bernstein
            return "#d83a3a";                         // rot
        };
        if (mCpu_) {
            if (m.cpu_percent < 0) mCpu_->setText("—");
            else {
                mCpu_->setText(QString::number(m.cpu_percent, 'f', 0) + " %");
                mCpu_->setStyleSheet(QString("color:%1;font-family:'Cascadia Code','Consolas',monospace;"
                    "font-size:11pt;font-weight:700;").arg(colorFor(m.cpu_percent)));
            }
        }
        if (mTemp_) {
            if (m.cpu_temp_c < 0) {
                // Die CPU-Thermalzone (WMI) gibt nur erhöhten Prozessen Werte frei.
                // Ohne Admin daher ehrlicher Hinweis statt nur "n/a".
                // (elevated_ wird einmalig im Konstruktor erfasst — ändert sich nicht.)
                mTemp_->setText(elevated_ ? "n/a (Sensor)" : "n/a (Admin nötig)");
                mTemp_->setStyleSheet("color:#7e8aa0;font-family:'Cascadia Code','Consolas',monospace;"
                    "font-size:10pt;font-weight:700;");
            } else {
                mTemp_->setText(QString::number(m.cpu_temp_c, 'f', 0) + " °C");
                double tp = (m.cpu_temp_c - 40.0) / 50.0 * 100.0; // 40→0%, 90→100%
                mTemp_->setStyleSheet(QString("color:%1;font-family:'Cascadia Code','Consolas',monospace;"
                    "font-size:11pt;font-weight:700;").arg(colorFor(tp)));
            }
        }
        if (mRam_) {
            mRam_->setText(QString("%1 / %2  (%3%)")
                .arg(QString::fromStdString(core::SystemMetrics::human_bytes(m.ram_used)))
                .arg(QString::fromStdString(core::SystemMetrics::human_bytes(m.ram_total)))
                .arg(QString::number(m.ram_percent(), 'f', 0)));
            mRam_->setStyleSheet(QString("color:%1;font-family:'Cascadia Code','Consolas',monospace;"
                "font-size:11pt;font-weight:700;").arg(colorFor(m.ram_percent())));
        }
        if (mDisk_) {
            mDisk_->setText(QString("%1 frei / %2")
                .arg(QString::fromStdString(core::SystemMetrics::human_bytes(m.disk_free)))
                .arg(QString::fromStdString(core::SystemMetrics::human_bytes(m.disk_total))));
            mDisk_->setStyleSheet(QString("color:%1;font-family:'Cascadia Code','Consolas',monospace;"
                "font-size:11pt;font-weight:700;").arg(colorFor(m.disk_percent())));
        }
    }

    QWidget* MainWindow::buildSecurityBar() {
        secBar_ = new QLabel("SYSTEM STATUS · PRÜFE...");
        secBar_->setObjectName("secbar");
        secBar_->setContentsMargins(16, 7, 16, 7);
        secBar_->setStyleSheet(
            "QLabel#secbar{background:#10151f;border-bottom:1px solid #27313f;"
            "font-family:'Cascadia Code','Consolas',monospace;font-size:8pt;"
            "font-weight:700;letter-spacing:1px;color:#7e8aa0;}");
        return secBar_;
    }

    void MainWindow::refreshSecurityStatus() {
        auto st = core::SystemStatus::capture();
        QString tag; QString color;
        switch (st.risk_level()) {
            case 0:  tag = "● SECURE";    color = "#3fae6a"; break; // ok
            case 1:  tag = "▲ ADVISORY";  color = "#e0a31e"; break; // achtung
            default: tag = "■ ALERT";     color = "#d83a3a"; break; // warnung
        }
        QString text = tag + "   //   " + QString::fromStdString(st.summary()).toUpper();
        secBar_->setText(text);
        secBar_->setStyleSheet(
            QString("QLabel#secbar{background:#10151f;border-bottom:1px solid #27313f;"
                    "font-family:'Cascadia Code','Consolas',monospace;font-size:8pt;"
                    "font-weight:700;letter-spacing:1px;color:%1;}").arg(color));
    }

    QWidget* MainWindow::buildSidebar() {
        auto* side = new QFrame;
        side->setObjectName("sidebar");
        side->setFixedWidth(240);
        auto* v = new QVBoxLayout(side);
        v->setContentsMargins(0, 0, 0, 0);
        v->setSpacing(2);

        auto* logo = new QLabel("DGKN@LABS");
        logo->setObjectName("logo");
        v->addWidget(logo);
        auto* logosub = new QLabel("CRYPTO SUITE · V7");
        logosub->setObjectName("logosub");
        v->addWidget(logosub);

        auto addSection = [&](const QString& t) {
            auto* l = new QLabel(t);
            l->setObjectName("sectionTitle");
            v->addWidget(l);
        };
        auto addBtn = [&](const QString& t, auto slot) {
            auto* b = makeBtn(t);
            connect(b, &QPushButton::clicked, this, slot);
            v->addWidget(b);
            return b;
        };

        addSection("VOLUME OPERATIONS");
        addBtn("▸  Container erstellen", &MainWindow::onCreateContainer);
        addBtn("▸  Container öffnen (mounten)", &MainWindow::onMountContainer);
        addBtn("▸  Aushängen (unmount)", &MainWindow::onUnmountContainer);
        addBtn("▸  Passwort ändern", &MainWindow::onChangePassword);
        addBtn("▸  Integrität prüfen", &MainWindow::onCheckIntegrity);
        addBtn("▸  Header-Backup", &MainWindow::onBackupHeader);

        addSection("FILE CRYPTO");
        addBtn("▸  Datei verschlüsseln", &MainWindow::onEncryptFile);
        addBtn("▸  Datei entschlüsseln", &MainWindow::onDecryptFile);

        addSection("SECURITY");
        addBtn("▸  2FA / TOTP einrichten", &MainWindow::onSetup2FA);

        v->addStretch(1);
        auto* panic = makeBtn("⚠  EMERGENCY WIPE", "danger");
        connect(panic, &QPushButton::clicked, this, &MainWindow::onEmergencyWipe);
        v->addWidget(panic);

        return side;
    }

    QWidget* MainWindow::buildDashboardTab() {
        auto* w = new QWidget;
        auto* v = new QVBoxLayout(w);
        v->setContentsMargins(28, 24, 28, 24);
        v->setSpacing(16);

        auto* h1 = new QLabel("OPERATIONS DASHBOARD");
        h1->setObjectName("h1");
        v->addWidget(h1);

        auto* sub = new QLabel("Lokaler, offline-fähiger verschlüsselter Volume-Manager. "
                               "Keine Cloud · keine Telemetrie · Schlüssel im gesperrten RAM (VirtualLock).");
        sub->setObjectName("dim");
        sub->setWordWrap(true);
        v->addWidget(sub);

        // ── Status-Kachelreihe (Agency-Look: Label oben, Wert in Mono) ──
        // Gibt das Wert-Label zurück, damit Live-Werte aktualisiert werden können.
        auto makeTile = [](const QString& label, const QString& value, const QString& valColor,
                           QLabel** outVal = nullptr) {
            auto* tile = new QFrame;
            tile->setObjectName("card");
            auto* tv = new QVBoxLayout(tile);
            tv->setContentsMargins(16, 12, 16, 12);
            tv->setSpacing(4);
            auto* l = new QLabel(label);
            l->setStyleSheet("color:#7e8aa0;font-size:7pt;font-weight:700;letter-spacing:2px;");
            auto* val = new QLabel(value);
            val->setStyleSheet(QString("color:%1;font-family:'Cascadia Code','Consolas',monospace;"
                                       "font-size:11pt;font-weight:700;").arg(valColor));
            tv->addWidget(l); tv->addWidget(val);
            if (outVal) *outVal = val;
            return tile;
        };

        // Reihe 1: Krypto-Konfiguration (statisch).
        auto* tiles = new QHBoxLayout;
        tiles->setSpacing(12);
        tiles->addWidget(makeTile("CIPHER", "XChaCha20-Poly1305", "#dfe6ef"));
        tiles->addWidget(makeTile("KDF", "Argon2id · 256 MiB", "#dfe6ef"));
        tiles->addWidget(makeTile("2FA", "TOTP · RFC 6238", "#5b8dd6"));
        tiles->addWidget(makeTile("TPM", core::SystemStatus::capture().elevated ? "verfügbar" : "optional", "#5b8dd6"));
        tiles->addWidget(makeTile("MOUNTS", "0 aktiv", "#3fae6a"));
        v->addLayout(tiles);

        // Reihe 2: Live-Systemmetriken (CPU / Temp / RAM / Disk).
        auto* hw = new QHBoxLayout;
        hw->setSpacing(12);
        hw->addWidget(makeTile("CPU LOAD",   "—", "#dfe6ef", &mCpu_));
        hw->addWidget(makeTile("CPU TEMP",   "—", "#dfe6ef", &mTemp_));
        hw->addWidget(makeTile("RAM",        "—", "#5b8dd6", &mRam_));
        hw->addWidget(makeTile("DISK (SYS)", "—", "#3fae6a", &mDisk_));
        v->addLayout(hw);
        refreshMetrics(); // initialer Wert (CPU-Last beim ersten Mal noch "—")

        auto* card = new QFrame;
        card->setObjectName("card");
        auto* cv = new QVBoxLayout(card);
        cv->setContentsMargins(20, 18, 20, 18);
        auto* ct = new QLabel("SCHNELLSTART");
        ct->setObjectName("h2");
        cv->addWidget(ct);
        auto* steps = new QLabel(
            "01   2FA / TOTP zuerst einrichten — Pflicht-Schlüsselfaktor (SECURITY).\n"
            "02   Container erstellen (linke Leiste · VOLUME OPERATIONS).\n"
            "03   Container öffnen (mounten) → als Laufwerk nutzen, dann \"Aushängen\".\n"
            "04   Einzelne Dateien direkt ver- / entschlüsseln (FILE CRYPTO).\n\n"
            "Laufwerk-Hinweis: Ein echtes Laufwerk (mit Buchstabe, Daten nur im RAM, kein "
            "Klartext auf der Platte) entsteht nur mit installiertem WinFsp UND als "
            "Administrator gestarteter App. Fehlt eines davon, wird der Container beim Öffnen "
            "zwar authentifiziert und ins RAM geladen, aber OHNE Laufwerksbuchstaben "
            "(RAM-only) — das ist erwartetes Verhalten, kein Fehler.");
        steps->setObjectName("dim");
        steps->setWordWrap(true);
        cv->addWidget(steps);
        v->addWidget(card);

        v->addStretch(1);
        return w;
    }

    QWidget* MainWindow::buildLogTab() {
        auto* w = new QWidget;
        auto* v = new QVBoxLayout(w);
        v->setContentsMargins(28, 24, 28, 24);
        logView_ = new QPlainTextEdit;
        logView_->setReadOnly(true);
        v->addWidget(logView_);
        return w;
    }

    void MainWindow::log(const QString& msg) {
        QString line = QDateTime::currentDateTime().toString("HH:mm:ss") + "  " + msg;
        if (logView_) logView_->appendPlainText(line);
        if (statusLabel_) statusLabel_->setText(msg);
        // Tamper-evidentes Audit-Log (HMAC-Hash-Chain).
        if (audit_) audit_->append(msg.toStdString());
    }

    // ─── Aktionen ───

    void MainWindow::onCreateContainer() {
        QString path = QFileDialog::getSaveFileName(this, "Container-Datei wählen", "vault.dgkn",
                                                    "DGKN Container (*.dgkn)");
        if (path.isEmpty()) return;

        QDialog dlg(this);
        dlg.setWindowTitle("Container erstellen");
        styleDialog(dlg, 480);
        auto* v = new QVBoxLayout(&dlg);
        v->setContentsMargins(20, 18, 20, 18);
        v->setSpacing(10);
        v->addWidget(dialogHeader("NEUER CONTAINER",
            "Verschlüsselter Volume-Container · XChaCha20-Poly1305 · Argon2id 256 MiB."));

        auto* form = new QFormLayout;
        form->setSpacing(8);
        auto* size = new QSpinBox; size->setRange(1, 1024 * 64); size->setValue(50); size->setSuffix(" MB");
        auto* pw = new QLineEdit; pw->setEchoMode(QLineEdit::Password); pw->setPlaceholderText("min. 16 Zeichen, 3 Zeichengruppen");
        // 2FA-Secret wird NICHT mehr manuell eingegeben: der Container nutzt automatisch
        // das gespeicherte App-Login-Secret. Das Feld ist nur ein Statushinweis (Pflicht),
        // damit nie wieder „aus Versehen" ein abweichendes/neues Secret getippt wird.
        bool twofaReady = controller_.twofa_store_status()
                          == dgkn::core::TwoFactorStore::Status::Usable;
        auto* twofaInfo = new QLabel(twofaReady
            ? "✓ App-Login-2FA wird verwendet (Pflicht). Beim Erstellen nur den TOTP-Code eingeben."
            : "⚠ Keine gespeicherte App-Login-2FA. Bitte zuerst unter \"2FA / TOTP einrichten\" anlegen (Pflicht in v7).");
        twofaInfo->setObjectName(twofaReady ? "acc" : "dim");
        twofaInfo->setWordWrap(true);
        auto* hiddenChk = new QCheckBox("Verstecktes Volume anlegen (Plausible Deniability)");
        auto* hiddenSize = new QSpinBox; hiddenSize->setRange(1, 1024 * 32); hiddenSize->setValue(10); hiddenSize->setSuffix(" MB"); hiddenSize->setEnabled(false);
        auto* pwB = new QLineEdit; pwB->setEchoMode(QLineEdit::Password); pwB->setEnabled(false);
        // Passwort B (Hidden-Volume) unterliegt DERSELBEN Staerke-Regel wie Passwort A
        // (validate_password_strength gilt fuer beide). Daher denselben Hinweis anzeigen,
        // damit der Nutzer nicht raet, wie lang Passwort B sein muss.
        pwB->setPlaceholderText("min. 16 Zeichen, 3 Zeichengruppen (muss sich von Passwort A unterscheiden)");
        auto* pwBHint = new QLabel("Mindestens 16 Zeichen · 3 Zeichengruppen · muss sich klar von "
                                   "Passwort A unterscheiden (sonst kein echtes verstecktes Volume).");
        pwBHint->setObjectName("dim"); pwBHint->setWordWrap(true); pwBHint->setEnabled(false);
        connect(hiddenChk, &QCheckBox::toggled, hiddenSize, &QWidget::setEnabled);
        connect(hiddenChk, &QCheckBox::toggled, pwB, &QWidget::setEnabled);
        connect(hiddenChk, &QCheckBox::toggled, pwBHint, &QWidget::setEnabled);
        // Dauerhaft sichtbarer Passwort-Hinweis (nicht nur Platzhalter, der beim Tippen
        // verschwindet). Spiegelt die erzwungene Regel aus validate_password_strength.
        auto* pwHint = new QLabel("Mindestens 16 Zeichen · 3 Zeichengruppen "
                                  "(Groß-/Kleinbuchstaben, Ziffern, Sonderzeichen) · keine trivialen Muster.");
        pwHint->setObjectName("dim"); pwHint->setWordWrap(true);
        form->addRow("Größe:", size);
        form->addRow("Passwort:", pw);
        form->addRow("", pwHint);
        form->addRow("2FA:", twofaInfo);
        form->addRow(hiddenChk);
        form->addRow("Hidden-Größe:", hiddenSize);
        form->addRow("Passwort B:", pwB);
        form->addRow("", pwBHint);
        v->addLayout(form);

        auto* row = new QHBoxLayout;
        auto* cancel = makeBtn("ABBRECHEN");
        auto* ok = makeBtn("CONTAINER ERSTELLEN", "primary");
        row->addStretch(1); row->addWidget(cancel); row->addWidget(ok);
        v->addLayout(row);
        connect(cancel, &QPushButton::clicked, &dlg, &QDialog::reject);
        connect(ok, &QPushButton::clicked, &dlg, &QDialog::accept);
        if (dlg.exec() != QDialog::Accepted) return;

        // 2FA: automatisch das gespeicherte App-Login-Secret verwenden (einmal pro
        // Sitzung per Master-PW entsperrt + gecacht) — nie mehr ein neues „von alleine".
        std::string secret; bool unlockOk = true;
        unlockTwofaSecret(secret, unlockOk);
        if (!unlockOk) {
            log("Container-Erstellung abgebrochen (2FA-Secret nicht entsperrt).");
            return;
        }
        // Code-Verifikation vor dem Anlegen: bestätigt Zugriff auf die Authenticator-App.
        // (Bei secret=="" — keine 2FA eingerichtet — überspringt require2FA die Prüfung.)
        if (!require2FA(secret, "Bestaetige den TOTP-Code fuer den neuen Container:")) {
            log("Container-Erstellung abgebrochen (2FA nicht bestaetigt).");
            return;
        }

        QApplication::setOverrideCursor(Qt::WaitCursor);
        log("Erstelle Container... (Argon2id-Ableitung, bitte warten)");
        std::string s_pw  = pw->text().toStdString();
        std::string s_pwB = hiddenChk->isChecked() ? pwB->text().toStdString() : std::string();
        auto r = controller_.manager().create_container(
            path.toStdString(), (uint64_t)size->value(), s_pw, "",
            s_pwB, "",
            hiddenChk->isChecked() ? (uint64_t)hiddenSize->value() : 0,
            secret);
        // Passwort-Kopien sicher im RAM löschen (best effort; Qt-Widgets halten
        // zusätzliche, nicht wischbare Kopien — siehe SECURITY.md).
        crypto_utils::secure_wipe_string(s_pw);
        crypto_utils::secure_wipe_string(s_pwB);
        crypto_utils::secure_wipe_string(secret);   // lokale Kopie; Cache bleibt erhalten
        pw->clear(); pwB->clear();
        QApplication::restoreOverrideCursor();

        if (r.ok) {
            log(QString::fromStdString(r.message));
            // Klarer nächster Schritt: Erstellen mountet NICHT automatisch.
            QMessageBox::information(this, "Container erstellt",
                QString::fromStdString(r.message) +
                "\n\nNÄCHSTER SCHRITT: Klicke \"Container öffnen (mounten)\", um den Container "
                "als Laufwerk zu öffnen — erst dann erscheint ein Laufwerksbuchstabe, in den du "
                "Dateien packen kannst. \"Erstellen\" legt nur die Container-Datei an.");
        }
        else { log("FEHLER: " + QString::fromStdString(r.message)); QMessageBox::warning(this, "Fehler", QString::fromStdString(r.message)); }
    }

    void MainWindow::onMountContainer() {
        QString path = QFileDialog::getOpenFileName(this, "Container öffnen", "", "DGKN (*.dgkn);;Alle (*)");
        if (path.isEmpty()) return;

        // Modus wählen: normales oder verstecktes Volume.
        QStringList modes; modes << "normal" << "hidden";
        bool okMode = false;
        QString mode = QInputDialog::getItem(this, "Volume-Modus",
            "Welches Volume öffnen?", modes, 0, false, &okMode);
        if (!okMode) return;

        QString pw;
        if (!promptText(this, "CONTAINER ÖFFNEN", "Passwort des Containers eingeben.",
                        "Passwort:", true, pw) || pw.isEmpty()) return;
        std::string s_pw = pw.toStdString(); pw.clear();

        // 2FA-Schlüsselfaktor: automatisch das gespeicherte App-Login-Secret + TOTP-Code.
        std::string secret; bool unlockOk = true;
        unlockTwofaSecret(secret, unlockOk);
        if (!unlockOk) { crypto_utils::secure_wipe_string(s_pw); log("Mounten abgebrochen (2FA nicht entsperrt)."); return; }
        if (!require2FA(secret, "TOTP-Code zum Öffnen des Containers bestätigen:")) {
            crypto_utils::secure_wipe_string(s_pw); crypto_utils::secure_wipe_string(secret);
            log("Mounten abgebrochen (2FA nicht bestätigt)."); return;
        }

        QApplication::setOverrideCursor(Qt::WaitCursor);
        log("Mounte Container... (Argon2id-Ableitung, bitte warten)");
        // attach_drive=true (Default): mit Admin + WinFsp entsteht ein Laufwerksbuchstabe,
        // sonst bleibt das Volume RAM-only registriert (kein Buchstabe).
        auto r = controller_.manager().mount_volume(path.toStdString(), s_pw, "",
                                                     mode.toStdString(), secret);
        crypto_utils::secure_wipe_string(s_pw);
        crypto_utils::secure_wipe_string(secret);
        QApplication::restoreOverrideCursor();

        if (!r.ok) {
            log("Mount fehlgeschlagen: " + QString::fromStdString(r.message));
            QMessageBox::warning(this, "Fehler", QString::fromStdString(r.message));
            return;
        }
        // mount_id ist r.message; Laufwerksbuchstabe aus list_mounts nachschlagen.
        QString drive;
        for (const auto& mv : controller_.manager().list_mounts())
            if (mv.mount_id == r.message) { drive = QString::fromStdString(mv.mount_point); break; }

        if (!drive.isEmpty()) {
            log("Container gemountet als Laufwerk " + drive);
            // Das frisch gemountete Laufwerk direkt im Explorer öffnen, damit der Nutzer
            // sofort Dateien hineinziehen kann. Mount läuft in derselben User-Session,
            // daher ist das Laufwerk hier ohne Reboot sichtbar.
            QString driveRoot = drive;            // z.B. "Z:"
            if (!driveRoot.endsWith('\\')) driveRoot += '\\';
            QDesktopServices::openUrl(QUrl::fromLocalFile(driveRoot));
            QMessageBox::information(this, "Gemountet",
                "Container ist als Laufwerk " + drive + " verfügbar und wurde im Explorer "
                "geöffnet.\n\n"
                "Zieh deine Dateien einfach in das Laufwerk. Achtung: Inhalte liegen nur im "
                "RAM — sie werden erst beim \"Aushängen (unmount)\" verschlüsselt zurück in "
                "die Container-Datei geschrieben.\n\n"
                "Falls " + drive + " nicht automatisch aufgeht: im Explorer unter \"Dieser PC\" "
                "erscheint es als Laufwerk " + drive + ".");
        } else {
            log("Container geöffnet (RAM-only, kein Laufwerksbuchstabe).");
            // Nach Entfernen der Elevation-Sperre ist der häufigste verbleibende Grund ein
            // fehlender/abgestürzter WinFsp-Treiber oder kein freier Laufwerksbuchstabe.
            QMessageBox::information(this, "Geöffnet — aber kein Laufwerk",
                "Der Container wurde entschlüsselt und ins RAM geladen, aber es wurde KEIN "
                "Laufwerksbuchstabe vergeben.\n\n"
                "Mögliche Ursachen:\n"
                "• WinFsp ist nicht installiert oder der Treiber läuft nicht "
                "(Installer: https://winfsp.dev).\n"
                "• Kein freier Laufwerksbuchstabe (F:–Z:) verfügbar.\n"
                "• Die Programmversion wurde ohne WinFsp-Support gebaut (Stub).\n\n"
                "Hinweis: Adminrechte sind NICHT nötig — WinFsp mountet auch als normaler "
                "Benutzer.");
        }
    }

    void MainWindow::onUnmountContainer() {
        auto mounts = controller_.manager().list_mounts();
        if (mounts.empty()) {
            QMessageBox::information(this, "Aushängen",
                "Es sind keine Container gemountet.\n\n"
                "Hinweis: \"Container erstellen\" mountet NICHT automatisch. Nach dem "
                "Erstellen musst du \"Container öffnen (mounten)\" klicken — erst dann "
                "erscheint das Laufwerk und kann wieder ausgehängt werden.");
            return;
        }
        QStringList items; std::vector<std::string> ids;
        for (const auto& mv : mounts) {
            QString drv = mv.mount_point.empty() ? "(RAM-only)" : QString::fromStdString(mv.mount_point);
            items << QString::fromStdString(mv.label) + "  ·  " + drv;
            ids.push_back(mv.mount_id);
        }
        bool okSel = false;
        QString chosen = QInputDialog::getItem(this, "Aushängen",
            "Welchen Container sicher schließen?", items, 0, false, &okSel);
        if (!okSel) return;
        int idx = items.indexOf(chosen);
        if (idx < 0 || idx >= static_cast<int>(ids.size())) return;

        QApplication::setOverrideCursor(Qt::WaitCursor);
        auto r = controller_.manager().unmount(ids[idx]);
        QApplication::restoreOverrideCursor();
        log(QString::fromStdString(r.message));
        (r.ok ? QMessageBox::information(this, "Aushängen", QString::fromStdString(r.message))
              : QMessageBox::warning(this, "Fehler", QString::fromStdString(r.message)));
    }

    void MainWindow::onEncryptFile() {
        QString in = QFileDialog::getOpenFileName(this, "Datei zum Verschlüsseln");
        if (in.isEmpty()) return;
        QString out = QFileDialog::getSaveFileName(this, "Ausgabe-Datei", in + ".dgkn");
        if (out.isEmpty()) return;
        std::string s_pw, s_keyfile;
        if (!promptPasswordAndKeyfile(this, "DATEI VERSCHLÜSSELN",
                                      "Passwort festlegen und optional eine Keyfile als zweiten "
                                      "Schlüsselfaktor wählen.",
                                      /*requirePassword=*/true, s_pw, s_keyfile)) return;

        // Zweiter Schlüsselfaktor: das gespeicherte App-Login-Secret wird AUTOMATISCH als
        // Key-Binding genutzt (kein Abtippen mehr). Der 6-stellige TOTP-Code kann den
        // Secret NICHT ersetzen (er wechselt alle 30 s), dient aber als Identitätsnachweis:
        // wir verlangen ihn zusätzlich, damit nur jemand mit Authenticator-Zugriff
        // verschlüsselt. Ohne eingerichtete 2FA bleibt es reines Passwort (s_tw == "").
        std::string s_tw; bool unlockOk = true;
        unlockTwofaSecret(s_tw, unlockOk);
        if (!unlockOk) { crypto_utils::secure_wipe_string(s_pw); log("Verschlüsselung abgebrochen (2FA-Secret nicht entsperrt)."); return; }
        if (!require2FA(s_tw, "TOTP-Code für die Datei-Verschlüsselung bestätigen:")) {
            crypto_utils::secure_wipe_string(s_tw); crypto_utils::secure_wipe_string(s_pw);
            log("Verschlüsselung abgebrochen (2FA nicht bestätigt).");
            return;
        }

        QApplication::setOverrideCursor(Qt::WaitCursor);
        bool with2fa = !s_tw.empty();
        bool withKeyfile = !s_keyfile.empty();
        bool r = controller_.manager().encrypt_file(in.toStdString(), out.toStdString(), s_pw, s_keyfile, s_tw);
        crypto_utils::secure_wipe_string(s_pw); crypto_utils::secure_wipe_string(s_tw);
        QApplication::restoreOverrideCursor();
        log(r ? QString("Datei verschlüsselt%1%2: %3")
                    .arg(with2fa ? " (mit 2FA-Secret)" : "")
                    .arg(withKeyfile ? " (mit Keyfile)" : "")
                    .arg(out)
              : "Verschlüsselung fehlgeschlagen.");
        if (!r) { QMessageBox::warning(this, "Fehler", "Verschlüsselung fehlgeschlagen."); return; }

        // Original-Klartext sicher entfernen: solange die Originaldatei daneben liegt,
        // ist die Verschlüsselung wertlos. Erst NACH erfolgreicher Verschlüsselung,
        // mit ausdrücklicher Bestätigung (nicht ohne Rückfrage löschen), und nur wenn
        // Eingabe und Ausgabe verschiedene Dateien sind.
        if (in != out) {
            auto choice = QMessageBox::question(this, "Original sicher löschen?",
                QString("Die verschlüsselte Datei wurde erstellt:\n%1\n\n"
                        "Soll die unverschlüsselte ORIGINAL-Datei jetzt sicher gelöscht "
                        "werden (mehrfaches Überschreiben + Löschen)?\n\n%2\n\n"
                        "Hinweis: Auf SSDs ist sicheres Überschreiben durch Wear-Leveling "
                        "nur eingeschränkt wirksam — dort schützt Full-Disk-Verschlüsselung "
                        "zuverlässiger.").arg(out).arg(in),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
            if (choice == QMessageBox::Yes) {
                dgkn::utils::secure_wipe_file(in.toStdString(), 3);
                std::error_code ec;
                if (std::filesystem::exists(in.toStdString(), ec)) {
                    QMessageBox::warning(this, "Original", "Original konnte nicht gelöscht werden.");
                    log("Original-Löschung fehlgeschlagen: " + in);
                } else {
                    log("Original sicher gelöscht: " + in);
                }
            } else {
                log("Original behalten (nicht gelöscht): " + in);
            }
        }
    }

    void MainWindow::onDecryptFile() {
        QString in = QFileDialog::getOpenFileName(this, "Datei zum Entschlüsseln", "", "DGKN (*.dgkn);;Alle (*)");
        if (in.isEmpty()) return;
        QString out = QFileDialog::getSaveFileName(this, "Ausgabe-Datei");
        if (out.isEmpty()) return;
        std::string s_pw, s_keyfile;
        if (!promptPasswordAndKeyfile(this, "DATEI ENTSCHLÜSSELN",
                                      "Passwort eingeben. Wurde beim Verschlüsseln eine Keyfile "
                                      "verwendet, exakt dieselbe Datei wieder wählen.",
                                      /*requirePassword=*/true, s_pw, s_keyfile)) return;

        // Erst-Versuch: das gespeicherte App-Login-Secret automatisch als Schlüsselfaktor
        // (so wurde die Datei mit dem neuen Verhalten verschlüsselt) + TOTP-Bestätigung.
        std::string s_tw; bool unlockOk = true;
        unlockTwofaSecret(s_tw, unlockOk);
        if (!unlockOk) { crypto_utils::secure_wipe_string(s_pw); log("Entschlüsselung abgebrochen (2FA nicht entsperrt)."); return; }
        if (!require2FA(s_tw, "TOTP-Code für die Datei-Entschlüsselung bestätigen:")) {
            crypto_utils::secure_wipe_string(s_pw); crypto_utils::secure_wipe_string(s_tw);
            log("Entschlüsselung abgebrochen (2FA nicht bestätigt).");
            return;
        }

        QApplication::setOverrideCursor(Qt::WaitCursor);
        bool r = controller_.manager().decrypt_file(in.toStdString(), out.toStdString(), s_pw, s_keyfile, s_tw);
        crypto_utils::secure_wipe_string(s_tw);
        QApplication::restoreOverrideCursor();

        // Fallback für ALT-Dateien: vor dieser Änderung wurde das Secret manuell getippt
        // (oder gar keins). Schlägt der Auto-Versuch fehl, manuelle Eingabe anbieten.
        if (!r) {
            auto tryManual = QMessageBox::question(this, "Entschlüsselung fehlgeschlagen",
                "Entschlüsselung mit dem gespeicherten App-Login-Secret fehlgeschlagen.\n\n"
                "Wurde diese Datei mit einem ANDEREN (manuell eingegebenen) 2FA-Secret oder "
                "ganz ohne Secret verschlüsselt? Dann kannst du das passende Secret jetzt "
                "manuell eingeben (leer lassen = ohne Secret).",
                QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
            if (tryManual == QMessageBox::Yes) {
                std::string manual;
                promptSecret(this, "MANUELLES 2FA-SECRET",
                             "Exakt das beim Verschlüsseln genutzte Secret eingeben "
                             "(leer = ohne Secret).", "2FA-Secret (Base32):", manual);
                QApplication::setOverrideCursor(Qt::WaitCursor);
                r = controller_.manager().decrypt_file(in.toStdString(), out.toStdString(), s_pw, s_keyfile, manual);
                crypto_utils::secure_wipe_string(manual);
                QApplication::restoreOverrideCursor();
            }
        }
        crypto_utils::secure_wipe_string(s_pw);

        log(r ? "Datei entschlüsselt: " + out : "Entschlüsselung fehlgeschlagen (falsches Passwort/Keyfile/Secret?).");
        if (!r) QMessageBox::warning(this, "Fehler",
            "Entschlüsselung fehlgeschlagen.\nFalsches Passwort, falsche/fehlende Keyfile, "
            "falsches/fehlendes 2FA-Secret oder korrupt.");
    }

    void MainWindow::onChangePassword() {
        QString path = QFileDialog::getOpenFileName(this, "Container", "", "DGKN (*.dgkn);;Alle (*)");
        if (path.isEmpty()) return;
        QString oldpw, newpw;
        if (!promptText(this, "PASSWORT ÄNDERN", "Aktuelles Passwort des Containers.", "Altes Passwort:", true, oldpw)) return;
        if (!promptText(this, "PASSWORT ÄNDERN", "Neues Passwort (min. 16 Zeichen, 3 Zeichengruppen).", "Neues Passwort:", true, newpw)) return;

        // Gespeichertes App-Login-Secret verwenden (kein manuelles Abtippen mehr).
        std::string secret; bool unlockOk = true;
        unlockTwofaSecret(secret, unlockOk);
        if (!unlockOk) { log("Passwort-Änderung abgebrochen (2FA-Secret nicht entsperrt)."); return; }
        if (!require2FA(secret, "TOTP-Code für die Passwort-Änderung bestätigen:")) {
            log("Passwort-Änderung abgebrochen (2FA nicht bestätigt).");
            crypto_utils::secure_wipe_string(secret);
            return;
        }
        QApplication::setOverrideCursor(Qt::WaitCursor);
        auto r = controller_.manager().change_password(path.toStdString(), oldpw.toStdString(), "",
                                                        newpw.toStdString(), "", "normal", secret);
        crypto_utils::secure_wipe_string(secret);
        QApplication::restoreOverrideCursor();
        log(QString::fromStdString(r.message));
        (r.ok ? QMessageBox::information(this, "OK", QString::fromStdString(r.message))
              : QMessageBox::warning(this, "Fehler", QString::fromStdString(r.message)));
    }

    void MainWindow::onCheckIntegrity() {
        QString path = QFileDialog::getOpenFileName(this, "Container", "", "DGKN (*.dgkn);;Alle (*)");
        if (path.isEmpty()) return;
        QString pw;
        if (!promptText(this, "INTEGRITÄT PRÜFEN", "Passwort des Containers.", "Passwort:", true, pw)) return;

        // Gespeichertes App-Login-Secret verwenden (kein manuelles Abtippen mehr).
        std::string secret; bool unlockOk = true;
        unlockTwofaSecret(secret, unlockOk);
        if (!unlockOk) { log("Integritätsprüfung abgebrochen (2FA-Secret nicht entsperrt)."); return; }
        if (!require2FA(secret, "TOTP-Code für die Integritätsprüfung bestätigen:")) {
            log("Integritätsprüfung abgebrochen (2FA nicht bestätigt).");
            crypto_utils::secure_wipe_string(secret);
            return;
        }
        QApplication::setOverrideCursor(Qt::WaitCursor);
        auto r = controller_.manager().check_integrity(path.toStdString(), pw.toStdString(), "", "normal", secret);
        crypto_utils::secure_wipe_string(secret);
        QApplication::restoreOverrideCursor();
        log(QString::fromStdString(r.message));
        (r.ok ? QMessageBox::information(this, "Integritaet", QString::fromStdString(r.message))
              : QMessageBox::warning(this, "Integritaet", QString::fromStdString(r.message)));
    }

    void MainWindow::onBackupHeader() {
        QString path = QFileDialog::getOpenFileName(this, "Container", "", "DGKN (*.dgkn);;Alle (*)");
        if (path.isEmpty()) return;
        QString bak = QFileDialog::getSaveFileName(this, "Backup speichern", path + ".hdrbak.json", "JSON (*.json)");
        if (bak.isEmpty()) return;
        auto r = controller_.manager().backup_header(path.toStdString(), bak.toStdString());
        log(QString::fromStdString(r.message));
        (r.ok ? QMessageBox::information(this, "Backup", QString::fromStdString(r.message))
              : QMessageBox::warning(this, "Backup", QString::fromStdString(r.message)));
    }

    void MainWindow::onEmergencyWipe() {
        auto res = QMessageBox::warning(this, "NOTFALL-WIPE",
            "Alle gemounteten Volumes sofort schliessen und temporaere Daten sicher loeschen.\n\nFortfahren?",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (res != QMessageBox::Yes) return;
        controller_.manager().emergency_wipe(false);
        clearTwofaCache();   // gecachtes 2FA-Secret ebenfalls aus dem RAM entfernen
        log("Notfall-Wipe ausgefuehrt: alle Mounts geschlossen.");
    }

    // ── 2FA / TOTP ──

    bool MainWindow::require2FA(const std::string& secret, const QString& reason) {
        // Kein Secret hinterlegt -> keine Code-Prüfung (2FA nicht aktiv).
        if (secret.empty()) return true;

        QDialog dlg(this);
        dlg.setWindowTitle("Zwei-Faktor-Bestaetigung");
        auto* v = new QVBoxLayout(&dlg);
        auto* title = new QLabel("Zwei-Faktor-Authentifizierung");
        title->setObjectName("h2");
        v->addWidget(title);
        auto* sub = new QLabel(reason + "\n\nGib den aktuellen 6-stelligen Code aus deiner Authenticator-App ein.");
        sub->setObjectName("dim"); sub->setWordWrap(true);
        v->addWidget(sub);
        auto* code = new QLineEdit;
        code->setMaxLength(8);
        code->setPlaceholderText("000000");
        code->setAlignment(Qt::AlignCenter);
        v->addWidget(code);
        auto* ok = makeBtn("Bestaetigen", "primary");
        v->addWidget(ok);
        connect(ok, &QPushButton::clicked, &dlg, &QDialog::accept);
        connect(code, &QLineEdit::returnPressed, &dlg, &QDialog::accept);

        // Recovery-Code-Option NUR fuer das persistente App-Login-Secret anbieten
        // (nicht fuer container-gebundene Secrets, die kein Recovery kennen).
        // QDialog::done(2) signalisiert "per Recovery-Code bestaetigt".
        if (controller_.twofa_store_exists()) {
            auto* rec = makeBtn("Recovery-Code verwenden");
            v->addWidget(rec);
            connect(rec, &QPushButton::clicked, &dlg, [&](){
                std::string rc;
                if (!promptSecret(&dlg, "RECOVERY-CODE",
                                  "Authenticator nicht verfuegbar? Einmal-Recovery-Code eingeben.",
                                  "Recovery-Code:", rc)) return;
                std::string err;
                bool good = controller_.twofa_consume_code(rc, err);
                dgkn::crypto_utils::secure_wipe_string(rc);
                if (good) { dlg.done(2); return; }
                QMessageBox::warning(&dlg, "2FA", QString::fromStdString("Recovery-Code abgelehnt: " + err));
            });
        }

        // Bis zu 3 Versuche.
        for (int attempt = 0; attempt < 3; ++attempt) {
            code->clear();
            code->setFocus();
            int rc = dlg.exec();
            if (rc == 2) {   // per Recovery-Code bestaetigt
                int left = controller_.twofa_remaining_codes();
                log("2FA per Recovery-Code bestaetigt. Verbleibend: " + QString::number(left));
                if (left <= 2)
                    QMessageBox::warning(this, "2FA",
                        QString("Nur noch %1 Recovery-Codes uebrig. Bitte neue erzeugen.").arg(left));
                return true;
            }
            if (rc != QDialog::Accepted) return false; // abgebrochen
            if (controller_.verify_totp(secret, code->text().toStdString())) {
                return true;
            }
            QMessageBox::warning(this, "2FA", "Falscher oder abgelaufener Code. Bitte erneut versuchen.");
        }
        log("2FA fehlgeschlagen: 3 Fehlversuche.");
        return false;
    }

    bool MainWindow::unlockTwofaSecret(std::string& out_secret, bool& ok) {
        ok = true;
        out_secret.clear();
        using TfsStatus = dgkn::core::TwoFactorStore::Status;
        TfsStatus st = controller_.twofa_store_status();

        // Keine 2FA eingerichtet → kein zweiter Faktor (Container ohne 2FA-Bindung).
        if (st == TfsStatus::Missing) return true;

        if (st == TfsStatus::Corrupt) {
            QMessageBox::warning(this, "2FA",
                "Die gespeicherte 2FA-Sicherung ist beschaedigt. Bitte zuerst unter "
                "\"2FA / TOTP einrichten\" reparieren. Container-Operationen koennen das "
                "App-Login-Secret derzeit nicht verwenden.");
            return true;   // kein Abbruch: weiterhin ohne 2FA moeglich
        }

        // Schon in dieser Sitzung entsperrt → gecachten Wert wiederverwenden.
        if (twofaUnlocked_) { out_secret = twofaSecretCache_; return true; }

        // Einmalig Master-PW abfragen, Secret laden, cachen.
        std::string mpw;
        if (!promptSecret(this, "2FA ENTSPERREN",
                          "Master-Passwort der 2FA-Sicherung eingeben, um das gespeicherte "
                          "Secret fuer diese Operation zu verwenden.",
                          "Master-Passwort:", mpw)) { ok = false; return false; }
        std::string err;
        auto loaded = controller_.twofa_load(mpw, err);
        dgkn::crypto_utils::secure_wipe_string(mpw);
        if (!loaded) {
            QMessageBox::warning(this, "2FA",
                QString::fromStdString("Entsperren fehlgeschlagen: " + err));
            ok = false;
            return false;
        }
        twofaSecretCache_ = *loaded;
        dgkn::crypto_utils::secure_wipe_string(*loaded);
        twofaUnlocked_ = true;
        out_secret = twofaSecretCache_;
        return true;
    }

    void MainWindow::clearTwofaCache() {
        if (!twofaSecretCache_.empty())
            dgkn::crypto_utils::secure_wipe_string(twofaSecretCache_);
        twofaSecretCache_.clear();
        twofaUnlocked_ = false;
    }

    void MainWindow::showRecoveryCodes(const std::vector<std::string>& codes) {
        QDialog dlg(this);
        dlg.setWindowTitle("Recovery-Codes");
        auto* v = new QVBoxLayout(&dlg);
        auto* h = new QLabel("RECOVERY-CODES"); h->setObjectName("h2"); v->addWidget(h);
        auto* info = new QLabel(
            "Jeder Code ersetzt EINMALIG den TOTP-Code, falls deine Authenticator-App "
            "fehlt. JETZT notieren oder ausdrucken — sie werden nie wieder vollstaendig "
            "angezeigt.");
        info->setObjectName("dim"); info->setWordWrap(true); v->addWidget(info);
        QString joined; for (const auto& c : codes) joined += QString::fromStdString(c) + "\n";
        auto* view = new QPlainTextEdit(joined); view->setReadOnly(true); v->addWidget(view);
        auto* row = new QHBoxLayout;
        auto* copy = makeBtn("Kopieren");
        auto* close = makeBtn("Schliessen", "primary");
        row->addWidget(copy); row->addStretch(1); row->addWidget(close); v->addLayout(row);
        connect(copy, &QPushButton::clicked, &dlg, [joined, this]() {
            QApplication::clipboard()->setText(joined);
            QTimer::singleShot(15000, this, [joined]() {
                auto* cb = QApplication::clipboard();
                if (cb->text() == joined) cb->clear();
            });
        });
        connect(close, &QPushButton::clicked, &dlg, &QDialog::accept);
        dlg.exec();
    }

    void MainWindow::onSetup2FA() {
        QDialog dlg(this);
        dlg.setWindowTitle("2FA einrichten (TOTP)");
        dlg.resize(640, 480);
        auto* v = new QVBoxLayout(&dlg);

        auto* h1 = new QLabel("2FA / TOTP EINRICHTEN");
        h1->setObjectName("h2");
        v->addWidget(h1);
        auto* info = new QLabel(
            "Erzeuge ein Secret, importiere es in eine Authenticator-App "
            "(Google Authenticator, Aegis, …) und sichere es mit einem Master-Passwort.\n\n"
            "WICHTIG: Das Master-Passwort schuetzt dein gespeichertes Secret. Recovery-Codes "
            "ersetzen einmalig den TOTP-Code, falls die App verloren geht.");
        info->setObjectName("dim"); info->setWordWrap(true);
        v->addWidget(info);

        // Persistentes Secret: existiert eine brauchbare Sicherung, laden wir sie
        // (Master-PW), statt jedes Mal ein neues Secret zu erzeugen (alter Bug).
        std::string initialSecret;
        using TfsStatus = dgkn::core::TwoFactorStore::Status;
        TfsStatus st = controller_.twofa_store_status();

        // Beschädigte/veraltete Datei (z. B. Alt-Format ohne 'salt_b64'): NICHT am
        // Entschlüsseln scheitern und den Nutzer aussperren. Stattdessen Reset anbieten.
        if (st == TfsStatus::Corrupt) {
            auto r = QMessageBox::warning(this, "2FA",
                "Die gespeicherte 2FA-Sicherung ist beschaedigt oder hat ein altes Format "
                "und kann nicht entsperrt werden.\n\n"
                "Beschaedigte Sicherung verwerfen und 2FA neu einrichten?\n"
                "WICHTIG: Die bisherige Authenticator-Bindung und alte Recovery-Codes "
                "werden dabei ungueltig.",
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            if (r != QMessageBox::Yes) return;
            std::string err;
            if (!controller_.twofa_reset(err)) {
                QMessageBox::critical(this, "2FA",
                    QString::fromStdString("Zuruecksetzen fehlgeschlagen: " + err));
                log(QString::fromStdString("2FA: Reset fehlgeschlagen (" + err + ")."));
                return;
            }
            log("2FA: Beschaedigte Sicherung verworfen, Neueinrichtung gestartet.");
            st = TfsStatus::Missing;   // weiter im Einrichtungsmodus
        }

        if (st == TfsStatus::Usable) {
            std::string mpw;
            if (!promptSecret(this, "2FA ENTSPERREN",
                              "Master-Passwort der 2FA-Sicherung eingeben.",
                              "Master-Passwort:", mpw)) return;
            std::string err;
            auto loaded = controller_.twofa_load(mpw, err);
            dgkn::crypto_utils::secure_wipe_string(mpw);
            if (!loaded) {
                QMessageBox::warning(this, "2FA",
                    QString::fromStdString("Entsperren fehlgeschlagen: " + err));
                log(QString::fromStdString("2FA: Entsperren fehlgeschlagen (" + err + ")."));
                return;   // KEIN stillschweigendes neues Secret
            }
            initialSecret = *loaded;
            dgkn::crypto_utils::secure_wipe_string(*loaded);
        } else {
            initialSecret = controller_.new_totp_secret();
        }

        v->addWidget(new QLabel("TOTP-Secret (Base32):"));
        auto* secretEdit = new QLineEdit(QString::fromStdString(initialSecret));
        secretEdit->setReadOnly(false);
        v->addWidget(secretEdit);

        // QR-Code rechts, URI/Info links — der QR ist der bequeme Weg zum App-Import.
        auto* mid = new QHBoxLayout;
        auto* leftCol = new QVBoxLayout;
        leftCol->addWidget(new QLabel("Scanne den QR-Code mit deiner Authenticator-App:"));
        auto* uriView = new QPlainTextEdit;
        uriView->setReadOnly(true);
        uriView->setMaximumHeight(70);
        leftCol->addWidget(new QLabel("oder otpauth-URI manuell importieren:"));
        leftCol->addWidget(uriView);
        leftCol->addStretch(1);
        mid->addLayout(leftCol, 1);

        auto* qr = new QrWidget;
        qr->setFixedSize(190, 190);
        mid->addWidget(qr, 0, Qt::AlignTop);
        v->addLayout(mid);

        auto* status = new QLabel("");
        status->setObjectName("acc");
        v->addWidget(status);

        auto refreshUri = [&, qr]() {
            std::string s = secretEdit->text().toStdString();
            if (controller_.totp_secret_valid(s)) {
                QString uri = QString::fromStdString(controller_.totp_uri(s));
                uriView->setPlainText(uri);
                qr->setText(uri);   // QR live aktualisieren
            } else {
                uriView->setPlainText("(ungueltiges Secret)");
                qr->setText("");
            }
        };
        refreshUri();
        connect(secretEdit, &QLineEdit::textChanged, &dlg, [&](const QString&){ refreshUri(); });

        auto* btnRow = new QHBoxLayout;
        auto* genBtn = makeBtn("Neues Secret");
        auto* copyBtn = makeBtn("Secret kopieren");
        auto* testBtn = makeBtn("Code testen", "primary");
        auto* saveBtn = makeBtn("Sichern (Master-PW)", "primary");
        btnRow->addWidget(genBtn); btnRow->addWidget(copyBtn); btnRow->addWidget(testBtn); btnRow->addWidget(saveBtn);
        v->addLayout(btnRow);

        connect(genBtn, &QPushButton::clicked, &dlg, [&, status](){
            if (controller_.twofa_store_exists()) {
                auto r = QMessageBox::question(&dlg, "Neues Secret",
                    "Es existiert bereits eine gesicherte 2FA. Ein neues Secret macht die "
                    "bestehende Authenticator-Bindung ungueltig. Fortfahren?");
                if (r != QMessageBox::Yes) return;
            }
            secretEdit->setText(QString::fromStdString(controller_.new_totp_secret()));
            status->setText("Neues Secret erzeugt — zum Aktivieren erneut sichern.");
        });
        connect(saveBtn, &QPushButton::clicked, &dlg, [&, status](){
            std::string secret = secretEdit->text().toStdString();
            if (!controller_.totp_secret_valid(secret)) {
                status->setText("Ungueltiges Secret — nicht gespeichert.");
                dgkn::crypto_utils::secure_wipe_string(secret); return;
            }
            std::string mpw, mpw2;
            if (!promptSecret(&dlg, "MASTER-PASSWORT", "Neues Master-Passwort fuer die 2FA-Sicherung.",
                              "Master-Passwort:", mpw)) { dgkn::crypto_utils::secure_wipe_string(secret); return; }
            auto [strong, msg] = dgkn::crypto_utils::validate_password_strength(mpw);
            if (!strong) {
                status->setText(QString::fromStdString("Schwaches Master-PW: " + msg));
                dgkn::crypto_utils::secure_wipe_string(secret); dgkn::crypto_utils::secure_wipe_string(mpw); return;
            }
            if (!promptSecret(&dlg, "MASTER-PASSWORT", "Master-Passwort wiederholen.", "Wiederholen:", mpw2)) {
                dgkn::crypto_utils::secure_wipe_string(secret); dgkn::crypto_utils::secure_wipe_string(mpw); return; }
            if (mpw != mpw2) {
                status->setText("Passwoerter stimmen nicht ueberein.");
                dgkn::crypto_utils::secure_wipe_string(secret); dgkn::crypto_utils::secure_wipe_string(mpw); dgkn::crypto_utils::secure_wipe_string(mpw2); return;
            }
            std::vector<std::string> codes; std::string err;
            bool ok = controller_.twofa_save(secret, mpw, codes, err);
            dgkn::crypto_utils::secure_wipe_string(secret);
            dgkn::crypto_utils::secure_wipe_string(mpw); dgkn::crypto_utils::secure_wipe_string(mpw2);
            if (!ok) { status->setText(QString::fromStdString("Speichern fehlgeschlagen: " + err)); return; }
            // Session-Cache invalidieren: beim nächsten Container-Vorgang wird das
            // (ggf. neue) Secret frisch entsperrt — kein veralteter Cache.
            clearTwofaCache();
            status->setText("2FA gesichert. Recovery-Codes JETZT notieren!");
            showRecoveryCodes(codes);
            log(QString::fromStdString("2FA-Secret persistent gesichert: " + controller_.twofa_store_path()));
        });
        connect(copyBtn, &QPushButton::clicked, &dlg, [&](){
            QString secret = secretEdit->text();
            QApplication::clipboard()->setText(secret);
            status->setText("Secret kopiert — wird in 15 s automatisch geloescht.");
            // Clipboard-Auto-Clear: nach 15 s nur löschen, wenn der Inhalt UNSER Secret
            // ist (sonst nicht in fremde Zwischenablage-Inhalte eingreifen).
            QTimer::singleShot(15000, this, [secret]() {
                auto* cb = QApplication::clipboard();
                if (cb->text() == secret) cb->clear();
            });
        });
        connect(testBtn, &QPushButton::clicked, &dlg, [&](){
            QString c;
            if (!promptText(&dlg, "CODE TESTEN", "6-stelligen Code aus deiner Authenticator-App eingeben.",
                            "TOTP-Code:", false, c)) return;
            bool good = controller_.verify_totp(secretEdit->text().toStdString(), c.toStdString());
            status->setText(good ? "Code korrekt — Secret funktioniert."
                                 : "Code falsch/abgelaufen — Secret oder App prüfen.");
        });

        auto* close = makeBtn("Schliessen");
        connect(close, &QPushButton::clicked, &dlg, &QDialog::accept);
        v->addWidget(close);

        dlg.exec();
        log("2FA-Einrichtungsdialog geschlossen.");
    }

}