// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <QWidget>
#include <QPainter>
#include <QLinearGradient>
#include <QRadialGradient>
#include <QElapsedTimer>
#include <QTimer>
#include <QApplication>
#include <QScreen>
#include <QFontDatabase>
#include <QPaintEvent>
#include <QtMath>
#include <functional>

namespace dgkn::gui {

    // Eigenständiger 7-Sekunden-Splashscreen im Bloomberg-/Agency-Stil der App
    // (dunkler Hintergrund, Stahlblau-Akzent). Komplett gemalt — kein Bild-Asset nötig.
    // Zeigt "DGKN@Labs" groß, darunter "CRYPTO SUITE v7.0", einen Sweep-Akzent und
    // einen Fortschrittsbalken, der über 7 s vollläuft. Danach schließt er sich selbst
    // und ruft den onFinished-Callback (zeigt das Hauptfenster).
    // Kein Q_OBJECT nötig: Splash deklariert keine eigenen Signale/Slots. Die connect()-
    // Verbindung nutzt QTimer::timeout (Sender hat das Signal) auf eine Lambda — das
    // funktioniert ohne moc für diese Klasse.
    class Splash : public QWidget {
    public:
        explicit Splash(std::function<void()> on_finished, int duration_ms = 7000)
            : on_finished_(std::move(on_finished)), duration_ms_(duration_ms) {
            setWindowFlags(Qt::SplashScreen | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
            setAttribute(Qt::WA_TranslucentBackground, false);
            setFixedSize(W_, H_);

            // Mittig auf dem primären Bildschirm platzieren.
            if (auto* scr = QApplication::primaryScreen()) {
                const QRect g = scr->geometry();
                move(g.center().x() - W_ / 2, g.center().y() - H_ / 2);
            }

            clock_.start();
            // ~60 FPS für den weichen Sweep + Balken.
            connect(&ticker_, &QTimer::timeout, this, [this] {
                qint64 e = clock_.elapsed();
                if (e >= duration_ms_) {
                    ticker_.stop();
                    close();
                    if (on_finished_) on_finished_();
                    deleteLater();
                    return;
                }
                update();
            });
            ticker_.start(16);
        }

    protected:
        void paintEvent(QPaintEvent*) override {
            const double t = qMin(1.0, double(clock_.elapsed()) / double(duration_ms_));
            QPainter p(this);
            p.setRenderHint(QPainter::Antialiasing, true);
            p.setRenderHint(QPainter::TextAntialiasing, true);

            const QColor bg("#0a0e14"), surface("#10151f"), border("#27313f");
            const QColor fg("#dfe6ef"), dim("#7e8aa0"), acc("#5b8dd6");

            // Hintergrund mit dezentem Radialglanz hinter dem Logo.
            p.fillRect(rect(), bg);
            QRadialGradient glow(QPointF(W_ / 2.0, H_ * 0.42), W_ * 0.7);
            glow.setColorAt(0.0, QColor(91, 141, 214, 38));
            glow.setColorAt(1.0, QColor(91, 141, 214, 0));
            p.fillRect(rect(), glow);

            // Rahmen.
            p.setPen(QPen(border, 1));
            p.drawRect(QRectF(0.5, 0.5, W_ - 1, H_ - 1));

            // Kopf-Hairline.
            p.setPen(QPen(QColor(91, 141, 214, 140), 1));
            p.drawLine(28, 30, W_ - 28, 30);

            // Marke oben links.
            QFont mono = monoFont(9);
            mono.setLetterSpacing(QFont::AbsoluteSpacing, 2.0);
            p.setFont(mono);
            p.setPen(dim);
            p.drawText(QRect(28, 8, W_ - 56, 20), Qt::AlignLeft | Qt::AlignVCenter,
                       "DGKN@LABS · SECURE CRYPTO TERMINAL");
            p.drawText(QRect(28, 8, W_ - 56, 20), Qt::AlignRight | Qt::AlignVCenter, "v7.0");

            // Großes Logo "DGKN@Labs".
            QFont big = monoFont(46);
            big.setBold(true);
            big.setLetterSpacing(QFont::AbsoluteSpacing, 1.0);
            p.setFont(big);
            p.setPen(fg);
            QRect logoRect(0, int(H_ * 0.24), W_, 70);
            p.drawText(logoRect, Qt::AlignCenter, "DGKN@Labs");

            // Unterzeile.
            QFont sub = monoFont(15);
            sub.setLetterSpacing(QFont::AbsoluteSpacing, 6.0);
            p.setFont(sub);
            p.setPen(acc);
            p.drawText(QRect(0, int(H_ * 0.24) + 64, W_, 28), Qt::AlignCenter, "CRYPTO SUITE v7.0");

            // Krypto-Zeile.
            QFont tiny = monoFont(8);
            tiny.setLetterSpacing(QFont::AbsoluteSpacing, 2.5);
            p.setFont(tiny);
            p.setPen(dim);
            p.drawText(QRect(0, int(H_ * 0.24) + 96, W_, 18), Qt::AlignCenter,
                       "XCHACHA20-POLY1305 · ARGON2ID · 2FA/TPM");

            // Sweep-Akzentlinie unter dem Logo (läuft hin und her).
            const double cx = W_ / 2.0;
            const double sweep = (qSin(clock_.elapsed() / 600.0) * 0.5 + 0.5); // 0..1
            const double half = 150.0;
            const double x0 = cx - half, x1 = cx + half;
            double lineY = H_ * 0.24 + 58;
            QLinearGradient lg(x0, 0, x1, 0);
            lg.setColorAt(qBound(0.0, sweep - 0.12, 1.0), QColor(91, 141, 214, 0));
            lg.setColorAt(qBound(0.0, sweep, 1.0), acc);
            lg.setColorAt(qBound(0.0, sweep + 0.12, 1.0), QColor(91, 141, 214, 0));
            p.setPen(QPen(QBrush(lg), 2));
            p.drawLine(QPointF(x0, lineY), QPointF(x1, lineY));

            // Fortschrittsbalken unten.
            const int barW = W_ - 120, barH = 4;
            const int barX = 60, barY = H_ - 64;
            p.setPen(Qt::NoPen);
            p.setBrush(QColor("#0c1118"));
            p.drawRoundedRect(QRect(barX, barY, barW, barH), 2, 2);
            QLinearGradient fillg(barX, 0, barX + barW, 0);
            fillg.setColorAt(0.0, QColor("#3c648f"));
            fillg.setColorAt(1.0, acc);
            p.setBrush(fillg);
            p.drawRoundedRect(QRect(barX, barY, int(barW * t), barH), 2, 2);

            // Prozent + Statuszeile.
            p.setFont(tiny);
            p.setPen(dim);
            p.drawText(QRect(barX, barY + 10, barW, 16), Qt::AlignLeft, "INITIALISIERE SICHEREN KERN…");
            p.drawText(QRect(barX, barY + 10, barW, 16), Qt::AlignRight,
                       QString::number(int(t * 100)).rightJustified(3, ' ') + " %");

            // Fußzeile.
            p.setPen(QColor("#4a5468"));
            p.drawText(QRect(0, H_ - 24, W_, 16), Qt::AlignCenter,
                       "© DGKN@Labs · Native C++/Qt · Zero-Trust Local Vault");
        }

    private:
        static QFont monoFont(int pt) {
            QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
            f.setPointSize(pt);
            return f;
        }

        std::function<void()> on_finished_;
        int duration_ms_;
        QElapsedTimer clock_;
        QTimer ticker_;
        static constexpr int W_ = 560;
        static constexpr int H_ = 380;
    };

}