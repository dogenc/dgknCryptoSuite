// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <QWidget>
#include <QString>
#include <QImage>

namespace dgkn::gui {

    // Rendert einen QR-Code aus Text (z.B. otpauth-URI). Schwarz-auf-weiß mit
    // Quiet-Zone, damit Authenticator-Apps zuverlässig scannen.
    class QrWidget : public QWidget {
        Q_OBJECT
    public:
        explicit QrWidget(QWidget* parent = nullptr);
        void setText(const QString& text);   // erzeugt + zeichnet den QR-Code neu

    protected:
        void paintEvent(QPaintEvent*) override;
        QSize sizeHint() const override { return QSize(200, 200); }

    private:
        QImage image_;
        bool valid_ = false;
    };

}