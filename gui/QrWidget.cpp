// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "QrWidget.hpp"

#include <QPainter>
#include <qrencode.h>

namespace dgkn::gui {

    QrWidget::QrWidget(QWidget* parent) : QWidget(parent) {
        setMinimumSize(180, 180);
    }

    void QrWidget::setText(const QString& text) {
        valid_ = false;
        if (text.isEmpty()) { update(); return; }

        // libqrencode: Byte-Modus, ECC-Level M, automatische Versionswahl.
        QByteArray utf8 = text.toUtf8();
        QRcode* qr = QRcode_encodeString(utf8.constData(), 0, QR_ECLEVEL_M, QR_MODE_8, 1);
        if (!qr) { update(); return; }

        int n = qr->width;
        const int quiet = 4;                         // Pflicht-Quiet-Zone
        int dim = n + 2 * quiet;
        QImage img(dim, dim, QImage::Format_RGB32);
        img.fill(Qt::white);
        for (int y = 0; y < n; ++y)
            for (int x = 0; x < n; ++x)
                if (qr->data[y * n + x] & 1)          // Bit 0 = dunkel
                    img.setPixel(x + quiet, y + quiet, qRgb(0, 0, 0));
        QRcode_free(qr);

        image_ = img;
        valid_ = true;
        update();
    }

    void QrWidget::paintEvent(QPaintEvent*) {
        QPainter p(this);
        p.fillRect(rect(), QColor("#0a0e14"));
        if (!valid_ || image_.isNull()) {
            p.setPen(QColor("#7e8aa0"));
            p.drawText(rect(), Qt::AlignCenter, "QR n/a");
            return;
        }
        int side = qMin(width(), height());
        int off = side / image_.width();             // ganzzahlige Skalierung -> scharf
        if (off < 1) off = 1;
        int scaled = off * image_.width();
        int x = (width() - scaled) / 2;
        int y = (height() - scaled) / 2;
        p.fillRect(x, y, scaled, scaled, Qt::white);
        p.drawImage(QRect(x, y, scaled, scaled), image_);
    }

}