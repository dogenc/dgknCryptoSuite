// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#pragma once

#include <QOpenGLWidget>
#include <QOpenGLFunctions>
#include <QOpenGLShaderProgram>
#include <QOpenGLBuffer>
#include <QOpenGLVertexArrayObject>
#include <QElapsedTimer>
#include <QTimer>
#include <vector>

namespace dgkn::gui {

    // Echte 3D-rotierende Erde via OpenGL. Eine UV-Kugel wird prozedural im
    // Fragment-Shader texturiert (Kontinente per Value-Noise) und mit einfacher
    // Beleuchtung gerendert — keine externe Bilddatei nötig.
    class EarthWidget : public QOpenGLWidget, protected QOpenGLFunctions {
        Q_OBJECT
    public:
        explicit EarthWidget(QWidget* parent = nullptr);
        ~EarthWidget() override;

    protected:
        void initializeGL() override;
        void resizeGL(int w, int h) override;
        void paintGL() override;

    private:
        void buildSphere(int stacks, int slices);

        QOpenGLShaderProgram program_;
        QOpenGLBuffer vbo_{QOpenGLBuffer::VertexBuffer};
        QOpenGLBuffer ibo_{QOpenGLBuffer::IndexBuffer};
        QOpenGLVertexArrayObject vao_;
        int indexCount_ = 0;
        QElapsedTimer clock_;
        QTimer frameTimer_;
    };

}