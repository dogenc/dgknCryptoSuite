// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "EarthWidget.hpp"

#include <QMatrix4x4>
#include <cmath>

namespace dgkn::gui {

    EarthWidget::EarthWidget(QWidget* parent) : QOpenGLWidget(parent) {
        setMinimumSize(120, 120);
        // ~60 FPS Repaint für flüssige Rotation.
        connect(&frameTimer_, &QTimer::timeout, this, [this]{ update(); });
        frameTimer_.start(16);
    }

    EarthWidget::~EarthWidget() {
        makeCurrent();
        vbo_.destroy();
        ibo_.destroy();
        vao_.destroy();
        doneCurrent();
    }

    void EarthWidget::buildSphere(int stacks, int slices) {
        std::vector<float> verts; // pos(3) + normal(3)
        for (int i = 0; i <= stacks; ++i) {
            float v = float(i) / stacks;
            float phi = v * float(M_PI);
            for (int j = 0; j <= slices; ++j) {
                float u = float(j) / slices;
                float theta = u * 2.0f * float(M_PI);
                float x = std::sin(phi) * std::cos(theta);
                float y = std::cos(phi);
                float z = std::sin(phi) * std::sin(theta);
                verts.insert(verts.end(), {x, y, z, x, y, z});
            }
        }
        std::vector<unsigned int> idx;
        for (int i = 0; i < stacks; ++i) {
            for (int j = 0; j < slices; ++j) {
                int a = i * (slices + 1) + j;
                int b = a + slices + 1;
                idx.insert(idx.end(), {(unsigned)a, (unsigned)b, (unsigned)(a + 1)});
                idx.insert(idx.end(), {(unsigned)(a + 1), (unsigned)b, (unsigned)(b + 1)});
            }
        }
        indexCount_ = (int)idx.size();

        vao_.create(); vao_.bind();
        vbo_.create(); vbo_.bind();
        vbo_.allocate(verts.data(), int(verts.size() * sizeof(float)));
        ibo_.create(); ibo_.bind();
        ibo_.allocate(idx.data(), int(idx.size() * sizeof(unsigned int)));

        program_.enableAttributeArray(0);
        program_.setAttributeBuffer(0, GL_FLOAT, 0, 3, 6 * sizeof(float));
        program_.enableAttributeArray(1);
        program_.setAttributeBuffer(1, GL_FLOAT, 3 * sizeof(float), 3, 6 * sizeof(float));
        vao_.release();
    }

    void EarthWidget::initializeGL() {
        initializeOpenGLFunctions();
        glClearColor(0.039f, 0.055f, 0.078f, 1.0f); // #0a0e14, passt zum Theme
        glEnable(GL_DEPTH_TEST);

        const char* vs = R"(
            #version 330 core
            layout(location=0) in vec3 aPos;
            layout(location=1) in vec3 aNormal;
            uniform mat4 uMVP;
            uniform mat4 uModel;
            out vec3 vNormal;
            out vec3 vLocal;
            void main(){
                gl_Position = uMVP * vec4(aPos, 1.0);
                vNormal = mat3(uModel) * aNormal;
                vLocal = aPos;        // Kugelkoordinaten für die prozedurale Textur
            }
        )";

        // Prozedurale Erde: Value-Noise erzeugt Land/Wasser; Stahlblau-Ozean,
        // gedämpftes Grün-Land — passend zum Agency-Theme. Einfaches Lambert-Licht.
        const char* fs = R"(
            #version 330 core
            in vec3 vNormal;
            in vec3 vLocal;
            out vec4 FragColor;
            uniform vec3 uLightDir;

            float hash(vec3 p){
                p = fract(p*0.3183099 + vec3(0.1,0.2,0.3));
                p *= 17.0;
                return fract(p.x*p.y*p.z*(p.x+p.y+p.z));
            }
            float noise(vec3 x){
                vec3 i = floor(x); vec3 f = fract(x);
                f = f*f*(3.0-2.0*f);
                float n000=hash(i+vec3(0,0,0)); float n100=hash(i+vec3(1,0,0));
                float n010=hash(i+vec3(0,1,0)); float n110=hash(i+vec3(1,1,0));
                float n001=hash(i+vec3(0,0,1)); float n101=hash(i+vec3(1,0,1));
                float n011=hash(i+vec3(0,1,1)); float n111=hash(i+vec3(1,1,1));
                return mix(mix(mix(n000,n100,f.x),mix(n010,n110,f.x),f.y),
                           mix(mix(n001,n101,f.x),mix(n011,n111,f.x),f.y),f.z);
            }
            float fbm(vec3 p){
                float v=0.0, a=0.5;
                for(int i=0;i<5;i++){ v+=a*noise(p); p*=2.03; a*=0.5; }
                return v;
            }
            void main(){
                vec3 n = normalize(vNormal);
                float h = fbm(vLocal*2.5);
                vec3 ocean = vec3(0.13,0.28,0.45);   // Stahlblau-Ozean
                vec3 land  = vec3(0.20,0.42,0.28);    // gedämpftes Grün
                vec3 ice   = vec3(0.75,0.82,0.90);
                vec3 base = (h > 0.52) ? mix(land, ice, smoothstep(0.7,0.85,abs(vLocal.y)))
                                       : ocean;
                float diff = max(dot(n, normalize(uLightDir)), 0.0);
                float amb = 0.25;
                vec3 col = base * (amb + 0.9*diff);
                // Atmosphären-Rand (Fresnel) in Stahlblau.
                float rim = pow(1.0 - max(dot(n, vec3(0,0,1)), 0.0), 3.0);
                col += vec3(0.18,0.32,0.55) * rim;
                FragColor = vec4(col, 1.0);
            }
        )";

        program_.addShaderFromSourceCode(QOpenGLShader::Vertex, vs);
        program_.addShaderFromSourceCode(QOpenGLShader::Fragment, fs);
        program_.bindAttributeLocation("aPos", 0);
        program_.bindAttributeLocation("aNormal", 1);
        program_.link();
        program_.bind();
        buildSphere(48, 64);
        program_.release();
        clock_.start();
    }

    void EarthWidget::resizeGL(int w, int h) {
        glViewport(0, 0, w, h);
    }

    void EarthWidget::paintGL() {
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        program_.bind();
        vao_.bind();

        float t = clock_.elapsed() / 1000.0f;
        float aspect = height() > 0 ? float(width()) / float(height()) : 1.0f;

        QMatrix4x4 proj; proj.perspective(35.0f, aspect, 0.1f, 10.0f);
        QMatrix4x4 view; view.translate(0, 0, -3.2f);
        QMatrix4x4 model;
        model.rotate(23.5f, 1, 0, 0);          // Achsneigung
        model.rotate(t * 18.0f, 0, 1, 0);       // langsame Rotation
        QMatrix4x4 mvp = proj * view * model;

        program_.setUniformValue("uMVP", mvp);
        program_.setUniformValue("uModel", model);
        program_.setUniformValue("uLightDir", QVector3D(0.6f, 0.4f, 0.8f));

        glDrawElements(GL_TRIANGLES, indexCount_, GL_UNSIGNED_INT, nullptr);

        vao_.release();
        program_.release();
    }

}