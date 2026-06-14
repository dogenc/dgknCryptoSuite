cmake_minimum_required(VERSION 3.20)
project(DGKNCryptoSuite VERSION 7.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Verhindert, dass <windows.h> die min/max-Makros definiert (kollidiert mit std::min/std::max)
if(WIN32)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

# ─── Sicherheits-Härtung (Compiler-/Linker-Mitigations, MSVC) ───
# /GS  Stack-Buffer-Overrun-Erkennung (Stack Canaries)
# /guard:cf  Control Flow Guard (indirekte Aufrufe abgesichert)
# /sdl  zusätzliche Security-Checks
# /Qspectre  Spectre-V1-Mitigation
# Linker: /DYNAMICBASE (ASLR) /HIGHENTROPYVA (64-Bit-ASLR) /NXCOMPAT (DEP)
#         /guard:cf /CETCOMPAT (Shadow-Stack/CET)
if(MSVC)
    add_compile_options(/GS /guard:cf /sdl /Qspectre)
    add_link_options(/guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT)
    # Reproduzierbarer Build: /Brepro entfernt Zeitstempel aus Objekt-/PE-Headern,
    # sodass identische Quellen + Toolchain bit-identische Binaries erzeugen
    # (Voraussetzung für unabhängige Verifikation — siehe SECURITY.md).
    add_compile_options(/Brepro)
    add_link_options(/Brepro)
endif()

# libsodium + argon2 + json (via vcpkg)
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(unofficial-argon2 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
# QR-Code-Encoder (für 2FA-Setup). Optional: GUI baut auch ohne, zeigt dann "QR n/a".
find_package(QREncode CONFIG QUIET)
if(NOT QREncode_FOUND)
    find_library(QRENCODE_LIB NAMES qrencode PATHS "${VCPKG_INSTALLED_DIR}")
    find_path(QRENCODE_INC qrencode.h)
endif()

# Core-Bibliothek (ohne main, damit auch Tests/GUI dagegen linken koennen)
add_library(dgkn_core STATIC
    core/Crypto.cpp
    core/CryptoUtils.cpp
    core/Manager.cpp
    core/TPMUtils.cpp
    core/SecureMemory.cpp
    core/Archive.cpp
    core/Totp.cpp
    core/TwoFactorStore.cpp
    core/SystemStatus.cpp
    core/SystemMetrics.cpp
    core/AuditLog.cpp
    utils/FsHelpers.cpp
)

target_include_directories(dgkn_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

target_link_libraries(dgkn_core PUBLIC
    unofficial-sodium::sodium
    unofficial::argon2::libargon2
    nlohmann_json::nlohmann_json
)

# ─── WinFsp (FUSE) — optional: In-RAM-VirtualVolume ───
# Nur wenn WinFsp installiert ist, wird das Mount-Backend kompiliert.
find_path(WINFSP_INCLUDE_DIR fuse/fuse.h PATHS "C:/Program Files (x86)/WinFsp/inc")
find_library(WINFSP_LIB NAMES winfsp-x64 PATHS "C:/Program Files (x86)/WinFsp/lib")
# Die Laufzeit-DLL liegt in WinFsp\bin (NICHT \lib). Sie muss zur Laufzeit neben der
# exe (oder auf dem PATH) liegen, sonst startet die exe nicht ("winfsp-x64.dll nicht
# gefunden"). Wir finden sie explizit, um sie unten per Post-Build neben die exe zu kopieren.
find_file(WINFSP_DLL NAMES winfsp-x64.dll PATHS "C:/Program Files (x86)/WinFsp/bin")
if(WINFSP_INCLUDE_DIR AND WINFSP_LIB)
    message(STATUS "WinFsp gefunden: ${WINFSP_LIB} — VirtualVolume wird gebaut.")
    target_sources(dgkn_core PRIVATE core/VirtualVolume.cpp)
    target_compile_definitions(dgkn_core PUBLIC DGKN_HAVE_WINFSP)
    target_include_directories(dgkn_core PUBLIC ${WINFSP_INCLUDE_DIR})
    target_link_libraries(dgkn_core PUBLIC ${WINFSP_LIB})
else()
    message(WARNING "WinFsp nicht gefunden — VirtualVolume baut als Stub (mount()=false).")
    target_sources(dgkn_core PRIVATE core/VirtualVolume.cpp)
endif()

# CLI-Executable
add_executable(dgkn_crypto main.cpp)
target_link_libraries(dgkn_crypto PRIVATE dgkn_core)

# ─── Qt6 GUI ───
# Qt-Pfad: Du gibst ihn via -DCMAKE_PREFIX_PATH="C:/Qt/6.x/msvc2022_64" an (siehe README).
# Ein explizit gesetzter Pfad hat immer Vorrang. Findet find_package Qt6 damit nicht
# (z.B. weil nur der vcpkg-Pfad gesetzt ist), suchen wir gängige Standard-Installationsorte
# automatisch ab und versuchen es erneut — so springt der GUI-Build auch ohne expliziten
# Qt-Pfad an. Wird gar kein Qt gefunden, baut der Rest (Core, CLI, Tests) trotzdem; nur das
# GUI-Target wird übersprungen (siehe unten).
find_package(Qt6 COMPONENTS Widgets OpenGL OpenGLWidgets QUIET)
if(NOT Qt6_FOUND)
    file(GLOB _qt_candidates
        "C:/Qt/6.*/msvc2022_64"
        "C:/Qt/6.*/msvc2019_64"
        "$ENV{HOME}/Qt/6.*/msvc2022_64")
    if(_qt_candidates)
        list(SORT _qt_candidates)
        list(GET _qt_candidates -1 _qt_auto)            # neueste gefundene Version
        list(APPEND CMAKE_PREFIX_PATH "${_qt_auto}")
        message(STATUS "Qt automatisch gefunden: ${_qt_auto} (override mit -DCMAKE_PREFIX_PATH=...)")
        find_package(Qt6 COMPONENTS Widgets OpenGL OpenGLWidgets QUIET)
    endif()
endif()
if(Qt6_FOUND)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)   # .qrc (Fenster-Icon) automatisch kompilieren
    add_executable(dgkn_gui WIN32
        gui/gui_main.cpp
        gui/MainWindow.cpp
        gui/AppController.cpp
        gui/EarthWidget.cpp
        gui/QrWidget.cpp
        gui/resources.qrc       # Qt-Ressource: Fenster-Icon
        gui/app_icon.rc         # Windows-Ressource: EXE-Icon (Taskleiste/Explorer)
        gui/dgkn.manifest       # Prozess-Härtung: SegmentHeap, DPI, asInvoker
    )
    target_include_directories(dgkn_gui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/gui)
    target_link_libraries(dgkn_gui PRIVATE dgkn_core Qt6::Widgets Qt6::OpenGL Qt6::OpenGLWidgets)
    # QR-Encoder anbinden (CONFIG-Target bevorzugt, sonst manuell gefundene Lib).
    if(QREncode_FOUND)
        target_link_libraries(dgkn_gui PRIVATE QREncode::QREncode)
    elseif(QRENCODE_LIB)
        target_link_libraries(dgkn_gui PRIVATE ${QRENCODE_LIB})
        target_include_directories(dgkn_gui PRIVATE ${QRENCODE_INC})
    endif()

    # WinFsp-Laufzeit-DLL zuverlässig neben die exe kopieren. Das automatische
    # applocal/windeployqt-Skript erfasst sie nicht immer (z.B. wenn dumpbin fehlt),
    # was zum Startfehler "winfsp-x64.dll nicht gefunden" führt. Dieser Post-Build-Step
    # garantiert sie unabhängig davon.
    if(WINFSP_DLL)
        add_custom_command(TARGET dgkn_gui POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${WINFSP_DLL}" "$<TARGET_FILE_DIR:dgkn_gui>"
            COMMENT "Kopiere winfsp-x64.dll neben dgkn_gui.exe")
    endif()
else()
    message(WARNING "Qt6 nicht gefunden — GUI-Target (dgkn_gui) wird uebersprungen.")
endif()

# ─── Tests (Catch2 via vcpkg) ───
find_package(Catch2 3 CONFIG REQUIRED)
enable_testing()

add_executable(dgkn_tests tests/test_crypto.cpp tests/test_manager.cpp tests/test_archive.cpp tests/test_hardening.cpp tests/test_totp.cpp tests/test_tpm.cpp tests/test_auditlog.cpp tests/test_twofa_store.cpp)
target_link_libraries(dgkn_tests PRIVATE dgkn_core Catch2::Catch2WithMain)

# Statt catch_discover_tests (führt die exe zur Build-Zeit aus und scheitert an
# fehlenden vcpkg-DLLs im PATH) registrieren wir die Suite als einen ctest-Eintrag.
add_test(NAME dgkn_crypto_tests COMMAND dgkn_tests)

# vcpkg-DLLs (Catch2, sodium, argon2) zur Laufzeit auffindbar machen. Der Pfad wird aus
# den von vcpkg gesetzten Variablen abgeleitet, damit er bei JEDER vcpkg-Installation passt
# (nicht hardcodiert auf C:/vcpkg). VCPKG_INSTALLED_DIR/_VCPKG_INSTALLED_DIR werden vom
# vcpkg-Toolchain-File gesetzt; als letzter Fallback der frühere feste Pfad.
if(DEFINED VCPKG_INSTALLED_DIR)
    set(_vcpkg_bin "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/bin")
elseif(DEFINED _VCPKG_INSTALLED_DIR)
    set(_vcpkg_bin "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/bin")
else()
    set(_vcpkg_bin "C:/vcpkg/installed/x64-windows/debug/bin")
endif()
file(TO_NATIVE_PATH "${_vcpkg_bin}" _vcpkg_bin_native)

set_tests_properties(dgkn_crypto_tests PROPERTIES
    ENVIRONMENT "PATH=${_vcpkg_bin_native};$ENV{PATH}")

# ─── Fuzz-Stress-Target (Standalone, baut auch mit MSVC für CI) ───
# Beschießt die Angreifer-kontrollierten Parser mit zufälligem Input; darf nie crashen.
# Für echtes Coverage-Fuzzing mit clang/libFuzzer:
#   clang++ -std=c++20 -fsanitize=fuzzer,address -DDGKN_FUZZ_LIBFUZZER \
#       tests/fuzz_parsers.cpp core/Archive.cpp -I core -I . -lsodium
add_executable(dgkn_fuzz tests/fuzz_parsers.cpp)
target_link_libraries(dgkn_fuzz PRIVATE dgkn_core)
add_test(NAME dgkn_fuzz_stress COMMAND dgkn_fuzz 20000)
set_tests_properties(dgkn_fuzz_stress PROPERTIES
    ENVIRONMENT "PATH=${_vcpkg_bin_native};$ENV{PATH}")
