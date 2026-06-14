// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "SystemMetrics.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#pragma comment(lib, "wbemuuid.lib")
#endif

#include <cstdio>
#include <atomic>

namespace dgkn::core {

#ifdef _WIN32
    namespace {
        // Vorherige CPU-Zeiten für die Delta-Berechnung (eine Prozess-weite Quelle reicht).
        std::atomic<uint64_t> g_prevIdle{0}, g_prevKernel{0}, g_prevUser{0};

        uint64_t ft2u(const FILETIME& ft) {
            return (uint64_t(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        }

        double cpu_load() {
            FILETIME idle, kernel, user;
            if (!GetSystemTimes(&idle, &kernel, &user)) return -1.0;
            uint64_t i = ft2u(idle), k = ft2u(kernel), u = ft2u(user);
            uint64_t pi = g_prevIdle.exchange(i);
            uint64_t pk = g_prevKernel.exchange(k);
            uint64_t pu = g_prevUser.exchange(u);
            if (pk == 0 && pu == 0) return -1.0; // erster Aufruf: noch kein Delta
            uint64_t sys = (k - pk) + (u - pu);   // kernel inkl. idle
            uint64_t idl = (i - pi);
            if (sys == 0) return -1.0;
            double busy = double(sys - idl) / double(sys) * 100.0;
            if (busy < 0) busy = 0; if (busy > 100) busy = 100;
            return busy;
        }

        // CPU-Temperatur via WMI ACPI-Thermalzone (oft, aber nicht immer verfügbar).
        double cpu_temp() {
            double result = -1.0;
            HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            bool did_init = SUCCEEDED(hr);
            if (hr == RPC_E_CHANGED_MODE) did_init = false;
            else if (FAILED(hr)) return -1.0;

            IWbemLocator* loc = nullptr; IWbemServices* svc = nullptr; IEnumWbemClassObject* en = nullptr;
            do {
                if (FAILED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                        IID_IWbemLocator, (LPVOID*)&loc)) || !loc) break;
                // ACPI-Thermalzone liegt in root\WMI.
                if (FAILED(loc->ConnectServer(_bstr_t(L"ROOT\\WMI"), nullptr, nullptr, 0, 0, 0, 0, &svc)) || !svc) break;
                CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
                if (FAILED(svc->ExecQuery(_bstr_t(L"WQL"),
                        _bstr_t(L"SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature"),
                        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en)) || !en) break;
                IWbemClassObject* obj = nullptr; ULONG ret = 0;
                if (en->Next(WBEM_INFINITE, 1, &obj, &ret) == S_OK && ret) {
                    VARIANT v; VariantInit(&v);
                    if (SUCCEEDED(obj->Get(L"CurrentTemperature", 0, &v, 0, 0)) &&
                        (v.vt == VT_I4 || v.vt == VT_UI4)) {
                        // Wert ist in Zehntel-Kelvin.
                        double tenthsK = double(v.vt == VT_I4 ? v.lVal : v.ulVal);
                        result = tenthsK / 10.0 - 273.15;
                    }
                    VariantClear(&v);
                    if (obj) obj->Release();
                }
            } while (false);
            if (en) en->Release();
            if (svc) svc->Release();
            if (loc) loc->Release();
            if (did_init) CoUninitialize();
            return result;
        }
    }
#endif

    SystemMetrics SystemMetrics::capture() {
        SystemMetrics m;
#ifdef _WIN32
        m.cpu_percent = cpu_load();
        m.cpu_temp_c = cpu_temp();

        MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
        if (GlobalMemoryStatusEx(&ms)) {
            m.ram_total = ms.ullTotalPhys;
            m.ram_used = ms.ullTotalPhys - ms.ullAvailPhys;
        }

        ULARGE_INTEGER freeA{}, totA{}, totFree{};
        // Systemlaufwerk (Windows-Verzeichnis).
        char winDir[MAX_PATH]; GetWindowsDirectoryA(winDir, MAX_PATH);
        char root[4] = { winDir[0], ':', '\\', 0 };
        if (GetDiskFreeSpaceExA(root, &freeA, &totA, &totFree)) {
            m.disk_total = totA.QuadPart;
            m.disk_free = totFree.QuadPart;
        }
#endif
        return m;
    }

    std::string SystemMetrics::human_bytes(uint64_t bytes) {
        const char* units[] = { "B", "KB", "MB", "GB", "TB", "PB" };
        double v = double(bytes); int u = 0;
        while (v >= 1024.0 && u < 5) { v /= 1024.0; ++u; }
        char buf[32];
        std::snprintf(buf, sizeof(buf), (v < 10 && u > 0) ? "%.1f %s" : "%.0f %s", v, units[u]);
        return buf;
    }

}