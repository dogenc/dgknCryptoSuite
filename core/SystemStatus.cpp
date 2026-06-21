// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "SystemStatus.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#pragma comment(lib, "wbemuuid.lib")
#endif

namespace dgkn::core {

#ifdef _WIN32
    namespace {
        // Prüft via WMI (root\SecurityCenter2), ob ein AntiVirus-Produkt aktiv ist.
        // productState-Bit 0x1000 im mittleren Byte = Echtzeitschutz aktiv.
        bool query_av(std::string& name_out) {
            bool active = false;
            HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            bool did_init = SUCCEEDED(hr);
            // RPC_E_CHANGED_MODE: COM ist bereits anders initialisiert -> trotzdem weiter.
            if (hr == RPC_E_CHANGED_MODE) did_init = false;
            else if (FAILED(hr)) return false;

            IWbemLocator* loc = nullptr;
            IWbemServices* svc = nullptr;
            IEnumWbemClassObject* en = nullptr;
            do {
                if (FAILED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                        IID_IWbemLocator, (LPVOID*)&loc)) || !loc) break;
                if (FAILED(loc->ConnectServer(_bstr_t(L"ROOT\\SecurityCenter2"), nullptr, nullptr,
                        0, 0, 0, 0, &svc)) || !svc) break;
                CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
                if (FAILED(svc->ExecQuery(_bstr_t(L"WQL"),
                        _bstr_t(L"SELECT displayName, productState FROM AntiVirusProduct"),
                        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en)) || !en) break;

                IWbemClassObject* obj = nullptr; ULONG ret = 0;
                while (en->Next(WBEM_INFINITE, 1, &obj, &ret) == S_OK && ret) {
                    VARIANT vState; VariantInit(&vState);
                    if (SUCCEEDED(obj->Get(L"productState", 0, &vState, 0, 0)) && vState.vt == VT_I4) {
                        // Echtzeitschutz-Bit (0x1000) im zweiten Byte.
                        if (((vState.lVal >> 8) & 0x10) != 0) {
                            active = true;
                            VARIANT vName; VariantInit(&vName);
                            if (SUCCEEDED(obj->Get(L"displayName", 0, &vName, 0, 0)) && vName.vt == VT_BSTR && vName.bstrVal) {
                                _bstr_t bn(vName.bstrVal);
                                name_out = static_cast<const char*>(bn);
                            }
                            VariantClear(&vName);
                        }
                    }
                    VariantClear(&vState);
                    obj->Release();
                    if (active) break;
                }
            } while (false);

            if (en) en->Release();
            if (svc) svc->Release();
            if (loc) loc->Release();
            if (did_init) CoUninitialize();
            return active;
        }

        bool query_elevated() {
            BOOL elevated = FALSE;
            HANDLE token = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
                TOKEN_ELEVATION te; DWORD sz = sizeof(te);
                if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &sz))
                    elevated = te.TokenIsElevated;
                CloseHandle(token);
            }
            return elevated != FALSE;
        }
    }
#endif

    SystemStatus SystemStatus::capture() {
        SystemStatus s;
#ifdef _WIN32
        s.debugger_present = (IsDebuggerPresent() != FALSE);
        BOOL remote = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
        if (remote) s.debugger_present = true;
        s.av_active = query_av(s.av_name);
        s.elevated = query_elevated();
#endif
        s.self_integrity_ok = true; // Platzhalter: optionaler EXE-Hash-Selbstcheck später.
        return s;
    }

    int SystemStatus::risk_level() const {
        if (debugger_present || !self_integrity_ok) return 2; // Warnung
        if (!av_active) return 1;                             // Achtung
        return 0;                                             // gut
    }

    std::string SystemStatus::summary() const {
        if (debugger_present) return "WARNUNG: Debugger erkannt - Betrieb unsicher";
        if (!self_integrity_ok) return "WARNUNG: Selbst-Integritaet verletzt";
        if (!av_active) return "Achtung: kein aktiver Echtzeit-Virenschutz erkannt";
        std::string av = av_name.empty() ? "Virenschutz aktiv" : (av_name + " aktiv");
        return "System ok - " + av + (elevated ? " - Admin" : "");
    }

}