#include <windows.h>
#include <wlanapi.h>
#include <objbase.h>
#include <wtypes.h>
#include <vector>
#include <string>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <fstream>
#include <locale>
#include <codecvt>
#include <cctype>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

// File containing preferred SSIDs (one per line, UTF-8 or UTF-16LE, with or without BOM)
const char* PREFERRED_SSIDS_FILE = "preferred_networks.txt";

// Helper to trim whitespace (including \r, \n, space, tab) from both ends of a wstring
std::wstring trim(const std::wstring& s) {
    size_t start = 0, end = s.length();
    while (start < end && (s[start] == L' ' || s[start] == L'\t' || s[start] == L'\r' || s[start] == L'\n'))
        ++start;
    while (end > start && (s[end - 1] == L' ' || s[end - 1] == L'\t' || s[end - 1] == L'\r' || s[end - 1] == L'\n'))
        --end;
    return s.substr(start, end - start);
}

// Read list of preferred networks from a file (supports UTF-8 (with/without BOM), UTF-16LE (with/without BOM))
std::vector<std::wstring> LoadPreferredNetworks(const char* filename) {
    std::vector<std::wstring> ssids;
    std::ifstream file(filename, std::ios::binary);
    if (!file) return ssids;

    // Read entire file to buffer
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (buffer.empty()) return ssids;

    // Check BOM
    bool is_utf16le = false, is_utf8 = false;
    size_t offset = 0;
    if (buffer.size() >= 2 && (unsigned char)buffer[0] == 0xFF && (unsigned char)buffer[1] == 0xFE) {
        is_utf16le = true;
        offset = 2;
    }
    else if (buffer.size() >= 3 && (unsigned char)buffer[0] == 0xEF && (unsigned char)buffer[1] == 0xBB && (unsigned char)buffer[2] == 0xBF) {
        is_utf8 = true;
        offset = 3;
    }
    else if (buffer.size() >= 2 && (unsigned char)buffer[0] == 0xFE && (unsigned char)buffer[1] == 0xFF) {
        // UTF-16BE not supported
        return ssids;
    }
    else {
        // No BOM: guess based on file size and nulls
        if (buffer.size() % 2 == 0 && buffer.size() >= 4) {
            size_t nulls = 0;
            for (size_t i = 1; i < buffer.size(); i += 2) if (buffer[i] == 0) nulls++;
            if (nulls > buffer.size() / 4) is_utf16le = true;
        }
    }

    if (is_utf16le) {
        // Parse as UTF-16LE
        std::wstring wcontent;
        for (size_t i = offset; i + 1 < buffer.size(); i += 2) {
            wchar_t wc = (unsigned char)buffer[i] | ((unsigned char)buffer[i + 1] << 8);
            wcontent += wc;
        }
        std::wistringstream wiss(wcontent);
        std::wstring line;
        while (std::getline(wiss, line)) {
            line = trim(line);
            if (!line.empty())
                ssids.push_back(line);
        }
    }
    else {
        // Parse as UTF-8
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
        std::string content(buffer.begin() + offset, buffer.end());
        std::istringstream iss(content);
        std::string line;
        while (std::getline(iss, line)) {
            std::wstring wline = conv.from_bytes(line);
            wline = trim(wline);
            if (!wline.empty())
                ssids.push_back(wline);
        }
    }
    return ssids;
}

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;
const wchar_t* SERVICE_NAME = L"WifiSwitchService";

// Logging utility: log error to a file (simple append, Unicode)
void LogError(const std::wstring& msg) {
    FILE* logf = nullptr;
    _wfopen_s(&logf, L"WifiSwitchService.log", L"a+, ccs=UNICODE");
    if (logf) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fwprintf(logf, L"[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg.c_str());
        fclose(logf);
    }
}

// Helper: Convert DOT11_SSID to wstring for display (assumes SSID is printable ASCII/UTF-8)
std::wstring SsidToWString(const DOT11_SSID& ssid) {
    std::wstring result;
    for (ULONG i = 0; i < ssid.uSSIDLength; ++i) {
        result += (wchar_t)ssid.ucSSID[i];
    }
    return result;
}

// Helper: Compare DOT11_SSID to wstring by byte (works for ASCII/UTF-8/space)
bool SsidEquals(const DOT11_SSID& ssid, const std::wstring& wssid) {
    if (wssid.length() != ssid.uSSIDLength) return false;
    for (ULONG i = 0; i < ssid.uSSIDLength; ++i) {
        if ((UCHAR)wssid[i] != ssid.ucSSID[i]) return false;
    }
    return true;
}

// Helper: Fill DOT11_SSID struct from wstring, copying only low byte per wchar_t
void FillSsidStruct(DOT11_SSID& ssidStruct, const std::wstring& ssidName) {
    ssidStruct.uSSIDLength = (ULONG)ssidName.size();
    for (ULONG i = 0; i < ssidStruct.uSSIDLength; ++i)
        ssidStruct.ucSSID[i] = (UCHAR)(ssidName[i] & 0xFF);
}

// Find the best preferred network from scan results
bool FindBestPreferredNetwork(PWLAN_AVAILABLE_NETWORK_LIST pNetList, const std::vector<std::wstring>& preferredNetworks, std::wstring& outSsid) {
    int maxSignal = -1;
    for (const auto& prefSsid : preferredNetworks) {
        for (unsigned int i = 0; i < pNetList->dwNumberOfItems; ++i) {
            PWLAN_AVAILABLE_NETWORK pNet = &pNetList->Network[i];
            if (SsidEquals(pNet->dot11Ssid, prefSsid) && (int)pNet->wlanSignalQuality > maxSignal) {
                maxSignal = pNet->wlanSignalQuality;
                outSsid = prefSsid;
            }
        }
    }
    return maxSignal != -1;
}

// Get the currently connected SSID for the given interface, returns true if connected, false otherwise
bool GetCurrentlyConnectedSsid(HANDLE hClient, GUID& interfaceGuid, std::wstring& outSsid) {
    WLAN_CONNECTION_ATTRIBUTES* connAttr = NULL;
    DWORD attrSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
    WLAN_OPCODE_VALUE_TYPE opCode;
    DWORD ret = WlanQueryInterface(hClient, &interfaceGuid, wlan_intf_opcode_current_connection, NULL, &attrSize, (PVOID*)&connAttr, &opCode);
    if (ret == ERROR_SUCCESS && connAttr &&
        connAttr->isState == wlan_interface_state_connected) {
        outSsid = SsidToWString(connAttr->wlanAssociationAttributes.dot11Ssid);
        WlanFreeMemory(connAttr);
        return true;
    }
    if (connAttr) WlanFreeMemory(connAttr);
    return false;
}

// Connect to a Wi-Fi network by SSID (profile name must match SSID)
bool ConnectToNetwork(HANDLE hClient, GUID& interfaceGuid, const std::wstring& ssid) {
    WLAN_CONNECTION_PARAMETERS params = {};
    DOT11_SSID ssidStruct = {};
    params.wlanConnectionMode = wlan_connection_mode_profile;
    params.strProfile = ssid.c_str();
    params.pDot11Ssid = &ssidStruct;
    params.dot11BssType = dot11_BSS_type_any;
    params.dwFlags = 0;

    if (ssid.size() > DOT11_SSID_MAX_LENGTH) {
        LogError(L"SSID too long: " + ssid);
        return false;
    }

    FillSsidStruct(ssidStruct, ssid);

    DWORD ret = WlanConnect(hClient, &interfaceGuid, &params, NULL);
    if (ret != ERROR_SUCCESS) {
        std::wstringstream ss;
        ss << L"WlanConnect failed for SSID \"" << ssid << L"\", error: " << ret;
        LogError(ss.str());
        return false;
    }
    else {
        std::wstringstream ss;
        ss << L"Switched to network: \"" << ssid << L"\"";
        LogError(ss.str());
    }
    return true;
}

// Service worker thread: scans and switches Wi-Fi
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    std::vector<std::wstring> preferredNetworks = LoadPreferredNetworks(PREFERRED_SSIDS_FILE);

    if (preferredNetworks.empty()) {
        LogError(L"No preferred networks loaded -- aborting service worker thread.");
        return 1;
    }

    HANDLE hClient = NULL;
    DWORD dwMaxClient = 2, dwCurVersion = 0;
    DWORD ret = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (ret != ERROR_SUCCESS) {
        std::wstringstream ss;
        ss << L"WlanOpenHandle failed, error: " << ret;
        LogError(ss.str());
        return 1;
    }

    while (WaitForSingleObject(g_ServiceStopEvent, 30000) == WAIT_TIMEOUT) {
        PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
        ret = WlanEnumInterfaces(hClient, NULL, &pIfList);
        if (ret != ERROR_SUCCESS) {
            std::wstringstream ss;
            ss << L"WlanEnumInterfaces failed, error: " << ret;
            LogError(ss.str());
            continue;
        }

        for (unsigned int i = 0; i < pIfList->dwNumberOfItems; ++i) {
            GUID interfaceGuid = pIfList->InterfaceInfo[i].InterfaceGuid;
            PWLAN_AVAILABLE_NETWORK_LIST pNetList = NULL;
            ret = WlanGetAvailableNetworkList(hClient, &interfaceGuid, 0, NULL, &pNetList);
            if (ret != ERROR_SUCCESS) {
                std::wstringstream ss;
                ss << L"WlanGetAvailableNetworkList failed, error: " << ret;
                LogError(ss.str());
                continue;
            }

            std::wstring bestSsid;
            if (FindBestPreferredNetwork(pNetList, preferredNetworks, bestSsid)) {
                std::wstring currentSsid;
                bool connected = GetCurrentlyConnectedSsid(hClient, interfaceGuid, currentSsid);
                if (!(connected && currentSsid == bestSsid)) {
                    if (!ConnectToNetwork(hClient, interfaceGuid, bestSsid)) {
                        LogError(L"ConnectToNetwork failed.");
                    }
                }
                // else: already connected to best, do nothing and do not log
            }
            else {
                LogError(L"No preferred network found in scan results.");
            }
            if (pNetList) WlanFreeMemory(pNetList);
        }
        if (pIfList) WlanFreeMemory(pIfList);
    }

    WlanCloseHandle(hClient, NULL);
    return 0;
}

// Service control handler
void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        SetEvent(g_ServiceStopEvent);
        break;
    default:
        break;
    }
}

// Main service function
void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_StatusHandle) {
        LogError(L"RegisterServiceCtrlHandler failed.");
        return;
    }

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_ServiceStopEvent) {
        LogError(L"CreateEvent failed.");
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    if (!hThread) {
        LogError(L"CreateThread failed.");
        CloseHandle(g_ServiceStopEvent);
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    CloseHandle(g_ServiceStopEvent);
    CloseHandle(hThread);
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// Entry point
int wmain(int argc, wchar_t* argv[]) {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };
    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        // Not started as service: run as console for debugging
        std::wcout << L"Running as console app for debug...\n";
        DWORD code = ServiceWorkerThread(NULL);
        if (code != 0) {
            std::wcout << L"ServiceWorkerThread exited with code " << code << L"\n";
        }
    }
    return 0;
}