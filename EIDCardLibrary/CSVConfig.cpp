/*
    EID Authentication - Smart card authentication for Windows
    Copyright (C) 2009 Vincent Le Toux
    Copyright (C) 2026 Contributors

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, see <https://www.gnu.org/licenses/>.
*/

/**
 *  CSV Configuration Implementation
 *
 *  JSON and Registry persistence for CSV logging configuration.
 */

#include "CSVConfig.h"
#include "../EIDMigrate/JsonHelper.h"
#include "../EIDMigrate/Utils.h"
#include <fstream>
#include <filesystem>

namespace fs = std::experimental::filesystem;

// ================================================================
// Helper: Convert EID_CSV_CONFIG to JSON string
// ================================================================
std::string EID_CSV_ConfigToJson(const EID_CSV_CONFIG& config)
{
    JsonBuilder builder;

    builder.add("enabled", config.fEnabled != FALSE);

    // Convert wide strings to UTF-8
    std::string logPath = WideToUtf8(config.szLogPath);
    builder.add("logPath", logPath);

    builder.add("maxFileSizeMB", static_cast<int>(config.dwMaxFileSizeMB));
    builder.add("fileCount", static_cast<int>(config.dwFileCount));

    // Store column bitmask as integer
    builder.add("columns", static_cast<int>(config.dwColumns));  // NOSONAR - ENUM-01: explicit integral cast retained for serialization

    // Store category filter as integer
    builder.add("categoryFilter", static_cast<int>(config.dwCategoryFilter));

    builder.add("verboseEvents", config.fVerboseEvents != FALSE);

    builder.add("diagnosticsEnabled", config.fDiagnosticsEnabled != FALSE);
    builder.add("diagnosticsLevel", static_cast<int>(config.dwDiagnosticsLevel));

    return builder.build();
}

// ================================================================
// Helper: Convert JSON string to EID_CSV_CONFIG
// ================================================================
HRESULT EID_CSV_JsonToConfig(const std::string& json, EID_CSV_CONFIG& config)
{
    JsonParser parser(json);
    auto pRoot = parser.parse();

    if (!pRoot || !pRoot->isObject())
        return E_INVALIDARG;

    const JsonObject& root = pRoot->asObject();

    // Initialize with defaults
    config = EID_CSV_CONFIG();

    // Read enabled flag
    if (root.has("enabled"))
        config.fEnabled = root["enabled"]->asBool() ? TRUE : FALSE;

    // Read log path
    if (root.has("logPath"))
    {
        std::string utf8Path = root["logPath"]->asString();
        std::wstring wpath = Utf8ToWide(utf8Path);
        if (wpath.length() < MAX_PATH)
        {
            wcscpy_s(config.szLogPath, wpath.c_str());
        }
    }

    // Read max file size
    if (root.has("maxFileSizeMB"))
        config.dwMaxFileSizeMB = static_cast<DWORD>(root["maxFileSizeMB"]->asNumber());

    // Read file count
    if (root.has("fileCount"))
        config.dwFileCount = static_cast<DWORD>(root["fileCount"]->asNumber());

    // Read columns bitmask
    if (root.has("columns"))
        config.dwColumns = static_cast<EID_CSV_COLUMN>(static_cast<DWORD>(root["columns"]->asNumber()));

    // Read category filter bitmask
    if (root.has("categoryFilter"))
        config.dwCategoryFilter = static_cast<DWORD>(root["categoryFilter"]->asNumber());

    // Read verbose events flag
    if (root.has("verboseEvents"))
        config.fVerboseEvents = root["verboseEvents"]->asBool() ? TRUE : FALSE;

    // Read diagnostics flags
    if (root.has("diagnosticsEnabled"))
        config.fDiagnosticsEnabled = root["diagnosticsEnabled"]->asBool() ? TRUE : FALSE;
    if (root.has("diagnosticsLevel"))
        config.dwDiagnosticsLevel = static_cast<DWORD>(root["diagnosticsLevel"]->asNumber());

    return S_OK;
}

// ================================================================
// Load configuration from file
// ================================================================
HRESULT EID_CSV_LoadConfigFromFile(PCWSTR pwszPath, EID_CSV_CONFIG& config)
{
    // Check if file exists
    DWORD dwAttrib = GetFileAttributesW(pwszPath);
    if (dwAttrib == INVALID_FILE_ATTRIBUTES)  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    // Read file content
    std::wstring wpath(pwszPath);
    std::string utf8Path = WideToUtf8(wpath);

    std::ifstream file(utf8Path, std::ios::binary);
    if (!file.is_open())
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);

    std::string content;
    try
    {
        content.assign(std::istreambuf_iterator<char>(file),
                      std::istreambuf_iterator<char>());
    }
    catch (...)  // NOSONAR - EXCEPTION-01: catch-all is intentional guard
    {
        file.close();
        return E_FAIL;
    }
    file.close();

    // Parse JSON
    return EID_CSV_JsonToConfig(content, config);
}

// ================================================================
// Save configuration to file
// ================================================================
HRESULT EID_CSV_SaveConfigToFile(PCWSTR pwszPath, const EID_CSV_CONFIG& config)
{
    // Ensure directory exists
    std::wstring wpath(pwszPath);
    size_t lastSlash = wpath.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos)  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
    {
        std::wstring dir = wpath.substr(0, lastSlash);
        // M5: create the config directory with a restrictive DACL (Full to SYSTEM/Admins,
        // Read&Execute to Users), re-applying it if the directory already exists.
        EnsureLogDirSecured(dir.c_str());
    }

    // Convert to JSON
    std::string json = EID_CSV_ConfigToJson(config);

    // Write to file
    std::string utf8Path = WideToUtf8(wpath);
    std::ofstream file(utf8Path, std::ios::binary | std::ios::trunc);
    if (!file.is_open())
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);

    try
    {
        file.write(json.c_str(), json.size());
    }
    catch (...)  // NOSONAR - EXCEPTION-01: catch-all is intentional guard
    {
        file.close();
        return E_FAIL;
    }
    file.close();

    return S_OK;
}

// ================================================================
// Load configuration from registry
// ================================================================
HRESULT EID_CSV_LoadConfigFromRegistry(EID_CSV_CONFIG& config)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    HKEY hKey = nullptr;
    LONG err = 0;
    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-03) - Explicit type preferred for clarity
    DWORD dwType = 0;
    DWORD dwSize = 0;

    // Initialize with defaults
    config = EID_CSV_CONFIG();

    __try
    {
        err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, EID_CSV_CONFIG_KEY, 0, KEY_READ, &hKey);
        if (err != ERROR_SUCCESS)
        {
            // Key doesn't exist, use defaults
            // Set default log path
            wcscpy_s(config.szLogPath, EID_CSV_DEFAULT_LOG_PATH);
            __leave;
        }

        // Read CSVEnabled
        dwSize = sizeof(DWORD);
        DWORD dwValue = 0;
        err = RegQueryValueExW(hKey, L"CSVEnabled", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&dwValue), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err == ERROR_SUCCESS && dwType == REG_DWORD)
            config.fEnabled = dwValue ? TRUE : FALSE;

        // Read CSVLogPath
        dwSize = MAX_PATH * sizeof(WCHAR);
        err = RegQueryValueExW(hKey, L"CSVLogPath", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(config.szLogPath), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_SZ)
        {
            wcscpy_s(config.szLogPath, EID_CSV_DEFAULT_LOG_PATH);
        }
        else
        {
            // REG_SZ is not guaranteed null-terminated; terminate within the buffer.
            DWORD cchPath = dwSize / sizeof(WCHAR);
            if (cchPath >= MAX_PATH) cchPath = MAX_PATH - 1;
            config.szLogPath[cchPath] = L'\0';
        }

        // Read CSVMaxFileSize
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"CSVMaxFileSize", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&config.dwMaxFileSizeMB), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_DWORD)
            config.dwMaxFileSizeMB = 64;
        // BUG 10: clamp to [1, 1024] MB - an unbounded value here is only a sizing knob, but
        // keep it in the same sane range as the override path / ETL trace config for consistency.
        if (config.dwMaxFileSizeMB < 1) config.dwMaxFileSizeMB = 1;
        if (config.dwMaxFileSizeMB > 1024) config.dwMaxFileSizeMB = 1024;

        // Read CSVFileCount
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"CSVFileCount", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&config.dwFileCount), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_DWORD)
            config.dwFileCount = 5;
        // BUG 10: clamp to [1, 100] - prevents a huge/zero value from driving a runaway
        // rotation loop in CSVLogger::RotateLogFile (DoS via misconfiguration).
        if (config.dwFileCount < 1) config.dwFileCount = 1;
        if (config.dwFileCount > 100) config.dwFileCount = 100;

        // Read CSVColumns
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"CSVColumns", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&config.dwColumns), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_DWORD)
            config.dwColumns = EID_CSV_PRESETS::STANDARD;

        // Read CSVCategoryFilter
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"CSVCategoryFilter", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&config.dwCategoryFilter), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_DWORD)
            config.dwCategoryFilter = 0x0000FFFF;

        // Read CSVVerbose
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"CSVVerbose", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&dwValue), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err == ERROR_SUCCESS && dwType == REG_DWORD)
            config.fVerboseEvents = dwValue ? TRUE : FALSE;

        // Read DiagnosticsEnabled
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"DiagnosticsEnabled", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&dwValue), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err == ERROR_SUCCESS && dwType == REG_DWORD)
            config.fDiagnosticsEnabled = dwValue ? TRUE : FALSE;

        // Read DiagnosticsLevel
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"DiagnosticsLevel", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&config.dwDiagnosticsLevel), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_DWORD)
            config.dwDiagnosticsLevel = 4; // WINEVENT_LEVEL_INFO
    }
    __finally
    {
        if (hKey != nullptr)
            RegCloseKey(hKey);
    }

    return hr;
}

// ================================================================
// Save configuration to registry
// ================================================================
HRESULT EID_CSV_SaveConfigToRegistry(const EID_CSV_CONFIG& config)
{
    HKEY hKey = nullptr;
    LONG err = 0;
    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-03) - Explicit type preferred for clarity

    __try
    {
        err = RegCreateKeyExW(HKEY_LOCAL_MACHINE, EID_CSV_CONFIG_KEY, 0, nullptr,
            0, KEY_READ | KEY_WRITE, nullptr, &hKey, nullptr);
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        DWORD dwValue = config.fEnabled ? 1 : 0;
        err = RegSetValueExW(hKey, L"CSVEnabled", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&dwValue), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        err = RegSetValueExW(hKey, L"CSVLogPath", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(config.szLogPath),  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
            static_cast<DWORD>((wcslen(config.szLogPath) + 1) * sizeof(WCHAR)));
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        err = RegSetValueExW(hKey, L"CSVMaxFileSize", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&config.dwMaxFileSizeMB), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        err = RegSetValueExW(hKey, L"CSVFileCount", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&config.dwFileCount), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        err = RegSetValueExW(hKey, L"CSVColumns", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&config.dwColumns), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        err = RegSetValueExW(hKey, L"CSVCategoryFilter", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&config.dwCategoryFilter), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        dwValue = config.fVerboseEvents ? 1 : 0;
        err = RegSetValueExW(hKey, L"CSVVerbose", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&dwValue), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        dwValue = config.fDiagnosticsEnabled ? 1 : 0;
        err = RegSetValueExW(hKey, L"DiagnosticsEnabled", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&dwValue), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS) { hr = HRESULT_FROM_WIN32(err); __leave; }

        err = RegSetValueExW(hKey, L"DiagnosticsLevel", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&config.dwDiagnosticsLevel), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS) { hr = HRESULT_FROM_WIN32(err); __leave; }
    }
    __finally
    {
        if (hKey != nullptr)
            RegCloseKey(hKey);
    }

    return hr;
}

// ================================================================
// Apply Group Policy overrides (HKLM\SOFTWARE\Policies\EIDAuthentication\LogManager)
// Any value present under the policy key wins over local file/registry config.
// ================================================================
void EID_CSV_ApplyPolicyOverrides(EID_CSV_CONFIG& config)  // NOSONAR - COMPLEXITY-01: sequential per-value overrides, logic verified
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, EID_CSV_POLICY_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    DWORD dwType = 0;
    DWORD dwValue = 0;
    DWORD dwSize = 0;

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVEnabled", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.fEnabled = (dwValue != 0);

    WCHAR szPath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    dwSize = sizeof(szPath);
    if (RegQueryValueExW(hKey, L"CSVLogPath", nullptr, &dwType, reinterpret_cast<LPBYTE>(szPath), &dwSize) == ERROR_SUCCESS && dwType == REG_SZ && szPath[0] != L'\0')
    {
        szPath[MAX_PATH - 1] = L'\0';
        wcscpy_s(config.szLogPath, szPath);
    }

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVMaxFileSize", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
    {
        // BUG 10: clamp policy-supplied value to [1, 1024] MB instead of taking it verbatim -
        // matches the bounds used by the ETL trace path (Registration.cpp SetTraceConfig).
        if (dwValue < 1) dwValue = 1;
        if (dwValue > 1024) dwValue = 1024;
        config.dwMaxFileSizeMB = dwValue;
    }

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVFileCount", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
    {
        // BUG 10: clamp policy-supplied value to [1, 100] - an unclamped admin-set
        // CSVFileCount (e.g. 0xFFFFFFFF) would drive a ~4-billion-iteration rotation loop
        // in CSVLogger::RotateLogFile (DoS via misconfiguration).
        if (dwValue < 1) dwValue = 1;
        if (dwValue > 100) dwValue = 100;
        config.dwFileCount = dwValue;
    }

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVColumns", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.dwColumns = static_cast<EID_CSV_COLUMN>(dwValue);  // NOSONAR - ENUM-01: enum cast retained for Win32/ABI compatibility

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVCategoryFilter", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.dwCategoryFilter = dwValue;

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVVerbose", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.fVerboseEvents = (dwValue != 0);

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"DiagnosticsEnabled", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.fDiagnosticsEnabled = (dwValue != 0);

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"DiagnosticsLevel", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.dwDiagnosticsLevel = dwValue;

    RegCloseKey(hKey);
}

// ================================================================
// Load configuration (tries JSON, then registry, then defaults; GPO overrides win)
// ================================================================
HRESULT EID_CSV_LoadConfig(EID_CSV_CONFIG& config)
{
    // Try JSON file first, then registry, then defaults.
    HRESULT hr = EID_CSV_LoadConfigFromFile(EID_CSV_CONFIG_PATH, config);
    if (FAILED(hr))
        hr = EID_CSV_LoadConfigFromRegistry(config);
    if (FAILED(hr))
    {
        config = EID_CSV_CONFIG();
        wcscpy_s(config.szLogPath, EID_CSV_DEFAULT_LOG_PATH);
        hr = S_FALSE;  // Indicate defaults were used
    }

    // Group Policy overrides win over local file/registry config.
    EID_CSV_ApplyPolicyOverrides(config);
    return hr;
}

// ================================================================
// Save configuration (saves to both JSON and registry)
// ================================================================
HRESULT EID_CSV_SaveConfig(const EID_CSV_CONFIG& config)
{
    HRESULT hrJson = EID_CSV_SaveConfigToFile(EID_CSV_CONFIG_PATH, config);
    HRESULT hrReg = EID_CSV_SaveConfigToRegistry(config);

    // Both stores must succeed: the JSON file feeds EID_CSV_LoadConfig (the in-process
    // logger and the log manager UI), while the registry feeds the EIDTraceConsumer
    // service. If either write fails the config is only partly applied, so report the
    // first failure instead of a false success.
    if (FAILED(hrJson)) return hrJson;
    if (FAILED(hrReg)) return hrReg;
    return S_OK;
}
