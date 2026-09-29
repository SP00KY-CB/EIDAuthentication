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


void EIDAuthenticationPackageDllRegister();
void EIDAuthenticationPackageDllUnRegister();
void EIDPasswordChangeNotificationDllRegister();
void EIDPasswordChangeNotificationDllUnRegister();
void EIDCredentialProviderDllRegister();
void EIDCredentialProviderDllUnRegister();
void EIDConfigurationWizardDllRegister();
void EIDConfigurationWizardDllUnRegister();
// Writes the ETW autologger configuration. The live trace session is started only when
// TraceAutoStart is enabled by config/GPO (so a boot task cannot force a VERBOSE capture
// against policy) - unless fForceStartSession is TRUE, which is reserved for an explicit
// operator action such as the DllEnableLogging verb.
BOOL EnableLogging(BOOL fForceStartSession = FALSE);
BOOL DisableLogging();
BOOL IsLoggingEnabled();

// Trace configuration functions
// Registry path: HKLM\SOFTWARE\EIDAuthentication\LogManager
BOOL SetTraceConfig(DWORD dwLevel, LPCWSTR szLogPath, DWORD dwMaxSizeMB, DWORD dwFileCounter, BOOL fAutoStart);
BOOL GetTraceConfig(DWORD* pdwLevel, LPWSTR szLogPath, DWORD cchPath, DWORD* pdwMaxSizeMB, DWORD* pdwFileCounter, BOOL* pfAutoStart);
void EnableCrashDump(PTSTR szPath);
void DisableCrashDump();
BOOL IsCrashDumpEnabled();
BOOL IsSecurityPackageLoaded(LPCTSTR szPackageName);
BOOL RegisterTheSecurityPackage();
BOOL UnRegisterTheSecurityPackage();
