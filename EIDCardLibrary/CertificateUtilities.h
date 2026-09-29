/*
    OpenAccess EID - Smart card authentication for Windows
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


#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <tchar.h>

PCCERT_CONTEXT SelectFirstCertificateWithPrivateKey();
PCCERT_CONTEXT SelectCertificateWithPrivateKey(HWND hWnd = nullptr);

BOOL AskForCard(LPWSTR szReader, DWORD ReaderLength,LPWSTR szCard,DWORD CardLength);

BOOL SchGetProviderNameFromCardName(__in LPCTSTR szCardName, __out LPTSTR szProviderName, __out PDWORD pdwProviderNameLen);

constexpr DWORD UI_CERTIFICATE_INFO_SAVEON_USERSTORE = 0;
constexpr DWORD UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE = 1;
constexpr DWORD UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE_MY = 2;
constexpr DWORD UI_CERTIFICATE_INFO_SAVEON_FILE = 3;
constexpr DWORD UI_CERTIFICATE_INFO_SAVEON_SMARTCARD = 4;

struct UI_CERTIFICATE_INFO
{
	LPTSTR szSubject;
	PCCERT_CONTEXT pRootCertificate;
	DWORD dwSaveon;
	LPTSTR wszCardName;     // Renamed from szCard to avoid shadowing global
	LPTSTR wszReaderName;   // Renamed from szReader to avoid shadowing global
	DWORD dwKeyType;
	DWORD dwKeySizeInBits;
	BOOL bIsSelfSigned;
	BOOL bHasSmartCardAuthentication;
	BOOL bHasServerAuthentication;
	BOOL bHasClientAuthentication;
	BOOL bHasEFS;
	BOOL bIsCA;
	SYSTEMTIME StartTime;
	SYSTEMTIME EndTime;

	// used to return new certificate context if needed
	// need to free it if returned
	BOOL fReturnCerticateContext;
	PCCERT_CONTEXT pNewCertificate;
};
using PUI_CERTIFICATE_INFO = UI_CERTIFICATE_INFO*;

PCCERT_CONTEXT GetCertificateWithPrivateKey();
BOOL CreateCertificate(PUI_CERTIFICATE_INFO CertificateInfo);
BOOL ClearCard(PTSTR szReaderName, PTSTR szCardName);
BOOL ImportFileToSmartCard(PTSTR szFileName, PTSTR szPassword, PTSTR szReaderName, PTSTR szCardname);
PCCERT_CONTEXT FindCertificateFromHash(PCRYPT_DATA_BLOB pCertInfo);

// Sets CERT_KEY_PROV_INFO_PROP_ID and CERT_KEY_CONTEXT_PROP_ID on a certificate context.
BOOL SetupCertificateContextWithKeyInfo(
    __in PCCERT_CONTEXT pCertContext, __in HCRYPTPROV hProv,
    __in LPCWSTR pwszProviderName, __in LPCWSTR pwszContainerName, __in DWORD dwKeySpec);

// Returns allocated string "\\.\\<readerName>\\" - caller must EIDFree
LPTSTR BuildContainerNameFromReader(LPCTSTR szReaderName);

// Uninstall cleanup: removes every certificate whose subject CN starts with "EID:"
// (the wizard-created root CA) or whose issuer CN starts with "EID:" (certificates
// issued by that CA) from the LocalMachine Root/CA/TrustedPeople/My stores and from
// the same stores of every user profile (loaded hives via CertEnumSystemStore, unloaded
// hives via temporary RegLoadKey). Deletes the CA's machine key container.
// Never deletes smart-card key containers (machine-keyset check).
// Returns S_OK when the sweep ran, even if individual stores/profiles were skipped.
HRESULT RemoveAllEIDCertificates(VOID);
