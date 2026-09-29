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

#include <cstddef>

// Compile-time validation for certificate hash length (SHA-256 = 32 bytes)
// Marked constexpr+noexcept for compile-time evaluation and LSASS compatibility
constexpr bool IsValidCertHashLength(size_t length) noexcept
{
    // CERT_HASH_LENGTH is defined as 32 (SHA-256) in EIDCardLibrary.h
    return length == 32;
}

// Compile-time assertion that CERT_HASH_LENGTH matches SHA-256
static_assert(IsValidCertHashLength(32), "CERT_HASH_LENGTH must be 32 bytes for SHA-256");

struct ChainValidationParams {
    CERT_ENHKEY_USAGE EnhkeyUsage;
    CERT_USAGE_MATCH CertUsage;
    CERT_CHAIN_PARA ChainPara;
    CERT_CHAIN_POLICY_PARA ChainPolicy;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;
};

void InitChainValidationParams(ChainValidationParams* params);

// dwCspDataLength is the length the LSA supplied for the CspData block
// (Logon.CspDataLength). Do not pass pCspInfo->dwCspInfoLen: that field lives
// inside the buffer being validated and is attacker-controlled.
PCCERT_CONTEXT GetCertificateFromCspInfo(__in PEID_SMARTCARD_CSP_INFO pCspInfo, __in ULONG dwCspDataLength);
BOOL IsTrustedCertificate(__in PCCERT_CONTEXT pCertContext, __in_opt DWORD dwFlag = 0);
BOOL HasCertificateRightEKU(__in PCCERT_CONTEXT pCertContext);
LPCTSTR GetTrustErrorText(DWORD Status);
BOOL MakeTrustedCertifcate(PCCERT_CONTEXT pCertContext);

// CSP provider whitelist validation - prevents malicious CSP injection
BOOL IsAllowedCSPProvider(__in LPCWSTR pwszProviderName);
