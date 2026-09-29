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


#pragma once

#include <utility>

enum class GPOPolicy
{
  AllowSignatureOnlyKeys,
  AllowCertificatesWithNoEKU,
  AllowTimeInvalidCertificates,
  AllowIntegratedUnblock,
  ReverseSubject,
  X509HintsNeeded,
  IntegratedUnblockPromptString,
  CertPropEnabledString,
  CertPropRootEnabledString,
  RootsCleanupOption,
  FilterDuplicateCertificates,
  ForceReadingAllCertificates,
  scforceoption,
  scremoveoption,
  EnforceCSPWhitelist,  // Security: block CSP providers not in whitelist
  RequireCardBoundCredentials,  // Security (H3): when set, only card-wrapped (crypted) credentials may be created/used/imported
  RequireRevocationCheck,  // Security (M1): when set, "revocation unknown" (no local CRL) is a hard failure (fail-closed)
};

// Validates that a GPOPolicy enum value is within valid bounds to prevent array overflow
// Marked constexpr+noexcept for compile-time evaluation and LSASS compatibility
constexpr bool IsValidPolicy(GPOPolicy policy) noexcept
{
    return policy >= GPOPolicy::AllowSignatureOnlyKeys && policy <= GPOPolicy::RequireRevocationCheck;
}

// Compile-time validation of GPOPolicy enum bounds
static_assert(IsValidPolicy(GPOPolicy::AllowSignatureOnlyKeys), "AllowSignatureOnlyKeys must be a valid policy");
static_assert(IsValidPolicy(GPOPolicy::RequireRevocationCheck), "RequireRevocationCheck must be a valid policy");

DWORD GetPolicyValue(GPOPolicy Policy);
BOOL SetPolicyValue(GPOPolicy Policy, DWORD dwValue);
