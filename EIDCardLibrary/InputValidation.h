/*
    EID Authentication - Smart card authentication for Windows
    Copyright (C) 2026 Contributors

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

//=============================================================================
// Canonical validation of every attacker-influenced buffer layout.
//
// MODULE INVARIANT - do not break it, the fuzz harness depends on it:
//   These functions are PURE and TOTAL. They never allocate, never trace,
//   never touch the registry / LSA / CryptoAPI, never impersonate, and never
//   read outside the (pointer, size) pair the caller supplies. A caller-
//   supplied size is the ONLY authority on how far it is safe to read; a
//   length field living inside the buffer is attacker data, never a bound.
//
// Because they are pure, fuzz targets and regression tests link this
// translation unit on its own - outside LSASS, with no smart card present.
// See fuzz/README.md and docs/FUZZING.md.
//
// Each rule below exists exactly once, in InputValidation.cpp. Do not
// re-implement a bounds check at a call site: call these instead. Two
// earlier hand-rolled copies of the blob rule had drifted apart and
// disagreed on whether the header size was sizeof() or FIELD_OFFSET().
//=============================================================================

#pragma once

#include "EIDCardLibrary.h"

struct EID_PRIVATE_DATA;

//-----------------------------------------------------------------------------
// EID_PRIVATE_DATA (stored-credential blob out of an LSA secret / .eidm import)
//-----------------------------------------------------------------------------

// TRUE only when every (offset,size) region declared in the header lies inside
// the blob, the regions do not overlap, and usPasswordLen is non-zero.
//
// usPasswordLen == 0 is rejected because the AES path derives
// dwRoundNumber = usPasswordLen/dwBlockLen (+1 if remainder) and then indexes
// with (dwRoundNumber - 1); a zero length underflows that DWORD and writes a
// terminator roughly 4 GB past a 2-byte allocation. No legitimate blob has a
// zero-length password: CreateCredential always stores at least one block.
BOOL EIDValidatePrivateDataLayout(__in_opt const EID_PRIVATE_DATA* pPrivateData, __in DWORD dwBlobSize);

// Byte count that is safe to SecureZeroMemory over a validated blob: the
// header plus the highest region end. Callers MUST use this instead of summing
// the three region sizes - the sizes are individually bounded but their sum is
// not, so summing overruns the allocation whenever regions overlap.
// Returns 0 for a blob that does not validate.
DWORD EIDPrivateDataSpan(__in_opt const EID_PRIVATE_DATA* pPrivateData, __in DWORD dwBlobSize);
// NOTE: the scrub-and-free helper deliberately lives in
// StoredCredentialManagement.cpp, not here. It needs EIDFree, and this
// translation unit must stay free of LSA/allocator dependencies so the fuzz
// targets can link it on its own.

//-----------------------------------------------------------------------------
// EID_SMARTCARD_CSP_INFO (inside the interactive-logon submit buffer)
//-----------------------------------------------------------------------------
// NOTE: bBuffer is TCHAR[] and the four nXxxNameOffset fields are offsets in
// WCHAR units, not bytes - mirroring KERB_SMARTCARD_CSP_INFO. Every bound here
// is computed in WCHAR units for that reason.

// TRUE only when dwCspInfoLen itself fits inside the caller-supplied
// dwCspDataLength, and every non-zero name offset addresses a NUL-terminated
// string wholly inside dwCspInfoLen.
//
// The critical rule is dwCspInfoLen <= dwCspDataLength. dwCspInfoLen lives
// inside the attacker's buffer, so bounding the name offsets against it while
// leaving it unbounded lets a 40-byte buffer claim a 64 KB interior.
BOOL EIDValidateCspInfo(__in_opt const EID_SMARTCARD_CSP_INFO* pCspInfo, __in DWORD dwCspDataLength);

// The only sanctioned way to read one of the four name strings. Returns nullptr
// for a zero offset (field absent) or any offset that is not a NUL-terminated
// string inside bounds. Never returns a pointer the caller must re-check.
PCWSTR EIDCspInfoStringAt(__in_opt const EID_SMARTCARD_CSP_INFO* pCspInfo, __in DWORD dwCspDataLength, __in ULONG nOffsetInChars);

//-----------------------------------------------------------------------------
// SSP token messages (SECBUFFER_TOKEN from any local SSPI caller)
//-----------------------------------------------------------------------------

// Byte length of a protocol challenge. MUST equal the CREDENTIALKEYLENGTH used
// as a byte count in StoredCredentialManagement.cpp (a static_assert there
// keeps the two in sync). Declared here because the validator has to reject a
// wrong-sized challenge before it ever reaches the verifier, and that file's
// constant is translation-unit local.
constexpr DWORD EID_CHALLENGE_LENGTH = 256;

// TRUE only when the token is large enough for the fixed header and every
// (offset,len) pair addresses bytes inside the token. Also rejects a
// UsernameLen whose +sizeof(WCHAR) terminator allowance would wrap a DWORD,
// and an odd UsernameLen (the field is copied as WCHARs).
BOOL EIDValidateChallengeMessage(__in_opt const void* pToken, __in DWORD cbToken);

// As above for the response token's single (ResponseOffset, ResponseLen) pair.
BOOL EIDValidateResponseMessage(__in_opt const void* pToken, __in DWORD cbToken);
