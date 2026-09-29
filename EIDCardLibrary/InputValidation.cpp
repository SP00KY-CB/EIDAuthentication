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

// See InputValidation.h for the module invariant. Keep this translation unit
// free of dependencies on LSA, the registry, CryptoAPI and tracing so the fuzz
// targets can compile it standalone under /fsanitize=address.

#include <windows.h>
#include "EIDCardLibrary.h"
#include "StoredCredentialManagement.h"
#include "InputValidation.h"

//=============================================================================
// EID_PRIVATE_DATA
//=============================================================================

namespace {

// Header size for offset arithmetic. FIELD_OFFSET, never sizeof: sizeof()
// includes the 4-byte Data[] placeholder plus tail padding, so using it here
// under-counts the usable data region by that much and disagrees with the
// writer in CreateCredential. Two earlier copies of this rule differed on
// exactly this point.
constexpr DWORD PrivateDataHeaderSize() noexcept
{
	return static_cast<DWORD>(FIELD_OFFSET(EID_PRIVATE_DATA, Data));
}

struct BlobRegion
{
	DWORD dwOffset;
	DWORD dwSize;
};

// One region fits when its offset is inside the data area and its size fits in
// what remains. Written as a subtraction against the remaining space so no
// addition can overflow.
bool RegionFits(const BlobRegion& region, DWORD dwDataSize) noexcept
{
	return region.dwOffset <= dwDataSize && region.dwSize <= dwDataSize - region.dwOffset;
}

bool RegionsOverlap(const BlobRegion& a, const BlobRegion& b) noexcept
{
	if (a.dwSize == 0 || b.dwSize == 0)
	{
		return false;
	}
	// Both ends are known to fit (RegionFits ran first), so these adds are safe.
	return a.dwOffset < b.dwOffset + b.dwSize && b.dwOffset < a.dwOffset + a.dwSize;
}

} // namespace

BOOL EIDValidatePrivateDataLayout(__in_opt const EID_PRIVATE_DATA* pPrivateData, __in DWORD dwBlobSize)
{
	const DWORD dwHeaderSize = PrivateDataHeaderSize();
	if (!pPrivateData || dwBlobSize < dwHeaderSize)
	{
		return FALSE;
	}
	const DWORD dwDataSize = dwBlobSize - dwHeaderSize;

	const BlobRegion regions[] = {
		{ pPrivateData->dwCertificatOffset,  pPrivateData->dwCertificatSize },
		{ pPrivateData->dwSymetricKeyOffset, pPrivateData->dwSymetricKeySize },
		{ pPrivateData->dwPasswordOffset,    pPrivateData->usPasswordLen },
	};

	// A zero-length password underflows dwRoundNumber at the decrypt site.
	if (pPrivateData->usPasswordLen == 0)
	{
		return FALSE;
	}

	for (size_t i = 0; i < ARRAYSIZE(regions); i++)
	{
		if (!RegionFits(regions[i], dwDataSize))
		{
			return FALSE;
		}
	}

	// Overlap rejection is structural sanity, NOT a memory-safety requirement:
	// EIDPrivateDataSpan takes max(region end) rather than the sum, so the span
	// is bounded by the blob whether regions overlap or not. (The old cleanup
	// summed the three sizes, and THAT is what overlapping regions inflated.)
	// Kept because a blob whose regions alias each other is malformed by
	// construction - every writer lays them out end to end - and rejecting it
	// early beats decrypting whatever the overlap produces.
	for (size_t i = 0; i < ARRAYSIZE(regions); i++)
	{
		for (size_t j = i + 1; j < ARRAYSIZE(regions); j++)
		{
			if (RegionsOverlap(regions[i], regions[j]))
			{
				return FALSE;
			}
		}
	}

	return TRUE;
}

DWORD EIDPrivateDataSpan(__in_opt const EID_PRIVATE_DATA* pPrivateData, __in DWORD dwBlobSize)
{
	if (!EIDValidatePrivateDataLayout(pPrivateData, dwBlobSize))
	{
		return 0;
	}

	const BlobRegion regions[] = {
		{ pPrivateData->dwCertificatOffset,  pPrivateData->dwCertificatSize },
		{ pPrivateData->dwSymetricKeyOffset, pPrivateData->dwSymetricKeySize },
		{ pPrivateData->dwPasswordOffset,    pPrivateData->usPasswordLen },
	};

	DWORD dwHighest = 0;
	for (size_t i = 0; i < ARRAYSIZE(regions); i++)
	{
		const DWORD dwEnd = regions[i].dwOffset + regions[i].dwSize;  // validated to fit
		if (dwEnd > dwHighest)
		{
			dwHighest = dwEnd;
		}
	}
	return PrivateDataHeaderSize() + dwHighest;
}

//=============================================================================
// EID_SMARTCARD_CSP_INFO
//=============================================================================

namespace {

constexpr DWORD CspInfoHeaderSize() noexcept
{
	return static_cast<DWORD>(FIELD_OFFSET(EID_SMARTCARD_CSP_INFO, bBuffer));
}

// Byte offset of a WCHAR-unit name offset, or FALSE when the multiply or the
// add would leave the 32-bit range. nOffsetInChars is fully attacker-controlled.
//
// The headroom subtracted here MUST be the header size that is added below.
// An earlier version subtracted a hardcoded 16 while adding 40, which left a
// window where the scaled offset wrapped: nOffsetInChars = 0x7FFFFFF7 gives
// 40 + 0x7FFFFFF7*2 = 0x100000016, truncated to 22. The result stayed inside
// the buffer, so it was neither an ASan report nor an obviously wrong answer -
// it silently aliased the fixed header (dwCspInfoLen, flags, KeySpec) and
// handed that back as a "name string" to _tcscmp and CryptAcquireContext.
bool CspInfoCharOffsetToByteOffset(ULONG nOffsetInChars, DWORD* pdwByteOffset) noexcept
{
	// const, not constexpr: FIELD_OFFSET expands to a reinterpret_cast, which
	// MSVC will not evaluate in a constant expression.
	const ULONG ulMaxChars = (MAXDWORD - CspInfoHeaderSize()) / static_cast<ULONG>(sizeof(WCHAR));
	if (nOffsetInChars > ulMaxChars)
	{
		return false;
	}
	*pdwByteOffset = CspInfoHeaderSize() + nOffsetInChars * static_cast<DWORD>(sizeof(WCHAR));
	return true;
}

// A name field is valid when it lies inside dwCspInfoLen AND terminates there.
// Without the termination test _tcscmp / CryptAcquireContext walk off the end
// of a validated-looking buffer.
bool CspInfoNameIsTerminated(const EID_SMARTCARD_CSP_INFO* pCspInfo, DWORD dwCspInfoLen, ULONG nOffsetInChars) noexcept
{
	DWORD dwByteOffset = 0;
	if (!CspInfoCharOffsetToByteOffset(nOffsetInChars, &dwByteOffset))
	{
		return false;
	}
	// Need room for at least one WCHAR (possibly just the terminator).
	if (dwByteOffset > dwCspInfoLen || dwCspInfoLen - dwByteOffset < sizeof(WCHAR))
	{
		return false;
	}
	const DWORD dwAvailableChars = (dwCspInfoLen - dwByteOffset) / static_cast<DWORD>(sizeof(WCHAR));
	const WCHAR* pStart = reinterpret_cast<const WCHAR*>(reinterpret_cast<const BYTE*>(pCspInfo) + dwByteOffset);
	for (DWORD i = 0; i < dwAvailableChars; i++)
	{
		if (pStart[i] == L'\0')
		{
			return true;
		}
	}
	return false;
}

} // namespace

BOOL EIDValidateCspInfo(__in_opt const EID_SMARTCARD_CSP_INFO* pCspInfo, __in DWORD dwCspDataLength)
{
	if (!pCspInfo || dwCspDataLength < CspInfoHeaderSize())
	{
		return FALSE;
	}

	// THE missing check. dwCspInfoLen is attacker data; the downstream
	// validators bound their offsets against it, so it must first be bounded
	// against the length the LSA actually handed us.
	const DWORD dwCspInfoLen = pCspInfo->dwCspInfoLen;
	if (dwCspInfoLen < CspInfoHeaderSize() || dwCspInfoLen > dwCspDataLength)
	{
		return FALSE;
	}

	const ULONG rgOffsets[] = {
		pCspInfo->nCardNameOffset,
		pCspInfo->nReaderNameOffset,
		pCspInfo->nContainerNameOffset,
		pCspInfo->nCSPNameOffset,
	};
	for (size_t i = 0; i < ARRAYSIZE(rgOffsets); i++)
	{
		// Zero means "field absent" throughout this codebase.
		if (rgOffsets[i] == 0)
		{
			continue;
		}
		if (!CspInfoNameIsTerminated(pCspInfo, dwCspInfoLen, rgOffsets[i]))
		{
			return FALSE;
		}
	}
	return TRUE;
}

PCWSTR EIDCspInfoStringAt(__in_opt const EID_SMARTCARD_CSP_INFO* pCspInfo, __in DWORD dwCspDataLength, __in ULONG nOffsetInChars)
{
	if (nOffsetInChars == 0 || !EIDValidateCspInfo(pCspInfo, dwCspDataLength))
	{
		return nullptr;
	}
	if (!CspInfoNameIsTerminated(pCspInfo, pCspInfo->dwCspInfoLen, nOffsetInChars))
	{
		return nullptr;
	}
	DWORD dwByteOffset = 0;
	if (!CspInfoCharOffsetToByteOffset(nOffsetInChars, &dwByteOffset))
	{
		return nullptr;
	}
	return reinterpret_cast<PCWSTR>(reinterpret_cast<const BYTE*>(pCspInfo) + dwByteOffset);
}

//=============================================================================
// SSP token messages
//=============================================================================

namespace {

// One (offset,len) pair inside a token of cbToken bytes. dwExtraForTerminator
// covers the consumer's "+ sizeof(WCHAR)" allocation allowance, which must not
// wrap: EIDAlloc(UsernameLen + sizeof(WCHAR)) with UsernameLen == 0xFFFFFFFF
// allocates 1 byte and is then memcpy'd 4 GB.
bool TokenRegionFits(DWORD dwOffset, DWORD dwLen, DWORD cbToken, DWORD dwExtraForTerminator) noexcept
{
	if (dwLen > MAXDWORD - dwExtraForTerminator)
	{
		return false;
	}
	if (dwOffset > cbToken)
	{
		return false;
	}
	return dwLen <= cbToken - dwOffset;
}

} // namespace

BOOL EIDValidateChallengeMessage(__in_opt const void* pToken, __in DWORD cbToken)
{
	if (!pToken || cbToken < sizeof(EID_CHALLENGE_MESSAGE))
	{
		return FALSE;
	}
	const EID_CHALLENGE_MESSAGE* pMessage = static_cast<const EID_CHALLENGE_MESSAGE*>(pToken);

	// Copied out as WCHARs, so an odd length would leave a torn character and
	// makes the /2 arithmetic at the consumer lossy.
	if ((pMessage->UsernameLen % sizeof(WCHAR)) != 0)
	{
		return FALSE;
	}
	if (!TokenRegionFits(pMessage->UsernameOffset, pMessage->UsernameLen, cbToken, sizeof(WCHAR)))
	{
		return FALSE;
	}
	if (!TokenRegionFits(pMessage->ChallengeOffset, pMessage->ChallengeLen, cbToken, 0))
	{
		return FALSE;
	}
	// The challenge must be EXACTLY the protocol length, not merely non-zero.
	// A short challenge is not just a weak nonce: the verifier reaches
	// CryptSetHashParam(HP_HASHVAL, ...), which copies the hash algorithm's
	// full digest length out of the buffer whatever its real size, so a
	// 1-byte challenge is a heap over-read inside LSASS. Accepting any
	// non-zero length here was enough to make that reachable from an
	// unprivileged SSPI caller. The GINA paths have always required equality;
	// this makes the SSP path agree with them.
	if (pMessage->ChallengeLen != EID_CHALLENGE_LENGTH)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL EIDValidateResponseMessage(__in_opt const void* pToken, __in DWORD cbToken)
{
	if (!pToken || cbToken < sizeof(EID_RESPONSE_MESSAGE))
	{
		return FALSE;
	}
	const EID_RESPONSE_MESSAGE* pMessage = static_cast<const EID_RESPONSE_MESSAGE*>(pToken);

	if (!TokenRegionFits(pMessage->ResponseOffset, pMessage->ResponseLen, cbToken, 0))
	{
		return FALSE;
	}
	if (pMessage->ResponseLen == 0)
	{
		return FALSE;
	}
	return TRUE;
}
