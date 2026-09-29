/*
    EID Authentication - fuzz target: EID_SMARTCARD_CSP_INFO
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
// THE ORACLE
//
// This target does not merely call the validator and discard the answer -
// that would only find crashes inside the validator itself. Instead it
// asserts the property the production code actually relies on:
//
//     EIDValidateCspInfo() == TRUE  =>  every read the consumers perform
//                                       stays inside the buffer.
//
// So when the validator wrongly returns TRUE, the reads below run off the end
// of an exact-sized ASan allocation and the target dies with a diagnosable
// heap-buffer-overflow. That is the same shape as the real defect: the inner
// dwCspInfoLen was trusted as a bound while being attacker data.
//
// The reads mirror the real consumers:
//   Package.cpp                 EIDDebugPrintEIDUnlockLogonStruct (%s printing)
//   CertificateValidation.cpp   GetCertificateFromCspInfoInternal
//   smartcardmodule.cpp         CheckPINandGetRemainingAttemptsIfPossible
//=============================================================================

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "EIDCardLibrary.h"
#include "InputValidation.h"
#include "oracle.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	// The struct has ULONG64 members, so give the copy 8-byte alignment.
	// Allocate EXACTLY the input size: any read past it is an ASan report
	// rather than a silent walk into adjacent heap.
	if (size < sizeof(DWORD) || size > (1u << 20))
	{
		return 0;
	}
	void* pRaw = _aligned_malloc(size, 8);
	if (!pRaw)
	{
		return 0;
	}
	memcpy(pRaw, data, size);

	const EID_SMARTCARD_CSP_INFO* pCspInfo = static_cast<const EID_SMARTCARD_CSP_INFO*>(pRaw);
	const DWORD cbCspData = static_cast<DWORD>(size);

	if (EIDValidateCspInfo(pCspInfo, cbCspData))
	{
		// Consumer behaviour 1: read all four names through the sanctioned
		// accessor and walk each to its terminator, exactly as %s printing and
		// _tcscmp do. An unterminated or out-of-bounds string overflows here.
		const ULONG rgOffsets[] = {
			pCspInfo->nCardNameOffset,
			pCspInfo->nReaderNameOffset,
			pCspInfo->nContainerNameOffset,
			pCspInfo->nCSPNameOffset,
		};
		size_t cchTotal = 0;
		const BYTE* pBufferStart = reinterpret_cast<const BYTE*>(pRaw) +
			FIELD_OFFSET(EID_SMARTCARD_CSP_INFO, bBuffer);
		const BYTE* pBufferEnd = reinterpret_cast<const BYTE*>(pRaw) + cbCspData;
		for (size_t i = 0; i < ARRAYSIZE(rgOffsets); i++)
		{
			PCWSTR psz = EIDCspInfoStringAt(pCspInfo, cbCspData, rgOffsets[i]);
			if (psz)
			{
				// A name offset addresses bBuffer, so the pointer must land in
				// [bBuffer, end). Merely being inside the allocation is NOT
				// enough: an offset whose WCHAR scaling wraps 32 bits can come
				// back around and alias the FIXED HEADER, which is in bounds and
				// therefore invisible to ASan. Without this check the oracle is
				// silent on exactly the arithmetic it is meant to police.
				const BYTE* pRet = reinterpret_cast<const BYTE*>(psz);
				EID_ORACLE_REQUIRE(pRet >= pBufferStart && pRet < pBufferEnd,
					"EIDCspInfoStringAt returned a pointer outside bBuffer - a "
					"name offset wrapped and now aliases the struct header");
				cchTotal += wcslen(psz);
			}
			else if (rgOffsets[i] != 0)
			{
				// Validator accepted the struct but the accessor refused this
				// field. That is a contradiction between two rules that are
				// supposed to agree; make it loud.
				EIDOracleViolation("EIDValidateCspInfo accepted a struct whose "
					"non-zero name offset EIDCspInfoStringAt rejects");
			}
		}

		// Consumer behaviour 2: copy the whole declared interior, as the
		// rebase/copy paths do. dwCspInfoLen must be within the real buffer.
		const DWORD dwCspInfoLen = pCspInfo->dwCspInfoLen;
		EID_ORACLE_REQUIRE(dwCspInfoLen <= cbCspData,
			"dwCspInfoLen exceeds the caller-supplied CspDataLength - the inner "
			"length is attacker data and must be bounded by the outer length");
		volatile BYTE bSink = 0;
		for (DWORD i = 0; i < dwCspInfoLen; i++)
		{
			bSink ^= static_cast<const BYTE*>(pRaw)[i];
		}
		(void)bSink;
		(void)cchTotal;
	}

	_aligned_free(pRaw);
	return 0;
}
