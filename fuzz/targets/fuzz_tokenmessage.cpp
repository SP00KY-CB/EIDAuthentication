/*
    EID Authentication - fuzz target: SSP challenge/response token messages
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
//     EIDValidateChallengeMessage() == TRUE  =>  the copies that
//     CSecurityContext::ReceiveChallengeMessage performs stay in bounds.
//
// The production code (CredentialManagement.cpp:443,:495) did:
//     szUserName  = EIDAlloc(message->UsernameLen + sizeof(WCHAR));
//     memcpy(szUserName, (PBYTE)message + message->UsernameOffset,
//                        message->UsernameLen);
// with no validation whatsoever. Both the allocation-size wrap and the
// out-of-range offset are reproduced faithfully below, so a validator that
// permits either is caught by ASan on the very next input.
//
// Note the allocation here is deliberately computed the SAME (unsafe) way the
// original code computed it. The point is to prove the validator makes that
// computation safe - not to paper over it in the harness.
//=============================================================================

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "EIDCardLibrary.h"
#include "InputValidation.h"
#include "oracle.h"

namespace {

void ExerciseChallenge(const void* pToken, DWORD cbToken)
{
	if (!EIDValidateChallengeMessage(pToken, cbToken))
	{
		return;
	}
	const EID_CHALLENGE_MESSAGE* pMessage = static_cast<const EID_CHALLENGE_MESSAGE*>(pToken);

	// Replicate the original username copy, wrap included.
	const DWORD cbAlloc = pMessage->UsernameLen + static_cast<DWORD>(sizeof(WCHAR));
	EID_ORACLE_REQUIRE(cbAlloc >= pMessage->UsernameLen,
		"UsernameLen + sizeof(WCHAR) wrapped a DWORD - the consumer would "
		"allocate 1 byte and then memcpy 4 GB into it");
	BYTE* pUser = static_cast<BYTE*>(malloc(cbAlloc));
	if (pUser)
	{
		memcpy(pUser, static_cast<const BYTE*>(pToken) + pMessage->UsernameOffset, pMessage->UsernameLen);
		memset(pUser + pMessage->UsernameLen, 0, sizeof(WCHAR));
		free(pUser);
	}

	// Replicate the challenge copy.
	BYTE* pChallenge = static_cast<BYTE*>(malloc(pMessage->ChallengeLen));
	if (pChallenge)
	{
		memcpy(pChallenge, static_cast<const BYTE*>(pToken) + pMessage->ChallengeOffset, pMessage->ChallengeLen);
		free(pChallenge);
	}
}

void ExerciseResponse(const void* pToken, DWORD cbToken)
{
	if (!EIDValidateResponseMessage(pToken, cbToken))
	{
		return;
	}
	const EID_RESPONSE_MESSAGE* pMessage = static_cast<const EID_RESPONSE_MESSAGE*>(pToken);

	BYTE* pResponse = static_cast<BYTE*>(malloc(pMessage->ResponseLen));
	if (pResponse)
	{
		memcpy(pResponse, static_cast<const BYTE*>(pToken) + pMessage->ResponseOffset, pMessage->ResponseLen);
		free(pResponse);
	}
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	if (size < sizeof(DWORD) || size > (1u << 20))
	{
		return 0;
	}

	// Exact-size, aligned copy so ASan redzones bracket the token precisely.
	void* pRaw = _aligned_malloc(size, 8);
	if (!pRaw)
	{
		return 0;
	}
	memcpy(pRaw, data, size);
	const DWORD cbToken = static_cast<DWORD>(size);

	// The same bytes are a candidate for both message shapes; the state machine
	// picks one by context, so fuzz both against the one buffer.
	ExerciseChallenge(pRaw, cbToken);
	ExerciseResponse(pRaw, cbToken);

	_aligned_free(pRaw);
	return 0;
}
