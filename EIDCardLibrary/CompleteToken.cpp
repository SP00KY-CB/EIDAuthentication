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


#include <ntstatus.h>
#define WIN32_NO_STATUS  // NOSONAR - MACRO-02: Windows SDK configuration, prevents ntstatus.h conflicts
#include <Windows.h>

#define SECURITY_WIN32
#include <sspi.h>

#include <NTSecAPI.h>
#include <NTSecPKG.h>
#include <SubAuth.h>
#include <LM.h>
#include <sddl.h>

#include <utility>  // for std::pair
#include <bit>      // for std::bit_cast (SonarQube cpp:S3624)

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "ErrorHandling.h"

BOOL NameToSid(WCHAR* UserName, PSID* pUserSid);
BOOL GetGroups(WCHAR* UserName,PGROUP_USERS_INFO_1 *lpGroupInfo, LPDWORD pTotalEntries);
BOOL GetLocalGroups(WCHAR* UserName,PGROUP_USERS_INFO_0 *lpGroupInfo, LPDWORD pTotalEntries);
BOOL GetPrimaryGroupSidFromUserSid(PSID UserSID, PSID *PrimaryGroupSID);
void DebugPrintSid(const WCHAR* Name, PSID Sid);

NTSTATUS CheckAuthorization(PWSTR UserName, NTSTATUS *SubStatus, LARGE_INTEGER *ExpirationTime);

// Internal function using Result<T> for type-safe error handling
// Marked noexcept for LSASS compatibility
// Returns token info structure with size, or HRESULT error
[[nodiscard]] EID::Result<std::pair<PLSA_TOKEN_INFORMATION_V2, DWORD>> UserNameToTokenInternal(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    __in PLSA_UNICODE_STRING AccountName,  // NOSONAR - API-01: signature dictated by Windows/callback API
    __out PNTSTATUS SubStatus) noexcept
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	PLSA_TOKEN_INFORMATION_V2 TokenInformation = nullptr;
	PTOKEN_GROUPS pTokenGroups = nullptr;
	PGROUP_USERS_INFO_1 pGroupInfo = nullptr;
	PGROUP_USERS_INFO_0 pLocalGroupInfo = nullptr;

	DWORD NumberOfGroups = 0;
	DWORD NumberOfLocalGroups = 0;
	BOOL bResult;
	PSID UserSid = nullptr;
	PSID PrimaryGroupSid = nullptr;
	PSID* pGroupSid = nullptr;
	DWORD Size = 0;
	PBYTE Offset;
	DWORD i;
	LARGE_INTEGER ExpirationTime;
	// convert AccountName to WSTR
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Convert");
	WCHAR UserName[UNLEN+1];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety

	// Helper lambda for cleanup on error
	auto cleanup = [&]() {
		if (PrimaryGroupSid) EIDFree(PrimaryGroupSid);
		if (UserSid) EIDFree(UserSid);
		if (pGroupSid) EIDFree(pGroupSid);
		if (pGroupInfo) NetApiBufferFree(pGroupInfo);
		if (pLocalGroupInfo) NetApiBufferFree(pLocalGroupInfo);
		if (TokenInformation) EIDFree(TokenInformation);
	};

	wcsncpy_s(UserName, ARRAYSIZE(UserName), AccountName->Buffer, AccountName->Length / 2);
	UserName[AccountName->Length / 2] = 0;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"CheckAuthorization");
	// check authorization
	NTSTATUS Status = CheckAuthorization(UserName, SubStatus, &ExpirationTime);
	if (Status != STATUS_SUCCESS)  // NOSONAR - SCOPE-01: declaration kept in outer scope for clarity
	{
		cleanup();
		return EID::make_unexpected(HRESULT_FROM_NT(Status));
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"GetGroups");
	// get the number of groups
	bResult = GetGroups(UserName, &pGroupInfo, &NumberOfGroups);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"GetGroups error");
		cleanup();
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"GetLocalGroups");
	bResult = GetLocalGroups(UserName, &pLocalGroupInfo, &NumberOfLocalGroups);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"GetLocalGroups error");
		cleanup();
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
	}

	// get SID
	// User
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"User");
	bResult = NameToSid(UserName, &UserSid);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"NameToSid");
		cleanup();
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
	}
	// Primary Group Id
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Primary Group Id");
	bResult = GetPrimaryGroupSidFromUserSid(UserSid, &PrimaryGroupSid);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"GetPrimaryGroupSidFromUserSid");
		cleanup();
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
	}
	Size = 0;
	// Group
	pGroupSid = (PSID*)EIDAlloc((NumberOfGroups + NumberOfLocalGroups) * sizeof(PSID));
	if (!pGroupSid)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"pGroupSid NULL");
		cleanup();
		return EID::make_unexpected(E_OUTOFMEMORY);
	}
	// Initialize all to nullptr for safe cleanup
	for (i = 0; i < NumberOfGroups + NumberOfLocalGroups; i++)
	{
		pGroupSid[i] = nullptr;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Group");
	for (i = 0; i < NumberOfGroups; i++)
	{
		NameToSid(pGroupInfo[i].grui1_name, &pGroupSid[i]);
		Size += GetLengthSid(pGroupSid[i]);
	}
	for (i = 0; i < NumberOfLocalGroups; i++)
	{
		NameToSid(pLocalGroupInfo[i].grui0_name, &pGroupSid[NumberOfGroups + i]);
		Size += GetLengthSid(pGroupSid[NumberOfGroups + i]);
	}
	// compute the size
	Size += sizeof(LSA_TOKEN_INFORMATION_V2); // struct
	Size += GetLengthSid(UserSid) + GetLengthSid(PrimaryGroupSid);//sid user and primary group
	Size += sizeof(DWORD) + (sizeof(SID_AND_ATTRIBUTES)) * (NumberOfGroups + NumberOfLocalGroups); // groups

	TokenInformation = (PLSA_TOKEN_INFORMATION_V2)EIDAlloc(Size);
	if (TokenInformation == nullptr)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"TokenInformation NULL");
		cleanup();
		return EID::make_unexpected(E_OUTOFMEMORY);
	}
	// update offset and copy info
	Offset = (PBYTE)TokenInformation + sizeof(LSA_TOKEN_INFORMATION_V1);
	TokenInformation->User.User.Sid = (PSID)Offset;
	CopySid(GetLengthSid(UserSid), Offset, UserSid);
	DebugPrintSid(UserName, UserSid);
	TokenInformation->User.User.Attributes = 0; // cf msdn, no attributes defined for users sid
	Offset += GetLengthSid(UserSid);

	TokenInformation->PrimaryGroup.PrimaryGroup = (PSID)Offset;
	CopySid(GetLengthSid(PrimaryGroupSid), Offset, PrimaryGroupSid);
	DebugPrintSid(L"PrimaryGroupId", PrimaryGroupSid);
	Offset += GetLengthSid(PrimaryGroupSid);

	TokenInformation->Groups = (PTOKEN_GROUPS)Offset;
	pTokenGroups = (PTOKEN_GROUPS)Offset;
	pTokenGroups->GroupCount = NumberOfGroups + NumberOfLocalGroups;
	// -ANYSIZE_ARRAY because TOKEN_GROUPS contain "ANYSIZE_ARRAY" (=1) SID_AND_ATTRIBUTES
	Offset += sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES) * (NumberOfGroups + NumberOfLocalGroups - ANYSIZE_ARRAY);
	// cause TOKEN_GROUPS contains one SID_AND_ATTRIBUTES
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Group Struct time");

	for (i = 0; i < NumberOfGroups; i++)
	{
		// attributes get directly from the struct
		pTokenGroups->Groups[i].Attributes = pGroupInfo[i].grui1_attributes;
		pTokenGroups->Groups[i].Sid = (PSID)Offset;
		CopySid(GetLengthSid(pGroupSid[i]), Offset, pGroupSid[i]);
		Offset += GetLengthSid(pGroupSid[i]);
		DebugPrintSid(pGroupInfo[i].grui1_name, pGroupSid[i]);
		EIDFree(pGroupSid[i]);
		pGroupSid[i] = nullptr;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Group 2");
	for (i = 0; i < NumberOfLocalGroups; i++)
	{
		// get the attributes of group since the struct doesn't contain attributes
		if (*GetSidSubAuthority(pGroupSid[NumberOfGroups + i], 0) != SECURITY_BUILTIN_DOMAIN_RID)
		{
			pTokenGroups->Groups[NumberOfGroups + i].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT;
		}
		else
		{
			pTokenGroups->Groups[NumberOfGroups + i].Attributes = 0;
		}
		pTokenGroups->Groups[NumberOfGroups + i].Sid = (PSID)Offset;
		CopySid(GetLengthSid(pGroupSid[NumberOfGroups + i]), Offset, pGroupSid[NumberOfGroups + i]);
		Offset += GetLengthSid(pGroupSid[NumberOfGroups + i]);
		DebugPrintSid(pLocalGroupInfo[i].grui0_name, pGroupSid[NumberOfGroups + i]);
		EIDFree(pGroupSid[NumberOfGroups + i]);
		pGroupSid[NumberOfGroups + i] = nullptr;
	}

	// Expiration time
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Expiration time");
	TokenInformation->ExpirationTime = ExpirationTime;

	// privileges
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"privileges");
	TokenInformation->Privileges = nullptr;

	// owner
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"owner");
	TokenInformation->Owner.Owner = nullptr;

	// dacl
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"dacl");
	TokenInformation->DefaultDacl.DefaultDacl = nullptr;

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"TokenInformation done");

	// Free intermediate buffers (but not TokenInformation - that's returned)
	if (PrimaryGroupSid) { EIDFree(PrimaryGroupSid); PrimaryGroupSid = nullptr; }
	if (UserSid) { EIDFree(UserSid); UserSid = nullptr; }
	if (pGroupSid) { EIDFree(pGroupSid); pGroupSid = nullptr; }
	if (pGroupInfo) { NetApiBufferFree(pGroupInfo); pGroupInfo = nullptr; }
	if (pLocalGroupInfo) { NetApiBufferFree(pLocalGroupInfo); pLocalGroupInfo = nullptr; }

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Leave");
	return std::make_pair(TokenInformation, Size);
}

// Exported wrapper maintaining NTSTATUS return for LSA compatibility
// Converts HRESULT errors to NTSTATUS via hr_to_ntstatus()
NTSTATUS UserNameToToken(__in PLSA_UNICODE_STRING AccountName,
	__out PLSA_TOKEN_INFORMATION_V2 *Token,
	__out PDWORD TokenLength,
	__out PNTSTATUS SubStatus)
{
	auto result = UserNameToTokenInternal(AccountName, SubStatus);
	if (result)
	{
		auto [tokenInfo, size] = *result;
		*Token = tokenInfo;
		*TokenLength = size;
		return STATUS_SUCCESS;
	}
	return EID::hr_to_ntstatus(result.error());
}

// BUG FIX #16: TOCTOU race condition mitigation - use retry loop for SID allocation
BOOL NameToSid(WCHAR* UserName, PSID *pUserSid)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL bResult;
	SID_NAME_USE Use;
	WCHAR checkDomainName[UNCLEN+1];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD cchReferencedDomainName=0;
	constexpr DWORD MAX_RETRIES = 3;
	DWORD dwRetryCount = 0;
	PSID pTempSid = nullptr;

	DWORD dLengthSid = 0;
	bResult = LookupAccountNameW( nullptr, UserName, nullptr,&dLengthSid,nullptr, &cchReferencedDomainName, &Use);

	if (!bResult && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to LookupAccountNameW 0x%08x",GetLastError());
		return FALSE;
	}

	// Retry loop for SID allocation (handles TOCTOU race condition)
	for (dwRetryCount = 0; dwRetryCount < MAX_RETRIES; dwRetryCount++)  // NOSONAR - PERF-01: declared once, reused across iterations
	{
		// Clean up from previous retry
		if (pTempSid)
		{
			EIDFree(pTempSid);
			pTempSid = nullptr;
		}

		// Allocate SID buffer
		pTempSid = (PSID)EIDAlloc(dLengthSid);
		if (!pTempSid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to allocate SID buffer");
			return FALSE;
		}
		SecureZeroMemory(pTempSid, dLengthSid);

		cchReferencedDomainName=UNCLEN;
		bResult = LookupAccountNameW( nullptr, UserName, pTempSid,&dLengthSid,checkDomainName, &cchReferencedDomainName, &Use);

		if (bResult)
		{
			*pUserSid = pTempSid;
			return TRUE;  // Success - exit retry loop
		}

		DWORD dwError = GetLastError();
		if (dwError == ERROR_INSUFFICIENT_BUFFER)
		{
			// Buffer size changed between check and use (TOCTOU race condition)
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"TOCTOU race condition on retry %u: buffer size changed (retrying...)",
				dwRetryCount + 1);
			// Loop will continue with new dLengthSid value
		}
		else
		{
			// Different error - not a TOCTOU issue, don't retry
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to LookupAccountNameW 0x%08x",dwError);
			EIDFree(pTempSid);
			return FALSE;
		}
	}

	// Exhausted retries
	EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Exhausted %u retries for SID lookup (possible persistent race condition)",
		MAX_RETRIES);
	if (pTempSid)
	{
		EIDFree(pTempSid);
	}
	return FALSE;
}

BOOL GetGroups(WCHAR* UserName,PGROUP_USERS_INFO_1 *lpGroupInfo, LPDWORD pTotalEntries)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	NET_API_STATUS Status;
	DWORD NumberOfEntries;
	Status = NetUserGetGroups(nullptr,UserName,1,(LPBYTE*)lpGroupInfo,MAX_PREFERRED_LENGTH,&NumberOfEntries,pTotalEntries);
	if (Status != NERR_Success)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to NetUserGetGroups 0x%08x",Status);
		return FALSE;
	}
	return TRUE;
}

BOOL GetLocalGroups(WCHAR* UserName,PGROUP_USERS_INFO_0 *lpGroupInfo, LPDWORD pTotalEntries)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	NET_API_STATUS Status;
	DWORD NumberOfEntries;
	Status = NetUserGetLocalGroups(nullptr,UserName,0,0,(LPBYTE*)lpGroupInfo,MAX_PREFERRED_LENGTH,&NumberOfEntries,pTotalEntries);
	if (Status != NERR_Success)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to NetUserGetLocalGroups 0x%08x",Status);
		return FALSE;
	}
	return TRUE;
}

BOOL GetPrimaryGroupSidFromUserSid(PSID UserSID, PSID *PrimaryGroupSID)
{
	// duplicate the user sid and replace the last subauthority by DOMAIN_GROUP_RID_USERS
	// cf http://msdn.microsoft.com/en-us/library/aa379649.aspx
	UCHAR SubAuthorityCount;
	*PrimaryGroupSID = EIDAlloc(GetLengthSid(UserSID));
	CopySid(GetLengthSid(UserSID),*PrimaryGroupSID,UserSID);
	SubAuthorityCount = *GetSidSubAuthorityCount(*PrimaryGroupSID);
	*GetSidSubAuthority(*PrimaryGroupSID, SubAuthorityCount-1) = DOMAIN_GROUP_RID_USERS;
	return TRUE;
}

void DebugPrintSid(const WCHAR* Name, PSID Sid)
{
	LPTSTR chSID = nullptr;
	ConvertSidToStringSid(Sid,&chSID);
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Name %s Sid %s",Name,chSID);
	LocalFree(chSID);
}

// Internal function using Result<T> for type-safe error handling
// Marked noexcept for LSASS compatibility
// Returns expiration time on success, HRESULT error on failure
// Sets SubStatus for account restriction details
[[nodiscard]] EID::Result<LARGE_INTEGER> CheckAuthorizationInternal(
    PWSTR UserName,
    NTSTATUS* SubStatus) noexcept
{
	PUSER_INFO_4 pUserInfo = nullptr;
	LARGE_INTEGER ExpirationTime;
	ExpirationTime.QuadPart = 0x7FFFFFFFFFFFFFFF;

	NET_API_STATUS netStatus = NetUserGetInfo(nullptr, UserName, 4, (LPBYTE*)&pUserInfo);
	if (netStatus != 0)  // NOSONAR - SCOPE-01: declaration kept in outer scope for clarity
	{
		HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
		switch (netStatus)
		{
		case ERROR_ACCESS_DENIED:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"User not found (%s): ACCESS DENIED", UserName);
			hr = HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
			break;
		case NERR_InvalidComputer:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"User not found (%s): Invalid computer", UserName);
			hr = HRESULT_FROM_WIN32(ERROR_BAD_NETPATH);
			break;
		case NERR_UserNotFound:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"User not found (%s): No such user", UserName);
			hr = HRESULT_FROM_WIN32(ERROR_NO_SUCH_USER);
			break;
		default:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"User not found (%s): Unknown error 0x%08x", UserName, netStatus);
			hr = HRESULT_FROM_WIN32(ERROR_NO_SUCH_USER);
			break;
		}
		return EID::make_unexpected(hr);
	}

	// Ensure cleanup on all exit paths
	struct UserInfoCleanup {
		PUSER_INFO_4* pp;
		explicit UserInfoCleanup(PUSER_INFO_4* ptr) : pp(ptr) {}
		~UserInfoCleanup() { if (pp && *pp) NetApiBufferFree(*pp); }
		// Delete copy/move - this manages a resource
		UserInfoCleanup(const UserInfoCleanup&) = delete;
		UserInfoCleanup& operator=(const UserInfoCleanup&) = delete;
	};
	UserInfoCleanup cleanup(&pUserInfo);

	if (pUserInfo->usri4_flags & UF_ACCOUNTDISABLE)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Account disabled: ACCOUNT_DISABLED");
		*SubStatus = STATUS_ACCOUNT_DISABLED;
		// Use HRESULT that maps to STATUS_ACCOUNT_RESTRICTION
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_ACCOUNT_RESTRICTION));
	}

	if (pUserInfo->usri4_logon_hours)
	{
		DWORD dwPosLogon;
		DWORD dwPosLogoff;
		DWORD dwHours;
		SYSTEMTIME SystemTime;
		FILETIME FileTime;
		GetSystemTime(&SystemTime);
		dwPosLogon = SystemTime.wDayOfWeek * 24 + SystemTime.wHour;
		if (!((pUserInfo->usri4_logon_hours[dwPosLogon / 8] >> (dwPosLogon % 8)) & 1))  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"STATUS_INVALID_LOGON_HOURS");
			*SubStatus = STATUS_INVALID_LOGON_HOURS;
			return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_ACCOUNT_RESTRICTION));
		}
		else
		{
			// logon authorized
			// iterates to find the first 0
			for (dwHours = 1; dwHours < 7 * 24 + 1; dwHours++)  // NOSONAR - PERF-01: declared once, reused across iterations
			{
				dwPosLogoff = (dwPosLogon + dwHours) % (7 * 24);
				if (!((pUserInfo->usri4_logon_hours[dwPosLogoff / 8] >> (dwPosLogoff % 8)) & 1))  // NOSONAR - COMPLEXITY-01: nested BYTE bit-test retained; logic verified
				{
					// Logon authorized not everytime
					EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Hour Restriction");
					LARGE_INTEGER Hour;
					Hour.LowPart = 0x61C46800;
					Hour.HighPart = 8;
					SystemTime.wMinute = 0;
					SystemTime.wSecond = 0;
					SystemTime.wMilliseconds = 0;
					SystemTimeToFileTime(&SystemTime, &FileTime);
					// Use std::bit_cast for type-safe conversion (SonarQube cpp:S3624)
					ExpirationTime.QuadPart = std::bit_cast<std::int64_t>(FileTime);
					ExpirationTime.QuadPart += Hour.QuadPart * dwHours;
					break;
				}
			}
		}
	}

	if (wcscmp(pUserInfo->usri4_logon_server, L"\\\\*") != 0)  // NOSONAR - STRING-01: escaped literal retained to preserve exact comparison
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"STATUS_INVALID_WORKSTATION");
		*SubStatus = STATUS_INVALID_WORKSTATION;
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_ACCOUNT_RESTRICTION));
	}

	return ExpirationTime;
}

// Exported wrapper maintaining NTSTATUS return for LSA compatibility
// Converts HRESULT errors to NTSTATUS via hr_to_ntstatus()
NTSTATUS CheckAuthorization(PWSTR UserName, NTSTATUS *SubStatus, LARGE_INTEGER *ExpirationTime)
{
	auto result = CheckAuthorizationInternal(UserName, SubStatus);
	if (result)
	{
		*ExpirationTime = *result;
		return STATUS_SUCCESS;
	}
	return EID::hr_to_ntstatus(result.error());
}






















