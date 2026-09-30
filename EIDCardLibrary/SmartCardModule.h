
#pragma once

// Note: PEID_SMARTCARD_CSP_INFO is defined in EIDCardLibrary.h
// cardmod.h is available in the repository's include directory

// szReader/szCard are read-only here; they now come from EIDCspInfoStringAt,
// which hands back a const pointer into the validated logon buffer.
BOOL CheckPINandGetRemainingAttempts(LPCTSTR szReader, LPCTSTR szCard, PTSTR szPin, PDWORD pdwAttempts);
// dwCspDataLength is the length the LSA supplied for the CspData block
// (Logon.CspDataLength), never pCspInfo->dwCspInfoLen.
NTSTATUS CheckPINandGetRemainingAttemptsIfPossible(PEID_SMARTCARD_CSP_INFO pCspInfo, ULONG dwCspDataLength, PTSTR szPin, NTSTATUS *pSubStatus);

