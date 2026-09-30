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
#include <iostream>
#include <list>
#include "../EIDCardLibrary/EIDCardLibrary.h"

class CContainer 
{

  public:
    CContainer(__in LPCTSTR szReaderName, __in LPCTSTR szCardName, __in LPCTSTR szProviderName, 
		__in LPCTSTR szContainerName, __in DWORD KeySpec, __in USHORT ActivityCount, __in PCCERT_CONTEXT pCertContext);

    virtual ~CContainer();

	PTSTR GetUserName();
	PTSTR GetProviderName() const;
	PTSTR GetContainerName() const;
	DWORD GetRid();
	DWORD GetKeySpec() const;

	PCCERT_CONTEXT GetCertificate() const;
	BOOL IsOnReader(__in LPCTSTR szReaderName) const;
	
	PEID_SMARTCARD_CSP_INFO GetCSPInfo() const;
	void FreeCSPInfo(PEID_SMARTCARD_CSP_INFO) const;

	BOOL Erase() const;
	BOOL ViewCertificate(HWND hWnd = nullptr) const;

	BOOL TriggerRemovePolicy() const;
	PEID_INTERACTIVE_LOGON AllocateLogonStruct(PWSTR szPin, PDWORD pdwSize);
  private:
 static LPTSTR ValidateAndCopyString(LPCTSTR szSource, DWORD maxLength, LPCWSTR szFieldName);

 LPTSTR					_szReaderName;
 LPTSTR					_szCardName;
 LPTSTR					_szProviderName;
 LPTSTR					_szContainerName;
 LPTSTR					_szUserName;
 DWORD					_KeySpec;
 USHORT					_ActivityCount;
 PCCERT_CONTEXT			_pCertContext;
 DWORD					_dwRid;
};
