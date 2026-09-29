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

#include <tchar.h>

#include "../EIDCardLibrary/CertificateValidation.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/Tracing.h"
#include <LM.h>
#include <wincred.h>


template <typename T>
CContainerHolderFactory<T>::CContainerHolderFactory()
{
	_cpus = CPUS_INVALID;
	_dwFlags = 0;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_fReviveOnReconnect = FALSE;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	InitializeCriticalSection(&CriticalSection);
}

template <typename T>
void CContainerHolderFactory<T>::SetReviveOnReconnect(BOOL fRevive)
{
	_fReviveOnReconnect = fRevive;
}

template <typename T> 
CContainerHolderFactory<T>::~CContainerHolderFactory()
{
	CleanList();
	DeleteCriticalSection(&CriticalSection);
}

template <typename T> 
VOID CContainerHolderFactory<T>::Lock()
{
	EnterCriticalSection(&CriticalSection);
}

template <typename T> 
VOID CContainerHolderFactory<T>::Unlock()
{
	LeaveCriticalSection(&CriticalSection);
}

template <typename T> 
HRESULT CContainerHolderFactory<T>::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags
    )
{
	_cpus = cpus;
	_dwFlags = dwFlags;
	return S_OK;
}

template <typename T>
BOOL CContainerHolderFactory<T>::ConnectNotification(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount)
{
	BOOL fReturn = ConnectNotificationGeneric(szReaderName,szCardName, ActivityCount);
	// Any tile still flagged disconnected on this reader belongs to a card that is no
	// longer here (a different card was inserted); drop it so it cannot linger.
	if (_fReviveOnReconnect)
	{
		PurgeStaleDisconnected(szReaderName);
	}
	return fReturn;
}

// called to enumerate the credential built with a CContainer
template <typename T> 
BOOL CContainerHolderFactory<T>::ConnectNotificationGeneric(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
	HCRYPTPROV HCryptProv;
	HCRYPTPROV hProv = NULL;
	BOOL bStatus;
	CHAR szContainerName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwContainerNameLen = ARRAYSIZE(szContainerName);
	TCHAR szProviderName[1024] = TEXT("");  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwProviderNameLen = ARRAYSIZE(szProviderName);
	DWORD pKeySpecs[2] = {AT_KEYEXCHANGE,AT_SIGNATURE};  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwKeyNumMax = 1;
	HCRYPTKEY hKey;
	// remove existing entries
	//DisconnectNotification(szReaderName);
	EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Connect Reader %s CardName %s",szReaderName,szCardName);
	// get provider name
	if (!SchGetProviderNameFromCardName(szCardName, szProviderName, &dwProviderNameLen))
	{
		return FALSE;
	}

	LPTSTR szMainContainerName = BuildContainerNameFromReader(szReaderName);
	if (!szMainContainerName)
	{
		return FALSE;
	}
	
	// if policy 
	if (GetPolicyValue(GPOPolicy::AllowSignatureOnlyKeys) || _cpus == CPUS_INVALID)
	{
		dwKeyNumMax = 2;
	}


	bStatus = CryptAcquireContext(&HCryptProv,
				szMainContainerName,
				szProviderName,
				PROV_RSA_FULL,
				CRYPT_SILENT);
	if (!bStatus)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 1 0x%08x",GetLastError());
		// for the spanish EID
		bStatus = CryptAcquireContext(&HCryptProv,
				nullptr,
				szProviderName,
				PROV_RSA_FULL,
				CRYPT_SILENT);
		if (!bStatus)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 2 0x%08x",GetLastError());
			EIDFree(szMainContainerName);
			return FALSE;
		}
	}
	DWORD dwFlags = CRYPT_FIRST;
	/* Enumerate all the containers */
	while (CryptGetProvParam(HCryptProv,
				PP_ENUMCONTAINERS,
				(LPBYTE) szContainerName,
				&dwContainerNameLen,
				dwFlags)
			)
	{
		// Ensure null-termination to prevent out-of-bounds read (CWE-125 fix for #31)
		if (dwContainerNameLen >= ARRAYSIZE(szContainerName))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Container name too long: %d", dwContainerNameLen);
			dwFlags = CRYPT_NEXT;
			dwContainerNameLen = ARRAYSIZE(szContainerName);
			continue;
		}
		szContainerName[dwContainerNameLen] = '\0';

		// convert the container name to unicode
#ifdef UNICODE
		int wLen = MultiByteToWideChar(CP_UTF8, 0, szContainerName, -1, nullptr, 0);
		LPTSTR szWideContainerName = (LPTSTR) EIDAlloc(sizeof(TCHAR)*wLen);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (szWideContainerName)
		{
			MultiByteToWideChar(CP_UTF8, 0, szContainerName, -1, szWideContainerName, wLen);
#else
		LPTSTR szWideContainerName = (LPTSTR) EIDAlloc(sizeof(TCHAR)*(_tcslen(szContainerName)+1));
		if (szWideContainerName)
			{
			_tcscpy_s(szWideContainerName,_tcslen(szContainerName)+1,szContainerName);

#endif
			// create a CContainer item
			if (CryptAcquireContext(&hProv,
				szWideContainerName,
				szProviderName,
				PROV_RSA_FULL,
				CRYPT_SILENT))
			{
				for (DWORD i = 0; i < dwKeyNumMax; i++)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					if (CryptGetUserKey(hProv,
							pKeySpecs[i],
							&hKey) )
					{
						BYTE Data[4096];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
						DWORD DataSize = 4096;
						if (CryptGetKeyParam(hKey,  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
								KP_CERTIFICATE,
								Data,
								&DataSize,
								0))
						{
							CreateItemFromCertificateBlob(hProv, szReaderName,szCardName,szProviderName,
									szWideContainerName, pKeySpecs[i],ActivityCount, Data, DataSize);
							}
							CryptDestroyKey(hKey);
							hKey = NULL;
					}
				}
			}
			CryptReleaseContext(hProv, 0);
			hProv = NULL;
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Failed to allocate memory for container name");
		}
		dwFlags = CRYPT_NEXT;
		dwContainerNameLen = ARRAYSIZE(szContainerName);
		EIDFree(szWideContainerName);
	}
	if (dwFlags == CRYPT_FIRST)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetProvParam 0x%08x - creating containers manually",GetLastError());
		// the default container can be enumerated but PP_ENUMCONTAINERS doesn't work
		for (DWORD i = 0; i < dwKeyNumMax; i++)
		{
			if (CryptGetUserKey(HCryptProv,
					pKeySpecs[i],
					&hKey) )
			{
				BYTE Data[4096];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
				DWORD DataSize = 4096;
				if (CryptGetKeyParam(hKey,  // NOSONAR - COMPLEXITY-01: nesting and local declaration retained; logic verified
						KP_CERTIFICATE,
						Data,
						&DataSize,
						0))
				{
					CreateItemFromCertificateBlob(HCryptProv, szReaderName,szCardName,szProviderName,
						szMainContainerName, pKeySpecs[i],ActivityCount, Data, DataSize);
					}
				CryptDestroyKey(hKey);
				hKey = NULL;
			}
		}
	}
	CryptReleaseContext(HCryptProv,0);
	EIDFree(szMainContainerName);
	return TRUE;
}

template <typename T>
BOOL CContainerHolderFactory<T>::CreateContainer(__in LPCTSTR szReaderName,__in LPCTSTR szCardName,
															   __in LPCTSTR szProviderName, __in LPCTSTR szWideContainerName,
															   __in DWORD KeySpec, __in USHORT ActivityCount, __in PCCERT_CONTEXT pCertContext)
{
	CContainer* pContainer = nullptr;
	pContainer = new CContainer(szReaderName,szCardName,szProviderName,szWideContainerName, KeySpec, ActivityCount, pCertContext);  // NOSONAR - COM-01: Container requires heap allocation
	this->Lock();
	T* ContainerHolder = new T(pContainer);  // NOSONAR - COM-01: Container holder requires heap allocation
	ContainerHolder->SetUsageScenario(_cpus, _dwFlags);
	_CredentialList.push_back(ContainerHolder);
	this->Unlock();
	return TRUE;
}

template <typename T>
BOOL CContainerHolderFactory<T>::CreateItemFromCertificateBlob(__in HCRYPTPROV hProv,  // NOSONAR - COMPLEXITY-01: parameter count and complexity retained; logic verified
																__in LPCTSTR szReaderName,__in LPCTSTR szCardName,
															   __in LPCTSTR szProviderName, __in LPCTSTR szWideContainerName,
															   __in DWORD KeySpec, __in USHORT ActivityCount,
															   __in PBYTE Data, __in DWORD DataSize)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL fReturn = FALSE;
	PCCERT_CONTEXT pCertContext = nullptr;
	BOOL fSuccess;
	PTSTR szUsername = nullptr;
	DWORD dwError = 0;

	// Revive-in-place: if this exact container/key is already present as a tile that was
	// flagged disconnected (its card was removed while selected), just clear the flag so the
	// existing, on-screen tile comes back to life. This avoids creating a duplicate tile and
	// lets LogonUI's currently selected tile switch back from "please reconnect" to the PIN box.
	if (_fReviveOnReconnect)
	{
		T* reviveItem = nullptr;
		this->Lock();
		for (T* item : _CredentialList)
		{
			CContainer* container = item->GetContainer();  // NOSONAR - API-01: non-const pointer retained; member access constness not guaranteed
			if (item->IsDisconnected() &&
				container->IsOnReader(szReaderName) &&
				container->GetKeySpec() == KeySpec &&
				_tcscmp(container->GetContainerName(), szWideContainerName) == 0)
			{
				reviveItem = item;
				break;
			}
		}
		this->Unlock();
		if (reviveItem)
		{
			// Clear the flag (and restore the PIN prompt) outside the lock; this runs before the
			// post-connect PurgeStaleDisconnected, so the revived tile will not be purged.
			reviveItem->SetDisconnected(FALSE);
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Revived disconnected tile %s", szWideContainerName);
			return TRUE;
		}
	}

	__try
	{
		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, Data, DataSize);
		if (!pCertContext)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
			__leave;
		}
		
		fReturn = SetupCertificateContextWithKeyInfo(pCertContext, hProv, szProviderName, szWideContainerName, KeySpec);
		if (!fReturn)
		{
			dwError = GetLastError();
			__leave;
		}
		// important : the hprov will be used later and free if the certificatecontext is free
		// so we have to add 1 to the reference count
		fReturn = CryptContextAddRef(hProv, nullptr, 0);
		if (!fReturn)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptContextAddRef 0x%08x",dwError);
			__leave;
		}

		if (_cpus != CPUS_CREDUI && _cpus != CPUS_INVALID)
		{
			fSuccess = IsTrustedCertificate(pCertContext);
			if (!fSuccess)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Untrusted certificate IsTrustedCertificate 0x%08x",dwError);
				__leave;
			}
		}
		else if (_cpus == CPUS_CREDUI)
		{
			fSuccess = HasCertificateRightEKU(pCertContext);
			if (!fSuccess)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Untrusted certificate HasCertificateRightEKU 0x%08x",dwError);
				__leave;
			}
		}
		// check if the Container meet the requirement
		if ((_cpus == CPUS_LOGON) || (_cpus == CPUS_UNLOCK_WORKSTATION))
		{
			// check if the user has an account to this workstation
			DWORD dwRid = LsaEIDGetRIDFromStoredCredential(pCertContext);	
			if (!dwRid)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"HasAccountOnCurrentComputer 0x%08x",dwError);
				__leave;
			}
			szUsername = GetUsernameFromRid(dwRid);
			if (!szUsername)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetUsernameFromRid 0x%08x",dwError);
				__leave;
			}
			if ((_dwFlags & CREDUIWIN_ENUMERATE_CURRENT_USER) || (_cpus == CPUS_UNLOCK_WORKSTATION))
			{
				fSuccess = IsCurrentUser(szUsername);
				if (!fSuccess)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"IsCurrentUser 0x%08x",dwError);
					__leave;
				}
			}
			if (_dwFlags & CREDUIWIN_ENUMERATE_ADMINS)
			{
				fSuccess = IsAdmin(szUsername);
				if (!fSuccess)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"IsAdmin 0x%08x",dwError);
					__leave;
				}
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Creating container szReaderName='%s'", szReaderName);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Creating container szCardName='%s'", szCardName);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Creating container szProviderName='%s'", szProviderName);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Creating container szWideContainerName='%s' KeySpec=%d ActivityCount=%d",
				szWideContainerName, KeySpec, ActivityCount);
		fSuccess = CreateContainer(szReaderName, szCardName, szProviderName, szWideContainerName, KeySpec, ActivityCount, pCertContext);
		if (!fSuccess) __leave;
		fReturn = TRUE;
	}
	__finally
	{
		if (szUsername) EIDFree(szUsername);
		if (!fReturn && pCertContext)
		{
			CertFreeCertificateContext(pCertContext);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

template <typename T>
BOOL CContainerHolderFactory<T>::DisconnectNotification(LPCTSTR szReaderName)
{
	// Tiles kept alive to be morphed to "please reconnect" after the lock is released
	// (SetDisconnected calls into LogonUI, which must not happen under our critical section).
	std::list<T*> morphItems;
	this->Lock();
	auto l_iter = _CredentialList.begin();
	while(l_iter!=_CredentialList.end())
	{
		T* item = (T *)*l_iter;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		CContainer* container = item->GetContainer();  // NOSONAR - API-01: non-const pointer retained; member access constness not guaranteed

#ifndef UNICODE
		int wLen = MultiByteToWideChar(CP_UTF8, 0, szReaderName, -1, nullptr, 0);
		LPWSTR szWideReaderName = (LPWSTR) EIDAlloc(sizeof(WCHAR)*wLen);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (szWideReaderName)
		{
			MultiByteToWideChar(CP_UTF8, 0, szReaderName, -1, szWideReaderName, wLen);
#else
		LPWSTR szWideReaderName = (LPWSTR) EIDAlloc((DWORD)(sizeof(WCHAR)*(_tcslen(szReaderName)+1)));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (szWideReaderName)
			{
			_tcscpy_s(szWideReaderName,_tcslen(szReaderName)+1,szReaderName);

#endif
			if(container->IsOnReader(szWideReaderName))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Disconnect match tile=%p revive=%d selected=%d",(void*)item,_fReviveOnReconnect,item->IsSelected());
				// Keep the currently selected tile alive but flagged disconnected, so it can
				// morph to "please reconnect" in place (LogonUI will not swap a selected tile)
				// and be revived when the card returns. All other tiles are removed as before.
				if (_fReviveOnReconnect && item->IsSelected())  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Disconnect -> MORPH tile=%p",(void*)item);
					morphItems.push_back(item);
					++l_iter;
				}
				else
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Disconnect -> ERASE tile=%p",(void*)item);
					l_iter = _CredentialList.erase(l_iter);
					item->Release();
				}
			}
			else
			{
				++l_iter;
			}
			EIDFree(szWideReaderName);
		}
	}
	this->Unlock();

	// The kept tiles stay owned by _CredentialList and card events are delivered serially,
	// so they cannot be erased from under us here.
	for (T* item : morphItems)
	{
		item->SetDisconnected(TRUE);
	}
	return TRUE;
}

template <typename T>
void CContainerHolderFactory<T>::PurgeStaleDisconnected(LPCTSTR szReaderName)
{
	this->Lock();
	auto l_iter = _CredentialList.begin();
	while(l_iter!=_CredentialList.end())
	{
		T* item = (T *)*l_iter;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		CContainer* container = item->GetContainer();  // NOSONAR - API-01: non-const pointer retained; member access constness not guaranteed
		if (item->IsDisconnected() && container->IsOnReader(szReaderName))
		{
			l_iter = _CredentialList.erase(l_iter);
			item->Release();
		}
		else
		{
			++l_iter;
		}
	}
	this->Unlock();
}

template <typename T>
BOOL CContainerHolderFactory<T>::RemoveContainerHolder(T* holder)
{
	BOOL fFound = FALSE;
	this->Lock();
	auto l_iter = _CredentialList.begin();
	while(l_iter!=_CredentialList.end())
	{
		if ((T*)*l_iter == holder)  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		{
			l_iter = _CredentialList.erase(l_iter);
			holder->Release();
			fFound = TRUE;
			break;
		}
		++l_iter;
	}
	this->Unlock();
	return fFound;
}

template <typename T>
BOOL CContainerHolderFactory<T>::CleanList()
{
	this->Lock();
	auto l_iter = _CredentialList.begin();
	while(l_iter!=_CredentialList.end())
	{
		T* item = (T *)*l_iter;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		l_iter = _CredentialList.erase(l_iter);
		item->Release();
	}
	this->Unlock();
	return TRUE;
}

template <typename T>
BOOL CContainerHolderFactory<T>::HasContainerHolder() const
{
	const_cast<CContainerHolderFactory<T>*>(this)->Lock();  // NOSONAR - COM-01: Thread-safe locking pattern requires const_cast
	BOOL result = _CredentialList.size() > 0;
	const_cast<CContainerHolderFactory<T>*>(this)->Unlock();  // NOSONAR - COM-01: Thread-safe locking pattern requires const_cast
	return result;
}


template <typename T>
DWORD CContainerHolderFactory<T>::ContainerHolderCount() const
{
	const_cast<CContainerHolderFactory<T>*>(this)->Lock();  // NOSONAR - COM-01: Thread-safe locking pattern requires const_cast
	DWORD count = (DWORD) _CredentialList.size();  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	const_cast<CContainerHolderFactory<T>*>(this)->Unlock();  // NOSONAR - COM-01: Thread-safe locking pattern requires const_cast
	return count;
}

template <typename T>
T* CContainerHolderFactory<T>::GetContainerHolderAt(DWORD dwIndex)
{
	this->Lock();
	T* result = nullptr;
	if (dwIndex < _CredentialList.size())
	{
		auto it = _CredentialList.begin();
		std::advance(it, dwIndex);
		result = *it;
	}
	this->Unlock();
	return result;
}