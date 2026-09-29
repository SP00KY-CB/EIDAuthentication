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

//
//


#include "CEIDCredential.h"
#include "CEIDProvider.h"
#include "EIDCredentialProvider.h"


#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"

#include <CodeAnalysis/Warnings.h>
#pragma warning(push)
#pragma warning(disable : 4995)
#include <Shlwapi.h>
#pragma warning(pop)
#pragma warning(push)
#pragma warning(disable : 4995)
#include <strsafe.h>
#pragma warning(pop)
// Static buffer for PWSTR* assignment (C++23 /Zc:strictStrings compatibility)
static wchar_t s_wszUnknownError[] = L"Unknow Error";  // NOSONAR - GLOBAL-01: Non-const for Windows API PWSTR compatibility

// Message shown in place of the PIN box once the card is removed while this tile is selected.
static const wchar_t s_szReconnectCard[] = L"Please reconnect your smart card";

// CEIDCredential ////////////////////////////////////////////////////////

CEIDCredential::CEIDCredential(CContainer* container):
    _cRef(1),  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
    _pCredProvCredentialEvents(nullptr)  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Creation");
	DllAddRef();
    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
	_pContainer = container;  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
	_fSelected = FALSE;  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
	_fDisconnected = FALSE;  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
	_pProvider = nullptr;  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
	Initialize();
}

CEIDCredential::~CEIDCredential()
{
	if (_pContainer)
	{
		delete _pContainer;  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
	}
	if (_rgFieldStrings[SFI_PIN])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPin;
        HRESULT hr = StringCchLengthW(_rgFieldStrings[SFI_PIN], 128, &lenPin);  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
        if (SUCCEEDED(hr))
        {
            SecureZeroMemory(_rgFieldStrings[SFI_PIN], lenPin * sizeof(*_rgFieldStrings[SFI_PIN]));
        }
        else
        {
            // If length calculation fails, use maximum length to ensure memory is cleared
            SecureZeroMemory(_rgFieldStrings[SFI_PIN], 128 * sizeof(*_rgFieldStrings[SFI_PIN]));
        }
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }

    DllRelease();
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Deletion");
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
HRESULT CEIDCredential::Initialize()
{
    HRESULT hr = S_OK;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(s_rgCredProvFieldDescriptors); i++)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairs[i];
		hr = FieldDescriptorCopy(s_rgCredProvFieldDescriptors[i], &_rgCredProvFieldDescriptors[i]);
    }

	// Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
	{
		SHStrDupW(_pContainer->GetUserNameW(), &_rgFieldStrings[SFI_USERNAME]);
	}
	if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
    }
	if (SUCCEEDED(hr))
    {
        HINSTANCE Handle = EIDLoadSystemLibrary(TEXT("SmartcardCredentialProvider.dll"));
		WCHAR Message[256] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		if (Handle)
		{
			LoadStringW(Handle, 34, Message, ARRAYSIZE(Message));
			FreeLibrary(Handle);
		}
		hr = SHStrDupW(Message, &_rgFieldStrings[SFI_MESSAGE]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        WCHAR szCertificateDetail[256] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		LoadStringW(g_hinst,IDS_CERTIFICATEDETAIL,szCertificateDetail,ARRAYSIZE(szCertificateDetail));
		hr = SHStrDupW(szCertificateDetail, &_rgFieldStrings[SFI_CERTIFICATE]);
    }
	else
	{
		EIDLogErrorWithContext("Initialize::SHStrDupW", hr, L"field=certificate");
	}
    return hr;
}

CContainer* CEIDCredential::GetContainer() const
{
	return _pContainer;
}

BOOL CEIDCredential::IsSelected() const
{
	return _fSelected;
}

BOOL CEIDCredential::IsDisconnected() const
{
	return _fDisconnected;
}

void CEIDCredential::SetProvider(CEIDProvider* pProvider)
{
	_pProvider = pProvider;
}

// Securely wipe and reset the PIN edit buffer (mirrors SetDeselected's handling).
void CEIDCredential::SecureClearPin()
{
	if (_rgFieldStrings[SFI_PIN])
	{
		size_t lenPin;
		if (SUCCEEDED(StringCchLengthW(_rgFieldStrings[SFI_PIN], 128, &lenPin)))
		{
			SecureZeroMemory(_rgFieldStrings[SFI_PIN], lenPin * sizeof(*_rgFieldStrings[SFI_PIN]));
		}
		else
		{
			SecureZeroMemory(_rgFieldStrings[SFI_PIN], 128 * sizeof(*_rgFieldStrings[SFI_PIN]));
		}
		CoTaskMemFree(_rgFieldStrings[SFI_PIN]);
		_rgFieldStrings[SFI_PIN] = nullptr;
		SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
	}
}

// Morph the tile between the PIN prompt and a "please reconnect your smart card" message.
// LogonUI will not swap a tile that the user has selected, so when the card is pulled we
// update this tile's own fields in place (fDisconnected==TRUE); when the card returns we
// restore the PIN prompt (fDisconnected==FALSE). GetFieldState/GetStringValue mirror this
// state so LogonUI stays consistent even if it re-queries the tile.
void CEIDCredential::SetDisconnected(BOOL fDisconnected)
{
	if (_fDisconnected == fDisconnected)
	{
		return;
	}
	_fDisconnected = fDisconnected;
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: SetDisconnected tile=%p fDisconnected=%d advised=%d",(void*)this,fDisconnected,_pCredProvCredentialEvents!=nullptr);

	// Never keep a typed PIN across a card removal.
	SecureClearPin();

	if (!_pCredProvCredentialEvents)
	{
		// Not currently advised by LogonUI; the state above is enough for the next query.
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: SetDisconnected tile=%p SKIPPED field updates (not advised)",(void*)this);
		return;
	}

	if (fDisconnected)
	{
		_pCredProvCredentialEvents->SetFieldState(this, SFI_PIN, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_BUTTON, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_CERTIFICATE, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldString(this, SFI_PIN, L"");
		_pCredProvCredentialEvents->SetFieldString(this, SFI_MESSAGE, s_szReconnectCard);
	}
	else
	{
		_pCredProvCredentialEvents->SetFieldState(this, SFI_PIN, _rgFieldStatePairs[SFI_PIN].cpfs);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_BUTTON, _rgFieldStatePairs[SFI_SUBMIT_BUTTON].cpfs);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_CERTIFICATE, _rgFieldStatePairs[SFI_CERTIFICATE].cpfs);
		_pCredProvCredentialEvents->SetFieldString(this, SFI_PIN, L"");
		_pCredProvCredentialEvents->SetFieldString(this, SFI_MESSAGE, _rgFieldStrings[SFI_MESSAGE]);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_PIN, CPFIS_FOCUSED);
	}
}
// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CEIDCredential::Advise(
    ICredentialProviderCredentialEvents* pcpce
    )
{
	if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Advise tile=%p",(void*)this);

    return S_OK;
}

void CEIDCredential::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags)
{
	_cpus = cpus;
	_dwFlags = dwFlags;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CEIDCredential::UnAdvise()
{
	if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: UnAdvise tile=%p",(void*)this);
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions.  But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CEIDCredential::SetSelected(BOOL* pbAutoLogon)
{
	*pbAutoLogon = FALSE;
	_fSelected = TRUE;
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: SetSelected tile=%p",(void*)this);
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is.  The most common thing to do here (which we do below)
// is to clear out the Pin field.
HRESULT CEIDCredential::SetDeselected()
{
    HRESULT hr = S_OK;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
	_fSelected = FALSE;
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: SetDeselected tile=%p",(void*)this);
	if (_rgFieldStrings[SFI_PIN])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPin;
        hr = StringCchLengthW(_rgFieldStrings[SFI_PIN], 128, &lenPin);
        if (SUCCEEDED(hr))
        {
            SecureZeroMemory(_rgFieldStrings[SFI_PIN], lenPin * sizeof(*_rgFieldStrings[SFI_PIN]));
        
            CoTaskMemFree(_rgFieldStrings[SFI_PIN]);
            hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
        }

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PIN, _rgFieldStrings[SFI_PIN]);
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"");
        }
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("SetDeselected", hr, L"field=SFI_PIN");
	}

	// If the card is gone and this tile was only being kept alive because LogonUI had it
	// selected (the "please reconnect" morph), deselection is our cue to finally drop it:
	// LogonUI will not remove a selected tile, but now that it is deselected the provider can
	// erase it and re-enumerate so it disappears. This runs LAST - RemoveDisconnectedTile
	// re-enters LogonUI via CredentialsChanged and releases the list's reference to us, so we
	// must not touch any member after it (LogonUI's own reference keeps `this` alive until the
	// call returns).
	if (_fDisconnected && _pProvider)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: SetDeselected while disconnected -> request purge tile=%p",(void*)this);
		_pProvider->RemoveDisconnectedTile(this);
	}

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information to
// display the tile.
HRESULT CEIDCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    if (dwFieldID < ARRAYSIZE(_rgFieldStatePairs) && pcpfs && pcpfis)
    {
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        // While the card is absent, hide the PIN entry, submit button and certificate link so
        // only the "please reconnect" message remains. Keeps LogonUI consistent if it re-queries.
        if (_fDisconnected &&
            (dwFieldID == SFI_PIN || dwFieldID == SFI_SUBMIT_BUTTON || dwFieldID == SFI_CERTIFICATE))
        {
            *pcpfs = CPFS_HIDDEN;
        }
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("GetFieldState", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CEIDCredential::GetStringValue(
    DWORD dwFieldID, 
    PWSTR* ppwsz
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    // Check to make sure dwFieldID is a legitimate index.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz)
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        if (_fDisconnected && dwFieldID == SFI_MESSAGE)
        {
            hr = SHStrDupW(s_szReconnectCard, ppwsz);
        }
        else
        {
            hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
        }
    }
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("GetStringValue", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}

// Get the image to show in the user tile.
HRESULT CEIDCredential::GetBitmapValue(
    DWORD dwFieldID,
    HBITMAP* phbmp
    )
{
    HRESULT hr = E_INVALIDARG;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
	if ((SFI_TILEIMAGE == dwFieldID) && phbmp)
    {
        *phbmp = nullptr;

		// Use LoadImage instead of deprecated LoadBitmap
		// LoadImage with LR_CREATEDIBSECTION creates a DIB section bitmap
		// which is more reliable for credential providers
		HBITMAP hbmp = static_cast<HBITMAP>(LoadImageW(  // NOSONAR (EXPLICIT-TYPE-02) - HBITMAP handle type retained for clarity
			HINST_THISDLL,
			MAKEINTRESOURCEW(IDB_TILE_IMAGE),
			IMAGE_BITMAP,
			0,  // Use actual width from resource
			0,  // Use actual height from resource
			LR_CREATEDIBSECTION | LR_DEFAULTSIZE
		));

		if (hbmp != nullptr)
		{
			hr = S_OK;
			*phbmp = hbmp;
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"GetBitmapValue: Bitmap loaded successfully");
		}
		else
		{
			DWORD dwErr = GetLastError();
			hr = HRESULT_FROM_WIN32(dwErr);
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"GetBitmapValue: LoadImageW failed with error 0x%08x", dwErr);
			EIDLogErrorWithContext("GetBitmapValue", hr, L"LoadImageW failed; g_hinst=0x%p, ID=%d", HINST_THISDLL, IDB_TILE_IMAGE);

			// Fallback: Try LoadBitmap as backup for older systems
			hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
			if (hbmp != nullptr)
			{
				hr = S_OK;
				*phbmp = hbmp;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"GetBitmapValue: Fallback to LoadBitmap succeeded");
			}
			else
			{
				dwErr = GetLastError();
				hr = HRESULT_FROM_WIN32(dwErr);
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"GetBitmapValue: LoadBitmap fallback also failed with error 0x%08x", dwErr);
			}
		}
    }
    else
    {
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"GetBitmapValue: Invalid field ID or null phbmp (fieldId=%lu)", dwFieldID);
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("GetBitmapValue", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CEIDCredential::GetSubmitButtonValue(
    DWORD dwFieldID,
    DWORD* pdwAdjacentTo
    )
{
    HRESULT hr = E_INVALIDARG;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    if (SFI_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to 
        // appear next to.
        *pdwAdjacentTo = SFI_PIN;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("GetSubmitButtonValue", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CEIDCredential::SetStringValue(
    DWORD dwFieldID, 
    PCWSTR pwz
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
       (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft || 
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft)) 
    {
        PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);

  hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("SetStringValue", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}

//-------------
// The following methods are for logonUI to get the values of various UI elements and then communicate
// to the credential about what the user did in that field.  However, these methods are not implemented
// because our tile doesn't contain these types of UI elements
HRESULT CEIDCredential::GetCheckboxValue(
    DWORD dwFieldID, 
    BOOL* pbChecked,
    PWSTR* ppwszLabel
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);

    return E_NOTIMPL;
}

HRESULT CEIDCredential::GetComboBoxValueCount(
    DWORD dwFieldID, 
    DWORD* pcItems, 
    DWORD* pdwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
	return E_NOTIMPL;
}

HRESULT CEIDCredential::GetComboBoxValueAt(
    DWORD dwFieldID, 
    DWORD dwItem,
    PWSTR* ppwszItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
	return E_NOTIMPL;
}

HRESULT CEIDCredential::SetCheckboxValue(
    DWORD dwFieldID, 
    BOOL bChecked
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);

    return E_NOTIMPL;
}

HRESULT CEIDCredential::SetComboBoxSelectedValue(
    DWORD dwFieldID,
    DWORD dwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwSelectedItem);
	return E_NOTIMPL;
}

HRESULT CEIDCredential::CommandLinkClicked(DWORD dwFieldID)
{
	HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
	if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
       (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft)) 
    {
		if (_pCredProvCredentialEvents)
		{
			HWND hWnd;
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"");
			_pCredProvCredentialEvents->OnCreatingWindow(&hWnd);
			_pContainer->ViewCertificate(hWnd);  
		}
		hr = S_OK;
	}
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("CommandLinkClicked", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}
//------ end of methods for controls we don't have in our tile ----//


//
// Initialize the members of a EID_INTERACTIVE_UNLOCK_LOGON with weak references to the
// passed-in strings.  This is useful if you will later use KerbInteractiveUnlockLogonPack
// to serialize the structure.  
//
// The password is stored in encrypted form for CPUS_LOGON and CPUS_UNLOCK_WORKSTATION
// because the system can accept encrypted credentials.  It is not encrypted in CPUS_CREDUI
// because we cannot know whether our caller can accept encrypted credentials.
//
HRESULT EIDUnlockLogonInit(
                                       PWSTR pwzDomain,
                                       PWSTR pwzUsername,
                                       PWSTR pwzPin,
                                       CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                       EID_INTERACTIVE_UNLOCK_LOGON* pkiul
                                       )
{
    UNREFERENCED_PARAMETER(cpus);
	EID_INTERACTIVE_UNLOCK_LOGON kiul;
    ZeroMemory(&kiul, sizeof(kiul));

    EID_INTERACTIVE_LOGON* pkil = &kiul.Logon;

    // Note: this method uses custom logic to pack a EID_INTERACTIVE_UNLOCK_LOGON with a
    // serialized credential.  We could replace the calls to UnicodeStringInitWithString
    // and KerbInteractiveUnlockLogonPack with a single cal to CredPackAuthenticationBuffer,
    // but that API has a drawback: it returns a EID_INTERACTIVE_UNLOCK_LOGON whose
    // MessageType is always KerbInteractiveLogon.  
    //
    // If we only handled CPUS_LOGON, this drawback would not be a problem.  For 
    // CPUS_UNLOCK_WORKSTATION, we could cast the output buffer of CredPackAuthenticationBuffer
    // to EID_INTERACTIVE_UNLOCK_LOGON and modify the MessageType to KerbWorkstationUnlockLogon,
    // but such a cast would be unsupported -- the output format of CredPackAuthenticationBuffer
    // is not officially documented.

    // Initialize the UNICODE_STRINGS to share our username and password strings.
    HRESULT hr = UnicodeStringInitWithString(pwzDomain, &pkil->LogonDomainName);  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    if (SUCCEEDED(hr))
    {
        hr = UnicodeStringInitWithString(pwzUsername, &pkil->UserName);

        if (SUCCEEDED(hr))
        {
            hr = UnicodeStringInitWithString(pwzPin, &pkil->Pin);
            
            if (SUCCEEDED(hr))
            {
                // Set a MessageType based on the usage scenario.
                pkil->MessageType = EID_INTERACTIVE_LOGON_SUBMIT_TYPE_VANILLA;
                pkil->CspDataLength = 0;
                pkil->CspData = nullptr;
                pkil->Flags = 0;

                // EID_INTERACTIVE_UNLOCK_LOGON is just a series of structures.  A
                // flat copy will properly initialize the output parameter.
                CopyMemory(pkiul, &kiul, sizeof(*pkiul));
            }
        }
    }

    return hr;
}


// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
// http://msdn.microsoft.com/en-us/library/bb776026(VS.85).aspx
HRESULT CEIDCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    WCHAR wsz[MAX_COMPUTERNAME_LENGTH+1];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    DWORD cch = ARRAYSIZE(wsz);

    // Guard clause: GetComputerNameW failed
    if (!GetComputerNameW(wsz, &cch))  // NOSONAR - SCOPE-01: variable declared before the block by design
    {
        DWORD dwErr = GetLastError();
        hr = HRESULT_FROM_WIN32(dwErr);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetComputerNameW failed 0x%08x",dwErr);
		EIDLogErrorWithContext("GetSerialization", hr, nullptr);
        return hr;
    }

    PWSTR pwzProtectedPin = nullptr;
    hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PIN], _cpus, _dwFlags, &pwzProtectedPin);

    // Guard clause: password protection failed
    if (FAILED(hr))
    {
        EIDLogErrorWithContext("GetSerialization::ProtectIfNecessaryAndCopyPassword", hr, nullptr);
        EIDLogErrorWithContext("GetSerialization", hr, nullptr);
        return hr;
    }

    EID_INTERACTIVE_UNLOCK_LOGON kiul;

    // Initialize kiul with weak references to our credential.
    // EIDUnlockLogonInit stores only a WEAK pointer to pwzProtectedPin inside kiul, and
    // EIDUnlockLogonPack (below) copies the PIN bytes FROM that buffer.  The CredProtect-wrapped
    // PIN copy must therefore stay alive until AFTER EIDUnlockLogonPack has consumed it; only then
    // is it zeroized and freed.  Every early-exit path between here and that point frees it too, so
    // it is neither leaked nor freed while kiul still references it.
    hr = EIDUnlockLogonInit(wsz, _rgFieldStrings[SFI_USERNAME], pwzProtectedPin, _cpus, &kiul);

    // Guard clause: logon init failed
    if (FAILED(hr))
    {
        // Zeroize the CredProtect-wrapped PIN copy before releasing it so it does not linger.
        if (pwzProtectedPin)
        {
            SecureZeroMemory(pwzProtectedPin, (wcslen(pwzProtectedPin) + 1) * sizeof(WCHAR));
        }
        CoTaskMemFree(pwzProtectedPin);
        EIDLogErrorWithContext("GetSerialization::EIDUnlockLogonInit", hr, nullptr);
        EIDLogErrorWithContext("GetSerialization", hr, nullptr);
        return hr;
    }

    // We use EID_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
    // EID_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
    // as necessary.
    PEID_SMARTCARD_CSP_INFO pCspInfo = _pContainer->GetCSPInfo();

    // Guard clause: no CSP info
    if (!pCspInfo)
    {
        // Zeroize the CredProtect-wrapped PIN copy before releasing it so it does not linger.
        if (pwzProtectedPin)
        {
            SecureZeroMemory(pwzProtectedPin, (wcslen(pwzProtectedPin) + 1) * sizeof(WCHAR));
        }
        CoTaskMemFree(pwzProtectedPin);
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCspInfo NULL");
        EIDLogErrorWithContext("GetSerialization", E_FAIL, nullptr);
        return E_FAIL;
    }

    hr = EIDUnlockLogonPack(kiul, pCspInfo, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
    _pContainer->FreeCSPInfo(pCspInfo);

    // EIDUnlockLogonPack has now consumed the weakly-referenced PIN.  Zeroize the CredProtect-wrapped
    // PIN copy before releasing it so it does not linger; this covers the pack-failed guard below and
    // every path to the end of the function.
    if (pwzProtectedPin)
    {
        SecureZeroMemory(pwzProtectedPin, (wcslen(pwzProtectedPin) + 1) * sizeof(WCHAR));
    }
    CoTaskMemFree(pwzProtectedPin);
    pwzProtectedPin = nullptr;

    // Guard clause: logon pack failed
    if (FAILED(hr))
    {
        EIDLogErrorWithContext("GetSerialization::EIDUnlockLogonPack", hr, nullptr);
        EIDLogErrorWithContext("GetSerialization", hr, nullptr);
        return hr;
    }

    ULONG ulAuthPackage;
    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

    // Guard clause: auth package retrieval failed
    if (FAILED(hr))
    {
        EIDLogErrorWithContext("GetSerialization::RetrieveNegotiateAuthPackage", hr, nullptr);
        EIDLogErrorWithContext("GetSerialization", hr, nullptr);
        return hr;
    }

    pcpcs->ulAuthenticationPackage = ulAuthPackage;
    pcpcs->clsidCredentialProvider = CLSID_CEIDProvider;

    // At this point the credential has created the serialized credential used for logon
    // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
    // that we have all the information we need and it should attempt to submit the
    // serialized credential.
    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

    EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OK");
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
    NTSTATUS ntsSubstatus;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =  // NOSONAR - LSASS-01: C-style lookup table retained for Win32 status mapping
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/Pin and in the case of the account
// being disabled.

HRESULT CEIDCredential::ReportResult(
    NTSTATUS ntsStatus, 
    NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText, 
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    if (ppwszOptionalStatusText) *ppwszOptionalStatusText = s_wszUnknownError;
    if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_NONE;
	
	if (ntsStatus == STATUS_SUCCESS)
	{
		_pContainer->TriggerRemovePolicy();
	}

    DWORD dwStatusInfo = (DWORD)-1;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
			if (pcpsiOptionalStatusIcon)  // NOSONAR - CONTROL-01: nested if kept for cleanup clarity
				*pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
    }

	if (ppwszOptionalStatusText)
	{
	    // get message from system table
		PWSTR Error = nullptr;
		if (ntsStatus == STATUS_SMARTCARD_WRONG_PIN && ntsSubstatus != 0xFFFFFFFF)
		{
			HINSTANCE Handle = EIDLoadSystemLibrary(TEXT("SmartcardCredentialProvider.dll"));
			WCHAR Message[256] = L"%d retries";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
			WCHAR MessageFormatted[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
			if (Handle)
			{
				LoadStringW(Handle, 4001, Message, ARRAYSIZE(Message));
				FreeLibrary(Handle);
			}
			swprintf_s(MessageFormatted,ARRAYSIZE(MessageFormatted), Message, ntsSubstatus);
			SHStrDupW(MessageFormatted, ppwszOptionalStatusText);
		}
		else
		{
			// FormatMessage's nSize is a WCHAR count, not a byte count, so the allocation
			// must be dwLen * sizeof(WCHAR) or a long system message overflows it by 2x.
			DWORD dwLen = 2048;
			Error = (PWSTR) CoTaskMemAlloc(dwLen * sizeof(WCHAR));
			if (Error)
			{
				FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,nullptr,LsaNtStatusToWinError(ntsStatus),0,Error,dwLen,nullptr);
			}
			*ppwszOptionalStatusText = Error;
		}
	}
    // If we failed the logon, try to erase the Pin field.
    if (!SUCCEEDED(HRESULT_FROM_NT(ntsStatus)))
    {
        // Zeroize the internal PIN buffer, not just the visible UI field, so the typed
        // PIN does not linger in memory after a failed logon.
        SecureClearPin();
        if (_pCredProvCredentialEvents)  // NOSONAR - CONTROL-01: nested if kept for cleanup clarity
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PIN, L"");
        }
    }

    // Since NULL is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    
	return S_OK;
}

