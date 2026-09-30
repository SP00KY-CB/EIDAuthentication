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

//
//

#include "CMessageCredential.h"
#include "EIDCredentialProvider.h"
#include <Unknwn.h>
#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"

#include <CodeAnalysis/Warnings.h>
#pragma warning(push)
#pragma warning(disable : 4995)
#include <Shlwapi.h>
#pragma warning(pop)

// CMessageCredential ////////////////////////////////////////////////////////

CMessageCredential::CMessageCredential():
    _cRef(1),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
    _pCredProvCredentialEvents(nullptr)  // NOSONAR - INIT-01: constructor initializer list retained for clarity
{
    DllAddRef();
    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
	_dwSmartCardCount = 0;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_dwStatus = CMessageCredentialStatus::Idle;
	_dwOldStatus = CMessageCredentialStatus::Idle;
}

CMessageCredential::~CMessageCredential()
{
	for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }

    DllRelease();
}

//
// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
//
HRESULT CMessageCredential::Initialize(
                        const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                        const FIELD_STATE_PAIR* rgfsp,
                        PCWSTR szMessage)
{
    HRESULT hr = S_OK;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of the message field.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(szMessage, &(_rgFieldStrings[SMFI_MESSAGE]));
    }
	if (SUCCEEDED(hr))
    {
        WCHAR szDisableForcePolicy[256] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		LoadStringW(g_hinst,IDS_DISABLEFORCEPOLICY,szDisableForcePolicy,ARRAYSIZE(szDisableForcePolicy));
		SHStrDupW(szDisableForcePolicy, &(_rgFieldStrings[SMFI_CANCELFORCEPOLICY]));
    }

    return S_OK;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of
// anything, such as for getting and setting values.
HRESULT CMessageCredential::Advise(
    ICredentialProviderCredentialEvents* pcpce
    )
{
	if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CMessageCredential::UnAdvise()
{
	if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed). If you simply want
// fields to show/hide based on the selected state, there's no need to do anything
// here - you can set that up in the field definitions.  But if you want to do something
// more complicated, like change the contents of a field when the tile is selected, you
// would do it here.
HRESULT CMessageCredential::SetSelected(BOOL* pbAutoLogon)
{
	UNREFERENCED_PARAMETER(pbAutoLogon);
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. Since this credential is simply read-only text, we do nothing.
HRESULT CMessageCredential::SetDeselected()
{
	return S_OK;
}

// Get info for a particular field of a tile. Called by logonUI to get information to
// display the tile.
HRESULT CMessageCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    // Make sure the field and other parameters are valid.
    if (dwFieldID < ARRAYSIZE(_rgFieldStatePairs) && pcpfs && pcpfis)
    {
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
		*pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
		// SECURITY (M4): the "disable force policy" command link is intentionally never displayed.
		// It opened a secure-desktop dialog that could launch the keymgr password-reset wizard and
		// downgrade the smart-card-required policy from the lock screen.

        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Called to request the string value of the indicated field.
HRESULT CMessageCredential::GetStringValue(
    DWORD dwFieldID,
    PWSTR* ppwsz
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz )
	{
		if (dwFieldID == SMFI_MESSAGE)
		{
			// Make a copy of the string and return that. The caller
			// is responsible for freeing it.
			UINT MessageId;
			if (_dwStatus == CMessageCredentialStatus::Reading)
			{
				MessageId = 38;
			}
			else if (_dwSmartCardCount)
			{
				MessageId = 70;
			}
			else
			{
				MessageId = 1;
			}
			HINSTANCE Handle = EIDLoadSystemLibrary(TEXT("SmartcardCredentialProvider.dll"));
			if (Handle)
			{
				DWORD dwMessageLen = 256;
				// C++17 init-statement: Message is only used within this if block
				if (PWSTR Message = static_cast<PWSTR>(CoTaskMemAlloc(dwMessageLen*sizeof(WCHAR))))  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
				{
					LoadString(Handle, MessageId, Message, dwMessageLen);
					*ppwsz = Message;
					hr = S_OK;
				}
				else
				{
					hr = HRESULT_FROM_WIN32(GetLastError());
				}
				FreeLibrary(Handle);
			}
			else
			{
				hr = HRESULT_FROM_WIN32(GetLastError());
			}
		}
		else
		{
			hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
		}
	}
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called to request the image value of the indicated field.
HRESULT CMessageCredential::GetBitmapValue(
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
		HBITMAP hbmp = static_cast<HBITMAP>(LoadImageW(  // NOSONAR (EXPLICIT-TYPE-02) - Explicit type preferred for clarity
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
		}
		else
		{
			// Fallback: Try LoadBitmap as backup for older systems
			DWORD dwErr = GetLastError();
			hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
			if (hbmp != nullptr)
			{
				hr = S_OK;
				*phbmp = hbmp;
			}
			else
			{
				hr = HRESULT_FROM_WIN32(dwErr);
			}
		}
	}
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when a command link is clicked.
HRESULT CMessageCredential::CommandLinkClicked(DWORD dwFieldID)
{
    UNREFERENCED_PARAMETER(dwFieldID);
	// SECURITY (M4): the lock-screen "disable force policy" wizard has been removed; this
	// credential no longer launches any secure-desktop dialog, so no command link is acted upon.
    return E_INVALIDARG;
}

// Since this credential isn't intended to provide a way for the user to submit their
// information, we do without a Submit button.
HRESULT CMessageCredential::GetSubmitButtonValue(
    DWORD dwFieldID,
    DWORD* pdwAdjacentTo
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pdwAdjacentTo);
    return E_NOTIMPL;
}

// Our credential doesn't have any settable strings.
HRESULT CMessageCredential::SetStringValue(
    DWORD dwFieldID,
    PCWSTR pwz
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pwz);
    return E_NOTIMPL;
}

// Our credential doesn't have any checkable boxes.
HRESULT CMessageCredential::GetCheckboxValue(
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

// Our credential doesn't have a checkbox.
HRESULT CMessageCredential::SetCheckboxValue(
    DWORD dwFieldID,
    BOOL bChecked
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);
    return E_NOTIMPL;
}

// Our credential doesn't have a combobox.
HRESULT CMessageCredential::GetComboBoxValueCount(
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

// Our credential doesn't have a combobox.
HRESULT CMessageCredential::GetComboBoxValueAt(
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

// Our credential doesn't have a combobox.
HRESULT CMessageCredential::SetComboBoxSelectedValue(
    DWORD dwFieldId,
    DWORD dwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(dwSelectedItem);
    return E_NOTIMPL;
}

// We're not providing a way to log on from this credential, so we don't need serialization.
HRESULT CMessageCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
    UNREFERENCED_PARAMETER(pcpgsr);
    UNREFERENCED_PARAMETER(pcpcs);
    return E_NOTIMPL;
}

// We're not providing a way to log on from this credential, so it can't have a result.
HRESULT CMessageCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    UNREFERENCED_PARAMETER(ntsStatus);
    UNREFERENCED_PARAMETER(ntsStatus);
    UNREFERENCED_PARAMETER(ntsSubstatus);
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
    return E_NOTIMPL;
}
