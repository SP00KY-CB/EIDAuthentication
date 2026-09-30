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


#include "CEIDFilter.h"
#include "../EIDCardLibrary/GPO.h"

CEIDFilter::CEIDFilter():
    _cRef(1)  // NOSONAR - INIT-01: reference count initialized in constructor init list
{
}

HRESULT CEIDFilter::UpdateRemoteCredential(      
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsIn,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut
)
{
	UNREFERENCED_PARAMETER(pcpcsIn);
	UNREFERENCED_PARAMETER(pcpcsOut);
	return S_OK;
}

HRESULT CEIDFilter::Filter(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags,
    GUID *rgclsidProviders,
    BOOL *rgbAllow,
    DWORD cProviders
)
{
	UNREFERENCED_PARAMETER(dwFlags);

	// Built-in Microsoft password credential provider (PasswordCredentialProvider):
	// {60b78e88-ead8-445c-9cfd-0b87f74ea6cd}.
	static const GUID CLSID_PasswordCredentialProvider =
		{ 0x60b78e88, 0xead8, 0x445c, { 0x9c, 0xfd, 0x0b, 0x87, 0xf7, 0x4e, 0xa6, 0xcd } };

	// Conservative enforcement: only during interactive logon/unlock, and only when smart card
	// logon is mandated by policy, hide the built-in password tile. Every other provider
	// (including this smart-card provider) is left allowed. LSA still enforces at auth time,
	// so this only tidies the UI and cannot lock the user out.
	if ((cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION)
		&& rgclsidProviders != nullptr && rgbAllow != nullptr
		&& GetPolicyValue(GPOPolicy::scforceoption))
	{
		for (DWORD i = 0; i < cProviders; i++)
		{
			if (IsEqualGUID(rgclsidProviders[i], CLSID_PasswordCredentialProvider))
			{
				rgbAllow[i] = FALSE;
			}
		}
	}

	// Default: allow everything.
	return S_OK;
}