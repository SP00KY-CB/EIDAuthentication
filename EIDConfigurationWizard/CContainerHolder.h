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

#include <Windows.h>
#include <tchar.h>
#include "global.h"
#include <utility>

enum class CheckType {
	CHECK_SIGNATUREONLY = 0,
	CHECK_TRUST = 1,
	CHECK_CRYPTO = 2,
	CHECK_MAX = 3
};

// Image result constants for GetImage function
constexpr int CHECK_SUCCESS = 1;
constexpr int CHECK_FAILED = 2;
constexpr int CHECK_WARNING = 3;

class CContainerHolderTest
{
public:
	explicit CContainerHolderTest(CContainer* pContainer);
	virtual ~CContainerHolderTest();
	CContainerHolderTest(const CContainerHolderTest&) = delete;
	CContainerHolderTest& operator=(const CContainerHolderTest&) = delete;
	void Release();
	CContainer* GetContainer() const;
	int GetIconIndex() const;
	BOOL HasSignatureUsageOnly() const;
	BOOL IsTrusted();  // Not const - has side effect (sets _dwTrustError)
	BOOL SupportEncryption() const;
	int GetCheckCount() const;
	int GetImage(DWORD dwCheckNum) const;
	PTSTR GetDescription(DWORD dwCheckNum) const;
	PTSTR GetSolveDescription(DWORD dwCheckNum) const;
	BOOL Solve(DWORD dwCheckNum);
	HRESULT SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags);
	// Required by CContainerHolderFactory's revive-on-reconnect path. The wizard rebuilds its
	// view on every card change and never enables that path, so these are inert here.
	BOOL IsSelected() const { return FALSE; }
	BOOL IsDisconnected() const { return FALSE; }
	void SetDisconnected(__in BOOL fDisconnected) const { UNREFERENCED_PARAMETER(fDisconnected); }
private:
	CContainer* _pContainer;
	BOOL _IsTrusted;
	BOOL _SupportEncryption;
	DWORD _dwTrustError;
};
