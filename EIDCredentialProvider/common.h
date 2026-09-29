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
// This file contains some global variables that describe what our
// sample tile looks like.  For example, it defines what fields a tile has 
// and which fields show in which states of LogonUI.

#pragma once
#include <credentialprovider.h>
#include <NTSecAPI.h>
#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>
#include <utility>

constexpr ULONG MAX_ULONG = static_cast<ULONG>(-1);

// The indexes of each of the fields in our credential provider's tiles.
enum SAMPLE_FIELD_ID  // NOSONAR - ENUM-01: Unscoped enum required for Windows SDK compatibility
{
    SFI_TILEIMAGE       = 0,
    SFI_USERNAME        = 1,
	SFI_MESSAGE         = 2,
    SFI_PIN		        = 3,
    SFI_CERTIFICATE		= 4,
	SFI_SUBMIT_BUTTON   = 5, 
    SFI_NUM_FIELDS      = 6,  // Note: if new fields are added, keep NUM_FIELDS last.  This is used as a count of the number of fields
};

// Same as SAMPLE_FIELD_ID above, but for the CMessageCredential.
enum SAMPLE_MESSAGE_FIELD_ID  // NOSONAR - ENUM-01: Unscoped enum required for Windows SDK compatibility
{
    SMFI_TILEIMAGE		= 0,
	SMFI_MESSAGE        = 1, 
	SMFI_CANCELFORCEPOLICY	= 2,
    SMFI_NUM_FIELDS     = 3,  // Note: if new fields are added, keep NUM_FIELDS last.  This is used as a count of the number of fields
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// These two arrays are separate because a credential provider might
// want to set up a credential with various combinations of field state pairs
// and field descriptors.

// Static buffer for empty string literals (C++23 /Zc:strictStrings compatibility)
// pszLabel in CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR is LPWSTR (non-const)
static wchar_t s_wszEmptyLabel[] = L"";  // NOSONAR - GLOBAL-01: Non-const for Windows API LPWSTR compatibility

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =   // NOSONAR - LSASS-01: C-style buffer required by Win32 API
{
    { CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SFI_TILEIMAGE
    { CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SFI_USERNAME
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SFI_MESSAGE
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },       // SFI_PIN
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },       // SFI_SUBMIT_BUTTON   
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },       // SFI_CERTIFICATE
};

// Same as s_rgFieldStatePairs above, but for the CMessageCredential.
static const FIELD_STATE_PAIR s_rgMessageFieldStatePairs[] =   // NOSONAR - LSASS-01: C-style buffer required by Win32 API
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SMFI_TILEIMAGE
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SMFI_MESSAGE
	{ CPFS_HIDDEN, CPFIS_NONE },          // SMFI_CANCELFORCEPOLICY
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
{
    { SFI_TILEIMAGE, CPFT_TILE_IMAGE, s_wszEmptyLabel},
    { SFI_USERNAME, CPFT_LARGE_TEXT, s_wszEmptyLabel},
	{ SFI_MESSAGE, CPFT_SMALL_TEXT, s_wszEmptyLabel},
    { SFI_PIN, CPFT_PASSWORD_TEXT, s_wszEmptyLabel},
	{ SFI_CERTIFICATE, CPFT_COMMAND_LINK, s_wszEmptyLabel},
    { SFI_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, s_wszEmptyLabel},

};

// Same as s_rgCredProvFieldDescriptors above, but for the CMessageCredential.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgMessageCredProvFieldDescriptors[] =  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
{
    { SMFI_TILEIMAGE, CPFT_TILE_IMAGE, s_wszEmptyLabel},
	{ SMFI_MESSAGE, CPFT_LARGE_TEXT, s_wszEmptyLabel},
	{ SMFI_CANCELFORCEPOLICY, CPFT_COMMAND_LINK, s_wszEmptyLabel },
};