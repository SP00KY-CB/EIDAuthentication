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

#include "ErrorHandling.h"
#include <ntstatus.h>

namespace EID {

//
// hr_to_ntstatus - Convert HRESULT to NTSTATUS for LSA authentication functions
//
// LSA authentication functions use NTSTATUS error codes, while internal
// Result<T> uses HRESULT. This function provides the mapping between them.
//
[[nodiscard]] NTSTATUS hr_to_ntstatus(HRESULT hr) noexcept {
    // Direct mappings for common HRESULT codes
    // Note: HRESULT_FROM_WIN32() macros produce equivalent values for some HRESULTs
    // (e.g., HRESULT_FROM_WIN32(ERROR_SUCCESS) == S_OK)
    switch (hr) {
        case S_OK:  // Same as HRESULT_FROM_WIN32(ERROR_SUCCESS)
            return STATUS_SUCCESS;
        case E_NOTIMPL:
            return STATUS_NOT_IMPLEMENTED;
        case E_NOINTERFACE:
            return STATUS_NOT_SUPPORTED;
        case E_POINTER:
            return STATUS_INVALID_PARAMETER;
        case E_ABORT:
            return STATUS_REQUEST_ABORTED;
        case E_FAIL:
        case E_UNEXPECTED:
            return STATUS_UNSUCCESSFUL;
        case E_ACCESSDENIED:  // Same as HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)
            return STATUS_ACCESS_DENIED;
        case E_OUTOFMEMORY:
            return STATUS_NO_MEMORY;
        case E_INVALIDARG:  // Same as HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER)
            return STATUS_INVALID_PARAMETER;
        // Win32 error codes wrapped in HRESULT (unique mappings)
        case HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY):
            return STATUS_NO_MEMORY;
        default:
            // For unmapped codes, convert FACILITY_WIN32 HRESULTs to NTSTATUS
            if (HRESULT_FACILITY(hr) == FACILITY_WIN32) {
                return static_cast<NTSTATUS>(HRESULT_CODE(hr));
            }
            // Generic failure for unknown HRESULTs
            return STATUS_UNSUCCESSFUL;
    }
}

} // namespace EID
