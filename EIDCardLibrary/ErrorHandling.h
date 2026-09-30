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

// Include Windows headers for HRESULT, DWORD, BOOL, etc.
#include <Windows.h>

#include <expected>

namespace EID {

//
// Result<T> - Type-safe error handling using C++23 std::expected
//
// Replaces the BOOL + SetLastError()/GetLastError() pattern for internal functions.
// Provides type safety, eliminates forgotten error checks via [[nodiscard]],
// and enables monadic error propagation (.and_then(), .transform()).
//
// Key constraints:
// - LSASS context: All functions must be noexcept (no exceptions)
// - HRESULT used as error type for Windows compatibility
// - API boundaries preserve HRESULT/BOOL/NTSTATUS signatures
//

// Primary result type using HRESULT as error type
template<typename T>
using Result = std::expected<T, HRESULT>;

// Void result for operations with no return value
using ResultVoid = std::expected<void, HRESULT>;

// Create an unexpected result from HRESULT error code
[[nodiscard]] inline auto make_unexpected(HRESULT hr) noexcept {
    return std::unexpected(hr);
}

// Convert Win32 error code to HRESULT
[[nodiscard]] inline HRESULT win32_to_hr(DWORD win32Error) noexcept {
    return HRESULT_FROM_WIN32(win32Error);
}

// Convert Result<T> to BOOL for API boundary
// Sets GetLastError() on error, returns TRUE on success
template<typename T>
[[nodiscard]] inline BOOL to_bool(Result<T>&& result) noexcept {  // NOSONAR - MOVE-01: rvalue param read-only at API boundary, nothing to move
    if (result) {
        return TRUE;
    }
    SetLastError(static_cast<DWORD>(result.error()));
    return FALSE;
}

// Specialization for ResultVoid (no value to extract)
[[nodiscard]] inline BOOL to_bool(ResultVoid&& result) noexcept {  // NOSONAR - MOVE-01: rvalue param read-only at API boundary, nothing to move
    if (result.has_value()) {
        return TRUE;
    }
    SetLastError(static_cast<DWORD>(result.error()));
    return FALSE;
}

// Helper: Check if result indicates success
template<typename T>
[[nodiscard]] inline bool succeeded(const Result<T>& result) noexcept {
    return result.has_value();
}

// Helper: Check if result indicates success (ResultVoid overload)
[[nodiscard]] inline bool succeeded(const ResultVoid& result) noexcept {
    return result.has_value();
}

// HRESULT to NTSTATUS conversion for LSA authentication functions
// Implemented in ErrorHandling.cpp
[[nodiscard]] NTSTATUS hr_to_ntstatus(HRESULT hr) noexcept;

} // namespace EID
