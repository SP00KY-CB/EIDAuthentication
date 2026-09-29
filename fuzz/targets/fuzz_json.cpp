/*
    EID Authentication - fuzz target: hand-rolled JSON parser
    Copyright (C) 2026 Contributors

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

//=============================================================================
// Target: JsonParser in EIDMigrate/JsonHelper.cpp - the only hand-rolled
// text parser in the codebase, reached from the .eidm credential import path.
// It performs manual index arithmetic (parseString's \u escape handling,
// parseNumber, and the mutually-recursive value/array/object parsers).
//
// WHAT THIS TARGET ASSERTS: memory safety only. Parse errors are thrown as
// std::runtime_error by design, so they are caught here and treated as a
// normal outcome.
//
// WHAT IT DELIBERATELY DOES NOT ASSERT: that a throw is *handled* by the
// callers. It is not - EIDMigrate has only four catch sites and none of them
// covers JsonToExportData, so a malformed .eidm terminates the process. That
// is a real availability defect, but it is an admin-supplied-file DoS rather
// than memory corruption, and fixing it means adding error handling in
// EIDMigrate rather than changing the parser. Tracked separately; do not
// "fix" it by widening this catch.
//
// The parser is also compiled into EIDCardLibrary (see EIDCardLibrary.vcxproj,
// which pulls in ..\EIDMigrate\JsonHelper.cpp), so this code runs inside the
// same binary as the LSA package even though the import tool is separate.
//=============================================================================

#include <stdint.h>
#include <string>
#include <stdexcept>

#include "../../EIDMigrate/JsonHelper.h"
#include "oracle.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	// Cap input so libFuzzer spends its budget on structure rather than on
	// one enormous document.
	if (size > (1u << 16))
	{
		return 0;
	}

	// std::string is constructed from an explicit (ptr, len) pair: the input is
	// not NUL-terminated, and the parser's own bounds logic is exactly what is
	// under test.
	const std::string json(reinterpret_cast<const char*>(data), size);

	try
	{
		JsonParser parser(json);
		auto value = parser.parse();
		if (value)
		{
			// Force the parsed tree to be walked, so lazily-built nodes and
			// any offset arithmetic in stringify() are exercised too.
			const std::string round = value->stringify();
			// Unreachable; exists so the optimiser cannot discard stringify().
			EID_ORACLE_REQUIRE(round.size() != SIZE_MAX, "stringify size sentinel");
		}
	}
	catch (const std::exception&)
	{
		// Expected: malformed input is reported by throwing. See the note above
		// about why this is caught here and not treated as a finding.
	}
	catch (...)
	{
		// A non-std exception type would be a surprise worth surfacing.
		EIDOracleViolation("JsonParser threw a type not derived from std::exception");
	}

	return 0;
}
