/*
    EID Authentication - fuzz harness oracle reporting
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
// How a fuzz target reports that an invariant was violated.
//
// DO NOT use __debugbreak() for this. It raises STATUS_BREAKPOINT (0xC0000003),
// which on Windows terminates the process before libFuzzer's handler runs: no
// "deadly signal" report is printed and - critically - NO crash-<sha1>
// reproducer file is written. A finding in CI would then be unreproducible,
// which is worse than useless. Verified empirically during development.
//
// abort() raises SIGABRT, which libFuzzer does handle (-handle_abrt=1 is on by
// default), so it prints a report and saves the input that caused it.
//=============================================================================

#pragma once

#include <stdio.h>
#include <stdlib.h>

// Report a violated harness invariant and terminate so libFuzzer records the
// input. pszInvariant should state the property that failed, not the symptom.
[[noreturn]] inline void EIDOracleViolation(const char* pszInvariant)
{
	fflush(stdout);
	fprintf(stderr,
		"\n"
		"=================================================================\n"
		"EID FUZZ ORACLE VIOLATION\n"
		"  %s\n"
		"A validator accepted input whose own arithmetic is unsafe.\n"
		"The reproducer for this input has been written to fuzz\\crashes\\.\n"
		"Replay it with:  x64\\Fuzz\\eidfuzz_<target>.exe <crash-file>\n"
		"=================================================================\n",
		pszInvariant);
	fflush(stderr);
	abort();
}

#define EID_ORACLE_REQUIRE(cond, invariant) \
	do { if (!(cond)) { EIDOracleViolation(invariant); } } while (0)
