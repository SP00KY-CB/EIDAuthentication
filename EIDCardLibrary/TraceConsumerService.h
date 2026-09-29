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

/**
 *  EID Trace Consumer Service Header
 */

#pragma once

#include <Windows.h>

// Service name
#define EID_TRACE_CONSUMER_SERVICE_NAME    L"EIDTraceConsumer"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define EID_TRACE_CONSUMER_DISPLAY_NAME   L"EID Trace Consumer"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define EID_TRACE_CONSUMER_DESCRIPTION    L"Consumes EID authentication events and writes to CSV log files"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use

// Service control functions
BOOL InstallEIDTraceConsumer();
BOOL UninstallEIDTraceConsumer();
BOOL StartEIDTraceConsumer();
BOOL StopEIDTraceConsumer();
BOOL IsEIDTraceConsumerInstalled();
BOOL IsEIDTraceConsumerRunning();
