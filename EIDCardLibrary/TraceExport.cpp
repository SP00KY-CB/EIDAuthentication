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

#include <Windows.h>
#include <tchar.h>
#include <wmistr.h>
#include <evntrace.h>

#include "TraceExport.h"

static HANDLE g_hTraceOutputFile = nullptr;  // NOSONAR - RUNTIME-01: File handle, opened at runtime

static VOID WINAPI ProcessEvents(PEVENT_TRACE pEvent)
{
  {
	  if (pEvent->MofLength && pEvent->Header.Class.Level > 0)
	  {
		DWORD dwWritten;
		FILETIME ft;
		SYSTEMTIME st;
		ft.dwHighDateTime = pEvent->Header.TimeStamp.HighPart;
		ft.dwLowDateTime = pEvent->Header.TimeStamp.LowPart;
		FileTimeToSystemTime(&ft,&st);
		TCHAR szLocalDate[255], szLocalTime[255];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		_stprintf_s(szLocalDate, ARRAYSIZE(szLocalDate),TEXT("%04d-%02d-%02d"),st.wYear,st.wMonth,st.wDay);
		_stprintf_s(szLocalTime, ARRAYSIZE(szLocalTime),TEXT("%02d:%02d:%02d"),st.wHour,st.wMinute,st.wSecond);
		WriteFile ( g_hTraceOutputFile, szLocalDate, (DWORD)_tcslen(szLocalDate) * (DWORD)sizeof(TCHAR), &dwWritten, nullptr);
		WriteFile ( g_hTraceOutputFile, TEXT(";"), 1 * (DWORD)sizeof(TCHAR), &dwWritten, nullptr);
		WriteFile ( g_hTraceOutputFile, szLocalTime, (DWORD)_tcslen(szLocalTime) * (DWORD)sizeof(TCHAR), &dwWritten, nullptr);
		WriteFile ( g_hTraceOutputFile, TEXT(";"), 1 * (DWORD)sizeof(TCHAR), &dwWritten, nullptr);
		WriteFile ( g_hTraceOutputFile, pEvent->MofData, pEvent->MofLength, &dwWritten, nullptr);
		WriteFile ( g_hTraceOutputFile, TEXT("\r\n"), 2 * (DWORD)sizeof(TCHAR), &dwWritten, nullptr);
	  }
  }
}

void ExportOneTraceFile(HANDLE hOutputFile, PTSTR szTraceFile)
{
	g_hTraceOutputFile = hOutputFile;
	ULONG rc;
	TRACEHANDLE handle = NULL;
	EVENT_TRACE_LOGFILE trace;
	memset(&trace,0, sizeof(EVENT_TRACE_LOGFILE));
	// File-mode consumer: set only LogFileName and leave LoggerName NULL. Setting both is
	// contradictory for OpenTrace (a session is identified by one or the other, not both).
	trace.LogFileName = szTraceFile;
	trace.EventCallback = reinterpret_cast<PEVENT_CALLBACK>(ProcessEvents);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
	handle = OpenTrace(&trace);
	if ((TRACEHANDLE)INVALID_HANDLE_VALUE == handle)
	{
		// NOSONAR - EMPTY-01: Intentionally empty - trace open failure is non-fatal, caller continues without trace data
	}
	else
	{
		FILETIME now;
		FILETIME start;
		SYSTEMTIME sysNow;
		SYSTEMTIME sysstart;
		GetLocalTime(&sysNow);
		SystemTimeToFileTime(&sysNow, &now);
		memcpy(&sysstart, &sysNow, sizeof(SYSTEMTIME));
		sysstart.wYear -= 1;
		SystemTimeToFileTime(&sysstart, &start);
		DWORD dwWritten;
		TCHAR szBuffer[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		_tcscpy_s(szBuffer,ARRAYSIZE(szBuffer),TEXT("================================================\r\n"));
		WriteFile ( hOutputFile, szBuffer, (DWORD)_tcslen(szBuffer) * (DWORD)sizeof(TCHAR), &dwWritten, nullptr);
		WriteFile ( hOutputFile, szTraceFile, (DWORD)_tcslen(szTraceFile) * (DWORD)sizeof(TCHAR), &dwWritten, nullptr);
		_tcscpy_s(szBuffer,ARRAYSIZE(szBuffer),TEXT("\r\n"));
		WriteFile ( hOutputFile, szBuffer, (DWORD)_tcslen(szBuffer) * (DWORD)sizeof(TCHAR), &dwWritten, nullptr);
		_tcscpy_s(szBuffer,ARRAYSIZE(szBuffer),TEXT("================================================\r\n"));
		WriteFile ( hOutputFile, szBuffer, (DWORD)_tcslen(szBuffer) * (DWORD)sizeof(TCHAR), &dwWritten, nullptr);
		rc = ProcessTrace(&handle, 1, nullptr, nullptr);
		if (rc != ERROR_SUCCESS && rc != ERROR_CANCELLED)
		{
			if (rc ==  0x00001069)
			{
				// NOSONAR - CONTROL-01: Known error code, no action needed
			}
			else
			{
				// NOSONAR - CONTROL-01: Error handled by caller
			}
		}
		CloseTrace(handle);
	}
}
