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

/**
 *  Event Definitions Implementation
 *
 *  String lookups for event categories, names, severities, and outcomes.
 *  All strings are static constants (no dynamic allocation).
 */

#include "EventDefinitions.h"

// Category name lookup table
static const WCHAR s_wszCategoryNames[][32] = {  // NOSONAR - LSASS-01: C-style fixed-size string lookup table
    L"AUTHENTICATION",   // 1000
    L"AUTHORIZATION",    // 2000
    L"SESSION",          // 3000
    L"CERTIFICATE",      // 4000
    L"SMARTCARD",        // 5000
    L"LSA",              // 6000
    L"CONFIG",           // 7000
    L"AUDIT"             // 8000
};

// Severity name lookup table
static const WCHAR s_wszSeverityNames[][16] = {  // NOSONAR - LSASS-01: C-style fixed-size string lookup table
    L"CRITICAL",         // 1
    L"ERROR",            // 2
    L"WARNING",          // 3
    L"INFO",             // 4
    L"VERBOSE"           // 5
};

// Outcome name lookup table
static const WCHAR s_wszOutcomeNames[][16] = {  // NOSONAR - LSASS-01: C-style fixed-size string lookup table
    L"Success",          // 0
    L"Failure",          // 1
    L"Partial",          // 2
    L"Unknown",          // 3
    L"Skipped",          // 4
    L"Cancelled"         // 5
};

PCWSTR GetCategoryName(EID_EVENT_CATEGORY category)
{
    WORD wCat = static_cast<WORD>(category);  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
    switch (wCat)
    {
        case 1000: return s_wszCategoryNames[0];  // AUTHENTICATION
        case 2000: return s_wszCategoryNames[1];  // AUTHORIZATION
        case 3000: return s_wszCategoryNames[2];  // SESSION
        case 4000: return s_wszCategoryNames[3];  // CERTIFICATE
        case 5000: return s_wszCategoryNames[4];  // SMARTCARD
        case 6000: return s_wszCategoryNames[5];  // LSA
        case 7000: return s_wszCategoryNames[6];  // CONFIG
        case 8000: return s_wszCategoryNames[7];  // AUDIT
        default:  return L"UNKNOWN";
    }
}

PCWSTR GetEventName(EID_EVENT_ID eventId)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    DWORD dwId = static_cast<DWORD>(eventId);  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility

    // Authentication events (1xxx)
    if (dwId >= 1001 && dwId <= 1013)
    {
        switch (dwId)
        {
            case 1001: return L"Card Inserted";
            case 1002: return L"Card Removed";
            case 1003: return L"PIN Prompt";
            case 1004: return L"PIN Success";
            case 1005: return L"PIN Failure";
            case 1006: return L"Authentication Success";
            case 1007: return L"Authentication Failure";
            case 1008: return L"Authentication Cancelled";
            case 1009: return L"Certificate Validated";
            case 1010: return L"Certificate Expired";
            case 1011: return L"Certificate Not Yet Valid";
            case 1012: return L"Certificate Chain Error";
            case 1013: return L"Account Lockout";
            default: break;
        }
    }

    // Authorization events (2xxx)
    if (dwId >= 2001 && dwId <= 2012)
    {
        switch (dwId)
        {
            case 2001: return L"Authorization Check Start";
            case 2002: return L"Authorization Check Success";
            case 2003: return L"Authorization Check Failure";
            case 2004: return L"Account Disabled";
            case 2005: return L"Account Expired";
            case 2006: return L"Logon Hours Restriction";
            case 2007: return L"Workstation Restriction";
            case 2008: return L"LSA Secret Read";
            case 2009: return L"LSA Secret Write";
            case 2010: return L"LSA Secret Not Found";
            case 2011: return L"Credential Access Denied";
            case 2012: return L"LSA Secret Scan Miss";
            default: break;
        }
    }

    // Session events (3xxx)
    if (dwId >= 3001 && dwId <= 3008)
    {
        switch (dwId)
        {
            case 3001: return L"Logon Initiated";
            case 3002: return L"Logon Success";
            case 3003: return L"Logon Failure";
            case 3004: return L"Logoff";
            case 3005: return L"Session Lock";
            case 3006: return L"Session Unlock";
            case 3007: return L"Session Renewed";
            case 3008: return L"Session Timeout";
            default: break;
        }
    }

    // Certificate events (4xxx)
    if (dwId >= 4001 && dwId <= 4014)
    {
        switch (dwId)
        {
            case 4001: return L"Certificate Read Start";
            case 4002: return L"Certificate Read Success";
            case 4003: return L"Certificate Read Failure";
            case 4004: return L"Certificate Validation Start";
            case 4005: return L"Certificate Validation Success";
            case 4006: return L"Certificate Validation Failure";
            case 4007: return L"Certificate Expired";
            case 4008: return L"Certificate Not Yet Valid";
            case 4009: return L"Certificate Revoked";
            case 4010: return L"Certificate Installed";
            case 4011: return L"Certificate Expiring Soon";
            case 4012: return L"Certificate Chain Build";
            case 4013: return L"Certificate Chain Error";
            case 4014: return L"Certificate Trust Error";
            default: break;
        }
    }

    // Smartcard events (5xxx)
    if (dwId >= 5001 && dwId <= 5010)
    {
        switch (dwId)
        {
            case 5001: return L"Reader Detected";
            case 5002: return L"Reader Removed";
            case 5003: return L"Card Detected";
            case 5004: return L"Card Removed";
            case 5005: return L"Card Transmit";
            case 5006: return L"Card Reset";
            case 5007: return L"Card Disconnected";
            case 5008: return L"ATR Read";
            case 5009: return L"Communication Error";
            case 5010: return L"Unknown Card Type";
            default: break;
        }
    }

    // LSA events (6xxx)
    if (dwId >= 6001 && dwId <= 6007)
    {
        switch (dwId)
        {
            case 6001: return L"LSA Package Initialized";
            case 6002: return L"LSA Package Started";
            case 6003: return L"LSA Call Authentication Package";
            case 6004: return L"LSA Processing Logon";
            case 6005: return L"LSA Secret Created";
            case 6006: return L"LSA Secret Deleted";
            case 6007: return L"LSA Secret Format Error";
            default: break;
        }
    }

    // Config events (7xxx)
    if (dwId >= 7001 && dwId <= 7011)
    {
        switch (dwId)
        {
            case 7001: return L"Configuration Loaded";
            case 7002: return L"Configuration Saved";
            case 7003: return L"Invalid Configuration";
            case 7004: return L"Default Configuration Used";
            case 7005: return L"JSON Configuration Loaded";
            case 7006: return L"JSON Parse Error";
            case 7007: return L"Registry Configuration Loaded";
            case 7008: return L"CSV Logging Enabled";
            case 7009: return L"CSV Logging Disabled";
            case 7010: return L"Column Selection Changed";
            case 7011: return L"Event Filter Changed";
            default: break;
        }
    }

    // Audit events (8xxx)
    if (dwId >= 8001 && dwId <= 8013)
    {
        switch (dwId)
        {
            case 8001: return L"Credential Export";
            case 8002: return L"Credential Import";
            case 8003: return L"Configuration Changed";
            case 8004: return L"Security Violation";
            case 8005: return L"Administrative Action";
            case 8006: return L"Privilege Used";
            case 8007: return L"Security Policy Breach";
            case 8008: return L"Export Success";
            case 8009: return L"Export Failure";
            case 8010: return L"Import Success";
            case 8011: return L"Import Failure";
            case 8012: return L"Validation Success";
            case 8013: return L"Validation Failure";
            default: break;
        }
    }

    return L"Unknown Event";
}

PCWSTR GetSeverityName(UCHAR severity)
{
    if (severity >= 1 && severity <= 5)
    {
        return s_wszSeverityNames[severity - 1];
    }
    return L"UNKNOWN";
}

PCWSTR GetOutcomeName(UCHAR outcome)
{
    if (outcome <= 5)
    {
        return s_wszOutcomeNames[outcome];
    }
    return L"UNKNOWN";
}
