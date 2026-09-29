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
 *  Event Definitions for CSV Logging
 *
 *  Defines event IDs and categories for structured CSV logging.
 *  Events are organized by category with 1000-ID ranges:
 *  - 1xxx: Authentication events
 *  - 2xxx: Authorization events
 *  - 3xxx: Session events
 *  - 4xxx: Certificate events
 *  - 5xxx: Smartcard events
 *  - 6xxx: LSA events
 *  - 7xxx: Configuration events
 *  - 8xxx: Audit events
 */

#pragma once

#include <Windows.h>

// Event category base values (1000-8000 range)
enum class EID_EVENT_CATEGORY : WORD
{
    AUTHENTICATION = 1000,    // 1000-1999: Login, credential validation
    AUTHORIZATION  = 2000,    // 2000-2999: Permission checks, access grants
    SESSION         = 3000,    // 3000-3999: Session lifecycle (logon/logoff/lock/unlock)
    CERTIFICATE     = 4000,    // 4000-4999: Certificate validation, expiry checks
    SMARTCARD       = 5000,    // 5000-5999: Card reader interactions
    LSA             = 6000,    // 6000-6999: LSA secret operations
    CONFIG          = 7000,    // 7000-7999: Configuration changes
    AUDIT           = 8000     // 8000-8999: High-risk security events
};

// Specific event IDs within categories
enum class EID_EVENT_ID : DWORD
{
    // ================================================================
    // AUTHENTICATION Events (1001-1999)
    // ================================================================
    AUTH_CARD_INSERTED       = 1001,  // Smart card detected
    AUTH_CARD_REMOVED        = 1002,  // Smart card removed
    AUTH_PIN_PROMPT          = 1003,  // PIN entry prompted
    AUTH_PIN_SUCCESS         = 1004,  // PIN verified successfully
    AUTH_PIN_FAILURE         = 1005,  // PIN verification failed
    AUTH_SUCCESS             = 1006,  // Authentication successful
    AUTH_FAILURE             = 1007,  // Authentication failed
    AUTH_CANCELLED           = 1008,  // Authentication cancelled by user
    AUTH_CERT_VALIDATED      = 1009,  // Certificate validated
    AUTH_CERT_EXPIRED        = 1010,  // Certificate has expired
    AUTH_CERT_NOT_YET_VALID  = 1011,  // Certificate validity in future
    AUTH_CERT_CHAIN_ERROR    = 1012,  // Certificate chain validation failed
    AUTH_LOCKOUT             = 1013,  // Account locked due to failed attempts

    // ================================================================
    // AUTHORIZATION Events (2001-2999)
    // ================================================================
    AUTHZ_CHECK_START        = 2001,  // Authorization check started
    AUTHZ_CHECK_SUCCESS      = 2002,  // Authorization check passed
    AUTHZ_CHECK_FAILURE      = 2003,  // Authorization check failed
    AUTHZ_ACCOUNT_DISABLED   = 2004,  // Account is disabled
    AUTHZ_ACCOUNT_EXPIRED    = 2005,  // Account has expired
    AUTHZ_LOGON_HOURS        = 2006,  // Outside allowed logon hours
    AUTHZ_WORKSTATION_LIMIT  = 2007,  // Workstation restriction
    AUTHZ_LSA_SECRET_READ            = 2008,  // LSA secret read successfully
    AUTHZ_LSA_SECRET_WRITE           = 2009,  // LSA secret written
    AUTHZ_LSA_SECRET_NOT_FOUND       = 2010,  // LSA secret does not exist (WARNING - unexpected)
    AUTHZ_CREDENTIAL_DENIED          = 2011,  // Credential access denied
    AUTHZ_LSA_SECRET_SCAN_NOT_FOUND  = 2012,  // LSA secret not found during credential scan (VERBOSE - expected)

    // ================================================================
    // SESSION Events (3001-3999)
    // ================================================================
    SESSION_LOGON_INIT       = 3001,  // Logon initiated
    SESSION_LOGON_SUCCESS    = 3002,  // Logon successful
    SESSION_LOGON_FAILURE    = 3003,  // Logon failed
    SESSION_LOGOFF           = 3004,  // Logoff initiated
    SESSION_LOCK             = 3005,  // Workstation locked
    SESSION_UNLOCK           = 3006,  // Workstation unlocked
    SESSION_RENEWED          = 3007,  // Session refreshed/renewed
    SESSION_TIMEOUT          = 3008,  // Session timed out

    // ================================================================
    // CERTIFICATE Events (4001-4999)
    // ================================================================
    CERT_READ_START          = 4001,  // Reading certificate from card
    CERT_READ_SUCCESS        = 4002,  // Certificate read successfully
    CERT_READ_FAILURE        = 4003,  // Certificate read failed
    CERT_VALIDATE_START      = 4004,  // Certificate validation started
    CERT_VALIDATE_SUCCESS    = 4005,  // Certificate chain validated
    CERT_VALIDATE_FAILURE    = 4006,  // Certificate validation failed
    CERT_EXPIRED             = 4007,  // Certificate has expired
    CERT_NOT_YET_VALID       = 4008,  // Certificate not yet valid
    CERT_REVOKED             = 4009,  // Certificate has been revoked
    CERT_INSTALL             = 4010,  // Certificate installed to store
    CERT_EXPIRING_SOON       = 4011,  // Certificate expires soon (warning)
    CERT_CHAIN_BUILD         = 4012,  // Building certificate chain
    CERT_CHAIN_ERROR         = 4013,  // Chain building failed
    CERT_TRUST_ERROR         = 4014,  // Certificate trust error

    // ================================================================
    // SMARTCARD Events (5001-5999)
    // ================================================================
    SC_READER_DETECTED       = 5001,  // Card reader detected
    SC_READER_REMOVED        = 5002,  // Card reader removed
    SC_CARD_DETECTED         = 5003,  // Smart card detected
    SC_CARD_REMOVED          = 5004,  // Smart card removed
    SC_CARD_TRANSMIT         = 5005,  // APDU transmission
    SC_CARD_RESET            = 5006,  // Card reset
    SC_CARD_DISCONNECT       = 5007,  // Card disconnected
    SC_ATR_READ              = 5008,  // Answer To Reset read
    SC_COMM_ERROR            = 5009,  // Communication error
    SC_CARD_TYPE_UNKNOWN     = 5010,  // Unknown card type

    // ================================================================
    // LSA Events (6001-6999)
    // ================================================================
    LSA_PACKAGE_INIT         = 6001,  // LSA package initialized
    LSA_PACKAGE_START        = 6002,  // LSA package started
    LSA_AUTH_PACKAGE_CALL    = 6003,  // LSA call authentication package
    LSA_LOGON_PROCESS        = 6004,  // LSA processing logon
    LSA_SECRET_CREATED       = 6005,  // LSA secret created
    LSA_SECRET_DELETED       = 6006,  // LSA secret deleted
    LSA_SECRET_FORMAT_ERROR  = 6007,  // Invalid secret name format

    // ================================================================
    // CONFIG Events (7001-7999)
    // ================================================================
    CONFIG_LOAD              = 7001,  // Configuration loaded
    CONFIG_SAVE              = 7002,  // Configuration saved
    CONFIG_INVALID           = 7003,  // Invalid configuration
    CONFIG_DEFAULT_USED      = 7004,  // Using default configuration
    CONFIG_JSON_LOAD         = 7005,  // JSON configuration loaded
    CONFIG_JSON_ERROR        = 7006,  // JSON parse error
    CONFIG_REG_LOAD          = 7007,  // Registry configuration loaded
    CONFIG_CSV_ENABLED       = 7008,  // CSV logging enabled
    CONFIG_CSV_DISABLED      = 7009,  // CSV logging disabled
    CONFIG_COLUMNS_CHANGED   = 7010,  // Column selection changed
    CONFIG_FILTER_CHANGED    = 7011,  // Event filter changed

    // ================================================================
    // AUDIT Events (8001-8999)
    // ================================================================
    AUDIT_CREDENTIAL_EXPORT  = 8001,  // Credentials exported
    AUDIT_CREDENTIAL_IMPORT  = 8002,  // Credentials imported
    AUDIT_CONFIG_CHANGE      = 8003,  // Configuration changed
    AUDIT_SECURITY_VIOLATION = 8004,  // Security policy violation
    AUDIT_ADMIN_ACTION       = 8005,  // Administrative action performed
    AUDIT_PRIVILEGE_USE      = 8006,  // Privilege used
    AUDIT_POLICY_BREACH      = 8007,  // Security policy breach
    AUDIT_EXPORT_SUCCESS     = 8008,  // Credential export successful
    AUDIT_EXPORT_FAILURE     = 8009,  // Credential export failed
    AUDIT_IMPORT_SUCCESS     = 8010,  // Credential import successful
    AUDIT_IMPORT_FAILURE     = 8011,  // Credential import failed
    AUDIT_VALIDATE_SUCCESS   = 8012,  // Export file validated
    AUDIT_VALIDATE_FAILURE   = 8013,  // Export file validation failed
};

// Helper to get category from event ID
inline EID_EVENT_CATEGORY GetEventCategory(EID_EVENT_ID eventId)
{
    DWORD dwId = static_cast<DWORD>(eventId);  // NOSONAR - ENUM-01: explicit DWORD cast retained for Win32/ABI compatibility
    return static_cast<EID_EVENT_CATEGORY>((dwId / 1000) * 1000);
}

// Helper to get category name as wide string
PCWSTR GetCategoryName(EID_EVENT_CATEGORY category);

// Helper to get event name as wide string
PCWSTR GetEventName(EID_EVENT_ID eventId);

// Helper to get severity name as wide string
PCWSTR GetSeverityName(UCHAR severity);

// Helper to get outcome name as wide string
PCWSTR GetOutcomeName(UCHAR outcome);
