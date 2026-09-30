<#
.SYNOPSIS
    Write well-formed seed inputs for each fuzz target.

.DESCRIPTION
    libFuzzer explores far faster from valid structure than from random bytes:
    every one of these buffers passes its validator, so mutations start at the
    boundary that matters instead of being rejected by the first length check.

    Also writes the known-bad proof-of-concept inputs. Those must never crash
    the target - they exist so a regression shows up as a corpus entry that
    suddenly fails rather than as a silent gap.

    Safe to re-run; files are overwritten.
#>

$ErrorActionPreference = "Stop"
$corpusRoot = Join-Path $PSScriptRoot "corpus"

function Write-Seed {
    param([string]$Target, [string]$Name, [byte[]]$Bytes)
    $dir = Join-Path $corpusRoot $Target
    New-Item -ItemType Directory -Force $dir | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $dir "$Name.bin"), $Bytes)
}

# Little-endian helpers matching the on-wire structs.
function U32 { param([uint32]$v) [BitConverter]::GetBytes($v) }
function U16 { param([uint16]$v) [BitConverter]::GetBytes($v) }

# ---------------------------------------------------------------------------
# tokenmessage - EID_CHALLENGE_MESSAGE / EID_RESPONSE_MESSAGE
# Layout: Signature[8], MessageType, Flags, UsernameLen, UsernameOffset,
#         ChallengeLen, ChallengeOffset, Version   (all DWORD after Signature)
# ---------------------------------------------------------------------------
$sig = [Text.Encoding]::ASCII.GetBytes("EIDAuth")  + @(0x00)   # 8 bytes
$hdr = 8 + 7 * 4                                              # 36 bytes

$challenge = @()
$challenge += $sig
$challenge += U32 2            # MessageType = EIDMTChallenge
$challenge += U32 0            # Flags
$challenge += U32 16           # UsernameLen  (even, as WCHARs)
$challenge += U32 ($hdr + 16)  # UsernameOffset
$challenge += U32 16           # ChallengeLen
$challenge += U32 $hdr         # ChallengeOffset
$challenge += U32 1            # Version
$challenge += (1..32 | ForEach-Object { [byte]0x41 })
Write-Seed -Target tokenmessage -Name "valid-challenge" -Bytes ([byte[]]$challenge)

# Response: Signature[8], MessageType, ResponseLen, ResponseOffset, Version
$rhdr = 8 + 4 * 4
$response = @()
$response += $sig
$response += U32 3             # MessageType = EIDMTResponse
$response += U32 24            # ResponseLen
$response += U32 $rhdr         # ResponseOffset
$response += U32 1             # Version
$response += (1..24 | ForEach-Object { [byte]0x42 })
Write-Seed -Target tokenmessage -Name "valid-response" -Bytes ([byte[]]$response)

# ---------------------------------------------------------------------------
# cspinfo - EID_SMARTCARD_CSP_INFO (packed 1)
# dwCspInfoLen, MessageType, union{ULONG64}, flags, KeySpec,
# nCardName, nReaderName, nContainerName, nCSPName, bBuffer[4 TCHAR]
# ---------------------------------------------------------------------------
$cspHeader = 4 + 4 + 8 + 4 + 4 + 4 + 4 + 4 + 4     # 40 bytes, pack(1)
$nameChars = 24
$cspTotal  = $cspHeader + $nameChars * 2

$csp = @()
$csp += U32 $cspTotal   # dwCspInfoLen == real size
$csp += U32 1           # MessageType
$csp += [byte[]]::new(8)
$csp += U32 0           # flags
$csp += U32 1           # KeySpec (AT_KEYEXCHANGE)
$csp += U32 0           # nCardNameOffset      (0 = absent)
$csp += U32 6           # nReaderNameOffset    (WCHAR units)
$csp += U32 12          # nContainerNameOffset
$csp += U32 1           # nCSPNameOffset
$names = [byte[]]::new($nameChars * 2)
function Put-Wide { param([byte[]]$Buf, [int]$CharIndex, [string]$Text)
    $b = [Text.Encoding]::Unicode.GetBytes($Text + "`0")
    [Array]::Copy($b, 0, $Buf, $CharIndex * 2, $b.Length)
}
Put-Wide $names 1  "MyEID"       # nCSPNameOffset = 1
Put-Wide $names 6  "Reader 0"    # nReaderNameOffset = 6
Put-Wide $names 12 "Container"   # nContainerNameOffset = 12
$csp += $names
Write-Seed -Target cspinfo -Name "valid-cspinfo" -Bytes ([byte[]]$csp)

# Known-bad: 40-byte buffer claiming a 64 KB interior (the core defect).
$bad = @()
$bad += U32 0x10000
$bad += U32 1
$bad += [byte[]]::new(8)
$bad += U32 0
$bad += U32 1
$bad += U32 0xFFF0
$bad += U32 0
$bad += U32 0
$bad += U32 0
Write-Seed -Target cspinfo -Name "poc-inner-length-exceeds" -Bytes ([byte[]]$bad)

# ---------------------------------------------------------------------------
# privatedata - EID_PRIVATE_DATA
# dwType(4), 6x USHORT(12), Hash[32], Data[...]
# ---------------------------------------------------------------------------
$pdHeader = 4 + 12 + 32       # 48 bytes before Data
$pd = @()
$pd += U32 1                  # dwType = eidpdtCrypted
$pd += U16 0                  # dwCertificatOffset
$pd += U16 16                 # dwCertificatSize
$pd += U16 16                 # dwSymetricKeyOffset
$pd += U16 16                 # dwSymetricKeySize
$pd += U16 32                 # dwPasswordOffset
$pd += U16 16                 # usPasswordLen (non-zero, one AES block)
$pd += [byte[]]::new(32)      # Hash
$pd += (1..48 | ForEach-Object { [byte]0x43 })
Write-Seed -Target privatedata -Name "valid-blob" -Bytes ([byte[]]$pd)

# Known-bad: usPasswordLen = 0 (the dwRoundNumber underflow).
$pdBad = @()
$pdBad += U32 1
$pdBad += U16 0
$pdBad += U16 16
$pdBad += U16 16
$pdBad += U16 16
$pdBad += U16 32
$pdBad += U16 0
$pdBad += [byte[]]::new(32)
$pdBad += (1..48 | ForEach-Object { [byte]0x43 })
Write-Seed -Target privatedata -Name "poc-zero-password-len" -Bytes ([byte[]]$pdBad)

# ---------------------------------------------------------------------------
# remappointer - EID_INTERACTIVE_UNLOCK_LOGON submit buffer
#
# Layout (x64): EID_INTERACTIVE_LOGON { MessageType(4) +pad(4),
#   3 x UNICODE_STRING{Length(2),MaximumLength(2),pad(4),Buffer(8)},
#   Flags(4), CspDataLength(4), CspData(8) } then LUID LogonId(8).
# Buffer/CspData hold CLIENT-SPACE OFFSETS, not pointers - that is the whole
# point of RemapPointer, and what makes this the richest attacker surface.
# ---------------------------------------------------------------------------
function U64 { param([uint64]$v) [BitConverter]::GetBytes($v) }

$hdr = 8 + (3 * 16) + 4 + 4 + 8 + 8   # 80 bytes
$nameChars = 8
$cspHeader = 40
$cspNames  = 16

$userOff = $hdr
$domOff  = $userOff + $nameChars * 2
$pinOff  = $domOff  + $nameChars * 2
$cspOff  = $pinOff  + $nameChars * 2
$cspLen  = $cspHeader + $cspNames * 2
$total   = $cspOff + $cspLen

$b = New-Object byte[] $total
# MessageType
[Array]::Copy((U32 2), 0, $b, 0, 4)
# UserName / LogonDomainName / Pin: Length, MaximumLength, then offset
$i = 8
foreach ($off in @($userOff, $domOff, $pinOff)) {
    [Array]::Copy((U16 ($nameChars * 2)), 0, $b, $i, 2)      # Length
    [Array]::Copy((U16 ($nameChars * 2)), 0, $b, $i + 2, 2)  # MaximumLength
    [Array]::Copy((U64 $off),             0, $b, $i + 8, 8)  # Buffer = offset
    $i += 16
}
[Array]::Copy((U32 0),       0, $b, 56, 4)   # Flags
[Array]::Copy((U32 $cspLen), 0, $b, 60, 4)   # CspDataLength
[Array]::Copy((U64 $cspOff), 0, $b, 64, 8)   # CspData = offset

# Three plausible UTF-16 names in the string area
$names = @('operator', 'WORKGRP\', 'A1B2C3D4')
$o = $userOff
foreach ($n in $names) {
    [Array]::Copy([Text.Encoding]::Unicode.GetBytes($n), 0, $b, $o, $nameChars * 2)
    $o += $nameChars * 2
}

# CSP info at $cspOff: dwCspInfoLen then the four WCHAR-unit name offsets
[Array]::Copy((U32 $cspLen), 0, $b, $cspOff, 4)
[Array]::Copy((U32 1),       0, $b, $cspOff + 4, 4)    # MessageType
[Array]::Copy((U32 1),       0, $b, $cspOff + 20, 4)   # KeySpec
[Array]::Copy((U32 0),       0, $b, $cspOff + 24, 4)   # nCardNameOffset (absent)
[Array]::Copy((U32 1),       0, $b, $cspOff + 28, 4)   # nReaderNameOffset
[Array]::Copy((U32 0),       0, $b, $cspOff + 32, 4)   # nContainerNameOffset
[Array]::Copy((U32 0),       0, $b, $cspOff + 36, 4)   # nCSPNameOffset
[Array]::Copy([Text.Encoding]::Unicode.GetBytes("Rdr0`0"), 0, $b, $cspOff + $cspHeader + 2, 10)
Write-Seed -Target remappointer -Name "valid-submit-buffer" -Bytes $b

# ---------------------------------------------------------------------------
# json - shapes drawn from the real .eidm schema plus the escape edge cases
# ---------------------------------------------------------------------------
$jsonSeeds = @{
    "schema-like"   = '{"version":1,"credentials":[{"rid":1001,"cert":"4d5a90","flags":0}],"groups":["Users"]}'
    "escapes"       = '{"a":"A\t\n\\\"\/","b":-12345,"c":true,"d":null}'
    "nested"        = '{"a":{"b":{"c":[[1,2],[3,4]]}}}'
    "truncated-esc" = '{"a":"\u00'
    "empty-object"  = '{}'
}
foreach ($kv in $jsonSeeds.GetEnumerator()) {
    Write-Seed -Target json -Name $kv.Key -Bytes ([Text.Encoding]::UTF8.GetBytes($kv.Value))
}

Write-Host "Seed corpora written under $corpusRoot" -ForegroundColor Green
Get-ChildItem $corpusRoot -Directory | ForEach-Object {
    $n = (Get-ChildItem $_.FullName -File).Count
    Write-Host ("  {0,-14} {1} file(s)" -f $_.Name, $n) -ForegroundColor Gray
}
