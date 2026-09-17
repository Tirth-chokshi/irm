<#
.SYNOPSIS
    Replays Sysmon events into a Windows Event Log so they can be browsed in
    Event Viewer, and optionally exports a genuine .evtx.

.DESCRIPTION
    Accepts either input file:

      *.ndjson  one compact JSON object per line  (fast - use this)
      *.json    the original concatenated-object file from the assignment
                (slower; the objects are split here in PowerShell)

    The assignment's sysmon-events.json is a run of JSON objects with no array
    brackets and two different indentation styles, so ConvertFrom-Json cannot
    read it whole and no line-based regex finds all the boundaries. This script
    splits it by tracking brace depth while respecting string literals and
    escapes, which is layout-independent.

    RUN AS ADMINISTRATOR - creating an event log requires elevation.

.PARAMETER Path
    Path to sysmon-events.ndjson or sysmon-events.json. If omitted, the script
    looks for either file next to itself and in ..\logs\.

.PARAMETER LogName
    Event log to create. Default "Sysmon-Replay".

.PARAMETER ExportEvtx
    Optional path to also export a real .evtx when the import finishes.

.EXAMPLE
    .\Import-SysmonToEventViewer.ps1

.EXAMPLE
    .\Import-SysmonToEventViewer.ps1 -Path .\sysmon-events.json -ExportEvtx C:\Temp\sysmon.evtx

.NOTES
    Two limitations that affect how you read the result:

    1. Fields land in the message BODY as text, not the structured EventData
       table. "Filter Current Log -> by Event ID" works and Ctrl+F works, but
       XPath field filters (*[EventData[Data[@Name='Image']]]) do NOT.

    2. Write-EventLog stamps each entry with the time it was WRITTEN. The Event
       Viewer time column is therefore useless for ordering. The original
       timestamp is the first line of every message body, and entries are
       written in file order so the sequence is preserved.

    Undo everything:  Remove-EventLog -LogName "Sysmon-Replay"
#>

[CmdletBinding()]
param(
    [string] $Path,
    [string] $LogName = "Sysmon-Replay",
    [string] $Source  = "SysmonReplay",
    [string] $ExportEvtx
)

$ErrorActionPreference = "Stop"

function Split-ConcatenatedJson {
    <#  Walk the text once, tracking brace depth. Braces inside string literals
        and escaped characters are ignored, so this is correct regardless of
        indentation, line endings or whether objects sit on one line.  #>
    param([string] $Text)

    $chars   = $Text.ToCharArray()
    $objects = New-Object System.Collections.Generic.List[string]
    $depth   = 0
    $start   = -1
    $inStr   = $false
    $escape  = $false

    for ($i = 0; $i -lt $chars.Length; $i++) {
        $c = $chars[$i]

        if ($escape)      { $escape = $false; continue }
        if ($inStr) {
            if     ($c -eq '\') { $escape = $true }
            elseif ($c -eq '"') { $inStr  = $false }
            continue
        }
        if ($c -eq '"') { $inStr = $true; continue }

        if ($c -eq '{') {
            if ($depth -eq 0) { $start = $i }
            $depth++
        }
        elseif ($c -eq '}') {
            $depth--
            if ($depth -eq 0 -and $start -ge 0) {
                $objects.Add($Text.Substring($start, $i - $start + 1))
                $start = -1
            }
        }
    }
    return $objects
}

# --- 1. Checks -------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  This must run in an ADMINISTRATOR PowerShell window." -ForegroundColor Red
    Write-Host "  Right-click RUN-IMPORT.cmd and choose 'Run as administrator', or" -ForegroundColor Yellow
    Write-Host "  open PowerShell as admin and run this script again." -ForegroundColor Yellow
    Write-Host ""
    throw "Not elevated."
}

# --- 2. Locate the input file ---------------------------------------------
if (-not $Path) {
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidates = @(
        (Join-Path $here "sysmon-events.ndjson"),
        (Join-Path $here "sysmon-events.json"),
        (Join-Path $here "..\logs\sysmon-events.ndjson"),
        (Join-Path $here "..\logs\sysmon-events.json"),
        (Join-Path $here "..\..\part1\logs\sysmon-events.json")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { $Path = (Resolve-Path $candidate).Path; break }
    }
}
if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
    throw "No input file found. Pass one with -Path, e.g. -Path .\sysmon-events.ndjson"
}
Write-Host "Input: $Path"

# --- 3. Read the events ----------------------------------------------------
$records = @()
if ($Path.ToLower().EndsWith(".ndjson")) {
    Write-Host "Reading NDJSON (one event per line)..."
    $records = Get-Content -LiteralPath $Path | Where-Object { $_.Trim() -ne "" }
} else {
    Write-Host "Reading concatenated JSON - splitting objects, this takes a few seconds..."
    $raw = [System.IO.File]::ReadAllText($Path)
    $records = Split-ConcatenatedJson -Text $raw
}
Write-Host ("Found {0} events." -f $records.Count)
if ($records.Count -eq 0) { throw "No events parsed - is the input file correct?" }

# --- 4. Create the destination log -----------------------------------------
if ([System.Diagnostics.EventLog]::SourceExists($Source)) {
    Write-Host "Source '$Source' already exists - reusing it."
} else {
    Write-Host "Creating event log '$LogName'..."
    New-EventLog -LogName $LogName -Source $Source
}
Limit-EventLog -LogName $LogName -MaximumSize 64MB -OverflowAction OverwriteAsNeeded

# --- 5. Write the events ---------------------------------------------------
$written = 0
$skipped = 0
$index   = 0

foreach ($record in $records) {
    $index++
    try {
        $ev = $record | ConvertFrom-Json
    } catch {
        Write-Warning "event ${index}: could not parse - skipped"
        $skipped++
        continue
    }

    # Handle both the wrapped {"Event": {...}} and the unwrapped shape
    if ($ev.PSObject.Properties.Name -contains "Event") { $ev = $ev.Event }

    $id = 0
    if ($ev.System -and $ev.System.EventID) { $id = [int]$ev.System.EventID }
    if ($id -lt 0 -or $id -gt 65535) { $id = 0 }

    $time = ""
    if ($ev.System -and $ev.System.TimeCreated) {
        $time = $ev.System.TimeCreated.SystemTime
        if (-not $time) { $time = $ev.System.TimeCreated.'#attributes'.SystemTime }
    }
    $rec = ""
    if ($ev.System) { $rec = $ev.System.EventRecordID }

    $body = "OriginalTime : $time`r`nEventRecordID: $rec`r`nEventID      : $id`r`n`r`n" +
            ($ev.EventData | ConvertTo-Json -Depth 10)
    if ($body.Length -gt 31000) { $body = $body.Substring(0, 31000) + "`r`n...[truncated]" }

    Write-EventLog -LogName $LogName -Source $Source -EventId $id `
                   -EntryType Information -Message $body
    $written++

    if ($written % 50 -eq 0) {
        Write-Progress -Activity "Importing Sysmon events" `
                       -Status "$written of $($records.Count)" `
                       -PercentComplete (100 * $written / $records.Count)
    }
}

Write-Progress -Activity "Importing Sysmon events" -Completed
Write-Host ""
Write-Host "Written : $written" -ForegroundColor Green
Write-Host "Skipped : $skipped"
Write-Host ""
Write-Host "Now open Event Viewer:" -ForegroundColor Cyan
Write-Host "  Applications and Services Logs  ->  $LogName"
Write-Host ""
Write-Host "Remember: the Date and Time column shows when events were IMPORTED."
Write-Host "The real timestamp is the first line of each event's message body."
Write-Host ""

# --- 6. Optional .evtx export ----------------------------------------------
if ($ExportEvtx) {
    $folder = Split-Path -Parent $ExportEvtx
    if ($folder -and -not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder | Out-Null }
    if (Test-Path -LiteralPath $ExportEvtx) { Remove-Item -LiteralPath $ExportEvtx -Force }
    wevtutil epl $LogName $ExportEvtx
    Write-Host "Exported: $ExportEvtx" -ForegroundColor Green
}
