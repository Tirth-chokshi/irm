<#
.SYNOPSIS
    Replays Sysmon events from NDJSON into a Windows Event Log so they can be
    browsed in Event Viewer, and optionally exports a genuine .evtx.

.DESCRIPTION
    The assignment's sysmon-events.json cannot be read directly: it is a
    concatenation of JSON objects with mixed indentation, so ConvertFrom-Json
    chokes on it and no regex split handles it reliably. Run
    convert_sysmon_json.py first to produce sysmon-events.ndjson - one complete
    JSON object per line - which this script reads line by line.

    RUN AS ADMINISTRATOR. Creating an event log requires elevation.

.PARAMETER Path
    Path to sysmon-events.ndjson.

.PARAMETER LogName
    Name of the event log to create. Default "Sysmon-Replay".

.PARAMETER ExportEvtx
    Optional path to also export a real .evtx file when the import finishes.

.EXAMPLE
    .\Import-SysmonToEventViewer.ps1 -Path .\sysmon-events.ndjson

.EXAMPLE
    .\Import-SysmonToEventViewer.ps1 -Path .\sysmon-events.ndjson -ExportEvtx C:\Temp\sysmon.evtx

.NOTES
    Two limitations you must know before drawing conclusions from this log:

    1. Fields land in the message BODY as text, not in the structured EventData
       table. So Event Viewer's "Filter Current Log -> by Event ID" works and
       Ctrl+F text search works, but XPath filtering by field
       (*[EventData[Data[@Name='Image']]]) does NOT.

    2. Write-EventLog stamps every entry with the time it was WRITTEN, not the
       time the event originally happened. The Event Viewer time column is
       therefore meaningless for ordering. The original timestamp is placed on
       the first line of each message body as "OriginalTime", and entries are
       written in file order so the sequence is preserved.

    To remove everything afterwards:  Remove-EventLog -LogName "Sysmon-Replay"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Path,

    [string] $LogName = "Sysmon-Replay",

    [string] $Source = "SysmonReplay",

    [string] $ExportEvtx
)

$ErrorActionPreference = "Stop"

# --- 1. Checks -------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in an Administrator PowerShell window - creating an event log needs elevation."
}

if (-not (Test-Path -LiteralPath $Path)) {
    throw "File not found: $Path"
}

# --- 2. Create the destination log ----------------------------------------
if ([System.Diagnostics.EventLog]::SourceExists($Source)) {
    Write-Host "Source '$Source' already exists - reusing it."
} else {
    Write-Host "Creating event log '$LogName' with source '$Source'..."
    New-EventLog -LogName $LogName -Source $Source
}
Limit-EventLog -LogName $LogName -MaximumSize 64MB -OverflowAction OverwriteAsNeeded

# --- 3. Read and write, one line at a time --------------------------------
$written = 0
$skipped = 0
$lineNo  = 0

Get-Content -LiteralPath $Path | ForEach-Object {
    $lineNo++
    $line = $_.Trim()
    if ([string]::IsNullOrWhiteSpace($line)) { return }

    try {
        $ev = $line | ConvertFrom-Json
    } catch {
        Write-Warning "line ${lineNo}: could not parse - skipped"
        $script:skipped++
        return
    }

    # The NDJSON has the {"Event": ...} envelope already stripped, but handle
    # both shapes so the script works on either file.
    if ($ev.PSObject.Properties.Name -contains "Event") { $ev = $ev.Event }

    $id = 0
    if ($ev.System -and $ev.System.EventID) { $id = [int]$ev.System.EventID }
    if ($id -lt 0 -or $id -gt 65535) { $id = 0 }

    $time = ""
    if ($ev.System -and $ev.System.TimeCreated) {
        $time = $ev.System.TimeCreated.SystemTime
        if (-not $time) { $time = $ev.System.TimeCreated.'#attributes'.SystemTime }
    }
    $record = ""
    if ($ev.System) { $record = $ev.System.EventRecordID }

    $header = "OriginalTime : $time`r`nEventRecordID: $record`r`nEventID      : $id`r`n`r`n"
    $body   = $header + ($ev.EventData | ConvertTo-Json -Depth 10)

    # Write-EventLog rejects messages beyond roughly 32 KB
    if ($body.Length -gt 31000) { $body = $body.Substring(0, 31000) + "`r`n...[truncated]" }

    Write-EventLog -LogName $LogName -Source $Source -EventId $id `
                   -EntryType Information -Message $body
    $script:written++

    if ($script:written % 100 -eq 0) {
        Write-Progress -Activity "Importing Sysmon events" -Status "$script:written written"
    }
}

Write-Progress -Activity "Importing Sysmon events" -Completed
Write-Host ""
Write-Host "Written : $written"
Write-Host "Skipped : $skipped"
Write-Host ""
Write-Host "Open Event Viewer -> Applications and Services Logs -> $LogName"

# --- 4. Optional: export a real .evtx -------------------------------------
if ($ExportEvtx) {
    $folder = Split-Path -Parent $ExportEvtx
    if ($folder -and -not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder | Out-Null }
    if (Test-Path -LiteralPath $ExportEvtx) { Remove-Item -LiteralPath $ExportEvtx -Force }
    wevtutil epl $LogName $ExportEvtx
    Write-Host "Exported: $ExportEvtx"
}
