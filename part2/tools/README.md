# tools — getting the Sysmon log into Event Viewer

## On Windows: one double-click

1. Right-click **`RUN-IMPORT.cmd`** → **Run as administrator**
   (or just double-click it — it will ask for elevation itself).
2. Wait. It finds the log automatically, creates the **Sysmon-Replay** event
   log and writes all 1484 events.
3. Open **Event Viewer** → **Applications and Services Logs** → **Sysmon-Replay**

That's it. Nothing to install — the script is plain PowerShell.

To also get a real `.evtx` file out of it, run the script directly instead:

```powershell
.\Import-SysmonToEventViewer.ps1 -ExportEvtx C:\Temp\sysmon.evtx
```

To remove everything afterwards:

```powershell
Remove-EventLog -LogName "Sysmon-Replay"
```

---

## What each file does

| File | Purpose |
|---|---|
| `RUN-IMPORT.cmd` | Double-click launcher. Self-elevates, bypasses execution policy, runs the import. |
| `Import-SysmonToEventViewer.ps1` | The import itself. Reads `.ndjson` **or** the original `.json`, creates the event log, writes every event. |
| `convert_sysmon_json.py` | Converts the original JSON into `.ndjson` and `.csv`. Already run — output is in `../logs/`. Only needed if you want to redo it. |

The script looks for its input in this order, so you normally pass nothing:

```
.\sysmon-events.ndjson
.\sysmon-events.json
..\logs\sysmon-events.ndjson      <-- this is the one in this repo
..\logs\sysmon-events.json
..\..\part1\logs\sysmon-events.json
```

---

## Why the original JSON needs special handling

`sysmon-events.json` is not one JSON document. It is 1484 objects written back
to back with no array brackets and no commas, and it mixes two indentation
styles — 1000 events indented two spaces, 484 indented four — with CRLF line
endings throughout.

So `ConvertFrom-Json` fails on the whole file, reading it line by line fails,
and no regex split finds all 1484 boundaries. Both tools here instead walk the
text and track **brace depth**, ignoring braces inside string literals and
after escape characters. That is layout-independent, which is the only property
that matters when you cannot trust the formatting.

---

## Two limitations of the Event Viewer view

| Limitation | What it means for you |
|---|---|
| Fields land in the message **body as text**, not the structured EventData table | Filter Current Log → by Event ID works. Ctrl+F text search works. XPath field filters (`*[EventData[Data[@Name='Image']]]`) do **not**. |
| `Write-EventLog` stamps entries with the **import** time | The Date and Time column is useless for ordering. The real timestamp is the first line of each message body (`OriginalTime`). Events are written in file order, so the sequence is still correct. |

For anything involving ordering or per-field filtering, use
**`../logs/sysmon-events.csv`** instead — 1484 rows × 62 columns, opens in
Timeline Explorer or Excel with real timestamps and every field sortable.
