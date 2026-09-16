# Investigation working log — Part 2

Worked through one step at a time. Steps are added here as they are completed,
so this file doubles as the record of *how* the investigation was done.

---

## Getting the log into a viewer

### Can JSON be converted to EVTX? No.

EVTX is a proprietary binary format and the tooling around it is
**one-directional** — `evtx_dump`, `EvtxECmd`, `python-evtx` and `libevtx` all
read EVTX and emit JSON/CSV, and none of them go the other way. There is no
`json2evtx`. A real EVTX binds its fields to a registered provider manifest
(`Microsoft-Windows-Sysmon`), so a hand-built file has nothing to bind to.

**Ask the faculty for the original `.evtx` first.** The JSON was almost
certainly exported from one, and the original opens straight in Event Viewer
with all fields intact. That single question beats every workaround below.

If the original is not available, there are two workable routes:

| Route | What you get | Cost |
|---|---|---|
| **A — replay into the Windows Event Log** | Events really do appear in Event Viewer, and can then be exported to a genuine `.evtx` with `wevtutil epl` | Needs Windows + admin PowerShell. Fields land in the Message body as text, so **filtering by Event ID works but XPath filtering by field (`Image`, `DestinationPort`) does not** |
| **B — JSON → CSV → Timeline Explorer / Excel** | Every Sysmon field becomes a sortable, filterable column; pivoting on `ProcessGuid` is a click | Not Event Viewer, but for this investigation it is the better tool and it is what most DFIR work actually uses |

---

## Step 1 — Identify the JSON layout  ☐ not yet done

Nothing gets converted until the layout is known, because every later step
depends on it.

**Windows (PowerShell):**
```powershell
Get-Content .\sysmon-events.json -TotalCount 3
(Get-Content .\sysmon-events.json | Measure-Object -Line).Lines
```

**Linux / macOS / WSL:**
```bash
head -c 600 sysmon-events.json; echo
wc -l sysmon-events.json
```

Read the first character:

| First character | Layout |
|---|---|
| `[` | JSON array of events |
| `{` with many lines | NDJSON — one event per line |
| `{` on essentially one line | a wrapper object such as `{"events":[ ... ]}` |

Then check the field style:

* **Flat** — `"EventID":1,"Image":"C:\\Windows\\..."`
* **Nested (Windows Event Log export)** — `"System":{"EventID":{"#text":"1"}},"EventData":{"Data":[{"@Name":"Image","#text":"..."}]}`

### Findings — `sysmon-events.json`

```
Total events : 1484
Layout       : concatenated JSON objects - one pretty-printed {...} after another,
               NOT an array and NOT NDJSON. json.load() fails with "Extra data".
Field style  : nested Windows Event XML shape, wrapped in an {"Event": {...}} envelope
               Event.System.EventID                                 -> the Event ID
               Event.System.TimeCreated.#attributes.SystemTime      -> the timestamp
               Event.EventData.<FieldName>                          -> named keys (not a Data list)
Host         : MSEDGEWIN10
Channel      : Microsoft-Windows-Sysmon/Operational
Time range   : 2021-05-07T12:18:52.399390Z -> 2021-05-07T12:33:03.669198Z  (~14 minutes)
EventRecordID: 1482 -> 3012
```

The `xmlns` attribute (`schemas.microsoft.com/win/2004/08/events/event`) confirms
this is a direct Event-XML-to-JSON conversion of the original `.evtx`.

**Consequence for every later step:** the file cannot be read with a plain
`json.load()` or line-by-line. It needs a decoder that reads one object at a
time and reports where it stopped:

```python
import json
text = open("sysmon-events.json", encoding="utf-8").read()
decoder, position, events = json.JSONDecoder(), 0, []
while position < len(text):
    while position < len(text) and text[position] in " \t\r\n":
        position += 1
    if position >= len(text):
        break
    obj, position = decoder.raw_decode(text, position)
    events.append(obj)
print(len(events))          # 1484
```

The whole investigation covers about 14 minutes on one host, which is small
enough to read end to end. That is worth knowing: automation is a convenience
here, not a necessity.

---

## Step 2 — Replay into the Windows Event Log (Route A)  ☐ not yet done

Needs a Windows machine and an **Administrator** PowerShell window.

### 2a. Turn the concatenated objects into one array PowerShell can parse

Every top-level closing brace sits at column 0, while nested ones are indented,
so a comma can be appended to exactly those and the whole thing wrapped in `[ ]`.

```powershell
$raw    = Get-Content .\sysmon-events.json -Raw
$joined = ($raw -replace "(?m)^\}", "},").Trim().TrimEnd(',')
$events = ConvertFrom-Json ("[" + $joined + "]")
$events.Count          # expect 1484
```

### 2b. Create the destination log (run once)

```powershell
New-EventLog   -LogName "Sysmon-Replay" -Source "SysmonReplay"
Limit-EventLog -LogName "Sysmon-Replay" -MaximumSize 64MB -OverflowAction OverwriteAsNeeded
```

### 2c. Write the events

The original timestamp is preserved in the message body, because
`Write-EventLog` stamps each entry with the time it was written, not the time
it originally occurred.

```powershell
$n = 0
foreach ($e in $events) {
    $ev   = $e.Event
    $id   = [int]$ev.System.EventID
    $time = $ev.System.TimeCreated.'#attributes'.SystemTime
    $rec  = $ev.System.EventRecordID
    $body = "OriginalTime : $time`r`nEventRecordID: $rec`r`nEventID      : $id`r`n`r`n" +
            ($ev.EventData | ConvertTo-Json -Depth 10)
    if ($body.Length -gt 31000) { $body = $body.Substring(0, 31000) }
    Write-EventLog -LogName "Sysmon-Replay" -Source "SysmonReplay" `
                   -EventId $id -EntryType Information -Message $body
    $n++
}
"wrote $n events"
```

### 2d. Open it

Event Viewer → **Applications and Services Logs** → **Sysmon-Replay**.

### 2e. Export a genuine .evtx (optional)

```powershell
wevtutil epl Sysmon-Replay C:\Temp\sysmon-replay.evtx
```

### Undo, if needed

```powershell
Remove-EventLog -LogName "Sysmon-Replay"
```

### Limitations to know before relying on this

| Limitation | Effect |
|---|---|
| Fields live in the Message body as text, not in the structured EventData table | **Filter Current Log → by Event ID works.** Filtering by field via XPath (`*[EventData[Data[@Name='Image']]]`) **does not**. Ctrl+F text search does work. |
| `Write-EventLog` stamps entries with the current time | The Event Viewer time column is useless for ordering. Use `OriginalTime` in the body — this matters for the question about which of several identical commands ran first |
| Event ID must be 0-65535, message capped near 32 KB | Not a problem here: Sysmon uses IDs 1-26 and these events are small |
| Entries are written in file order | Sequence is preserved even though timestamps are not |

### Findings

```
Events written :
Opened in Event Viewer (y/n) :
Notes :
```

---

## Step 3 — (to be added once Step 2 is recorded)
