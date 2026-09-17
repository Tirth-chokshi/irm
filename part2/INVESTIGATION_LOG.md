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

## Step 2 — Convert the file, then replay it into Event Viewer  ☐ not yet done

### Correction to an earlier plan

An earlier draft of this step split the file with the PowerShell regex
`$raw -replace "(?m)^\}", "},"` to turn the concatenated objects into an array.
**That does not work on this file** and was removed. Inspecting the real file
showed it is two exports concatenated with *different indentation*:

* 1000 events are indented two spaces and close with `}` at column 0
* 484 events are indented four spaces and close indented, with no delimiter at column 0

So no line-anchored pattern finds all 1484 boundaries. The file also uses CRLF
line endings, which breaks `$`-anchored patterns as well. The reliable method
is to decode one object at a time and let the decoder report where it stopped —
which is what `tools/convert_sysmon_json.py` does.

### 2a. Convert the JSON into usable formats

Runs anywhere Python 3 is installed — Windows, Linux or Mac.

```bash
python3 tools/convert_sysmon_json.py part1/logs/sysmon-events.json part2/logs
```

Produces two files in `part2/logs/`, both already committed to this repo so
this step can be skipped if you just want the output:

| File | What it is | Use it for |
|---|---|---|
| `sysmon-events.ndjson` | one compact event per line, `{"Event":…}` envelope stripped | feeding the PowerShell import below; also `jq`-friendly |
| `sysmon-events.csv` | 1484 rows x 62 columns, investigation fields ordered first | **Timeline Explorer or Excel — sort and filter every field** |

Verified: all 1484 NDJSON lines parse independently, and the content is
identical to the original objects (round-trip compared, no data lost).

### 2b. Replay into the Windows Event Log

On Windows, in an **Administrator** PowerShell window:

```powershell
.\Import-SysmonToEventViewer.ps1 -Path .\sysmon-events.ndjson
```

Add `-ExportEvtx C:\Temp\sysmon.evtx` to also write out a genuine `.evtx`
file at the end.

The script checks for elevation, creates the log, reads the NDJSON line by
line, and writes each event with its original timestamp on the first line of
the message body.

### 2c. Open it

Event Viewer → **Applications and Services Logs** → **Sysmon-Replay**

### Undo

```powershell
Remove-EventLog -LogName "Sysmon-Replay"
```

### Limitations — read before drawing conclusions

| Limitation | Effect |
|---|---|
| Fields land in the message **body as text**, not the structured EventData table | Filter Current Log → by Event ID works, and Ctrl+F text search works. XPath field filters (`*[EventData[Data[@Name='Image']]]`) do **not**. |
| `Write-EventLog` stamps entries with the time they were **written** | Event Viewer's time column is meaningless for ordering. Use `OriginalTime` on the first line of each message. Entries are written in file order, so sequence is preserved. |
| Message capped near 32 KB, Event ID must be 0-65535 | Not a problem here — Sysmon uses IDs 1-26 and these events are small. |

**Because of limitation 2, the CSV is the better tool for anything involving
ordering or per-field filtering.** Event Viewer is useful for getting a feel
for the data and for screenshots; the CSV is where the actual work happens.

### Findings

```
Events written :
Opened in Event Viewer (y/n) :
Notes :
```

---

## Step 3 — Triage and find an anchor  ☐ not yet done

Do **not** start from question 1. You cannot answer "which file granted
access" until you know what the attacker did, and you learn that by finding
one certainly-bad event first and following it outward.

### The principle

An investigation starts at the **smallest high-signal event set**, not the
biggest one. In this log:

| Event ID | Count | Signal quality |
|---|---|---|
| 11 FileCreate | 815 | Huge and mostly noise — every temp file Windows touches |
| 1 Process creation | 428 | The backbone, but most of it is normal Windows activity |
| 3 Network connection | 200 | Good, once web traffic is set aside |
| **22 DNS query** | **32** | **Best starting point — smallest set, and a domain either belongs to Microsoft or it does not** |

So work 22 → 3 → 1, narrowing as you go.

### 3a. Look at every DNS query (32 events)

In Event Viewer: select **Sysmon-Replay** → right panel → **Filter Current
Log…** → in **"Includes/Excludes Event IDs"** type `22` → OK.

Read the `QueryName` in each message body. Sort them into two piles:

* **Expected** — anything ending in `microsoft.com`, `windows.com`,
  `msftncsi.com`, `live.com`, `bing.com`, `msedge.net`, `windowsupdate.com`.
  MSEDGEWIN10 is a stock Microsoft test VM and chatters constantly.
* **Not expected** — everything else. A domain that is not Microsoft, on a
  test VM that does nothing but run the attack, is your anchor.

Also note which `Image` made each query. A browser resolving a random domain
is ordinary; a process in `\Temp\` or `\Downloads\` resolving one is not.

### 3b. Look at the outbound connections (200 events)

Change the filter to Event ID `3`. You are looking for `DestinationPort`
values that are **not** 80, 443 or 53. There will not be many. Write down
every one, with the `Image` that opened it.

Two different non-web ports usually means two different purposes — worth
noticing now, it matters later.

### 3c. Name your anchor

By the end of 3a and 3b you should be able to finish this sentence with
specifics:

> "Process `____________` connected to `____________` on port `______` at
> `____________`, and that is not something this machine should be doing."

That sentence is your anchor. Everything in Step 4 hangs off it.

### Using Event Viewer effectively here

* **Filter Current Log → Event IDs** is the only structured filter that works
  on this replayed log. Use it constantly.
* **Ctrl+F** searches message text — use it to find a string across events.
* The **Date and Time** column is import time, not real time. Read
  `OriginalTime` on the first line of each message body instead.
* Events are listed in file order, so the list sequence is the true sequence.
* To read many events quickly, widen the bottom preview pane, then walk the
  list with the arrow keys instead of double-clicking each one.

**If clicking through 200 events gets tedious, switch to
`logs/sysmon-events.csv`.** Sort by `EventID`, filter the `DestinationPort`
column, and 3b takes about thirty seconds. That is not cheating — it is what
the tooling is for.

### Findings

```
Unexpected domains (Event ID 22):

Non-web ports and the process that opened each (Event ID 3):

My anchor sentence:
```

---

## Step 4 — (to be added once Step 3 is recorded)
