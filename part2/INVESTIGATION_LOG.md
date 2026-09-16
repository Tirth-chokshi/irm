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

### Findings

```
Total events :
Layout       :
Field style  :
Time range   :
```

---

## Step 2 — (to be added once Step 1 is recorded)
