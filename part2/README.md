# Assignment 2 — Part 2: Investigating an Incident (Sysmon)

An endpoint was compromised. `sysmon-events.json` is the host telemetry from that endpoint. The job is to reconstruct what the attacker did and answer eight questions.

> ### Investigate this yourself first
>
> This file is a **method guide**, not a solution. It tells you which Sysmon Event ID and which field answers each question, and leaves the answering to you.
>
> The automated analyser lives in **`solution-checker/`** and is deliberately kept out of the way. Do not run it until you have worked through the log yourself — then use it to check your answers, and read its `evidence_qN.txt` files to see whether it reasoned from the same events you did. Working notes go in `INVESTIGATION_LOG.md`; the document you submit goes in `REPORT_TEMPLATE.md`.
>
> **The log file is not in this repo.** The two filebin.net links in the assignment are blocked by this environment's network policy, and filebin deletes uploads after about a week, so those links are very likely dead for you too. Ask your faculty for the file — and ask for the **original `.evtx`** while you are at it, since the JSON was almost certainly exported from one and the original opens directly in Event Viewer.
>
> **Every answer printed in §6 came from synthetic test fixtures, not from the real log.** They exist to prove the tooling works. They are not answers to your assignment.

---

## 1. The investigator's mindset

Sysmon does not record "an attack". It records **process creations, file writes, network connections, registry writes, DNS queries and DLL loads**, each stamped with a `ProcessGuid`. An investigation is therefore always the same three moves:

```
1. TRIAGE   what event types exist, how many, over what time window?
2. ANCHOR   find one certainly-bad event (an odd process, an external IP)
3. PIVOT    follow its ProcessGuid backwards to the parent (how did it start?)
            and forwards to the children (what did it do next?)
```

`ProcessGuid` is the thread that stitches everything together: the same GUID appears on the Event ID 1 that started a process, on every Event ID 3 connection it opened, every Event ID 11 file it wrote and every Event ID 7 DLL it loaded. **Pivoting on ProcessGuid is the whole technique.** Everything else is filtering.

---

## 2. The Event ID map — memorise this table

| Event ID | Records | What it answers in an investigation |
|---|---|---|
| **1** | Process creation (Image, CommandLine, ParentImage, User, Hashes) | *What ran, with what arguments, started by whom* — the single most useful ID |
| **3** | Network connection (DestinationIp, DestinationPort, Initiated) | *Where it called out to, and on which port* |
| **7** | Image/DLL loaded | *What runtime the program needs* → the language it is written in |
| **11** | FileCreate | *What was dropped on disk* |
| **12/13/14** | Registry add/delete, value set, rename | *Persistence and environment variables* |
| **22** | DNS query (QueryName, QueryResults) | *What domain it resolved before connecting* |
| 8 / 10 | CreateRemoteThread / ProcessAccess | *Injection and credential theft (LSASS)* |
| 15 | FileCreateStreamHash | *Downloaded from the internet (Zone.Identifier ADS)* |
| 17/18 | Named pipe created/connected | *C2 frameworks and lateral movement* |
| 23/26 | File delete | *Anti-forensics / cleanup* |

Full list: <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events>

---

## 3. Strategy — each question mapped to an Event ID and a field

This is the core of the assignment. Every question is "filter to one Event ID, then look at one field".

| # | Question | Event ID | Field to read | Reasoning |
|---|---|---|---|---|
| 1 | Which file granted access? | **11** + **1** | `TargetFilename`, `ParentImage`, `ParentCommandLine` | A document only "grants access" if it *executed* something. Find an Event ID 1 whose `ParentImage` is WINWORD/EXCEL/OUTLOOK/a browser — the lure filename is sitting in that event's `ParentCommandLine`. Cross-check with the Event ID 11 that wrote it to `Downloads\` or `Temp\`. |
| 2 | PowerShell cmdlet for malware retrieval + port | **1** + **3** | `CommandLine`, `DestinationPort` | The cmdlet is in the command line (`Invoke-WebRequest`/`iwr`, `Invoke-RestMethod`, `DownloadString`, `Start-BitsTransfer`). For the port: either it is written into the URL (`http://host:8080/...`), or take the `ProcessGuid` of that PowerShell process and find its Event ID 3. |
| 3 | Identifier of the environment variable | **1** + **13** | `CommandLine`, `TargetObject` | Set via `setx NAME value`, `$env:NAME=`, or `[Environment]::SetEnvironmentVariable('NAME',...)`. Whichever is used, Windows also writes it to the registry, so Event ID 13 shows `HKU\...\Environment\NAME` — the last path segment **is** the identifier. |
| 4 | Which process is the LOLBIN? | **1** | `Image` | A LOLBIN is a *signed Microsoft binary* abused to run attacker code: `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `wmic.exe`, `msbuild.exe`, `cscript/wscript.exe`. Look for one of these with an abnormal parent or an abnormal argument. |
| 5 | Identical simultaneous commands — which ran first? | **1** | `CommandLine` + `UtcTime` | Group Event ID 1 by exact `CommandLine`, keep the groups with more than one entry, sort that group by `UtcTime`, take the earliest. Sub-second timestamps decide it. |
| 6 | What language is the malware written in? | **7** | `ImageLoaded` | This is what "dependency events" means. A program's DLLs betray its runtime: `python3xx.dll` / `_socket.pyd` / `base_library.zip` → **Python** (usually PyInstaller-packed); `mscoree.dll`/`clr.dll` → **.NET (C#)**; `jvm.dll` → **Java**; `node.dll` → **Node.js**. |
| 7 | Complete URL of the next file | **1** + **22** + **3** | `CommandLine`, `QueryName`, `DestinationPort` | Rebuild it from three sources that must agree: the scheme+path from the command line, the hostname from the DNS query, the port from the connection. If the URL is not written literally anywhere, `http://` + `QueryName` + `:` + `DestinationPort` + path. |
| 8 | Reverse-shell port | **3** + **1** | `DestinationPort`, `CommandLine` | **Do not just pick the odd port** — the download/staging port is also odd. A reverse shell is a port opened by a process whose command line *builds a socket*: `New-Object Net.Sockets.TCPClient('ip',PORT)`, `nc -e`, `/dev/tcp/`. Match that process's `ProcessGuid` to its Event ID 3. Ports like 4444 (Metasploit default), 1337, 9001 are strong tells. |

### The kill chain these questions trace

The eight questions walk the standard intrusion in order — say this in your report:

```
Q1  Initial Access      lure document opened            T1566.001  Spearphishing Attachment
Q2  Execution           PowerShell downloads stage 1    T1059.001  PowerShell
                                                        T1105      Ingress Tool Transfer
Q3  Persistence/Defense env var set for the payload     T1574.007  Path Interception
Q4  Defense Evasion     LOLBIN runs the code            T1218      System Binary Proxy Execution
Q5  Discovery           enumeration commands fired      T1033/T1082 System & Owner Discovery
Q6  (attribution)       runtime DLLs reveal language    —
Q7  Command & Control   second-stage download           T1105      Ingress Tool Transfer
Q8  Command & Control   reverse shell back to attacker  T1571      Non-Standard Port
```

---

## 4. Running the script

```bash
cd part2/solution-checker
# put the file here: logs/sysmon-events.json
python3 sysmon_analysis.py
```

Outputs land in `output/`:

| File | Contents |
|---|---|
| `investigation_report.txt` | All eight questions, the method used, and the candidate answer |
| `evidence_q1.txt` … `evidence_q8.txt` | The raw events behind each answer — **this is what you screenshot for your report** |
| `event_id_summary.txt` | How many of each Event ID (do this triage first) |
| `process_tree.txt` | Parent → child tree rebuilt from ProcessGuid, including parents missing from the log |

**Dependencies: none to install.** Two standard-library imports — `json` (the log is JSON) and `os` (creates the output folder).

**The script does not assume a JSON layout.** It accepts a JSON array, JSON-lines/NDJSON, a `{"events": [...]}` wrapper, flat Sysmon fields, and the nested Windows Event Log export shape where fields are `{"@Name": "Image", "#text": "..."}` pairs. Everything is flattened to `field → text`, and field lookup is case-insensitive, so `EventID`, `event_id` and `System.EventID.#text` all resolve.

---

## 5. Doing it by hand (put a couple of these in your report)

The script is a convenience; you should be able to answer each question with one command. Using `jq`:

```bash
# Triage: what event types are present?
jq -r '.EventID' sysmon-events.json | sort | uniq -c | sort -rn

# Q2: every PowerShell download command
jq -r 'select(.EventID==1) | .CommandLine' sysmon-events.json | grep -iE 'invoke-webrequest|iwr|downloadstring|bitstransfer'

# Q4: LOLBIN executions
jq -r 'select(.EventID==1) | "\(.ParentImage) -> \(.Image)"' sysmon-events.json | grep -iE 'mshta|rundll32|regsvr32|certutil|wmic'

# Q5: repeated command lines, most frequent first
jq -r 'select(.EventID==1) | .CommandLine' sysmon-events.json | sort | uniq -c | sort -rn | head

# Q6: dependency (DLL) loads
jq -r 'select(.EventID==7) | .ImageLoaded' sysmon-events.json | sort -u | grep -iE 'python|clr|mscoree|jvm|node'

# Q8: outbound ports, ignoring normal web traffic
jq -r 'select(.EventID==3) | .DestinationPort' sysmon-events.json | sort | uniq -c | sort -rn
```

No `jq`? Plain grep works on a JSON-lines file:

```bash
grep -o '"CommandLine":"[^"]*"' sysmon-events.json | sort | uniq -c | sort -rn | head -20
```

---

## 6. How the tooling was tested

The real log was not reachable, so the script was validated against two synthetic fixtures in `solution-checker/test/` that encode a full attack chain — Outlook drops a `.docm`, Word spawns PowerShell, `Invoke-WebRequest` pulls a `.hta` over port 8080, an environment variable is set, `mshta.exe` executes it, identical discovery commands fire in the same second, a PyInstaller payload loads `python311.dll`, a second stage is fetched, and a `Net.Sockets.TCPClient` reverse shell connects on 4444.

* `solution-checker/test/sample_flat_sysmon.json` — flat Sysmon fields, JSON array
* `solution-checker/test/sample_winevt_sysmon.json` — the same 22 events in nested Windows Event Log shape, NDJSON

Results (**synthetic data — illustrative only, not answers to your assignment**):

```
Q1  C:\Users\jdoe\Downloads\Invoice_Aug2023.docm
Q2  invoke-webrequest    Port: 8080
Q3  KDMTMP
Q4  mshta.exe
Q5  cmd.exe /c whoami /all
Q6  Python  [3 modules]
Q7  http://cdn.malicious-update.io:8080/payload/final_stage.zip
Q8  4444  (Metasploit / msfvenom default handler)
```

All eight answers are **identical across both JSON layouts**, which is what proves the normaliser works. Two bugs were found and fixed during this testing, both worth understanding:

1. **Q8 picked the download port (8080) over the shell port (4444)**, because the staging server was contacted more often. Frequency is the wrong signal. The fix scores a port by *why* it was contacted: +10 if the connecting process's command line builds a socket, +3 for a known C2 port, and ports already explained as a file download are excluded outright. The evidence file prints the scoring so you can audit it.
2. **Ties were broken by `sorted(set(...))`**, and set iteration order depends on Python's per-process string-hash randomisation — the same log gave different answers on different runs. Replaced with a `rank()` helper that breaks ties by first appearance. Verified with six runs under different `PYTHONHASHSEED` values, all byte-identical.

---

## 7. Important caveat on the answers

The script produces **candidates from keyword and Event ID matching, not proof.** Its keyword lists (LOLBINs, download cmdlets, language signatures) cover the common cases; a novel technique will not match. So for every question:

1. Open the matching `evidence_qN.txt`.
2. Confirm the events actually say what the answer claims.
3. If the answer is "No … observed", that is a prompt to look manually — start with `event_id_summary.txt` and `process_tree.txt`.

An answer you have not read the evidence for is a guess, and a viva will find it.

---

## 8. What to submit

`REPORT_TEMPLATE.md` in this folder is the document to fill in and upload. It has: executive summary, timeline, the eight answers each with its evidence and Sysmon Event ID, the reconstructed attack chain, MITRE ATT&CK mapping, IOCs, and detection/remediation recommendations.
