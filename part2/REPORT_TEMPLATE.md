# Incident Investigation Report — Sysmon Endpoint Compromise

**Student:**
**Course / Batch:**
**Date:**
**Evidence file:** `sysmon-events.json`  (SHA256: ____________________)

---

## 1. Executive summary

*Three to five sentences, no jargon: what happened, how the attacker got in,
what they achieved, and whether the compromise is contained.*

---

## 2. Scope and methodology

* **Evidence analysed:** Sysmon operational log from the compromised endpoint — _____ events spanning _____ to _____.
* **Tools used:**
* **Method:** Event ID triage → anchor on a known-bad event → pivot on `ProcessGuid` backwards to the parent and forwards to the children → rebuild the timeline.

### Event ID distribution

| Event ID | Meaning | Count |
|---|---|---|
| 1 | Process creation | |
| 3 | Network connection | |
| 7 | Image/DLL loaded | |
| 11 | FileCreate | |
| 12/13 | Registry | |
| 22 | DNS query | |

---

## 3. Answers to the assignment questions

> For each: state the answer, name the Sysmon Event ID it came from, and paste
> the raw event (or a screenshot) that proves it. An answer without its
> supporting event is a guess.

### Q1. Which file granted the attacker access?
**Answer:**
**Evidence (Event ID ___):**
```

```
**Reasoning:**

### Q2. Which PowerShell cmdlet retrieved the malware, and on what port?
**Answer:**
**Evidence (Event ID ___):**
```

```
**Reasoning:**

### Q3. What is the identifier of the environment variable the attacker set?
**Answer:**
**Evidence (Event ID ___):**
```

```
**Reasoning:**

### Q4. Which process is the LOLBIN used to run malicious commands?
**Answer:**
**Evidence (Event ID ___):**
```

```
**Reasoning:** *(why is this a LOLBIN — what is the binary's legitimate purpose, and how was it abused?)*

### Q5. The malware ran several identical commands at once — what ran first?
**Answer:**
**Evidence (Event ID ___):**
```

```
**Reasoning:** *(how did you order them — which timestamp field, and to what precision?)*

### Q6. What language is the malware written in?
**Answer:**
**Evidence (Event ID ___):**
```

```
**Reasoning:** *(which loaded modules give it away, and what do they belong to?)*

### Q7. What is the complete URL of the next file downloaded?
**Answer:**
**Evidence (Event ID ___):**
```

```
**Reasoning:** *(which parts came from the command line, the DNS query, and the connection?)*

### Q8. Which port does the attacker use for the reverse shell?
**Answer:**
**Evidence (Event ID ___):**
```

```
**Reasoning:** *(how did you separate the reverse-shell port from the download/staging port?)*

---

## 4. Attack chain reconstruction

*Narrative, in order, from the lure to the shell. One paragraph or a numbered
list — but it must read as a story, not a list of findings.*

### Process tree

```
```

### Timeline

| # | Time (UTC) | Event ID | What happened |
|---|---|---|---|
| 1 | | | |
| 2 | | | |

---

## 5. MITRE ATT&CK mapping

| Stage | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Spearphishing Attachment | T1566.001 | |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | |
| Defense Evasion | System Binary Proxy Execution | T1218 | |
| Discovery | System / Owner Discovery | T1082, T1033 | |
| Command and Control | Ingress Tool Transfer | T1105 | |
| Command and Control | Non-Standard Port | T1571 | |

---

## 6. Indicators of compromise

| Type | Indicator | Where observed |
|---|---|---|
| File | | Event ID 11 |
| Process | | Event ID 1 |
| Registry / env var | | Event ID 13 |
| Domain | | Event ID 22 |
| IP : Port | | Event ID 3 |
| URL | | Event ID 1 |

---

## 7. Detection and remediation recommendations

**Detection** — *what Sysmon or SIEM rule would have caught this earlier? Be specific: which Event ID, which field, which condition.*

1.
2.

**Containment and remediation** — *what to do on this host, and what to change org-wide.*

1.
2.

---

## 8. Conclusion
