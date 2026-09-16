# Assignment 2 — Part 1: Log Analysis Using Python

Parse the Apache access log and produce **three individual output files**:

| # | Required output | File produced |
|---|---|---|
| a | List of all IP addresses | `output/a_all_ip_addresses.txt` |
| b | List of all unique IP addresses | `output/b_unique_ip_addresses.txt` |
| c | List of all the visited URLs | `output/c_all_visited_urls.txt` (every hit) + `output/c_unique_visited_urls.txt` (de-duplicated) |

Bonus files for the analysis/marks section: `output/summary_report.txt`, and `output/unparsed_lines.txt` (only created if some line fails to parse).

> **Dependencies: none.** No third-party packages (nothing to `pip install`), and only **one** standard-library import — `os`, used solely to create the output folder. All parsing, counting and sorting is plain Python: `str.split()`, `list`, `dict`, `set`.

---

## 1. Strategy — how to attack this problem

The whole task is **one pipeline**. Build it in this order; each step is independently testable.

```
 log file ──▶ read line by line ──▶ split into fields ──▶ collect ──▶ de-duplicate ──▶ write files
   (I/O)         (streaming)          (the hard part)      (lists)      (set())         (output)
```

### Step 1 — Understand the log format *before* writing any code
This log is the Apache **Combined Log Format**. Take one line and map every field:

```
83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /presentations/... HTTP/1.1" 200 203023 "http://semicomplete.com/..." "Mozilla/5.0 ..."
│            │ │  │                            │                                 │   │      │                             │
│            │ │  │                            │                                 │   │      │                             └─ user-agent
│            │ │  │                            │                                 │   │      └─ referrer
│            │ │  │                            │                                 │   └─ bytes sent  (can be "-")
│            │ │  │                            │                                 └─ HTTP status code
│            │ │  │                            └─ request line: METHOD  URL  PROTOCOL   ← the URL lives here
│            │ │  └─ timestamp in [ ]
│            │ └─ authenticated user   ("-" = none)
│            └─ RFC-1413 identity      ("-" = none)
└─ client IP address                                                           ← field (a) and (b)
```

Two conclusions fall out of this map:
* **IP = field 1**, i.e. everything before the first space.
* **URL = the 2nd token inside the first quoted string**, *not* a whole field — so it needs a second, nested split.

### Step 2 — Choose the parsing technique
Three options; the point is to pick one **deliberately** and be able to justify it:

| Technique | Verdict |
|---|---|
| `line.split()` and take fixed positions | ❌ Works for the IP, **breaks for the URL** — the user-agent contains spaces, so token numbers shift from line to line. |
| **Split on the quote character `"`, then split the request** | ✅ **Used here.** The quotes are the structural markers of the format, so the field boundaries are exact regardless of how many spaces a user-agent contains. No imports needed. |
| Regular expressions (`re` module) | Also correct, and it validates the whole line in one step — but it is an extra dependency and much harder to explain line by line. Kept as an alternative in §5. |

The chosen technique in three lines (this is the heart of the script):

```python
ip    = line.split(" ", 1)[0]     # everything before the first space
parts = line.split('"')           # parts[1] = 'GET /path HTTP/1.1', parts[2] = ' 200 203023 '
url   = parts[1].split()[1]       # 2nd token of the request line
```

Splitting one sample line on `"` gives:

| index | content | use |
|---|---|---|
| `parts[0]` | `83.149.9.216 - - [17/May/2015:10:05:03 +0000] ` | IP + timestamp |
| `parts[1]` | `GET /presentations/... HTTP/1.1` | **request line → URL** |
| `parts[2]` | ` 200 203023 ` | status + bytes |
| `parts[3]` | `http://semicomplete.com/...` | referrer |
| `parts[5]` | `Mozilla/5.0 ...` | user-agent |

### Step 3 — Validate instead of trusting
A line is accepted only if it has a quoted request (`len(parts) >= 3`), the request holds at least a method and a URL, and the token after the closing quote is a **3-digit number** (the HTTP status). Anything else goes to `unparsed_lines.txt` with its line number, so bad data is *reported* rather than silently turning into a garbage "IP".

### Step 4 — Read the file the right way
Iterate the file object (`for line in log:`) instead of `read()` / `readlines()`. It streams one line at a time, so the script behaves the same on a 2 MB log and on a 2 GB log. Open with `errors="replace"` so one corrupt byte cannot crash the run.

### Step 5 — Collect while you parse (single pass)
One pass fills everything: `all_ips` and `all_urls` as plain **lists** preserving order of appearance (answers a and c), plus the status codes and a running byte total for the report. No second read of the file.

### Step 6 — Count with a dict, sort with a key
* **Counting** — `counts[item] = counts.get(item, 0) + 1`. That is all `collections.Counter` does internally; doing it by hand removes the import and is one line.
* **De-duplicating** — `set(all_ips)`. Hash-based, so it is O(n); `if x not in list` would be O(n²).
* **Sorting IPs numerically** — a set has no order, so sort before writing. `ip_sort_key()` converts `"83.149.9.216"` into `[83, 149, 9, 216]` so the numbers compare as numbers. A plain text sort would put `10.0.0.1` before `9.0.0.1`, because the character `"1"` sorts before `"9"`. Hostnames (no dotted quad) return `(1, text)` so they land after all real IPs, alphabetically.

### Step 7 — Write each answer to its own file
The assignment says *"in form of individual files"* — one deliverable per file, one value per line, named `a_`, `b_`, `c_` so the evaluator maps them to the questions instantly.

### Step 8 — Verify, don't trust
Prove the Python is right by recomputing the same numbers with a completely different tool (see §4). A result you have independently reproduced is worth an extra line in the report.

---

## 2. How to run

```bash
cd part1
python3 log_analysis.py
```

To point it at a different log file, edit the two settings at the top of `log_analysis.py`:

```python
LOG_FILE   = "logs/apache_logs"
OUTPUT_DIR = "output"
```

The output folder is created automatically if it does not exist. Works on any Python 3.x — no virtual environment, no installs.

---

## 3. Results on the supplied log

```
Total log lines read     : 10000
Successfully parsed      : 10000
Unparsed / malformed     : 0
Total IP addresses       : 10000
Unique IP addresses      : 1753
Non-IPv4 hosts in log    : 0
Total URL requests       : 10000
Unique URLs visited      : 1498
Total bytes transferred  : 2747282740 bytes (2620.01 MB)

Top talker : 66.249.73.135  (482 requests — Googlebot)
Top URL    : /favicon.ico   (807 requests)
```

---

## 4. Verification (put this in your report)

Recompute the same answers with shell tools and compare:

```bash
# unique IP count
awk '{print $1}' logs/apache_logs | sort -u | wc -l           # 1753

# unique URL count  (field 2 of the quoted request string)
awk -F'"' '{print $2}' logs/apache_logs | awk '{print $2}' | sort -u | wc -l   # 1498

# prove the two IP lists are byte-for-byte identical
diff <(awk '{print $1}' logs/apache_logs | sort -u) <(sort output/b_unique_ip_addresses.txt)
# (no output = identical)
```

Both tools independently give **1753 unique IPs** and **1498 unique URLs**.

The parser was also tested on a deliberately messy log containing a junk line, a request with no URL, a Common-Log-Format line with no referrer/user-agent, a `-` byte count, a blank line and a hostname instead of an IP: the two bad lines were rejected into `unparsed_lines.txt`, everything else parsed, and the IPs sorted as `1.2.3.4 < 9.0.0.1 < 10.0.0.1 < 83.149.9.216 < 192.168.1.1 < crawler.example.com` — which is exactly what the numeric sort key is there to guarantee.

**Known limitation:** a URL containing a literal (un-encoded) space would be cut at the space, since the request line is tokenised on whitespace. Apache percent-encodes spaces as `%20`, so this does not occur in practice.

---

## 5. Alternative technique — the regex version

If asked "could this be done with regular expressions?", yes — this is the same job in one pattern. It is not used in the final script because it adds the `re` import for no extra accuracy on this data (both versions were run and produced byte-for-byte identical output files):

```python
import re
pattern = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(?:\S+) (\S+) [^"]*" \d{3}')
ips, urls = [], []
for line in open("logs/apache_logs"):
    m = pattern.match(line)
    if m:
        ips.append(m.group(1))   # group 1 = IP
        urls.append(m.group(2))  # group 2 = URL

open("all_ips.txt",    "w").write("\n".join(ips))
open("unique_ips.txt", "w").write("\n".join(sorted(set(ips))))
open("urls.txt",       "w").write("\n".join(urls))
```

Regex wins when the format is irregular or when escaped quotes (`\"`) appear inside a quoted field — this log contains none, which was confirmed with `grep -c '\\"' logs/apache_logs` → `0`.

---

## 6. Likely viva questions

| Question | Answer |
|---|---|
| Which libraries did you use? | None. One standard-library import (`os`) just to create the output folder; the analysis itself uses only built-in strings, lists, dicts and sets. |
| Why split on `"` instead of on spaces? | The user-agent and referrer contain spaces, so counting space-separated tokens is unreliable. The quote characters are the format's real field boundaries. |
| Why is the unique count lower than the total? | The same client makes many requests — 10000 requests came from 1753 distinct hosts. |
| Why the custom IP sort key? | Text sorting compares character by character, so `10.0.0.1` would come before `9.0.0.1`. Converting to `[10, 0, 0, 1]` sorts numerically. |
| What is `set()` doing here? | Hash-based de-duplication in O(n), instead of O(n²) with `if x not in list`. |
| How do you know a line is valid? | It must contain a quoted request with at least a method and a URL, followed by a 3-digit status code. Failures are written to `unparsed_lines.txt` with line numbers. |
| What does the URL field actually mean? | The path requested on the server (from the request line), not a full `http://host/...` URL — the host lives in the `Host:` header, which this format does not log. |
| How would you scale this to a 10 GB log? | It already streams line by line; write results incrementally and replace `set()` with an on-disk `sort -u` step if the unique values stop fitting in RAM. |
| How does this relate to incident response? | The same pipeline feeds detection: top-talker IPs → brute force or scraping, 404 spikes → directory enumeration, odd user-agents → automated tooling. |
