# Assignment 2 — Part 1: Log Analysis Using Python

Parse the Apache access log and produce **three individual output files**:

| # | Required output | File produced |
|---|---|---|
| a | List of all IP addresses | `output/a_all_ip_addresses.txt` |
| b | List of all unique IP addresses | `output/b_unique_ip_addresses.txt` |
| c | List of all the visited URLs | `output/c_all_visited_urls.txt` (every hit) + `output/c_unique_visited_urls.txt` (de-duplicated) |

Bonus files for the analysis/marks section: `output/summary_report.txt`, and `output/unparsed_lines.txt` (only created if some line fails to parse).

---

## 1. Strategy — how to attack this problem

The whole task is **one pipeline**. Build it in this order; each step is independently testable.

```
 log file ──▶ read line by line ──▶ regex parse into fields ──▶ collect ──▶ de-duplicate ──▶ write files
   (I/O)         (streaming)            (the hard part)        (lists)      (set())          (output)
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
Three options, pick deliberately and say why in your report:

| Technique | Code | Verdict |
|---|---|---|
| `line.split()` | `ip = line.split()[0]` | Fine for the IP. **Breaks for the URL** — the user-agent contains spaces, so token positions shift. |
| `split('"')` | split on quote characters | Works, but silently mangles lines containing escaped `\"`. |
| **Regular expression** | one `re.compile()` with named groups | ✅ Used here. Validates the line *and* extracts every field at once; a line that does not match is flagged instead of producing garbage. |

The regex used (`LOG_PATTERN` in `log_analysis.py`) — each group is one log field:

```python
r'^(?P<ip>\S+)\s+'                       # client IP
r'(?P<identity>\S+)\s+'                  # identity  ( - )
r'(?P<user>\S+)\s+'                      # auth user ( - )
r'\[(?P<timestamp>[^\]]+)\]\s+'          # [17/May/2015:10:05:03 +0000]
r'"(?P<request>(?:[^"\\]|\\.)*)"\s+'     # "GET /path HTTP/1.1"
r'(?P<status>\d{3})\s+'                  # 200
r'(?P<size>\d+|-)'                       # 203023 or -
r'(?:\s+"(?P<referrer>(?:[^"\\]|\\.)*)")?'
r'(?:\s+"(?P<useragent>(?:[^"\\]|\\.)*)")?'
```

Key details worth mentioning in the viva:
* `(?P<name>...)` = **named group**, so fields are read as `record['ip']`, not `match.group(1)`.
* `(?:[^"\\]|\\.)*` accepts escaped quotes inside a quoted field instead of ending it early.
* `(?:...)?` on the last two groups keeps the parser working on plain **Common** Log Format lines (no referrer/user-agent).
* The request string is then split a second time by `REQUEST_PATTERN` → `method`, `url`, `protocol`.

### Step 3 — Read the file the right way
Iterate the file object (`for line in handle:`) instead of `read()` / `readlines()`. It streams one line at a time, so the script works the same on a 2 MB log and on a 2 GB log. Open with `errors='replace'` so one corrupt byte cannot crash the run.

### Step 4 — Collect while you parse (single pass)
One pass fills everything:
* `all_ips` / `all_urls` — plain **lists**, preserving order of appearance → answers (a) and (c).
* `Counter()` for IPs, URLs, status codes → the frequency analysis, free of extra loops.
* `total_bytes` accumulator, and `bad_lines` for anything the regex rejected.

### Step 5 — De-duplicate correctly
`set(all_ips)` gives uniqueness, but sets are unordered — sort before writing:
* **IPs are sorted numerically**, via `ipaddress.ip_address()` as the sort key. Plain text sort would put `2.38.110.208` after `199.x` (string order: `"1" < "2" < "9"` compares character by character). Hostnames that cannot be converted are pushed to the end via the tuple key `(0, ip)` / `(1, text)`.
* URLs are sorted alphabetically.

### Step 6 — Write each answer to its own file
The assignment says *"in form of individual files"* — one deliverable per file, one value per line, named `a_`, `b_`, `c_` so the evaluator maps them to the question instantly.

### Step 7 — Verify, don't trust
Prove the Python is right by recomputing the same numbers with a completely different tool (see §4). A result you have independently reproduced is worth an extra line in the report.

---

## 2. How to run

```bash
cd part1
python3 log_analysis.py                              # uses logs/apache_logs → output/
python3 log_analysis.py --log /path/to/your.log --outdir output
```

No third-party packages — standard library only (`re`, `os`, `sys`, `argparse`, `ipaddress`, `collections`).

Replace `logs/apache_logs` with the exact file your faculty attached if it differs; everything else stays the same.

---

## 3. Results on the supplied log

```
Total log lines read     : 10000
Successfully parsed      : 10000
Unparsed / malformed     : 0
Total IP addresses       : 10000
Unique IP addresses      : 1753
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

---

## 5. Minimal version (for explaining the core idea)

If asked "what is the smallest code that does this?", this is the 10-line core the full script is built around:

```python
import re
pattern = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(?:\S+) (\S+) [^"]*" \d{3}')
ips, urls = [], []
for line in open('logs/apache_logs'):
    m = pattern.match(line)
    if m:
        ips.append(m.group(1))
        urls.append(m.group(2))

open('all_ips.txt',    'w').write('\n'.join(ips))
open('unique_ips.txt', 'w').write('\n'.join(sorted(set(ips))))
open('urls.txt',       'w').write('\n'.join(urls))
```

`log_analysis.py` adds on top of this: error handling for malformed lines, numeric IP sorting, CLI arguments, the frequency/summary report, and streaming I/O.

---

## 6. Likely viva questions

| Question | Answer |
|---|---|
| Why regex instead of `split()`? | The user-agent field contains spaces, so fixed token indexes are unreliable; regex validates the line structure and names each field. |
| Why is the unique count lower than the total? | Same client makes many requests — 10000 requests came from 1753 distinct hosts. |
| Why sort IPs with `ipaddress`? | String sorting compares character by character, so `10.0.0.1` would sort before `9.0.0.1`. Numeric sorting orders them correctly. |
| What is a `set` doing here? | Hash-based membership → de-duplication in O(n) instead of O(n²) with `if x not in list`. |
| What does the URL field actually mean? | The path requested on the server (from the request line), not the full `http://host/...` URL — the host is in the `Host:` header, which is not logged in this format. |
| How would you scale this to a 10 GB log? | Already streaming line-by-line; write results incrementally, replace `set()` with an on-disk/`sort -u` step or a Bloom filter if unique counts exceed RAM. |
| How does this relate to incident response? | Same pipeline feeds detection: top-talker IPs → brute force/scraping, 404 spikes → directory enumeration, odd user-agents → automated tooling. |
