#!/usr/bin/env python3
"""
Practical Assignment - 2 | Part 2 : Investigating an Incident (Sysmon)
----------------------------------------------------------------------
Reads sysmon-events.json and works through the eight investigation
questions, printing the candidate answer plus the raw events that support it.

DEPENDENCIES: none to install.
    Two standard-library imports: `json` (the log is JSON - writing a JSON
    parser by hand would be pointless) and `os` (creates the output folder).
    Everything else is plain Python.

The log's exact JSON shape is not assumed. The loader accepts:
    * a JSON array of events            [ {...}, {...} ]
    * JSON-lines / NDJSON               {...}\n{...}
    * a wrapper object                  {"events": [ ... ]}
    * flat Sysmon fields                {"EventID": 1, "Image": "..."}
    * Windows Event Log export shape    {"System": {"EventID": {"#text": 1}},
                                         "EventData": {"Data": [
                                            {"@Name": "Image", "#text": "..."}]}}
Every event is flattened to plain "field -> text" pairs, so the same
analysis code works on all of them.

Usage:
    python3 sysmon_analysis.py          # edit LOG_FILE below if needed
"""

import json  # the log is JSON
import os    # only for os.makedirs()

# ---------------------------------------------------------------------------
# Settings - edit these two lines to point at your own files
# ---------------------------------------------------------------------------
LOG_FILE = "logs/sysmon-events.json"
OUTPUT_DIR = "output"

# ---------------------------------------------------------------------------
# Reference data used by the analysis
# ---------------------------------------------------------------------------

# Sysmon Event ID -> what it records (https://learn.microsoft.com/sysinternals)
EVENT_NAMES = {
    "1": "Process creation",
    "2": "File creation time changed",
    "3": "Network connection",
    "4": "Sysmon service state changed",
    "5": "Process terminated",
    "6": "Driver loaded",
    "7": "Image (DLL) loaded",
    "8": "CreateRemoteThread",
    "9": "RawAccessRead",
    "10": "ProcessAccess",
    "11": "FileCreate",
    "12": "Registry object added/deleted",
    "13": "Registry value set",
    "14": "Registry key/value renamed",
    "15": "FileCreateStreamHash",
    "16": "Sysmon configuration changed",
    "17": "Pipe created",
    "18": "Pipe connected",
    "19": "WmiEventFilter activity",
    "20": "WmiEventConsumer activity",
    "21": "WmiEventConsumerToFilter activity",
    "22": "DNS query",
    "23": "File delete (archived)",
    "24": "Clipboard change",
    "25": "Process tampering",
    "26": "File delete (logged)",
    "255": "Sysmon error",
}

# Documents / archives / scripts that typically deliver initial access
LURE_EXTENSIONS = [
    ".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm",
    ".pdf", ".rtf", ".one", ".lnk", ".iso", ".img", ".zip", ".rar", ".7z",
    ".hta", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".chm", ".scr", ".bat",
    ".cmd", ".ps1", ".msi", ".jar", ".py",
]

# Office / mail / browser processes: a child process here means the document ran code
DELIVERY_PARENTS = [
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "acrord32.exe", "wordpad.exe", "chrome.exe", "firefox.exe", "msedge.exe",
    "iexplore.exe", "explorer.exe", "7zfm.exe", "winrar.exe",
]

# Living Off the Land Binaries - signed Microsoft tools abused to run code
LOLBINS = [
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "cscript.exe", "wscript.exe", "msbuild.exe", "installutil.exe",
    "mavinject.exe", "forfiles.exe", "cmstp.exe", "odbcconf.exe", "msiexec.exe",
    "hh.exe", "ieexec.exe", "pcalua.exe", "scriptrunner.exe", "xwizard.exe",
    "expand.exe", "extrac32.exe", "makecab.exe", "esentutl.exe", "curl.exe",
    "explorer.exe", "control.exe", "dllhost.exe", "conhost.exe", "at.exe",
    "schtasks.exe", "regasm.exe", "regsvcs.exe", "ftp.exe", "print.exe",
]

# PowerShell / Windows ways of pulling a file down from the network
DOWNLOAD_CMDLETS = [
    "invoke-webrequest", "iwr", "invoke-restmethod", "irm", "wget", "curl",
    "downloadstring", "downloadfile", "downloaddata", "start-bitstransfer",
    "net.webclient", "system.net.webclient", "bitsadmin", "certutil -urlcache",
    "invoke-expression", "iex",
]

# Ways of creating/changing an environment variable
ENVVAR_MARKERS = [
    "setx", "$env:", "set-item env:", "setenvironmentvariable",
    "\\environment\\", "environment variable",
]

# Loaded module -> language the running program was written in (Sysmon Event 7)
LANGUAGE_SIGNATURES = [
    ("Python", ["python3", "python2", "python.dll", "python27", "python31",
                "python.exe", "pythoncom", "pywintypes", "_ctypes.pyd",
                "vcruntime140.dll+python", "site-packages", "library.zip",
                "base_library.zip", "_socket.pyd", "select.pyd", "unicodedata.pyd"]),
    (".NET (C#/VB.NET)", ["mscoree.dll", "mscorlib", "clr.dll", "clrjit.dll",
                          "coreclr.dll", "system.ni.dll", "system.dll",
                          "microsoft.csharp"]),
    ("Java", ["jvm.dll", "java.dll", "jli.dll", "verify.dll", "zip.dll+java"]),
    ("Node.js / JavaScript", ["node.dll", "node.exe", "libnode"]),
    ("Go", ["go-build", "golang"]),
    ("AutoIt", ["autoit"]),
    ("PowerShell / .NET scripting", ["system.management.automation"]),
    ("Visual C / C++ (native)", ["msvcrt.dll", "vcruntime", "msvcp"]),
]

# Command-line patterns that mean "open a shell back to the attacker"
SHELL_MARKERS = [
    "tcpclient", "net.sockets", "system.net.sockets", "-e cmd", "-e /bin/",
    "nc.exe", "ncat", "socat", "reverse_tcp", "reverse_shell", "meterpreter",
    "/dev/tcp/", "invoke-shellcode", "powercat", "bind_tcp", "-nolisten",
]

# Ports worth calling out when they appear in a connection
NOTABLE_PORTS = {
    "4444": "Metasploit / msfvenom default handler",
    "4443": "common reverse-shell / C2 port",
    "1337": "classic 'leet' backdoor port",
    "9001": "common reverse-shell port",
    "9002": "common reverse-shell port",
    "8080": "HTTP alternate - common malware staging server",
    "8000": "HTTP alternate - common python -m http.server",
    "8888": "HTTP alternate - common staging server",
    "443": "HTTPS (also hides C2 traffic)",
    "80": "HTTP",
    "53": "DNS (also DNS tunnelling)",
    "445": "SMB - lateral movement / file share",
    "3389": "RDP",
    "22": "SSH",
}

# ---------------------------------------------------------------------------
# 1. Loading and normalising the log
# ---------------------------------------------------------------------------


def load_events(path):
    """Return a list of event dicts, whatever JSON layout the file uses."""
    handle = open(path, "r", encoding="utf-8", errors="replace")
    text = handle.read()
    handle.close()

    # Try the whole file as one JSON document first
    try:
        data = json.loads(text)
    except ValueError:
        data = None

    if data is None:
        # Fall back 1: concatenated JSON objects - }{ back to back, often
        # pretty-printed over many lines. raw_decode reads one object at a
        # time and reports where it stopped, so we walk the whole file.
        decoder = json.JSONDecoder()
        events = []
        position = 0
        length = len(text)
        while position < length:
            while position < length and text[position] in " \t\r\n":
                position += 1
            if position >= length:
                break
            try:
                obj, position = decoder.raw_decode(text, position)
            except ValueError:
                break
            events.append(obj)
        if events:
            return unwrap(events)

        # Fall back 2: JSON-lines - one complete JSON object per line
        events = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
        return unwrap(events)

    if isinstance(data, list):
        return unwrap(data)
    if isinstance(data, dict):
        # A wrapper object such as {"events": [...]} or {"Events": {...}}
        for key in ("events", "Events", "records", "Records", "data", "value"):
            if key in data and isinstance(data[key], list):
                return unwrap(data[key])
        return unwrap([data])
    return []


def unwrap(events):
    """Strip the {"Event": {...}} envelope that Event-XML-to-JSON exports add."""
    result = []
    for event in events:
        while (isinstance(event, dict) and len(event) == 1 and
               list(event.keys())[0] in ("Event", "event", "Events")):
            event = list(event.values())[0]
        result.append(event)
    return result


def flatten(value, prefix, out):
    """Flatten nested JSON into {"dotted.key": "text value"}.

    Windows Event Log exports store fields as a list of name/value pairs:
        "Data": [{"@Name": "Image", "#text": "C:\\...\\cmd.exe"}]
    Those are promoted to real fields ("Image") so they can be read directly.
    """
    if isinstance(value, dict):
        for key in value:
            child = (prefix + "." + str(key)) if prefix else str(key)
            flatten(value[key], child, out)
    elif isinstance(value, list):
        promoted = False
        for item in value:
            if isinstance(item, dict):
                name = item.get("@Name", item.get("Name", item.get("name")))
                if name is not None:
                    text = item.get("#text", item.get("Text", item.get("value", "")))
                    flatten(text, str(name), out)
                    promoted = True
        if not promoted:
            for position, item in enumerate(value):
                flatten(item, prefix + "[" + str(position) + "]", out)
    else:
        out[prefix] = "" if value is None else str(value)


def normalise(event):
    """One event -> a lookup table that tolerates different field spellings."""
    flat = {}
    flatten(event, "", flat)

    index = {}
    for key in flat:
        value = flat[key]
        parts = key.split(".")
        # "System.EventID.#text" should also be reachable as "eventid"
        if parts and parts[-1] in ("#text", "Text", "value"):
            parts = parts[:-1]
        if not parts:
            continue
        index.setdefault(key.lower(), value)
        index.setdefault(parts[-1].lower(), value)
    return index


def field(event, *names):
    """First non-empty value among the given field names (case-insensitive)."""
    for name in names:
        value = event.get(name.lower(), "")
        if value:
            return value
    return ""


def event_id(event):
    return field(event, "EventID", "Event_ID", "event_id", "ID", "eventidentifier")


def describe(event):
    """One-line rendering of an event for the evidence section of the report."""
    eid = event_id(event)
    time = field(event, "UtcTime", "TimeCreated", "SystemTime", "timestamp", "@timestamp")
    parts = ["[EID " + (eid or "?") + " " + EVENT_NAMES.get(eid, "?") + "]"]
    if time:
        parts.append(time)
    for name in ("Image", "TargetFilename", "QueryName", "DestinationIp",
                 "ImageLoaded", "TargetObject"):
        value = field(event, name)
        if value:
            parts.append(name + "=" + value)
            break
    for name in ("CommandLine", "Details", "DestinationPort", "QueryResults"):
        value = field(event, name)
        if value:
            parts.append(name + "=" + value)
    return " | ".join(parts)


def by_event_id(events, *wanted):
    wanted = [str(item) for item in wanted]
    return [event for event in events if event_id(event) in wanted]


def contains_any(text, needles):
    """Return the needles found in text (case-insensitive)."""
    lowered = text.lower()
    return [needle for needle in needles if needle in lowered]


def rank(items):
    """Most frequent first, ties broken by first appearance.

    Using sorted(set(items)) here would be a bug: set iteration order depends
    on Python's per-run string hash randomisation, so the same log could give
    a different answer on a different run.
    """
    counts = {}
    first_seen = {}
    for position, item in enumerate(items):
        counts[item] = counts.get(item, 0) + 1
        first_seen.setdefault(item, position)
    return sorted(counts, key=lambda item: (-counts[item], first_seen[item]))


def sort_by_time(events):
    return sorted(events, key=lambda event: field(
        event, "UtcTime", "TimeCreated", "SystemTime", "timestamp", "@timestamp"))


def basename(path):
    return path.replace("/", "\\").split("\\")[-1]


# ---------------------------------------------------------------------------
# 2. One analyser per investigation question
#    Each returns (answer_text, [evidence lines])
# ---------------------------------------------------------------------------


def q1_initial_access(events):
    """Which file granted the attacker access?

    Strategy: a document only "grants access" if it ran something. So look for
    Event ID 1 whose ParentImage is Office/mail/browser, then tie that back to
    the Event ID 11 (FileCreate) that dropped the document on disk.
    """
    evidence = []
    suspects = []

    for event in by_event_id(events, 1):
        parent = field(event, "ParentImage")
        if basename(parent).lower() in DELIVERY_PARENTS:
            parent_cmd = field(event, "ParentCommandLine")
            evidence.append("child of delivery app -> " + describe(event))
            if parent_cmd:
                evidence.append("    ParentCommandLine=" + parent_cmd)
                for extension in LURE_EXTENSIONS:
                    for token in parent_cmd.replace('"', " ").split():
                        if token.lower().endswith(extension):
                            suspects.append(token)

    for event in by_event_id(events, 11, 15):
        target = field(event, "TargetFilename")
        for extension in LURE_EXTENSIONS:
            if target.lower().endswith(extension):
                evidence.append("dropped lure file -> " + describe(event))
                suspects.append(target)
                break

    if not suspects:
        return ("No lure document identified automatically - "
                "review the Event ID 11 list manually.", evidence)

    ranked = rank(suspects)
    return ("Most likely file: " + ranked[0] +
            ("   (other candidates: " + ", ".join(ranked[1:4]) + ")" if len(ranked) > 1 else ""),
            evidence)


def q2_download_cmdlet(events):
    """Which PowerShell cmdlet retrieves the malware, and on what port?

    Strategy: Event ID 1 command lines containing a download cmdlet give the
    cmdlet; the port comes either from the URL in that command line or from the
    Event ID 3 network connection made by the same process (match ProcessGuid).
    """
    evidence = []
    cmdlets = []
    ports = []
    guids = []

    for event in by_event_id(events, 1):
        command = field(event, "CommandLine")
        found = contains_any(command, DOWNLOAD_CMDLETS)
        if found:
            cmdlets.extend(found)
            guids.append(field(event, "ProcessGuid", "ProcessId"))
            evidence.append("download command -> " + describe(event))
            for port in extract_ports_from_urls(command):
                ports.append(port)

    for event in by_event_id(events, 3):
        guid = field(event, "ProcessGuid", "ProcessId")
        port = field(event, "DestinationPort")
        if guid and guid in guids and port:
            ports.append(port)
            evidence.append("connection by the same process -> " + describe(event))

    if not cmdlets:
        return ("No download cmdlet found - widen the search to Event ID 3 "
                "destination ports.", evidence)

    cmdlet = rank(cmdlets)[0]
    if ports:
        port = rank(ports)[0]
        note = NOTABLE_PORTS.get(port, "")
        answer = ("Cmdlet: " + cmdlet + "    Port: " + port +
                  ("  (" + note + ")" if note else ""))
    else:
        answer = "Cmdlet: " + cmdlet + "    Port: not observed"
    return (answer, evidence)


def extract_ports_from_urls(text):
    """Pull the :port out of any http://host:port/... appearing in text."""
    ports = []
    lowered = text.lower()
    marker = 0
    while True:
        start = lowered.find("http", marker)
        if start == -1:
            break
        marker = start + 4
        chunk = text[start:].split()[0].strip('"\'();,')
        without_scheme = chunk.split("//", 1)[-1]
        host = without_scheme.split("/", 1)[0]
        if ":" in host:
            candidate = host.rsplit(":", 1)[-1]
            if candidate.isdigit():
                ports.append(candidate)
        elif chunk.lower().startswith("https"):
            ports.append("443")
        elif chunk.lower().startswith("http"):
            ports.append("80")
    return ports


def q3_environment_variable(events):
    """What is the identifier (name) of the environment variable the attacker set?

    Strategy: two places record it - Event ID 1 command lines using setx /
    $env: / SetEnvironmentVariable, and Event ID 12/13 registry writes under
    ...\\Environment\\<NAME>.
    """
    evidence = []
    names = []

    for event in by_event_id(events, 1):
        command = field(event, "CommandLine")
        if contains_any(command, ENVVAR_MARKERS):
            evidence.append("env-var command -> " + describe(event))
            names.extend(parse_env_names(command))

    for event in by_event_id(events, 12, 13, 14):
        target = field(event, "TargetObject")
        if "\\environment\\" in target.lower():
            evidence.append("registry env write -> " + describe(event))
            names.append(target.replace("/", "\\").split("\\")[-1])

    if not names:
        return ("No environment variable creation observed.", evidence)
    ranked = rank(names)
    return ("Environment variable: " + ranked[0] +
            ("   (also seen: " + ", ".join(ranked[1:4]) + ")" if len(ranked) > 1 else ""),
            evidence)


def parse_env_names(command):
    """Best-effort extraction of the variable name from a command line."""
    names = []
    tokens = command.replace('"', " ").replace("'", " ").split()
    lowered = [token.lower() for token in tokens]

    for position, token in enumerate(lowered):
        # setx NAME value      /     set NAME=value
        if token in ("setx", "set") and position + 1 < len(tokens):
            candidate = tokens[position + 1]
            names.append(candidate.split("=")[0])
        # $env:NAME = "value"
        if token.startswith("$env:"):
            names.append(tokens[position].split(":", 1)[1].split("=")[0])
        # [Environment]::SetEnvironmentVariable("NAME", ...)
        if "setenvironmentvariable" in token:
            tail = command[command.lower().find("setenvironmentvariable"):]
            inside = tail.split("(", 1)[-1]
            first = inside.replace('"', ",").replace("'", ",").split(",")
            for piece in first:
                piece = piece.strip()
                if piece and piece not in ("(", ")"):
                    names.append(piece)
                    break
    return [name.strip(" ;=$") for name in names if name.strip(" ;=$")]


def q4_lolbin(events):
    """Which process is the LOLBIN used to run malicious commands?

    Strategy: Event ID 1, keep processes whose image is a known LOLBIN, and
    rank by how much they were used. A LOLBIN spawned by Office or PowerShell
    outranks one spawned normally.
    """
    evidence = []
    hits = []

    for event in by_event_id(events, 1):
        image = basename(field(event, "Image")).lower()
        if image in LOLBINS:
            parent = basename(field(event, "ParentImage")).lower()
            weight = 2 if parent in DELIVERY_PARENTS or "powershell" in parent else 1
            hits.extend([image] * weight)
            evidence.append("LOLBIN execution -> " + describe(event))
            evidence.append("    ParentImage=" + field(event, "ParentImage"))

    if not hits:
        return ("No known LOLBIN observed.", evidence)
    ranked = rank(hits)
    return ("LOLBIN: " + ranked[0] +
            ("   (also present: " + ", ".join(ranked[1:4]) + ")" if len(ranked) > 1 else ""),
            evidence)


def q5_repeated_commands(events):
    """The malware ran several identical commands at once - what ran first?

    Strategy: group Event ID 1 by command line, keep groups that fired more
    than once, then sort that group by UtcTime and take the earliest entry.
    """
    evidence = []
    groups = {}

    for event in by_event_id(events, 1):
        command = field(event, "CommandLine")
        if not command:
            continue
        groups.setdefault(command, []).append(event)

    repeated = [(command, group) for command, group in groups.items() if len(group) > 1]
    if not repeated:
        return ("No command line was executed more than once.", evidence)

    repeated.sort(key=lambda pair: -len(pair[1]))
    for command, group in repeated[:5]:
        times = sorted(field(event, "UtcTime", "TimeCreated", "SystemTime")
                       for event in group)
        evidence.append("x%d  %s" % (len(group), command))
        evidence.append("    first=%s  last=%s" % (times[0], times[-1]))

    # Earliest event across every repeated group = the first command executed
    first_event = sort_by_time([event for _, group in repeated for event in group])[0]
    return ("First of the repeated commands: " +
            field(first_event, "CommandLine") + "\n            executed at " +
            field(first_event, "UtcTime", "TimeCreated", "SystemTime"), evidence)


def q6_malware_language(events):
    """What language is the malware written in?

    Strategy: Event ID 7 (ImageLoad) is the dependency record. The set of DLLs
    a process loads identifies its runtime - python3xx.dll means Python,
    mscoree/clr means .NET, jvm.dll means Java, and so on.
    """
    evidence = []
    scores = {}

    for event in by_event_id(events, 7, 6):
        loaded = field(event, "ImageLoaded", "Image")
        for language, markers in LANGUAGE_SIGNATURES:
            if contains_any(loaded, markers):
                scores[language] = scores.get(language, 0) + 1
                evidence.append(language + " dependency -> " + describe(event))
                break

    if not scores:
        return ("No Event ID 7 (ImageLoad) records matched a known runtime.",
                evidence)

    ranked = sorted(scores.items(), key=lambda pair: (-pair[1], pair[0]))
    summary = ", ".join(name + " (" + str(count) + " modules)" for name, count in ranked)
    return ("Language: " + ranked[0][0] + "    [evidence counts: " + summary + "]",
            evidence)


def q7_download_url(events):
    """Full URL of the NEW file the malware fetches after it starts running.

    Strategy: collect every URL that appears anywhere in the log together with
    the time of the event that carried it, then put them in chronological
    order. The first URL is the initial stage (that is Q2). The question asks
    what is fetched *after* that, so the answer is the next distinct URL in
    the timeline. Event ID 22 (DNS) and Event ID 3 (connection) to the same
    host corroborate it.
    """
    evidence = []
    timeline = []

    for event in sort_by_time(events):
        when = field(event, "UtcTime", "TimeCreated", "SystemTime", "timestamp")
        for name in ("CommandLine", "TargetFilename", "QueryName", "Details",
                     "DestinationHostname", "QueryResults", "ImageLoaded"):
            value = field(event, name)
            if "http://" in value.lower() or "https://" in value.lower():
                for url in extract_urls(value):
                    timeline.append((when, url, describe(event)))

    seen = []
    for when, url, description in timeline:
        if url not in [item[1] for item in seen]:
            seen.append((when, url, description))

    evidence.append("URLs in chronological order:")
    for position, (when, url, description) in enumerate(seen, 1):
        evidence.append("  %d. %s  %s" % (position, when, url))
        evidence.append("       via " + description)
    evidence.append("")
    for event in by_event_id(events, 22):
        evidence.append("DNS query -> " + describe(event))
    for event in by_event_id(events, 3):
        evidence.append("network connection -> " + describe(event))

    if not seen:
        return ("No literal URL found - rebuild it from the Event ID 22 "
                "QueryName plus the Event ID 3 DestinationPort.", evidence)
    if len(seen) == 1:
        return ("Only one URL in the log: " + seen[0][1] +
                "   (same as the Q2 download - no second file observed)", evidence)

    answer = ("Download URL (2nd stage): " + seen[1][1] +
              "\n            first seen at " + seen[1][0] +
              "\n            initial stage was " + seen[0][1] + " (see Q2)")
    if len(seen) > 2:
        answer += ("\n            later URLs: " +
                   ", ".join(item[1] for item in seen[2:5]))
    return (answer, evidence)


def extract_urls(text):
    urls = []
    lowered = text.lower()
    marker = 0
    while True:
        start = lowered.find("http", marker)
        if start == -1:
            break
        marker = start + 4
        chunk = text[start:].split()[0]
        urls.append(chunk.strip('"\'();,'))
    return urls


def q8_reverse_shell_port(events):
    """Which port does the attacker try to use for a reverse shell?

    Strategy: a reverse shell is not just "an odd port" - it is a port opened
    by a process whose command line builds a socket back to the attacker
    (TCPClient, Net.Sockets, nc -e, /dev/tcp/...). So:
      1. find those processes in Event ID 1,
      2. take the Event ID 3 ports they connected on (strongest evidence),
      3. ignore ports already explained as file downloads (that is Q2/Q7),
      4. fall back to any remaining non-web port.
    """
    evidence = []
    scores = {}

    def add(port, weight, why):
        if not port or port in ("80", "443", "53"):
            return
        scores[port] = scores.get(port, 0) + weight
        evidence.append("  +%-2d %-6s %s" % (weight, port, why))

    # Ports that are explained by a download - these are staging ports, not shells
    download_ports = set()
    download_guids = set()
    for event in by_event_id(events, 1):
        command = field(event, "CommandLine")
        if contains_any(command, DOWNLOAD_CMDLETS) or "http" in command.lower():
            download_guids.add(field(event, "ProcessGuid", "ProcessId"))
            for port in extract_ports_from_urls(command):
                download_ports.add(port)
    for event in by_event_id(events, 3):
        if field(event, "ProcessGuid", "ProcessId") in download_guids:
            download_ports.add(field(event, "DestinationPort"))

    # Processes whose command line actually builds a shell socket
    shell_guids = set()
    for event in by_event_id(events, 1):
        command = field(event, "CommandLine")
        if contains_any(command, SHELL_MARKERS):
            shell_guids.add(field(event, "ProcessGuid", "ProcessId"))
            evidence.append("reverse-shell command -> " + describe(event))
            for token in command.replace('"', " ").replace("'", " ").replace("(", " ").replace(")", " ").replace(",", " ").split():
                stripped = token.strip(":;")
                if stripped.isdigit() and 1 <= int(stripped) <= 65535:
                    add(stripped, 5, "port literal inside the shell command")

    for event in by_event_id(events, 3):
        port = field(event, "DestinationPort")
        guid = field(event, "ProcessGuid", "ProcessId")
        evidence.append("connection -> " + describe(event))
        if guid in shell_guids:
            add(port, 10, "connection made by the shell process itself")
        elif port in download_ports:
            evidence.append("  --  %-6s skipped: already explained as a file download"
                            % port)
        elif port in NOTABLE_PORTS:
            add(port, 3, "known C2/backdoor port: " + NOTABLE_PORTS[port])
        else:
            add(port, 1, "non-web outbound port")

    if not scores:
        return ("No reverse-shell port observed.", evidence)

    ranked = sorted(scores.items(), key=lambda pair: (-pair[1], pair[0]))
    best, best_score = ranked[0]
    note = NOTABLE_PORTS.get(best, "")
    answer = ("Reverse-shell port: " + best + ("  (" + note + ")" if note else "") +
              "   [score %d]" % best_score)
    if len(ranked) > 1:
        answer += ("\n            runners-up: " +
                   ", ".join("%s (score %d)" % pair for pair in ranked[1:4]))
    if download_ports:
        answer += ("\n            download/staging ports excluded: " +
                   ", ".join(sorted(port for port in download_ports if port)))
    return (answer, evidence)


# ---------------------------------------------------------------------------
# 3. Supporting output: event summary and process tree
# ---------------------------------------------------------------------------


def event_summary(events):
    counts = {}
    for event in events:
        eid = event_id(event) or "?"
        counts[eid] = counts.get(eid, 0) + 1

    lines = ["SYSMON EVENT ID SUMMARY", "=" * 60,
             "Total events: %d" % len(events), ""]
    for eid in sorted(counts, key=lambda value: (len(value), value)):
        lines.append("%7d  EID %-4s %s"
                     % (counts[eid], eid, EVENT_NAMES.get(eid, "unknown")))
    return lines


def process_tree(events):
    """Parent -> child listing built from ProcessGuid / ParentProcessGuid.

    A process whose parent has no Event ID 1 of its own becomes a root, and the
    tree notes what that missing parent was - that is often the most important
    line in the whole investigation (e.g. "parent: WINWORD.EXE, not in log").
    """
    creations = sort_by_time(by_event_id(events, 1))

    labels = {}        # guid -> "image   commandline"
    parent_of = {}     # guid -> parent guid        (dict lookup, not a scan)
    parent_image = {}  # guid -> parent image name
    children = {}      # parent guid -> [child guid, ...]

    for event in creations:
        guid = field(event, "ProcessGuid", "ProcessId")
        parent_guid = field(event, "ParentProcessGuid", "ParentProcessId")
        labels[guid] = field(event, "Image") + "   " + field(event, "CommandLine")
        parent_of[guid] = parent_guid
        parent_image[guid] = field(event, "ParentImage")
        children.setdefault(parent_guid, []).append(guid)

    lines = ["PROCESS TREE (from Event ID 1)", "=" * 60]

    def walk(guid, depth, seen):
        if guid in seen:                      # guard against a malformed cycle
            lines.append("  " * depth + "|- [cycle] " + guid)
            return
        lines.append("  " * depth + "|- " + labels.get(guid, guid))
        for child in children.get(guid, []):
            walk(child, depth + 1, seen + [guid])

    roots = [guid for guid in labels if parent_of.get(guid) not in labels]
    for root in roots:
        missing = parent_image.get(root, "")
        if missing:
            lines.append("[parent not in log: " + missing + "]")
        walk(root, 0, [])

    if not roots:
        lines.append("(no root found - every process has a logged parent)")
        for event in creations:
            lines.append("|- " + field(event, "Image") + "   " +
                         field(event, "CommandLine"))
    return lines


# ---------------------------------------------------------------------------
# 4. Run everything and write the report
# ---------------------------------------------------------------------------

QUESTIONS = [
    ("Q1", "Which file granted the attacker access?",
     "Event ID 1 (ParentImage = Office/mail/browser) + Event ID 11 (FileCreate)",
     q1_initial_access),
    ("Q2", "Which PowerShell cmdlet retrieves the malware, and on what port?",
     "Event ID 1 (CommandLine) + Event ID 3 (DestinationPort)",
     q2_download_cmdlet),
    ("Q3", "What is the identifier of the environment variable the attacker set?",
     "Event ID 1 (setx / $env: / SetEnvironmentVariable) + Event ID 12/13 (\\Environment\\)",
     q3_environment_variable),
    ("Q4", "Which process is the LOLBIN used to run malicious commands?",
     "Event ID 1 (Image matches a known LOLBIN)",
     q4_lolbin),
    ("Q5", "Several identical commands ran at once - what was the first?",
     "Event ID 1 grouped by CommandLine, earliest UtcTime wins",
     q5_repeated_commands),
    ("Q6", "What language is the malware written in?",
     "Event ID 7 (ImageLoad) - the dependency/runtime DLLs it pulls in",
     q6_malware_language),
    ("Q7", "What is the complete URL of the next file downloaded?",
     "Event ID 1 (CommandLine) + Event ID 22 (DNS) + Event ID 3 (connection)",
     q7_download_url),
    ("Q8", "Which port is used for the reverse shell?",
     "Event ID 3 (DestinationPort), cross-checked with Event ID 1",
     q8_reverse_shell_port),
]


def write_file(name, lines):
    path = OUTPUT_DIR + "/" + name
    handle = open(path, "w", encoding="utf-8")
    for line in lines:
        handle.write(str(line) + "\n")
    handle.close()
    print("  [+] %-40s %5d lines" % (path, len(lines)))


def main():
    print("Reading Sysmon log: " + LOG_FILE)
    events = [normalise(raw) for raw in load_events(LOG_FILE)]
    print("Loaded %d events\n" % len(events))

    report = ["SYSMON INCIDENT INVESTIGATION - ANSWER SHEET",
              "=" * 72,
              "Log file    : " + LOG_FILE,
              "Total events: %d" % len(events), ""]
    evidence_pages = []

    for tag, question, method, analyser in QUESTIONS:
        answer, evidence = analyser(events)
        print("%s  %s" % (tag, answer.split("\n")[0]))

        report.append(tag + ". " + question)
        report.append("-" * 72)
        report.append("  Method  : " + method)
        report.append("  ANSWER  : " + answer)
        report.append("  Evidence: %d supporting event(s) -> evidence_%s.txt"
                      % (len(evidence), tag.lower()))
        report.append("")

        page = [tag + ". " + question, "=" * 72, "Method: " + method,
                "Answer: " + answer, "", "SUPPORTING EVENTS", "-" * 72]
        page.extend(evidence if evidence else ["(none found)"])
        evidence_pages.append((tag.lower(), page))

    report.append("NOTE: every answer above is a candidate produced by keyword and")
    report.append("Event ID matching. Confirm each one against the evidence file")
    report.append("before writing it into the final report.")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("\nWriting output files:")
    write_file("investigation_report.txt", report)
    for tag, page in evidence_pages:
        write_file("evidence_" + tag + ".txt", page)
    write_file("event_id_summary.txt", event_summary(events))
    write_file("process_tree.txt", process_tree(events))
    print("\nDone. Start with output/investigation_report.txt")


main()
