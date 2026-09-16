#!/usr/bin/env python3
"""
Convert the assignment's sysmon-events.json into formats you can actually work with.

WHY THIS EXISTS
    The supplied file is a concatenation of JSON objects - one {...} after
    another with no array brackets and no commas - and it mixes two different
    indentation styles, so neither json.load() nor a line-by-line read nor any
    regex split will read it correctly. The only reliable way is to decode one
    object at a time and let the decoder tell you where it stopped.

WHAT IT PRODUCES
    sysmon-events.ndjson   one compact event per line - PowerShell, jq and
                           anything else can read this line by line
    sysmon-events.csv      one row per event, every field a column - open in
                           Timeline Explorer or Excel and sort/filter

DEPENDENCIES: none to install. Three standard-library imports.

Usage:
    python3 convert_sysmon_json.py path/to/sysmon-events.json [output_dir]
"""

import csv
import json
import sys


def read_concatenated_json(path):
    """Read a file containing back-to-back JSON objects into a list.

    json.JSONDecoder().raw_decode(text, position) parses ONE value starting at
    position and returns it along with the index it finished at. Looping on
    that handles any layout: pretty-printed, compact, mixed indentation, with
    or without newlines between objects.
    """
    handle = open(path, "r", encoding="utf-8", errors="replace")
    text = handle.read()
    handle.close()

    decoder = json.JSONDecoder()
    events = []
    position = 0
    length = len(text)

    while position < length:
        while position < length and text[position] in " \t\r\n":
            position += 1          # skip whitespace between objects
        if position >= length:
            break
        try:
            obj, position = decoder.raw_decode(text, position)
        except ValueError as error:
            print("  ! stopped at character %d: %s" % (position, error))
            break
        events.append(obj)

    return events


def unwrap(event):
    """Strip the {"Event": {...}} envelope that Event-XML-to-JSON adds."""
    while isinstance(event, dict) and len(event) == 1 and \
            list(event.keys())[0] in ("Event", "event"):
        event = list(event.values())[0]
    return event


def flatten(value, prefix, out):
    """Nested JSON -> {"dotted.key": "text"}, promoting #attributes upward.

    "TimeCreated": {"#attributes": {"SystemTime": "..."}}  becomes
    "TimeCreated.SystemTime": "..."   - the #attributes level is noise.
    """
    if isinstance(value, dict):
        for key in value:
            if key == "#attributes":
                flatten(value[key], prefix, out)      # skip the level entirely
            else:
                child = (prefix + "." + str(key)) if prefix else str(key)
                flatten(value[key], child, out)
    elif isinstance(value, list):
        for position, item in enumerate(value):
            flatten(item, prefix + "[" + str(position) + "]", out)
    else:
        out[prefix] = "" if value is None else str(value)


def simplify(flat):
    """Drop the System./EventData. path prefixes so columns read nicely."""
    simple = {}
    for key in flat:
        name = key
        for prefix in ("System.", "EventData."):
            if name.startswith(prefix):
                name = name[len(prefix):]
        simple.setdefault(name, flat[key])
    return simple


# Columns that matter most in an investigation, shown first in the CSV
PREFERRED_COLUMNS = [
    "EventRecordID", "TimeCreated.SystemTime", "UtcTime", "EventID", "Computer",
    "Image", "CommandLine", "ProcessGuid", "ProcessId", "User",
    "ParentImage", "ParentCommandLine", "ParentProcessGuid",
    "TargetFilename", "ImageLoaded", "TargetObject", "Details",
    "QueryName", "QueryResults", "DestinationIp", "DestinationHostname",
    "DestinationPort", "SourceIp", "SourcePort", "Protocol", "Initiated",
    "Hashes", "CurrentDirectory", "Description", "Company", "Product",
]


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: python3 convert_sysmon_json.py <sysmon-events.json> [output_dir]")

    source = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "."

    print("Reading " + source)
    raw_events = read_concatenated_json(source)
    print("  parsed %d JSON objects" % len(raw_events))

    events = [unwrap(event) for event in raw_events]

    rows = []
    for event in events:
        flat = {}
        flatten(event, "", flat)
        rows.append(simplify(flat))

    # --- NDJSON: one compact event per line ------------------------------
    ndjson_path = out_dir + "/sysmon-events.ndjson"
    handle = open(ndjson_path, "w", encoding="utf-8", newline="\n")
    for event in events:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    handle.close()
    print("  [+] %-34s %d lines" % (ndjson_path, len(events)))

    # --- CSV: one row per event, every field a column --------------------
    all_columns = set()
    for row in rows:
        all_columns.update(row.keys())

    columns = [name for name in PREFERRED_COLUMNS if name in all_columns]
    columns += sorted(name for name in all_columns if name not in columns)

    csv_path = out_dir + "/sysmon-events.csv"
    handle = open(csv_path, "w", encoding="utf-8-sig", newline="")
    writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    handle.close()
    print("  [+] %-34s %d rows, %d columns" % (csv_path, len(rows), len(columns)))

    # --- Summary ----------------------------------------------------------
    counts = {}
    for row in rows:
        eid = row.get("EventID", "?")
        counts[eid] = counts.get(eid, 0) + 1
    times = sorted(row.get("TimeCreated.SystemTime", "") for row in rows)

    print("\nSummary")
    print("  events    : %d" % len(rows))
    print("  hosts     : %s" % ", ".join(sorted(set(
        row.get("Computer", "?") for row in rows))))
    print("  time range: %s -> %s" % (times[0], times[-1]))
    print("  event IDs : %s" % ", ".join(
        "%s(x%d)" % (eid, counts[eid])
        for eid in sorted(counts, key=lambda value: int(value) if value.isdigit() else 999)))


main()
