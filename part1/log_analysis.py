#!/usr/bin/env python3
"""
Practical Assignment - 2 | Part 1 : Log Analysis Using Python
-------------------------------------------------------------
Parses an Apache access log (Combined Log Format) and writes the required
outputs as individual files:

    a) LIST OF ALL IP ADDRESSES          -> a_all_ip_addresses.txt
    b) LIST OF ALL UNIQUE IP ADDRESSES   -> b_unique_ip_addresses.txt
    c) LIST OF ALL THE VISITED URLS      -> c_all_visited_urls.txt
                                            c_unique_visited_urls.txt

Extra (for the analysis section of the report):
    summary_report.txt   - counts, top talkers, top URLs, status codes
    unparsed_lines.txt   - any line the parser could not understand

DEPENDENCIES: none.
    No third-party packages, and only ONE standard-library import (`os`),
    used solely to create the output folder. Everything else - parsing,
    counting, sorting - is plain Python string/list/dict work.

Usage:
    python3 log_analysis.py

    To use a different log file, edit the two settings below.
"""

import os  # only for os.makedirs() - creates the output folder if missing

# ---------------------------------------------------------------------------
# Settings - edit these two lines to point at your own files
# ---------------------------------------------------------------------------
LOG_FILE = "logs/apache_logs"
OUTPUT_DIR = "output"


# ---------------------------------------------------------------------------
# 1. The log format we are parsing (Apache "combined" format)
#
# 83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /path HTTP/1.1" 200 203023
# |             | |  |                           |                   |   |
# ip         ident user      timestamp         request             status size
#
# Splitting strategy, using nothing but str.split():
#   * the IP  is everything before the FIRST space
#   * the request line is the text inside the FIRST pair of double quotes,
#     so line.split('"')[1]  ->  'GET /path HTTP/1.1'
#   * the URL is the 2nd token of that request line
#   * status + size are the first two tokens AFTER that closing quote
# ---------------------------------------------------------------------------


def parse_line(line):
    """Pull (ip, url, status, size) out of one log line.

    Returns None if the line does not look like a valid access-log entry.
    """
    line = line.strip()
    if not line:
        return None

    # The IP address: everything before the first space
    ip = line.split(" ", 1)[0]

    # Split on the double-quote character.
    #   parts[0] = '83.149.9.216 - - [17/May/2015:10:05:03 +0000] '
    #   parts[1] = 'GET /path HTTP/1.1'          <- the request line
    #   parts[2] = ' 200 203023 '                <- status and size
    #   parts[3] = referrer,  parts[5] = user-agent
    parts = line.split('"')
    if len(parts) < 3:
        return None  # no quoted request -> not a valid line

    request_tokens = parts[1].split()  # ['GET', '/path', 'HTTP/1.1']
    if len(request_tokens) < 2:
        return None  # no URL in the request line
    url = request_tokens[1]

    after_tokens = parts[2].split()  # ['200', '203023']
    status = after_tokens[0] if after_tokens else "-"
    size = after_tokens[1] if len(after_tokens) > 1 else "-"

    # A valid entry always carries a 3-digit HTTP status code
    if len(status) != 3 or not status.isdigit():
        return None

    return ip, url, status, size


def is_ipv4(text):
    """True if text is a dotted-quad IPv4 address (four numbers, each 0-255)."""
    octets = text.split(".")
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet.isdigit() or not 0 <= int(octet) <= 255:
            return False
    return True


def ip_sort_key(ip):
    """Sort IPv4 addresses numerically; anything else goes last, A-Z.

    Without this, a plain text sort compares character by character and puts
    10.0.0.1 before 9.0.0.1, because the character '1' sorts before '9'.
    """
    if is_ipv4(ip):
        return (0, [int(octet) for octet in ip.split(".")])
    return (1, ip)


def count_items(items):
    """Frequency table as a plain dict: {value: how many times it appeared}."""
    counts = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    return counts


def top_n(counts, n):
    """The n most frequent entries, highest count first (ties sorted A-Z)."""
    ordered = sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
    return ordered[:n]


def write_file(name, lines):
    """Write a list of values to OUTPUT_DIR/name, one per line."""
    path = OUTPUT_DIR + "/" + name
    handle = open(path, "w", encoding="utf-8")
    for item in lines:
        handle.write(str(item) + "\n")
    handle.close()
    print("  [+] %-42s %6d lines" % (path, len(lines)))


def main():
    all_ips = []     # every IP, in order of appearance (repeats kept)
    all_urls = []    # every URL, in order of appearance (repeats kept)
    statuses = []    # every status code, for the distribution table
    bad_lines = []   # lines the parser rejected
    total_lines = 0
    total_bytes = 0

    # 2. Read the log line by line. Iterating the file object streams one line
    #    at a time, so this works on a 2 MB log and on a 2 GB log alike.
    print("Reading log file: " + LOG_FILE)
    log = open(LOG_FILE, "r", encoding="utf-8", errors="replace")
    for line_no, line in enumerate(log, 1):
        if not line.strip():
            continue
        total_lines += 1

        record = parse_line(line)
        if record is None:
            bad_lines.append(str(line_no) + ": " + line.rstrip())
            continue

        ip, url, status, size = record
        all_ips.append(ip)
        all_urls.append(url)
        statuses.append(status)
        if size.isdigit():
            total_bytes += int(size)
    log.close()

    # 3. De-duplicate with set(), then sort (sets have no order of their own)
    unique_ips = sorted(set(all_ips), key=ip_sort_key)
    unique_urls = sorted(set(all_urls))

    # 4. Write the required deliverables, one file per answer
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("\nWriting output files:")
    write_file("a_all_ip_addresses.txt", all_ips)
    write_file("b_unique_ip_addresses.txt", unique_ips)
    write_file("c_all_visited_urls.txt", all_urls)
    write_file("c_unique_visited_urls.txt", unique_urls)
    if bad_lines:
        write_file("unparsed_lines.txt", bad_lines)

    # 5. Extra analysis / summary report
    ip_counts = count_items(all_ips)
    url_counts = count_items(all_urls)
    status_counts = count_items(statuses)
    non_ipv4 = [ip for ip in unique_ips if not is_ipv4(ip)]

    report = []
    report.append("APACHE ACCESS LOG - ANALYSIS SUMMARY")
    report.append("=" * 60)
    report.append("Log file                 : " + LOG_FILE)
    report.append("Total log lines read     : %d" % total_lines)
    report.append("Successfully parsed      : %d" % len(all_ips))
    report.append("Unparsed / malformed     : %d" % len(bad_lines))
    report.append("Total IP addresses       : %d" % len(all_ips))
    report.append("Unique IP addresses      : %d" % len(unique_ips))
    report.append("Non-IPv4 hosts in log    : %d" % len(non_ipv4))
    report.append("Total URL requests       : %d" % len(all_urls))
    report.append("Unique URLs visited      : %d" % len(unique_urls))
    report.append("Total bytes transferred  : %d bytes (%.2f MB)"
                  % (total_bytes, total_bytes / (1024.0 * 1024.0)))

    report.append("")
    report.append("TOP 10 IP ADDRESSES (by number of requests)")
    report.append("-" * 60)
    for ip, count in top_n(ip_counts, 10):
        report.append("%7d  %s" % (count, ip))

    report.append("")
    report.append("TOP 10 REQUESTED URLS")
    report.append("-" * 60)
    for url, count in top_n(url_counts, 10):
        report.append("%7d  %s" % (count, url))

    report.append("")
    report.append("HTTP STATUS CODE DISTRIBUTION")
    report.append("-" * 60)
    for status in sorted(status_counts):
        report.append("%7d  HTTP %s" % (status_counts[status], status))

    write_file("summary_report.txt", report)

    print("\nDone. Quick stats:")
    print("  Total IPs : %-8d Unique IPs : %d" % (len(all_ips), len(unique_ips)))
    print("  Total URLs: %-8d Unique URLs: %d" % (len(all_urls), len(unique_urls)))


main()
