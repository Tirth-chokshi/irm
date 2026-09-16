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

Extra (for marks / analysis section):
    summary_report.txt   - counts, top talkers, top URLs, status codes
    unparsed_lines.txt   - any line the parser could not understand

Usage:
    python3 log_analysis.py
    python3 log_analysis.py --log logs/apache_logs --outdir output
"""

import argparse
import ipaddress
import os
import re
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# 1. The log format we are parsing (Apache "combined" format)
#
# 83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /path HTTP/1.1" 200 203023
#     "http://referrer/" "Mozilla/5.0 ..."
#  |            | |  |                          |                   |   |
#  ip        ident user      timestamp            request         status size
# ---------------------------------------------------------------------------
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'                                  # client IP / host
    r'(?P<identity>\S+)\s+'                             # RFC 1413 identity ( - )
    r'(?P<user>\S+)\s+'                                 # HTTP auth user   ( - )
    r'\[(?P<timestamp>[^\]]+)\]\s+'                     # [17/May/2015:10:05:03 +0000]
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+'                # "GET /path HTTP/1.1"
    r'(?P<status>\d{3})\s+'                             # 200
    r'(?P<size>\d+|-)'                                  # 203023  or  -
    r'(?:\s+"(?P<referrer>(?:[^"\\]|\\.)*)")?'          # "http://referrer/"
    r'(?:\s+"(?P<useragent>(?:[^"\\]|\\.)*)")?'         # "Mozilla/5.0 ..."
)

# Splits   GET /path?x=1 HTTP/1.1   into method / url / protocol
REQUEST_PATTERN = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<protocol>\S+)$')


def parse_line(line):
    """Return a dict of fields for one log line, or None if it does not match."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    record = match.groupdict()

    # Break the request string into method + URL + protocol
    request = (record.get('request') or '').strip()
    req_match = REQUEST_PATTERN.match(request)
    if req_match:
        record.update(req_match.groupdict())
    else:
        # Malformed / raw requests (scanners, binary junk) still carry a "URL"
        parts = request.split()
        record['method'] = parts[0] if parts else '-'
        record['url'] = parts[1] if len(parts) > 1 else (request or '-')
        record['protocol'] = parts[2] if len(parts) > 2 else '-'

    return record


def ip_sort_key(value):
    """Sort IPv4/IPv6 numerically; keep hostnames at the end, alphabetically."""
    try:
        return (0, ipaddress.ip_address(value))
    except ValueError:
        return (1, value)


def write_lines(path, lines, header=None):
    """Write a list of strings to a file, one per line."""
    with open(path, 'w', encoding='utf-8') as handle:
        if header:
            handle.write(header.rstrip('\n') + '\n')
        for item in lines:
            handle.write(str(item) + '\n')
    print(f'  [+] {path:<45} {len(lines):>6} lines')


def analyse(log_path, out_dir):
    all_ips = []            # every IP, in the order it appears (with repeats)
    all_urls = []           # every URL,in the order it appears (with repeats)
    ip_counter = Counter()
    url_counter = Counter()
    status_counter = Counter()
    bad_lines = []
    total_lines = 0
    total_bytes = 0

    # 2. Read the log line by line (streaming = works on huge files too)
    with open(log_path, 'r', encoding='utf-8', errors='replace') as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            total_lines += 1

            record = parse_line(line)
            if record is None:
                bad_lines.append(f'{line_no}: {line.rstrip()}')
                continue

            ip = record['ip']
            url = record['url']

            all_ips.append(ip)
            all_urls.append(url)
            ip_counter[ip] += 1
            url_counter[url] += 1
            status_counter[record['status']] += 1
            if record['size'] and record['size'].isdigit():
                total_bytes += int(record['size'])

    os.makedirs(out_dir, exist_ok=True)
    join = lambda name: os.path.join(out_dir, name)

    # 3. Write the three required deliverables
    print('\nWriting output files:')
    write_lines(join('a_all_ip_addresses.txt'), all_ips)
    write_lines(join('b_unique_ip_addresses.txt'), sorted(set(all_ips), key=ip_sort_key))
    write_lines(join('c_all_visited_urls.txt'), all_urls)
    write_lines(join('c_unique_visited_urls.txt'), sorted(set(all_urls)))

    if bad_lines:
        write_lines(join('unparsed_lines.txt'), bad_lines)

    # 4. Extra analysis / summary report
    report = []
    report.append('APACHE ACCESS LOG - ANALYSIS SUMMARY')
    report.append('=' * 60)
    report.append(f'Log file                 : {os.path.abspath(log_path)}')
    report.append(f'Total log lines read     : {total_lines}')
    report.append(f'Successfully parsed      : {len(all_ips)}')
    report.append(f'Unparsed / malformed     : {len(bad_lines)}')
    report.append(f'Total IP addresses       : {len(all_ips)}')
    report.append(f'Unique IP addresses      : {len(set(all_ips))}')
    report.append(f'Total URL requests       : {len(all_urls)}')
    report.append(f'Unique URLs visited      : {len(set(all_urls))}')
    report.append(f'Total bytes transferred  : {total_bytes} bytes '
                  f'({total_bytes / (1024 * 1024):.2f} MB)')

    report.append('\nTOP 10 IP ADDRESSES (by number of requests)')
    report.append('-' * 60)
    for ip, count in ip_counter.most_common(10):
        report.append(f'{count:>7}  {ip}')

    report.append('\nTOP 10 REQUESTED URLS')
    report.append('-' * 60)
    for url, count in url_counter.most_common(10):
        report.append(f'{count:>7}  {url}')

    report.append('\nHTTP STATUS CODE DISTRIBUTION')
    report.append('-' * 60)
    for status, count in sorted(status_counter.items()):
        report.append(f'{count:>7}  HTTP {status}')

    write_lines(join('summary_report.txt'), report)

    print('\nDone. Quick stats:')
    print(f'  Total IPs : {len(all_ips)}   Unique IPs : {len(set(all_ips))}')
    print(f'  Total URLs: {len(all_urls)}   Unique URLs: {len(set(all_urls))}')


def main():
    parser = argparse.ArgumentParser(
        description='Apache access log analyser (Assignment-2, Part 1)')
    parser.add_argument('--log', default=os.path.join('logs', 'apache_logs'),
                        help='path to the apache access log file')
    parser.add_argument('--outdir', default='output',
                        help='directory where the output files are written')
    args = parser.parse_args()

    if not os.path.isfile(args.log):
        sys.exit(f'ERROR: log file not found -> {args.log}')

    print(f'Reading log file: {args.log}')
    analyse(args.log, args.outdir)


if __name__ == '__main__':
    main()
