#!/usr/bin/env python3
"""
============================================================
siem_parser.py — SIEM Log Parser & Normalizer
Normalisasi log dari berbagai sumber menjadi format JSON seragam:
  - Nginx / Apache access log
  - Linux auth.log (SSH login)
  - Linux syslog
  - UFW firewall log
  - Windows Event Log (exported CSV)
============================================================
"""

import re
import os
import json
import datetime
from pathlib import Path

# ── Warna ────────────────────────────────────────────────────
class C:
    RED    = "\033[0;31m"
    YELLOW = "\033[1;33m"
    GREEN  = "\033[0;32m"
    BLUE   = "\033[0;34m"
    CYAN   = "\033[0;36m"
    RESET  = "\033[0m"

def red(t):    return f"{C.RED}{t}{C.RESET}"
def green(t):  return f"{C.GREEN}{t}{C.RESET}"
def yellow(t): return f"{C.YELLOW}{t}{C.RESET}"
def blue(t):   return f"{C.BLUE}{t}{C.RESET}"

# ════════════════════════════════════════════════════════════
# REGEX PATTERNS
# ════════════════════════════════════════════════════════════

PATTERNS = {
    "nginx_apache": re.compile(
        r'(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    ),
    "auth_log": re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+'
        r'(?P<hostname>\S+)\s+(?P<service>\S+):\s+(?P<message>.+)'
    ),
    "syslog": re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+'
        r'(?P<hostname>\S+)\s+(?P<process>[^\[]+)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.+)'
    ),
    "ufw": re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+kernel:'
        r'.*\[UFW (?P<action>\w+)\].*'
        r'SRC=(?P<src_ip>\S+).*DST=(?P<dst_ip>\S+).*'
        r'(?:SPT=(?P<src_port>\d+))?.*(?:DPT=(?P<dst_port>\d+))?'
    ),
}

# ════════════════════════════════════════════════════════════
# DETEKSI TIPE LOG
# ════════════════════════════════════════════════════════════

def detect_log_type(filepath: str) -> str:
    """Auto-deteksi tipe log dari nama file dan konten."""
    name = Path(filepath).name.lower()

    if any(k in name for k in ("access", "nginx", "apache", "httpd")):
        return "nginx_apache"
    if "auth" in name:
        return "auth_log"
    if "ufw" in name or "firewall" in name:
        return "ufw"
    if name.endswith(".csv"):
        return "windows_event"

    # Cek isi file
    try:
        with open(filepath, "r", errors="replace") as f:
            sample = f.read(500)
        if '"GET' in sample or '"POST' in sample:
            return "nginx_apache"
        if "UFW" in sample:
            return "ufw"
        if "sshd" in sample or "Failed password" in sample:
            return "auth_log"
    except Exception:
        pass

    return "syslog"

# ════════════════════════════════════════════════════════════
# PARSERS PER TIPE LOG
# ════════════════════════════════════════════════════════════

def parse_nginx_apache(line: str) -> dict | None:
    m = PATTERNS["nginx_apache"].match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    # Parse timestamp
    try:
        ts = datetime.datetime.strptime(d["timestamp"][:20], "%d/%b/%Y:%H:%M:%S")
        d["@timestamp"] = ts.isoformat()
    except ValueError:
        d["@timestamp"] = d["timestamp"]

    return {
        "@timestamp"  : d["@timestamp"],
        "log_type"    : "web_access",
        "src_ip"      : d["src_ip"],
        "method"      : d.get("method", "-"),
        "path"        : d.get("path", "-"),
        "status"      : int(d.get("status", 0)),
        "size"        : d.get("size", "0"),
        "user_agent"  : d.get("user_agent", "-"),
        "referer"     : d.get("referer", "-"),
        "raw"         : line.strip(),
    }

def parse_auth_log(line: str) -> dict | None:
    m = PATTERNS["auth_log"].match(line.strip())
    if not m:
        return None
    d = m.groupdict()

    # Deteksi event spesifik
    msg    = d.get("message", "")
    event  = "unknown"
    src_ip = None
    user   = None

    if "Failed password" in msg:
        event = "ssh_failed_login"
        ip_m  = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
        usr_m = re.search(r'for (?:invalid user )?(\S+)', msg)
        src_ip = ip_m.group(1) if ip_m else None
        user   = usr_m.group(1) if usr_m else None
    elif "Accepted password" in msg or "Accepted publickey" in msg:
        event = "ssh_success_login"
        ip_m  = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
        usr_m = re.search(r'for (\S+) from', msg)
        src_ip = ip_m.group(1) if ip_m else None
        user   = usr_m.group(1) if usr_m else None
    elif "Invalid user" in msg:
        event = "ssh_invalid_user"
        ip_m  = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
        src_ip = ip_m.group(1) if ip_m else None
    elif "session opened" in msg:
        event = "session_opened"
    elif "session closed" in msg:
        event = "session_closed"
    elif "sudo" in d.get("service", ""):
        event = "sudo_command"

    year = datetime.datetime.now().year
    try:
        ts = datetime.datetime.strptime(
            f"{year} {d['month']} {d['day']} {d['time']}", "%Y %b %d %H:%M:%S"
        )
        timestamp = ts.isoformat()
    except ValueError:
        timestamp = f"{d.get('month')} {d.get('day')} {d.get('time')}"

    return {
        "@timestamp" : timestamp,
        "log_type"   : "auth",
        "event"      : event,
        "src_ip"     : src_ip,
        "user"       : user,
        "hostname"   : d.get("hostname"),
        "service"    : d.get("service"),
        "message"    : msg,
        "raw"        : line.strip(),
    }

def parse_ufw(line: str) -> dict | None:
    m = PATTERNS["ufw"].match(line.strip())
    if not m:
        return None
    d = m.groupdict()

    year = datetime.datetime.now().year
    try:
        ts = datetime.datetime.strptime(
            f"{year} {d['month']} {d['day']} {d['time']}", "%Y %b %d %H:%M:%S"
        )
        timestamp = ts.isoformat()
    except ValueError:
        timestamp = f"{d.get('month')} {d.get('day')} {d.get('time')}"

    return {
        "@timestamp" : timestamp,
        "log_type"   : "firewall",
        "action"     : d.get("action"),
        "src_ip"     : d.get("src_ip"),
        "dst_ip"     : d.get("dst_ip"),
        "src_port"   : d.get("src_port"),
        "dst_port"   : d.get("dst_port"),
        "raw"        : line.strip(),
    }

def parse_syslog(line: str) -> dict | None:
    m = PATTERNS["syslog"].match(line.strip())
    if not m:
        return None
    d = m.groupdict()

    year = datetime.datetime.now().year
    try:
        ts = datetime.datetime.strptime(
            f"{year} {d['month']} {d['day']} {d['time']}", "%Y %b %d %H:%M:%S"
        )
        timestamp = ts.isoformat()
    except ValueError:
        timestamp = f"{d.get('month')} {d.get('day')} {d.get('time')}"

    return {
        "@timestamp" : timestamp,
        "log_type"   : "syslog",
        "hostname"   : d.get("hostname"),
        "process"    : d.get("process", "").strip(),
        "pid"        : d.get("pid"),
        "message"    : d.get("message"),
        "raw"        : line.strip(),
    }

# ════════════════════════════════════════════════════════════
# MAIN PARSER
# ════════════════════════════════════════════════════════════

PARSER_MAP = {
    "nginx_apache"  : parse_nginx_apache,
    "auth_log"      : parse_auth_log,
    "ufw"           : parse_ufw,
    "syslog"        : parse_syslog,
}

def parse_file(filepath: str, log_type: str = None) -> list:
    """Parse file log, kembalikan list event ternormalisasi."""
    if not os.path.exists(filepath):
        print(red(f"  [!] File tidak ditemukan: {filepath}"))
        return []

    if not log_type:
        log_type = detect_log_type(filepath)

    parser = PARSER_MAP.get(log_type, parse_syslog)
    print(green(f"  [+] Tipe log terdeteksi : {log_type}"))

    events = []
    errors = 0

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            parsed = parser(line)
            if parsed:
                events.append(parsed)
            else:
                errors += 1

    print(green(f"  [+] {len(events):,} event diparsed  ({errors} baris skip)"))
    return events

def run(args: list = None):
    """Entry point dari menu utama."""
    print(blue("\n  SIEM Parser — Normalisasi Log"))
    print("  " + "─"*40)

    if args:
        filepath = args[0]
        log_type = args[1] if len(args) > 1 else None
    else:
        filepath = input("\n  Path file log: ").strip()
        print("\n  Tipe log (kosongkan untuk auto-detect):")
        print("  1. nginx_apache   4. syslog")
        print("  2. auth_log       5. auto")
        print("  3. ufw")
        choice = input("\n  Pilih [1-5, default=5]: ").strip()
        type_map = {"1": "nginx_apache", "2": "auth_log",
                    "3": "ufw", "4": "syslog"}
        log_type = type_map.get(choice)

    events = parse_file(filepath, log_type)
    if not events:
        return []

    # Simpan output
    outfile = f"siem_parsed_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(outfile, "w") as f:
        json.dump(events, f, indent=2, default=str)
    print(green(f"\n  [✓] Output disimpan: {outfile}"))

    # Preview
    print(yellow(f"\n  Preview 3 event pertama:"))
    for e in events[:3]:
        print(f"  {json.dumps(e, default=str)[:120]}...")

    return events

if __name__ == "__main__":
    import sys
    run(sys.argv[1:] if len(sys.argv) > 1 else None)
