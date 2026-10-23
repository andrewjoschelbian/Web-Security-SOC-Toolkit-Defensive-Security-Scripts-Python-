#!/usr/bin/env python3
"""
============================================================
ioc_extractor.py — Indicators of Compromise Extractor
Ekstrak IOC dari log atau teks:
  - IP Address (IPv4 & IPv6)
  - Domain & URL
  - MD5 / SHA1 / SHA256 hash
  - Email address
  - CVE ID
  - File path mencurigakan
============================================================
"""

import re
import os
import json
import datetime
from collections import defaultdict

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
def cyan(t):   return f"{C.CYAN}{t}{C.RESET}"

# ════════════════════════════════════════════════════════════
# IOC REGEX PATTERNS
# ════════════════════════════════════════════════════════════

IOC_PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "ipv6": re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:)*::[0-9a-fA-F:]*\b'
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|id|co\.id|io|dev|xyz|info|biz|gov|edu|mil|int'
        r'|ac\.id|go\.id|sch\.id|web\.id|my\.id|or\.id)\b',
        re.IGNORECASE
    ),
    "url": re.compile(
        r'https?://[^\s\'"<>\]]+',
        re.IGNORECASE
    ),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "email": re.compile(
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
    ),
    "cve": re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
    "file_path": re.compile(
        r'(?:/(?:etc|var|tmp|home|root|proc|sys|bin|usr)/[^\s\'"<>]+|'
        r'[A-Za-z]:\\[^\s\'"<>]+)',
        re.IGNORECASE
    ),
}

# IP yang tidak perlu dilaporkan (private, loopback, broadcast)
WHITELIST_IP = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "::1", "localhost",
}

PRIVATE_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^169\.254\.'),   # link-local
    re.compile(r'^127\.'),        # loopback
]

def is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_RANGES)

# ════════════════════════════════════════════════════════════
# EXTRACTOR
# ════════════════════════════════════════════════════════════

def extract_iocs(text: str, include_private: bool = False) -> dict:
    """Ekstrak semua IOC dari teks."""
    iocs = defaultdict(set)

    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = pattern.findall(text)
        for match in matches:
            val = match.strip()
            if not val:
                continue

            # Filter IP private/whitelist
            if ioc_type == "ipv4":
                if val in WHITELIST_IP:
                    continue
                if not include_private and is_private_ip(val):
                    continue

            # Jangan masukkan hash yang kemungkinan bukan hash (terlalu umum)
            if ioc_type == "md5" and len(set(val.lower())) < 5:
                continue

            iocs[ioc_type].add(val)

    # Konversi set ke list dan sort
    return {k: sorted(v) for k, v in iocs.items() if v}

def extract_from_file(filepath: str, include_private: bool = False) -> dict:
    """Ekstrak IOC dari file."""
    try:
        with open(filepath, "r", errors="replace") as f:
            content = f.read()
        return extract_iocs(content, include_private)
    except Exception as e:
        print(red(f"  [!] Error membaca file: {e}"))
        return {}

def extract_from_events(events: list) -> dict:
    """Ekstrak IOC dari list event (output siem_parser)."""
    # Gabungkan semua raw log
    combined = " ".join(
        str(e.get("raw", "")) + " " + str(e.get("message", ""))
        for e in events
    )
    return extract_iocs(combined)

# ════════════════════════════════════════════════════════════
# ENRICHMENT
# ════════════════════════════════════════════════════════════

def enrich_iocs(iocs: dict) -> dict:
    """
    Tambahkan konteks/kategori ke tiap IOC.
    (Untuk pengecekan reputasi online, gunakan ip_reputation.py)
    """
    enriched = {}

    for ioc_type, values in iocs.items():
        enriched[ioc_type] = []
        for val in values:
            entry = {"value": val, "type": ioc_type}

            # Kategorisasi IP
            if ioc_type == "ipv4":
                if is_private_ip(val):
                    entry["category"] = "private"
                else:
                    entry["category"] = "public"

            # Kategorisasi domain
            elif ioc_type == "domain":
                if any(sus in val for sus in [".tk", ".ml", ".ga", ".cf", ".gq"]):
                    entry["suspicious"] = True
                    entry["reason"] = "Free TLD sering dipakai phishing"

            # Kategorisasi hash
            elif ioc_type in ("md5", "sha1", "sha256"):
                entry["hash_type"] = ioc_type.upper()

            enriched[ioc_type].append(entry)

    return enriched

# ════════════════════════════════════════════════════════════
# PRINT REPORT
# ════════════════════════════════════════════════════════════

def print_ioc_report(iocs: dict, enriched: dict = None):
    """Tampilkan IOC dalam format yang mudah dibaca."""
    type_labels = {
        "ipv4"      : "IPv4 Address",
        "ipv6"      : "IPv6 Address",
        "domain"    : "Domain",
        "url"       : "URL",
        "md5"       : "MD5 Hash",
        "sha1"      : "SHA1 Hash",
        "sha256"    : "SHA256 Hash",
        "email"     : "Email Address",
        "cve"       : "CVE ID",
        "file_path" : "File Path",
    }

    total = sum(len(v) for v in iocs.values())
    print(yellow(f"\n  Total IOC ditemukan: {total}"))
    print("  " + "─"*50)

    for ioc_type, values in iocs.items():
        label = type_labels.get(ioc_type, ioc_type)
        print(blue(f"\n  [{label}] — {len(values)} item"))

        for val in values[:20]:  # tampilkan max 20 per kategori
            # Cek apakah ada info enrichment
            flag = ""
            if enriched and ioc_type in enriched:
                for e in enriched[ioc_type]:
                    if e["value"] == val:
                        if e.get("suspicious"):
                            flag = red("  ⚠ " + e.get("reason", ""))
                        elif e.get("category") == "private":
                            flag = yellow("  (private)")
                        break
            print(f"    {val}{flag}")

        if len(values) > 20:
            print(yellow(f"    ... dan {len(values)-20} lainnya"))

# ════════════════════════════════════════════════════════════
# MAIN / ENTRY POINT
# ════════════════════════════════════════════════════════════

def run(args: list = None, events: list = None):
    """Entry point dari menu utama."""
    print(blue("\n  IOC Extractor — Ekstrak Indicators of Compromise"))
    print("  " + "─"*50)

    iocs = {}

    if events:
        # Mode: terima events dari siem_parser
        print(green(f"  [+] Mode: ekstrak dari {len(events)} event log"))
        iocs = extract_from_events(events)

    elif args:
        filepath = args[0]
        iocs = extract_from_file(filepath)

    else:
        print("\n  Sumber IOC:")
        print("  1. File log / teks")
        print("  2. Input teks langsung")
        choice = input("\n  Pilih [1-2]: ").strip()

        if choice == "1":
            filepath = input("  Path file: ").strip()
            include_priv = input("  Sertakan IP private? [y/N]: ").strip().lower() == "y"
            iocs = extract_from_file(filepath, include_priv)
        else:
            print("  Paste teks (ketik END di baris baru untuk selesai):")
            lines = []
            while True:
                line = input()
                if line.strip().upper() == "END":
                    break
                lines.append(line)
            iocs = extract_iocs("\n".join(lines))

    if not iocs:
        print(yellow("  [~] Tidak ada IOC ditemukan"))
        return {}

    # Enrich
    enriched = enrich_iocs(iocs)
    print_ioc_report(iocs, enriched)

    # Simpan output
    outfile = f"ioc_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(outfile, "w") as f:
        json.dump({
            "timestamp" : datetime.datetime.now().isoformat(),
            "iocs"      : iocs,
            "enriched"  : enriched,
            "summary"   : {k: len(v) for k, v in iocs.items()},
        }, f, indent=2)
    print(green(f"\n  [✓] IOC report disimpan: {outfile}"))

    return iocs

if __name__ == "__main__":
    import sys
    run(sys.argv[1:] if len(sys.argv) > 1 else None)
