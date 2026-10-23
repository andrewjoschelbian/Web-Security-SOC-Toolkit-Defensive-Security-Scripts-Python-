#!/usr/bin/env python3
"""
============================================================
alert_correlator.py — Event Correlation & Alert Generator
Korelasi beberapa event dari log menjadi alert bermakna:
  - Brute force SSH (banyak failed login dari 1 IP)
  - Port scan (banyak koneksi ke port berbeda dari 1 IP)
  - Web scan (banyak 404 dari 1 IP dalam waktu singkat)
  - Credential stuffing (banyak IP berbeda gagal login user sama)
  - Data exfiltration (response size besar tidak wajar)
  - Lateral movement (login sukses setelah sebelumnya gagal berkali-kali)
============================================================
"""

import json
import datetime
import os
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
# SEVERITY LEVELS
# ════════════════════════════════════════════════════════════

SEVERITY = {
    "CRITICAL" : (C.RED,    "🔴"),
    "HIGH"     : (C.RED,    "🟠"),
    "MEDIUM"   : (C.YELLOW, "🟡"),
    "LOW"      : (C.GREEN,  "🟢"),
    "INFO"     : (C.CYAN,   "🔵"),
}

def severity_label(level: str) -> str:
    color, icon = SEVERITY.get(level, (C.RESET, "⚪"))
    return f"{color}{icon} {level}{C.RESET}"

# ════════════════════════════════════════════════════════════
# RULE ENGINE
# ════════════════════════════════════════════════════════════

class Alert:
    def __init__(self, rule: str, severity: str, src_ip: str,
                 description: str, evidence: list, recommendation: str):
        self.rule           = rule
        self.severity       = severity
        self.src_ip         = src_ip
        self.description    = description
        self.evidence       = evidence
        self.recommendation = recommendation
        self.timestamp      = datetime.datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "timestamp"      : self.timestamp,
            "rule"           : self.rule,
            "severity"       : self.severity,
            "src_ip"         : self.src_ip,
            "description"    : self.description,
            "evidence"       : self.evidence[:5],  # max 5 sample
            "recommendation" : self.recommendation,
        }

# ════════════════════════════════════════════════════════════
# CORRELATION RULES
# ════════════════════════════════════════════════════════════

def rule_ssh_brute_force(events: list, threshold: int = 10) -> list:
    """
    Rule: IP yang melakukan failed SSH login >= threshold kali.
    """
    alerts = []
    ip_fails = defaultdict(list)

    for e in events:
        if e.get("log_type") == "auth" and e.get("event") == "ssh_failed_login":
            ip = e.get("src_ip")
            if ip:
                ip_fails[ip].append(e)

    for ip, fails in ip_fails.items():
        if len(fails) >= threshold:
            alerts.append(Alert(
                rule        = "SSH_BRUTE_FORCE",
                severity    = "HIGH" if len(fails) >= 50 else "MEDIUM",
                src_ip      = ip,
                description = (f"IP {ip} melakukan {len(fails)} kali percobaan "
                               f"login SSH yang gagal"),
                evidence    = [e.get("raw", "") for e in fails[:5]],
                recommendation = (
                    f"1. Block IP: sudo ufw deny from {ip}\n"
                    "2. Aktifkan Fail2ban untuk SSH\n"
                    "3. Pertimbangkan ganti port SSH dari 22 ke port lain\n"
                    "4. Gunakan SSH key, nonaktifkan password login"
                )
            ))

    return alerts

def rule_web_scanner(events: list, threshold: int = 50,
                     window_seconds: int = 60) -> list:
    """
    Rule: IP yang generate banyak HTTP 404 dalam waktu singkat = scanning.
    """
    alerts = []
    ip_404 = defaultdict(list)

    for e in events:
        if e.get("log_type") == "web_access" and e.get("status") == 404:
            ip = e.get("src_ip")
            if ip:
                ip_404[ip].append(e)

    for ip, hits in ip_404.items():
        if len(hits) >= threshold:
            # Cek unique path — scanner biasanya coba banyak path berbeda
            paths = set(e.get("path", "") for e in hits)
            if len(paths) >= 20:
                alerts.append(Alert(
                    rule        = "WEB_SCANNER_DETECTED",
                    severity    = "MEDIUM",
                    src_ip      = ip,
                    description = (f"IP {ip} melakukan web scanning: "
                                   f"{len(hits)} request 404 ke {len(paths)} path berbeda"),
                    evidence    = [e.get("path", "") for e in hits[:5]],
                    recommendation = (
                        f"1. Block IP: sudo ufw deny from {ip}\n"
                        "2. Pasang WAF atau rate limiting\n"
                        "3. Tambahkan ke blacklist Nginx/Apache"
                    )
                ))

    return alerts

def rule_credential_stuffing(events: list, threshold: int = 20) -> list:
    """
    Rule: Satu user yang dicoba login dari banyak IP berbeda = credential stuffing.
    """
    alerts = []
    user_ips = defaultdict(set)

    for e in events:
        if e.get("log_type") == "auth" and e.get("event") == "ssh_failed_login":
            user = e.get("user")
            ip   = e.get("src_ip")
            if user and ip:
                user_ips[user].add(ip)

    for user, ips in user_ips.items():
        if len(ips) >= threshold:
            alerts.append(Alert(
                rule        = "CREDENTIAL_STUFFING",
                severity    = "HIGH",
                src_ip      = "multiple",
                description = (f"User '{user}' dicoba login dari {len(ips)} IP berbeda "
                               f"= indikasi credential stuffing"),
                evidence    = list(ips)[:5],
                recommendation = (
                    f"1. Reset password user '{user}' segera\n"
                    "2. Aktifkan MFA untuk akun tersebut\n"
                    "3. Periksa apakah credentials bocor di haveibeenpwned.com\n"
                    "4. Block semua IP yang terlibat"
                )
            ))

    return alerts

def rule_successful_after_brute(events: list,
                                 fail_threshold: int = 5) -> list:
    """
    Rule: IP yang sebelumnya gagal login berkali-kali lalu berhasil login
    = kemungkinan brute force berhasil (lateral movement).
    """
    alerts = []
    ip_fails   = defaultdict(int)
    ip_success = defaultdict(list)

    for e in events:
        if e.get("log_type") != "auth":
            continue
        ip = e.get("src_ip")
        if not ip:
            continue
        if e.get("event") == "ssh_failed_login":
            ip_fails[ip] += 1
        elif e.get("event") == "ssh_success_login":
            ip_success[ip].append(e)

    for ip, successes in ip_success.items():
        fails = ip_fails.get(ip, 0)
        if fails >= fail_threshold:
            user = successes[0].get("user", "unknown")
            alerts.append(Alert(
                rule        = "BRUTE_FORCE_SUCCESS",
                severity    = "CRITICAL",
                src_ip      = ip,
                description = (f"IP {ip} berhasil login sebagai '{user}' "
                               f"setelah sebelumnya gagal {fails} kali "
                               f"= kemungkinan brute force BERHASIL"),
                evidence    = [e.get("raw", "") for e in successes[:3]],
                recommendation = (
                    f"1. SEGERA block IP: sudo ufw deny from {ip}\n"
                    f"2. Kill session aktif user '{user}'\n"
                    f"3. Reset password '{user}' segera\n"
                    "4. Periksa aktivitas user setelah login (command history)\n"
                    "5. Laporkan sebagai incident"
                )
            ))

    return alerts

def rule_data_exfiltration(events: list,
                            size_threshold: int = 10_000_000) -> list:
    """
    Rule: Response size sangat besar = kemungkinan data exfiltration.
    Threshold default: 10MB per response.
    """
    alerts = []

    for e in events:
        if e.get("log_type") != "web_access":
            continue
        try:
            size = int(e.get("size", 0))
        except (ValueError, TypeError):
            continue

        if size >= size_threshold:
            ip   = e.get("src_ip", "unknown")
            path = e.get("path", "unknown")
            alerts.append(Alert(
                rule        = "LARGE_RESPONSE_EXFILTRATION",
                severity    = "MEDIUM",
                src_ip      = ip,
                description = (f"Response {size/1_000_000:.1f}MB dari endpoint {path} "
                               f"ke IP {ip} — kemungkinan data exfiltration"),
                evidence    = [e.get("raw", "")],
                recommendation = (
                    "1. Periksa endpoint tersebut apakah seharusnya bisa diakses\n"
                    "2. Cek apakah data yang diakses sensitif\n"
                    "3. Terapkan rate limiting pada endpoint\n"
                    "4. Pasang autentikasi jika belum ada"
                )
            ))

    return alerts

def rule_firewall_blocked_scan(events: list, threshold: int = 20) -> list:
    """
    Rule: IP yang di-block firewall berkali-kali ke port berbeda = port scan.
    """
    alerts = []
    ip_ports = defaultdict(set)

    for e in events:
        if e.get("log_type") == "firewall" and e.get("action") == "BLOCK":
            ip   = e.get("src_ip")
            port = e.get("dst_port")
            if ip and port:
                ip_ports[ip].add(port)

    for ip, ports in ip_ports.items():
        if len(ports) >= threshold:
            alerts.append(Alert(
                rule        = "PORT_SCAN_DETECTED",
                severity    = "MEDIUM",
                src_ip      = ip,
                description = (f"IP {ip} terdeteksi melakukan port scan: "
                               f"mencoba {len(ports)} port berbeda (semua di-block firewall)"),
                evidence    = sorted(ports)[:10],
                recommendation = (
                    f"1. Block IP: sudo ufw deny from {ip}\n"
                    "2. Pastikan firewall aktif dan rules sudah benar\n"
                    "3. Monitor IP tersebut apakah mencoba exploit setelah scan"
                )
            ))

    return alerts

# ════════════════════════════════════════════════════════════
# CORRELATION ENGINE
# ════════════════════════════════════════════════════════════

ALL_RULES = [
    ("SSH Brute Force"          , rule_ssh_brute_force),
    ("Web Scanner"              , rule_web_scanner),
    ("Credential Stuffing"      , rule_credential_stuffing),
    ("Brute Force Success"      , rule_successful_after_brute),
    ("Data Exfiltration"        , rule_data_exfiltration),
    ("Firewall Port Scan"       , rule_firewall_blocked_scan),
]

def correlate(events: list) -> list:
    """Jalankan semua rule terhadap events, kembalikan list alert."""
    all_alerts = []

    print(f"\n  Menjalankan {len(ALL_RULES)} correlation rules...")
    for rule_name, rule_fn in ALL_RULES:
        try:
            alerts = rule_fn(events)
            if alerts:
                print(red(f"  [!] {rule_name}: {len(alerts)} alert"))
            else:
                print(green(f"  [+] {rule_name}: bersih"))
            all_alerts.extend(alerts)
        except Exception as e:
            print(yellow(f"  [~] {rule_name} error: {e}"))

    return all_alerts

def print_alerts(alerts: list):
    """Tampilkan alert dalam format yang mudah dibaca."""
    if not alerts:
        print(green("\n  ✅ Tidak ada alert yang dihasilkan"))
        return

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    alerts.sort(key=lambda a: sev_order.get(a.severity, 5))

    print(f"\n  {'═'*54}")
    print(f"  ALERT SUMMARY — {len(alerts)} alert ditemukan")
    print(f"  {'═'*54}")

    for i, alert in enumerate(alerts, 1):
        print(f"\n  [{i}] {severity_label(alert.severity)}  —  {alert.rule}")
        print(f"      IP      : {alert.src_ip}")
        print(f"      Detail  : {alert.description}")
        if alert.evidence:
            print(f"      Bukti   : {str(alert.evidence[0])[:80]}...")
        print(f"      Saran   :")
        for line in alert.recommendation.split("\n"):
            print(f"        {line}")

# ════════════════════════════════════════════════════════════
# MAIN / ENTRY POINT
# ════════════════════════════════════════════════════════════

def run(args: list = None, events: list = None):
    """Entry point dari menu utama."""
    print(blue("\n  Alert Correlator — Korelasi Event Menjadi Alert"))
    print("  " + "─"*50)

    if not events:
        if args:
            filepath = args[0]
        else:
            filepath = input("\n  Path file JSON (output siem_parser): ").strip()

        if not os.path.exists(filepath):
            print(red(f"  [!] File tidak ditemukan: {filepath}"))
            return []

        with open(filepath) as f:
            events = json.load(f)
        print(green(f"  [+] {len(events)} event dimuat dari {filepath}"))

    alerts = correlate(events)
    print_alerts(alerts)

    if alerts:
        # Simpan output
        outfile = f"alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(outfile, "w") as f:
            json.dump(
                [a.to_dict() for a in alerts],
                f, indent=2
            )
        print(green(f"\n  [✓] Alerts disimpan: {outfile}"))

        # Summary
        from collections import Counter
        sev_count = Counter(a.severity for a in alerts)
        print(yellow("\n  Summary severity:"))
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sev_count.get(sev, 0)
            if count:
                print(f"    {severity_label(sev)}: {count}")

    return alerts

if __name__ == "__main__":
    import sys
    run(sys.argv[1:] if len(sys.argv) > 1 else None)
