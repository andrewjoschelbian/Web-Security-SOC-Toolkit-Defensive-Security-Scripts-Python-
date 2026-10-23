#!/usr/bin/env python3
"""
============================================================
soc_toolkit.py — SOC Analyst Tier 1 Interactive Toolkit
Menu interaktif untuk tools analisis keamanan sehari-hari.

Tools tersedia:
  1. Log Analyzer       — Analisis & deteksi ancaman dari access log
  2. SIEM Parser        — Normalisasi log berbagai sumber ke JSON
  3. IOC Extractor      — Ekstrak IP, domain, hash dari log/teks
  4. Alert Correlator   — Korelasi event log menjadi alert bermakna
  5. Full Pipeline      — Jalankan semua tool secara berurutan

Gunakan hanya pada sistem yang kamu miliki atau kelola.
============================================================
"""

import os
import sys
import json
import datetime

# ── Warna ────────────────────────────────────────────────────
class C:
    RED    = "\033[0;31m"
    YELLOW = "\033[1;33m"
    GREEN  = "\033[0;32m"
    BLUE   = "\033[0;34m"
    CYAN   = "\033[0;36m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def red(t):    return f"{C.RED}{t}{C.RESET}"
def green(t):  return f"{C.GREEN}{t}{C.RESET}"
def yellow(t): return f"{C.YELLOW}{t}{C.RESET}"
def blue(t):   return f"{C.BLUE}{t}{C.RESET}"
def cyan(t):   return f"{C.CYAN}{t}{C.RESET}"
def bold(t):   return f"{C.BOLD}{t}{C.RESET}"
def dim(t):    return f"{C.DIM}{t}{C.RESET}"

# ════════════════════════════════════════════════════════════
# BANNER
# ════════════════════════════════════════════════════════════

def print_banner():
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(cyan("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        ███████╗ ██████╗  ██████╗                            ║
║        ██╔════╝██╔═══██╗██╔════╝                            ║
║        ███████╗██║   ██║██║                                 ║
║        ╚════██║██║   ██║██║                                 ║
║        ███████║╚██████╔╝╚██████╗                            ║
║        ╚══════╝ ╚═════╝  ╚═════╝                            ║
║                                                              ║
║         Tier 1 SOC Analyst Toolkit  v1.0                     ║
║         Gunakan hanya pada sistem milik Anda                 ║
╚══════════════════════════════════════════════════════════════╝
"""))
    print(dim(f"  Waktu sekarang : {now}"))
    print(dim(f"  Python         : {sys.version.split()[0]}"))
    print()

# ════════════════════════════════════════════════════════════
# MENU DEFINITION
# ════════════════════════════════════════════════════════════

MENU_ITEMS = [
    {
        "id"         : "1",
        "name"       : "Log Analyzer",
        "module"     : "log_analyzer",
        "icon"       : "📋",
        "description": "Analisis access log web server (Nginx/Apache)",
        "detail"     : [
            "Deteksi SQL Injection, XSS, Path Traversal, RCE",
            "Deteksi brute force login & high request rate",
            "Identifikasi scanner tools (sqlmap, nikto, dll)",
            "Output: laporan teks + JSON + blocklist IP",
        ],
        "input"      : "File log (access.log)",
        "output"     : "log_report/",
    },
    {
        "id"         : "2",
        "name"       : "SIEM Parser",
        "module"     : "siem_parser",
        "icon"       : "🔄",
        "description": "Normalisasi log berbagai sumber ke format JSON seragam",
        "detail"     : [
            "Support: Nginx, Apache, auth.log, syslog, UFW firewall",
            "Auto-deteksi tipe log dari nama file & konten",
            "Output: JSON terstruktur siap diproses tool lain",
            "Berguna sebagai input untuk IOC Extractor & Alert Correlator",
        ],
        "input"      : "File log (format apapun)",
        "output"     : "siem_parsed_[timestamp].json",
    },
    {
        "id"         : "3",
        "name"       : "IOC Extractor",
        "module"     : "ioc_extractor",
        "icon"       : "🔍",
        "description": "Ekstrak Indicators of Compromise dari log atau teks",
        "detail"     : [
            "Ekstrak: IPv4, IPv6, Domain, URL, Email",
            "Ekstrak: MD5, SHA1, SHA256 hash",
            "Ekstrak: CVE ID, file path mencurigakan",
            "Filter IP private, enrich dengan kategori otomatis",
        ],
        "input"      : "File log/teks atau input langsung",
        "output"     : "ioc_report_[timestamp].json",
    },
    {
        "id"         : "4",
        "name"       : "Alert Correlator",
        "module"     : "alert_correlator",
        "icon"       : "🚨",
        "description": "Korelasi event log menjadi alert bermakna dengan severity",
        "detail"     : [
            "Rule: SSH Brute Force (banyak failed login dari 1 IP)",
            "Rule: Web Scanner (banyak 404 ke path berbeda)",
            "Rule: Credential Stuffing (1 user dari banyak IP)",
            "Rule: Brute Force Success (gagal berkali-kali lalu berhasil)",
            "Rule: Data Exfiltration (response size tidak wajar)",
            "Rule: Port Scan (banyak port di-block firewall dari 1 IP)",
        ],
        "input"      : "JSON output dari SIEM Parser",
        "output"     : "alerts_[timestamp].json",
    },
    {
        "id"         : "5",
        "name"       : "Full Pipeline",
        "module"     : "pipeline",
        "icon"       : "⚡",
        "description": "Jalankan SIEM Parser → IOC Extractor → Alert Correlator sekaligus",
        "detail"     : [
            "1. Parse & normalisasi log",
            "2. Ekstrak semua IOC otomatis",
            "3. Jalankan semua correlation rules",
            "4. Generate laporan lengkap",
        ],
        "input"      : "File log apapun",
        "output"     : "pipeline_report_[timestamp]/",
    },
    {
        "id"         : "6",
        "name"       : "Log Analyzer (Classic)",
        "module"     : "log_analyzer_classic",
        "icon"       : "📊",
        "description": "Versi classic dengan statistik detail dan threat patterns",
        "detail"     : [
            "Top IP, path, user-agent, HTTP method",
            "Distribusi status code (4xx, 5xx)",
            "Distribusi waktu request per jam",
            "Output: LOG_REPORT.txt + suspect_ips.txt",
        ],
        "input"      : "File access log (Nginx/Apache combined format)",
        "output"     : "log_report/",
    },
]

# ════════════════════════════════════════════════════════════
# MENU DISPLAY
# ════════════════════════════════════════════════════════════

def print_menu():
    print(bold("  ┌─ MENU UTAMA " + "─"*48 + "┐"))
    print()

    for item in MENU_ITEMS:
        num    = item["id"]
        icon   = item["icon"]
        name   = item["name"]
        desc   = item["description"]

        # Nomor + nama tool
        print(f"  {bold(cyan(f'[{num}]'))}  {icon}  {bold(name)}")
        # Deskripsi singkat
        print(f"       {dim(desc)}")
        # Detail poin
        for point in item["detail"]:
            print(f"         {dim('•')} {dim(point)}")
        # Input/output
        print(f"       {dim('Input  :')} {dim(item['input'])}")
        print(f"       {dim('Output :')} {dim(item['output'])}")
        print()

    print(f"  {bold(cyan('[0]'))}  🚪  {bold('Keluar')}")
    print()
    print(bold("  └" + "─"*60 + "┘"))

# ════════════════════════════════════════════════════════════
# MODULE LOADER
# ════════════════════════════════════════════════════════════

def load_module(module_name: str):
    """Import modul dari direktori yang sama."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    try:
        import importlib
        mod = importlib.import_module(module_name)
        return mod
    except ImportError as e:
        print(red(f"\n  [!] Modul '{module_name}' tidak ditemukan: {e}"))
        print(yellow(f"  [~] Pastikan file {module_name}.py ada di folder yang sama"))
        return None

# ════════════════════════════════════════════════════════════
# TOOL RUNNERS
# ════════════════════════════════════════════════════════════

def run_log_analyzer():
    """Jalankan log_analyzer (integrasi langsung)."""
    print(cyan("\n  ━━━ Log Analyzer ━━━"))

    mod = load_module("log_analyzer")
    if not mod:
        return

    logfile = input("\n  Path file log (Enter untuk demo): ").strip()
    if not logfile:
        logfile = None

    # Patch sys.argv sementara agar argparse di log_analyzer bisa jalan
    old_argv = sys.argv
    sys.argv = ["log_analyzer.py"] + ([logfile] if logfile else [])
    try:
        mod.main()
    except SystemExit:
        pass
    finally:
        sys.argv = old_argv

def run_siem_parser():
    """Jalankan siem_parser."""
    print(cyan("\n  ━━━ SIEM Parser ━━━"))
    mod = load_module("siem_parser")
    if not mod:
        return
    return mod.run()

def run_ioc_extractor(events=None):
    """Jalankan ioc_extractor."""
    print(cyan("\n  ━━━ IOC Extractor ━━━"))
    mod = load_module("ioc_extractor")
    if not mod:
        return
    return mod.run(events=events)

def run_alert_correlator(events=None):
    """Jalankan alert_correlator."""
    print(cyan("\n  ━━━ Alert Correlator ━━━"))
    mod = load_module("alert_correlator")
    if not mod:
        return
    return mod.run(events=events)

def run_full_pipeline():
    """Jalankan semua modul secara berurutan."""
    print(cyan("\n  ━━━ Full Pipeline ━━━"))
    print(dim("  SIEM Parser → IOC Extractor → Alert Correlator"))
    print()

    logfile = input("  Path file log: ").strip()
    if not logfile or not os.path.exists(logfile):
        print(red(f"  [!] File tidak ditemukan: {logfile}"))
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir    = f"pipeline_report_{timestamp}"
    os.makedirs(outdir, exist_ok=True)

    print(green(f"\n  [*] Output folder: {outdir}/"))
    print()

    # Step 1: SIEM Parser
    print(bold(blue("  [Step 1/3] SIEM Parser")))
    siem_mod = load_module("siem_parser")
    events   = []
    if siem_mod:
        events = siem_mod.parse_file(logfile)
        if events:
            siem_out = os.path.join(outdir, "01_siem_parsed.json")
            with open(siem_out, "w") as f:
                json.dump(events, f, indent=2, default=str)
            print(green(f"  [✓] {len(events)} event diparsed → {siem_out}"))

    if not events:
        print(red("  [!] Tidak ada event yang bisa diparse. Pipeline berhenti."))
        return

    # Step 2: IOC Extractor
    print(bold(blue("\n  [Step 2/3] IOC Extractor")))
    ioc_mod = load_module("ioc_extractor")
    iocs    = {}
    if ioc_mod:
        iocs = ioc_mod.extract_from_events(events)
        ioc_mod.print_ioc_report(iocs)
        ioc_out = os.path.join(outdir, "02_ioc_report.json")
        with open(ioc_out, "w") as f:
            json.dump({
                "iocs"    : iocs,
                "summary" : {k: len(v) for k, v in iocs.items()},
            }, f, indent=2)
        print(green(f"  [✓] IOC report → {ioc_out}"))

    # Step 3: Alert Correlator
    print(bold(blue("\n  [Step 3/3] Alert Correlator")))
    corr_mod = load_module("alert_correlator")
    alerts   = []
    if corr_mod:
        alerts = corr_mod.correlate(events)
        corr_mod.print_alerts(alerts)
        if alerts:
            alert_out = os.path.join(outdir, "03_alerts.json")
            with open(alert_out, "w") as f:
                json.dump([a.to_dict() for a in alerts], f, indent=2)
            print(green(f"  [✓] Alerts → {alert_out}"))

    # Summary laporan
    summary = {
        "logfile"         : logfile,
        "timestamp"       : datetime.datetime.now().isoformat(),
        "total_events"    : len(events),
        "ioc_summary"     : {k: len(v) for k, v in iocs.items()},
        "alert_count"     : len(alerts),
        "alerts_by_sev"   : {},
    }

    if alerts:
        from collections import Counter
        sev = Counter(a.severity for a in alerts)
        summary["alerts_by_sev"] = dict(sev)

    summary_path = os.path.join(outdir, "PIPELINE_SUMMARY.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    # Tampilkan ringkasan akhir
    print(cyan(f"\n  {'═'*54}"))
    print(cyan(f"  PIPELINE SELESAI"))
    print(cyan(f"  {'═'*54}"))
    print(f"  Total event  : {len(events):,}")
    print(f"  IOC ditemukan: {sum(len(v) for v in iocs.values()):,}")
    print(f"  Alert        : {len(alerts)}")
    if alerts:
        from collections import Counter
        for sev, count in Counter(a.severity for a in alerts).most_common():
            print(f"    {sev:10s}: {count}")
    print(green(f"\n  [✓] Semua hasil disimpan di: {outdir}/"))

def run_log_analyzer_classic():
    """Jalankan log_analyzer versi classic dengan semua fiturnya."""
    run_log_analyzer()

# ════════════════════════════════════════════════════════════
# MAIN LOOP
# ════════════════════════════════════════════════════════════

RUNNERS = {
    "1": run_log_analyzer,
    "2": run_siem_parser,
    "3": run_ioc_extractor,
    "4": run_alert_correlator,
    "5": run_full_pipeline,
    "6": run_log_analyzer_classic,
}

def main():
    print_banner()

    while True:
        print_menu()

        try:
            choice = input(bold("  Pilih tool [0-6]: ")).strip()
        except (KeyboardInterrupt, EOFError):
            print(yellow("\n\n  Keluar... sampai jumpa!"))
            sys.exit(0)

        if choice == "0":
            print(yellow("\n  Keluar... sampai jumpa!"))
            sys.exit(0)

        if choice not in RUNNERS:
            print(red(f"\n  [!] Pilihan tidak valid: '{choice}'. Masukkan angka 0-6.\n"))
            input(dim("  Tekan Enter untuk kembali ke menu..."))
            # Clear screen
            os.system("clear" if os.name == "posix" else "cls")
            print_banner()
            continue

        # Jalankan tool yang dipilih
        selected = next(item for item in MENU_ITEMS if item["id"] == choice)
        print()
        print(bold(cyan(f"  ┌─ {selected['icon']} {selected['name']} " + "─"*40)))
        print()

        try:
            RUNNERS[choice]()
        except KeyboardInterrupt:
            print(yellow("\n\n  [~] Dibatalkan oleh user"))
        except Exception as e:
            print(red(f"\n  [!] Error: {e}"))
            import traceback
            print(dim(traceback.format_exc()))

        print()
        input(dim("  Tekan Enter untuk kembali ke menu..."))

        # Clear screen sebelum tampilkan menu lagi
        os.system("clear" if os.name == "posix" else "cls")
        print_banner()


if __name__ == "__main__":
    main()
