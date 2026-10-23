# 🔐 Web Security & SOC Toolkit

Kumpulan script Python untuk **defensive security** — dirancang untuk developer, sysadmin, dan SOC analyst yang ingin menganalisis dan memperkuat keamanan sistem mereka sendiri.

> ⚠️ **PERINGATAN**: Gunakan tool ini **hanya pada website/server yang kamu miliki** atau yang sudah mendapat izin tertulis. Penggunaan pada target tanpa izin adalah tindakan ilegal.

---

## 📁 Struktur Folder

```
.
├── scanner/                    # Tools scanning & assessment
│   ├── vuln_assessment.py      # Assessment keamanan website (Python)
│   ├── vuln_assessment.sh      # Assessment keamanan website (Bash)
│   └── vuln_suite.py           # Suite: SSL + Subdomain + Port + Deps
│
├── defender/                   # Tools hardening & monitoring
│   ├── header_fixer.py         # Generator security headers config
│   ├── log_analyzer.py         # Web server log analyzer
│   └── toolkit/                # SOC Analyst Tier 1 Toolkit
│       ├── soc_toolkit.py      # Menu interaktif utama
│       ├── siem_parser.py      # Normalisasi log berbagai sumber
│       ├── ioc_extractor.py    # Ekstrak IOC dari log/teks
│       └── alert_correlator.py # Korelasi event → alert
│
└── README.md
```

---

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/username/web-security-toolkit.git
cd web-security-toolkit

# Cek Python (minimal 3.10)
python3 --version

# Install tools sistem (opsional, direkomendasikan)
sudo apt install nmap whois dnsutils openssl
```

---

## 📂 scanner/

### `vuln_assessment.py` — Website Security Assessment

Assessment keamanan website all-in-one dalam satu perintah.

```bash
python3 scanner/vuln_assessment.py example.com
```

**Yang dicek:**
| Modul | Isi |
|---|---|
| DNS & WHOIS | IP address, DNS records, subdomain umum |
| Port Scan | 17 port umum (FTP, SSH, HTTP, DB, dll) |
| HTTP Headers | HSTS, CSP, X-Frame-Options, dan lainnya |
| SSL/TLS | Info sertifikat, expired check, protokol lemah |
| Sensitive Files | .env, .git, wp-config, phpinfo, backup, dll |

**Output:**
```
vuln_report_[timestamp]/
├── 01_dns_whois.json
├── 02_ports.json
├── 03_headers.json
├── 04_ssl.json
├── 05_sensitive_files.json
├── full_results.json
└── SUMMARY_REPORT.txt
```

---

### `vuln_suite.py` — All-in-One Suite

Suite 4-in-1 dengan kemampuan lebih mendalam.

```bash
# Jalankan semua modul
python3 scanner/vuln_suite.py --target example.com

# Pilih modul tertentu
python3 scanner/vuln_suite.py --target example.com --modules ssl ports

# SSL Monitor banyak domain
python3 scanner/vuln_suite.py --domains example.com api.example.com --modules ssl

# Dependency check project lokal
python3 scanner/vuln_suite.py --project /path/to/project --modules deps

# Dengan wordlist subdomain eksternal
python3 scanner/vuln_suite.py --target example.com --wordlist wordlist.txt --modules subdomain
```

**Modul tersedia:**

| Modul | Flag | Deskripsi |
|---|---|---|
| SSL Monitor | `--modules ssl` | Cek sertifikat SSL, alert jika hampir expired |
| Subdomain Enum | `--modules subdomain` | Brute force DNS, 70+ subdomain built-in |
| Port Watcher | `--modules ports` | Scan port + deteksi perubahan dari scan sebelumnya |
| Dep Checker | `--modules deps` | Cek CVE di package.json, requirements.txt, dll |

**Output:**
```
suite_report_[timestamp]/
├── ssl_monitor.json
├── subdomain_enum.json
├── port_snapshot.json
├── port_watcher.json
├── dep_checker.json
└── SUITE_SUMMARY.txt
```

---

## 📂 defender/

### `header_fixer.py` — Security Headers Generator

Generate konfigurasi security headers siap pakai untuk web server.

```bash
# Generate untuk semua web server
python3 defender/header_fixer.py --domain example.com

# Nginx saja
python3 defender/header_fixer.py --domain example.com --server nginx

# Apache dengan CSP ketat
python3 defender/header_fixer.py --domain example.com --server apache --csp strict

# Analisis header dari URL yang sudah live
python3 defender/header_fixer.py --analyze https://example.com

# HSTS 2 tahun + preload
python3 defender/header_fixer.py --domain example.com --hsts-days 730 --preload
```

**Server yang didukung:** Nginx · Apache · Express/Node.js · Caddy

**Headers yang di-generate:**

| Header | Fungsi |
|---|---|
| `Strict-Transport-Security` | Paksa HTTPS (HSTS) |
| `Content-Security-Policy` | Cegah XSS & code injection |
| `X-Frame-Options` | Cegah clickjacking |
| `X-Content-Type-Options` | Cegah MIME sniffing |
| `Referrer-Policy` | Kontrol info referrer |
| `Permissions-Policy` | Batasi akses fitur browser |
| `Cross-Origin-*-Policy` | Isolasi cross-origin resource |

**Output:**
```
header_configs/
├── nginx_security_headers.conf
├── apache_security_headers.htaccess
├── express_security_headers.js
├── Caddyfile_security_headers
└── headers.json
```

---

### `log_analyzer.py` — Web Server Log Analyzer

Analisis access log dan deteksi ancaman secara otomatis.

```bash
# Analisis log Nginx
python3 defender/log_analyzer.py /var/log/nginx/access.log

# Custom output + tuning threshold brute force
python3 defender/log_analyzer.py access.log --output ./report --bf-threshold 10 --bf-window 2

# Mode demo (tanpa file log)
python3 defender/log_analyzer.py
```

**Ancaman yang dideteksi:**

| Kategori | Pattern |
|---|---|
| SQL Injection | `UNION SELECT`, `sleep()`, `information_schema` |
| XSS | `<script>`, `onerror=`, `document.cookie` |
| Path Traversal | `../`, `%2e%2e`, `/etc/passwd` |
| RCE Attempt | `cmd.exe`, `eval(`, `base64_decode(` |
| Sensitive Files | `/.env`, `/.git/`, `/phpinfo.php` |
| Scanner Tools | `sqlmap`, `nikto`, `nuclei`, `ffuf` |

**Output:**
```
log_report/
├── LOG_REPORT.txt
├── log_analysis.json
└── suspect_ips.txt     ← langsung bisa di-block via UFW/iptables
```

---

### `toolkit/` — SOC Analyst Tier 1 Toolkit

Menu interaktif all-in-one untuk SOC analyst.

```bash
python3 defender/toolkit/soc_toolkit.py
```

```
╔══════════════════════════════════════════════════════════════╗
║         Tier 1 SOC Analyst Toolkit  v1.0                     ║
╚══════════════════════════════════════════════════════════════╝

  [1]  📋  Log Analyzer        — Analisis & deteksi ancaman dari access log
  [2]  🔄  SIEM Parser         — Normalisasi log berbagai sumber ke JSON
  [3]  🔍  IOC Extractor       — Ekstrak IP, domain, hash dari log/teks
  [4]  🚨  Alert Correlator    — Korelasi event log menjadi alert bermakna
  [5]  ⚡  Full Pipeline       — Parser → IOC → Alert sekaligus
  [6]  📊  Log Analyzer Classic — Statistik detail + threat patterns
  [0]  🚪  Keluar
```

**Deskripsi tiap tool:**

#### 🔄 SIEM Parser
Normalisasi log dari berbagai sumber ke format JSON seragam.
- Support: Nginx, Apache, `auth.log`, `syslog`, UFW firewall log
- Auto-deteksi tipe log dari nama file & konten
- Output digunakan sebagai input IOC Extractor & Alert Correlator

#### 🔍 IOC Extractor
Ekstrak Indicators of Compromise secara otomatis.
- IPv4, IPv6, Domain, URL, Email
- MD5, SHA1, SHA256 hash
- CVE ID, file path mencurigakan
- Filter IP private, enrichment kategori otomatis

#### 🚨 Alert Correlator
Korelasi event menjadi alert dengan severity level.

| Rule | Severity | Deskripsi |
|---|---|---|
| SSH Brute Force | HIGH | Banyak failed login SSH dari 1 IP |
| Web Scanner | MEDIUM | Banyak 404 ke path berbeda |
| Credential Stuffing | HIGH | 1 user dicoba dari banyak IP |
| Brute Force Success | CRITICAL | Gagal berkali-kali lalu berhasil login |
| Data Exfiltration | MEDIUM | Response size sangat besar |
| Port Scan | MEDIUM | Banyak port di-block dari 1 IP |

#### ⚡ Full Pipeline
Jalankan semua tool sekaligus dari satu file log:
```
Log File → SIEM Parser → IOC Extractor → Alert Correlator → Laporan
```

---

## ⚙️ Requirements

### Python
```bash
python3 --version   # minimal Python 3.10
```
Semua script menggunakan **Python standard library** — tidak perlu `pip install`.

### Tools Sistem (Opsional)
```bash
sudo apt install nmap whois dnsutils openssl
```

| Tool | Kegunaan |
|---|---|
| `nmap` | Deteksi versi service di port |
| `whois` | Info registrasi domain |
| `dnsutils` | Query DNS records detail |
| `openssl` | Cek protokol SSL/TLS lemah |

---

## 📅 Otomasi dengan Cron

```bash
# SSL Monitor setiap hari jam 8 pagi
0 8 * * * python3 /path/to/scanner/vuln_suite.py --target example.com --modules ssl

# Analisis log setiap malam jam 11
0 23 * * * python3 /path/to/defender/log_analyzer.py /var/log/nginx/access.log

# Port Watcher setiap hari jam 7 pagi (deteksi port baru)
0 7 * * * python3 /path/to/scanner/vuln_suite.py --target example.com --modules ports
```

---

## 🔧 Tools Lanjutan

| Tool | Instalasi | Kegunaan |
|---|---|---|
| **OWASP ZAP** | [zaproxy.org](https://www.zaproxy.org/) | Full web app pentest GUI |
| **Nikto** | `sudo apt install nikto` | Web server scanner |
| **Burp Suite** | [portswigger.net](https://portswigger.net/burp) | Web proxy & pentest suite |
| **Wazuh** | [wazuh.com](https://wazuh.com) | Open source SIEM |
| **Fail2ban** | `sudo apt install fail2ban` | Auto-block IP dari log |
| **pip-audit** | `pip install pip-audit` | Audit CVE pada pip packages |

---

## 📜 Etika Penggunaan

Script ini dibuat untuk keperluan **defensive security**.

✅ **Diperbolehkan:**
- Website dan server yang kamu kelola sendiri
- Lab environment / VM lokal
- Dengan izin tertulis dari pemilik sistem

❌ **Dilarang:**
- Website/server milik orang lain tanpa izin
- Infrastruktur publik atau pemerintah
- Aktivitas yang melanggar hukum siber (UU ITE)

---

## 📄 Lisensi

MIT License — bebas digunakan, dimodifikasi, dan didistribusikan dengan tetap mencantumkan kredit.
