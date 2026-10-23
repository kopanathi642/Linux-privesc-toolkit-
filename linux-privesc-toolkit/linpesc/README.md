# Linux Privilege Escalation Automation Toolkit & Dark UI Dashboard

A **detection-only**, modular defensive cybersecurity auditing framework that scans a local Linux host for privilege-escalation vectors, weak permissions, abusable SUID binaries, misconfigured services, vulnerable cron jobs, and known kernel/polkit CVE indicators.

Includes both a standalone **CLI engine** (zero third-party dependencies) and a modern **Streamlit Dark Security Dashboard**.

> 🔒 **Safety Model:** Every scanner module is strictly read-only. The toolkit runs passive enumeration commands (`find`, `uname`, `sudo -n -l`, `crontab -l`, `getcap`, `ls`) and parses their output. It **never** executes exploits, creates persistence, modifies system configuration, drops payloads, steals credentials, or escalates privileges.

---

## Architecture & Detection Pipeline

```
START: python3 main.py / streamlit run app.py
  │
  ├─► [1] sysinfo     : User session, UID/GID context, root check, kernel/OS release
  ├─► [2] suid_scan   : Grouped SUID/SGID discovery (-type f) + GTFOBins catalog matching + getcap file capabilities
  ├─► [3] permissions : World-writable files, non-sticky writable dirs (! -perm -1000), /etc/passwd & /etc/shadow modes
  ├─► [4] services    : Non-interactive sudo -l rules + systemd unit & drop-in ExecStart target writability
  ├─► [5] cron_scan   : User/system crontabs, comments & env var stripping, writable script & directory hijacking
  ├─► [6] kernel_scan : Kernel version vs Dirty Pipe / Dirty COW / OverlayFS CVEs + dedicated pkexec (CVE-2021-4034) polkit check
  │
  ▼
[7] report.py : Severity sorting (CRITICAL → INFO) + Confidence tracking
  │
  ├─► report_<timestamp>.json (Machine-readable)
  ├─► report_<timestamp>.txt  (Terminal pager / text review)
  └─► report_<timestamp>.html (Standalone styled HTML report)
```

---

## Module Summary

| Module | Inspection Targets | Privilege Escalation Vectors Identified |
|---|---|---|
| **`sysinfo`** | `whoami`, `id`, `uname -a`, `/etc/os-release` | Identity context, administrative group memberships (`docker`, `lxd`, `sudo`), session privilege level. |
| **`suid_scan`** | `find / -xdev -type f ( -perm -4000 -o -perm -2000 )`, `getcap -r /` | Discovers SUID/SGID binaries cross-referenced with GTFOBins abuse patterns, plus elevated POSIX capabilities (`cap_setuid`, `cap_dac_override`). |
| **`permissions`** | Filesystem permissions, sensitive auth paths | World-writable files, world-writable directories lacking sticky bit (`+t`), `/etc/passwd` write access, `/etc/shadow` read/write access. |
| **`services`** | `sudo -n -l`, `/etc/systemd/system/**/*.service` & `.d/*.conf` | `NOPASSWD` / `ALL` sudo allowances, systemd units running as root pointing at user-writable binaries or parent directories. |
| **`cron_scan`** | `crontab -l`, `/etc/crontab`, `/etc/cron.*/*` | Scripts or wrapper directories executed by root cron tasks that can be modified or hijacked by non-root users. |
| **`kernel_scan`** | `uname -r`, `which pkexec`, `pkexec --version` | Upstream kernel version matching against Dirty Pipe (CVE-2022-0847), Dirty COW (CVE-2016-5195), OverlayFS (CVE-2023-2640), and polkit PwnKit check. |

---

## Operating System Requirements & Compatibility

* **Target Operating System:** **Linux** (Ubuntu 20.04/22.04/24.04, Debian 11/12, Kali Linux, Red Hat Enterprise Linux / CentOS / Fedora).
* **Running from Windows:** If you are developing or running on a Windows workstation, run the toolkit inside **WSL2** (Windows Subsystem for Linux) or an **Ubuntu/Kali Virtual Machine** (VirtualBox / VMware) so that genuine POSIX permissions, SUID bits, and Linux kernel interfaces can be audited.

---

## Installation & Setup

### 1. Clone or Copy the Repository
```bash
git clone https://github.com/your-username/linux-privesc-toolkit.git
cd linux-privesc-toolkit/linpesc
```

### 2. Set Up Virtual Environment (Recommended)
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows PowerShell: .venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
The core CLI scanner requires **no external packages** (Python 3.8+ standard library only).
To launch the dark UI dashboard, install Streamlit:
```bash
pip install -r requirements.txt
```

---

## Usage

### A. Launch the Streamlit Dark UI Dashboard
```bash
streamlit run app.py
```
* Binds to `http://localhost:8501` by default.
* **Overview:** View host identity, root state, metric cards, severity breakdown bar chart, and module counts.
* **Run Scan:** Select/deselect modules (`sysinfo`, `suid`, `permissions`, `services`, `cron`, `kernel`) and click **Run Audit Scan** with real-time status and console output.
* **Findings Explorer:** Search by title/evidence, filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), and inspect detailed cards with confidence ratings, exploitability notes, and copyable mitigation commands.
* **Reports:** View and download generated JSON, HTML, and plain-text reports with one click.
* **About & Safety:** Comprehensive safety, authorization, and scope disclosures.

### B. Run via Command Line (CLI)
Run the scanner from a non-root user shell:
```bash
python3 main.py --out-dir ./report_output --formats json,text,html
```

#### CLI Options:
* `--out-dir DIR` — Directory where report files are stored (default: `./report_output`).
* `--formats FORMATS` — Comma-separated report formats: `json`, `text`, `html` (default: `json,text,html`).
* `--skip MODULES` — Skip specific modules by name: e.g. `--skip suid,cron`.

> 💡 **Best Practice:** Run the scanner as the **low-privilege user** you want to evaluate. Running as `root` trivially makes all files "writable," causing the toolkit to automatically skip writability checks to avoid false positives.

---

## Running the Automated Test Suite

All unit tests use mock subprocess execution and do not alter host files:
```bash
python3 -m unittest discover -s tests -v
```

Syntax and bytecode verification:
```bash
python3 -m compileall -q .
```

---

## Limitations & Defensive Caveats

1. **Local Host Scope:** The scanner audits the system where the Python process runs. It does not remotely scan network endpoints or client browsers.
2. **Preliminary CVE Classification:** Kernel version matches are flagged as `Preliminary` because enterprise distributions (Debian, Ubuntu, Red Hat) frequently backport security fixes into older kernel versions without bumping upstream major version numbers. Always verify patch status with your vendor tracker (`apt changelog` or `rpm -q --changelog`).
3. **Detection-Only:** No exploit verification is executed. Operators should verify each finding manually before taking remediation action.

---

## Screenshots to Capture (Project Submission Checklist)

Capture the following screenshots when testing on your target Linux machine/VM:
- [ ] **CLI Execution:** Terminal running `python3 main.py` showing module progress and summary breakdown.
- [ ] **HTML Report:** Browser view of generated `report_<timestamp>.html` showing severity stat boxes.
- [ ] **Streamlit Overview Dashboard:** Dark UI showing metrics row, host context, and severity bar chart.
- [ ] **Streamlit Findings Explorer:** Filtered table and expanded finding card showing Evidence & Remediation.
- [ ] **Streamlit Reports Page:** Report file list with download buttons.
- [ ] **Unit Tests:** Terminal showing `python3 -m unittest discover -s tests -v` passing all tests.
