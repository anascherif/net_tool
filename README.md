# ICT Tool

> **A modern, menu-driven CLI toolkit for subnetting, VLSM, and IPv6 — perfect for CCNA/DevNet practice and real-world network planning.**

---

## ✨ Features

- **IPv4 Subnet Calculator** — Network, broadcast, mask, wildcard, usable range, class, private/public detection
- **IPv6 Prefix Calculator** — Prefix boundaries, address count, type flags
- **VLSM Subnet Planner** — Largest-first allocation for efficient address use
- **EUI-64 Tool** — MAC ↔ IPv6 link-local conversion with step-by-step explanation
- **Subnet Summary Table** — List all child subnets from a base prefix
- **ERREETOOL Advanced Toolkit** — Typer-based subcommands for scanning, ports, DNS, ping, traceroute, Wi-Fi, speed test, and diagnostics

---

## 🧰 ERREETOOL (Advanced Toolkit)

ERREETOOL is a professional, command-style toolkit built for advanced networking operations.

**Launch from the main menu:**
1. Select **[6] ERREETOOL | Advanced Networking Toolkit**
2. Enter a one-off command (e.g., `scan 192.168.1.0/24`)

**Direct CLI usage:**
```sh
python -m erreetool.cli scan 192.168.1.0/24
python -m erreetool.cli ports 192.168.1.1 --full
python -m erreetool.cli dns openai.com
python -m erreetool.cli ping google.com
python -m erreetool.cli trace google.com
python -m erreetool.cli wifi
python -m erreetool.cli speedtest
python -m erreetool.cli doctor
```

---

## 📸 Example Output

Below are real screenshots of the tool in action:

**Main Menu**

<p align="center">
	<img src="images/menu.png" alt="Main Menu" width="400"/>
</p>

**Main Menu (Exit)**

<p align="center">
	<img src="images/exit.png" alt="Main Menu Exit" width="400"/>
</p>

**IPv4 Subnet Calculator**

<p align="center">
	<img src="images/ipv4_cal.png" alt="IPv4 Subnet Calculator" width="500"/>
</p>

**IPv6 Prefix Calculator**

<p align="center">
	<img src="images/ipv6.png" alt="IPv6 Prefix Calculator" width="500"/>
</p>

**VLSM Subnet Planner**

<p align="center">
	<img src="images/VLSM_planner.png" alt="VLSM Subnet Planner" width="600"/>
</p>

**Subnet Summary Table**

<p align="center">
	<img src="images/subnet_table.png" alt="Subnet Summary Table" width="800"/>
</p>

---

## 🚀 Quick Start

### Requirements

- Python 3.10+

### Getting Started

1. **Clone this repository:**
   ```sh
   git clone https://github.com/anascherif/ict_tool.git
   cd ict_tool
   ```
2. **Set up your environment and run the tool:**
   - Open a terminal in the project folder and run **one** of the following commands:

   **PowerShell:**

   ```powershell
   python -m venv .venv; .venv\Scripts\Activate.ps1; pip install -r requirements.txt; python ict_tool.py
   ```

   **CMD:**

   ```cmd
   python -m venv .venv && .venv\Scripts\activate.bat && pip install -r requirements.txt && python ict_tool.py
   ```

   This will automatically create a virtual environment, install dependencies, and launch the tool.

3. **Re-run the tool anytime:**
   - After setup, you can launch the tool again with:

   **PowerShell or CMD:**

   ```sh
   .venv\Scripts\python.exe ict_tool.py
   ```

---

## 🔮 Upcoming Features

### `assess` — AI-Assisted Vulnerability Triage

A new `assess` subcommand that turns raw recon output into an AI-generated vulnerability report, targeting lab environments such as Metasploitable2 or HackTheBox-style VMs.

**How it works (pipeline):**

1. **Scan** — Runs the existing port scanner (nmap or socket-based) against the target to collect open ports, detected services, and version strings (e.g. `vsftpd 2.3.4`, `Apache 2.4.29`).
2. **CVE Enrichment** — For each identified service/version, queries the NVD (National Vulnerability Database) public API to find matching known CVEs. Handles rate-limiting with retry/backoff — no API key required.
3. **Report Compilation** — Aggregates open ports, services, versions, and CVE matches into a structured JSON object.
4. **AI Triage** — Sends the compiled report to a free LLM via OpenRouter (`openrouter/auto`) with a security-analyst system prompt. The model:
   - Ranks findings by severity (Critical / High / Medium / Low)
   - Explains each finding in plain English
   - Identifies the most likely entry point for further manual exploitation
5. **Formatted Output** — Prints the LLM's response in a terminal-friendly, scannable format using `rich`.

**Usage:**
```sh
python -m erreetool.cli assess 192.168.56.102 --full
python -m erreetool.cli assess 10.10.10.27 --offline   # skip CVE lookups, demo mode
python -m erreetool.cli assess 192.168.56.102 --explain # includes AI explanation
```

**Key design notes:**
- No API keys required — NVD is free (rate-limited), OpenRouter uses the existing `OPENROUTER_API_KEY` already set in `.env`
- Private/lab IPs (e.g. `192.168.x.x`, `10.x.x.x`) are automatically handled — CVE lookups still run, IP reputation checks are skipped since they don't apply to private addresses
- `--offline` flag skips the NVD API calls entirely, sending raw scan results directly to the LLM for demo or environments without internet access
- All API interactions fail gracefully with clear messages; the scan itself never requires internet

> **Reminder:** Only run `assess` against systems you own or are explicitly authorized to test.

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🙋 Contact

For questions or feedback, open an issue or contact [anas abd elmalek cherif](https://github.com/anascherif).
