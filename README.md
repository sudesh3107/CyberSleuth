# CyberSleuth
**Advanced Multi-Threaded OSINT & Vulnerability Scanner**

---

## 🚀 Installation

### ⚠️ Important Configuration

> **Note:**  
> Before running CyberSleuth, make sure to update all required configuration fields—such as your **Shodan API key**—in the appropriate configuration files or environment variables.  
>  
> Failure to set the correct API keys will cause certain modules (like Shodan-based scans) to fail.

Clone the repository:
```bash
git clone https://github.com/sudesh3107/CyberSleuth.git
```

Install the required dependencies:
```bash
pip install requests beautifulsoup4 python-whois dnspython shodan builtwith
```



(Optional) Make the script executable:
```bash
chmod +x cybersleuth.py
```

---

## 🔍 Basic Scan

```bash
./cybersleuth.py example.com
```

---

## 💪 Full Intensive Scan (Use All CPU Cores)

```bash
./cybersleuth.py example.com --full
```

---

## 💾 Saving Results

```bash
./cybersleuth.py example.com -o scan_results.json
```

---

## 🌟 Key Features

### Comprehensive OSINT Gathering
- Domain registration details (WHOIS)
- Subdomain discovery (brute-force)
- DNS record enumeration
- Port scanning with service detection
- Technology stack identification
- Email and phone number harvesting
- Sensitive file discovery

### Advanced Vulnerability Scanning
- Exposed .git directories
- Directory listing vulnerabilities
- Accessible admin panels
- Outdated server software
- Exposed environment files
- CORS misconfigurations
- Clickjacking vulnerabilities
- Insecure cookies

### Performance Optimizations
- Multi-threaded architecture (utilizes all CPU cores)
- Parallel execution of scan modules
- Intelligent task scheduling
- Connection pooling and timeout management

### Professional Reporting
- Terminal summary with key findings
- Detailed vulnerability descriptions
- Remediation guidance
- JSON output for programmatic processing

### Safety Features
- Ethical scanning guidelines
- Rate limiting considerations
- Error handling for unstable targets
- Clear permission warnings

---

## ⚠️ Disclaimer

CyberSleuth is intended for authorized use only. Always obtain proper permission before scanning any target.
