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
## OUTPUT

---

```bash
[+] Scan Summary:
  - Target IP: 93.184.216.34
  - Domain Info: 8 records
  - Subdomains Found: 7
  - Open Ports: 3
  - Technologies: 12 detected
  - Emails Collected: 3
  - Phone Numbers: 1
  - Sensitive Files: 2 found
  - Vulnerabilities: 2 detected
  - Scan Duration: 32.14 seconds

[!] VULNERABILITIES FOUND:

1. Outdated Server Software (High)
   Description: Outdated server version detected: Apache/2.4.1
   Solution: Upgrade to the latest secure version of the web server software

2. Exposed Environment File (Critical)
   Description: .env file found containing potentially sensitive environment variables
   Solution: Move environment variables to secure storage and remove .env from web root
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
