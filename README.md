# 🔴 Redlense

<div align="center">

```
    ____           ____                    
   / __ \___  ____/ / /   ___  ____  _____ 
  / /_/ / _ \/ __  / /   / _ \/ __ \/ ___/ 
 / _, _/  __/ /_/ / /___/  __/ / / (__  )  
/_/ |_|\___/\__,_/_____/\___/_/ /_/____/   
```

### Professional Web Application Security Scanner

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.0.1-green.svg)](https://github.com/TENETx0/Redlense)

**Created by Monish Kanna**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-modules) • [Customization](#-customization) • [Contributing](#-contributing)

</div>

---

## 📋 Overview

**Redlense** is a comprehensive, professional-grade web application security scanner designed for penetration testers, security researchers, and bug bounty hunters. It provides an extensive suite of reconnaissance and vulnerability assessment modules in a sleek, animated terminal interface.

### ✨ Why Redlense?

- 🎯 **11 Comprehensive Modules** - From reconnaissance to cloud exposure analysis
- 🚀 **Professional Interface** - Beautiful animated terminal with 30 twinkling stars
- 🔧 **Highly Customizable** - Easy wordlist customization and configuration
- 📊 **Detailed Reports** - JSON and TXT reports for all scans
- 🌐 **Multiple Scan Modes** - Single module, multiple modules, or complete scan
- 🔒 **Privacy-First** - All scans run locally, no data sent externally

---

## 🎯 Features

### Core Capabilities

- ✅ **Pre-flight Validation** - URL normalization, DNS resolution, redirect chain analysis
- ✅ **Passive Reconnaissance** - WHOIS, DNS enumeration, subdomain discovery
- ✅ **TLS/SSL Analysis** - Certificate validation, cipher suite analysis, vulnerability detection
- ✅ **HTTP Security Headers** - Comprehensive header analysis with security scoring
- ✅ **Technology Fingerprinting** - Web server, framework, CMS detection
- ✅ **Application Surface Mapping** - Intelligent web crawling and sitemap generation
- ✅ **Directory & File Discovery** - Customizable wordlist-based enumeration (200+ paths)
- ✅ **Authentication & Session Analysis** - Login detection, session management testing
- ✅ **Input Validation Testing** - XSS, SQLi, command injection detection
- ✅ **API Reconnaissance** - REST/GraphQL endpoint discovery, JWT analysis, 200+ patterns
- ✅ **Cloud Exposure Analysis** - AWS/Azure/GCP detection, bucket scanning, 13+ providers

### Advanced Features

- 🎨 **Beautiful UI** - Gradient ASCII art, animated stars, progress bars
- 🔄 **Multi-Scan Support** - Run multiple modules sequentially
- 📈 **Progress Tracking** - Real-time scan progress and statistics
- 🎯 **Target Switching** - Change targets without restarting
- 📝 **Comprehensive Reports** - Detailed findings with severity classification
- 🛠️ **Helper Scripts** - 10+ additional tools for deep analysis

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git

### Step 1: Clone the Repository

```bash
git clone https://github.com/TENETx0/Redlense.git
cd Redlense
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

**Or with break-system-packages flag (if needed):**

```bash
pip install -r requirements.txt --break-system-packages
```

### Step 3: Set Up Directory Structure

```bash
# The directory structure should look like this:
Redlense/
├── Redlense.py           # Main menu interface
├── requirements.txt      # Python dependencies
├── modules/              # Scanning modules
│   ├── preflight.py
│   ├── passive.py
│   ├── tls.py
│   ├── headers.py
│   ├── tech.py
│   ├── crawler.py
│   ├── discovery.py
│   ├── auth.py
│   ├── validation.py
│   ├── api.py
│   └── cloud.py
├── scripts/              # Helper scripts
│   ├── session_tester.py
│   ├── fuzzer.py
│   ├── error_analyzer.py
│   ├── jwt_analyzer_pro.py
│   ├── api_fuzzer_pro.py
│   ├── graphql_tester_pro.py
│   ├── cloud_bucket_scanner.py
│   ├── cloud_metadata_tester.py
│   └── container_detector.py
├── Dirb/                 # Wordlists directory
│   └── Dir.txt          # Default wordlist (customizable)
└── Results/              # Scan results (auto-created)
```

### Step 4: Make Executable (Optional)

```bash
chmod +x Redlense.py
```

---

## 📖 Usage

### Basic Usage

```bash
python3 Redlense.py
```

### Quick Start Guide

1. **Launch Redlense**
   ```bash
   cd Redlense
   python3 Redlense.py
   ```

2. **Enter Target URL**
   ```
   Enter target URL (e.g., https://example.com): https://target.com
   ```

3. **Select a Module**
   ```
   [1]  Pre-flight Validation
   [2]  Passive Reconnaissance
   ...
   [14] Run All Modules
   
   [>] Enter your choice: 1
   ```

4. **View Results**
   - Results are saved in `./Results/` directory
   - Both TXT and JSON formats available

### Advanced Usage

#### Run Multiple Modules

```
[>] Enter your choice: 12
[>] Your selection: 1,4,7,10
```

#### Run Complete Scan

```
[>] Enter your choice: 14
```

#### Change Target Mid-Session

```
[>] Enter your choice: 13
```

---

## 🔧 Modules

### 1. Pre-flight Validation
- URL normalization and validation
- DNS resolution (A, AAAA, MX, NS, TXT, CNAME)
- HTTP/HTTPS availability checks
- Redirect chain analysis
- CDN/WAF detection (Cloudflare, Fastly, Akamai, etc.)
- Load balancer identification
- Protocol downgrade testing
- 200+ path discovery patterns

**Report:** `PreFlight_<domain>_<timestamp>.txt`

### 2. Passive Reconnaissance
- WHOIS information gathering
- DNS enumeration
- Subdomain discovery
- Email harvesting
- Technology stack detection
- IP geolocation
- Historical DNS records

**Report:** `PassiveRecon_<domain>_<timestamp>.txt`

### 3. TLS/SSL Analysis
- Certificate chain validation
- SSL/TLS protocol testing
- Cipher suite analysis
- Known vulnerability detection (POODLE, BEAST, Heartbleed)
- Certificate expiration checks
- HSTS verification

**Report:** `TLSAnalysis_<domain>_<timestamp>.txt`

### 4. HTTP Security Headers
- 30+ security header analysis
- Missing header detection
- Security score calculation (0-100)
- Best practice recommendations
- CSP, HSTS, X-Frame-Options validation

**Report:** `SecurityHeaders_<domain>_<timestamp>.txt`

### 5. Technology Fingerprinting
- Web server detection (Nginx, Apache, IIS, etc.)
- Framework identification (Django, Rails, Laravel, etc.)
- CMS detection (WordPress, Joomla, Drupal, etc.)
- JavaScript library detection
- Analytics platform identification

**Report:** `TechStack_<domain>_<timestamp>.txt`

### 6. Application Surface Mapping
- Intelligent web crawling
- Link discovery and analysis
- Form detection
- JavaScript file extraction
- API endpoint discovery
- Sitemap generation

**Report:** `SurfaceMap_<domain>_<timestamp>.txt`

### 7. Directory & File Discovery
- **200+ built-in paths** tested by default
- Customizable wordlist support
- Soft-404 detection
- Interesting file discovery
- Admin panel detection
- Backup file identification

**Report:** `Discovery_<domain>_<timestamp>.txt`

### 8. Authentication & Session Analysis
- Login page detection
- Session management testing
- Cookie security analysis
- Authentication bypass attempts
- Multi-factor authentication detection
- Session timeout testing

**Report:** `AuthAnalysis_<domain>_<timestamp>.txt`

### 9. Input Validation & Weak Signal Detection
- XSS vulnerability testing
- SQL injection detection
- Command injection testing
- Path traversal checks
- LDAP injection testing
- Error message analysis

**Report:** `InputValidation_<domain>_<timestamp>.txt`

### 10. API Reconnaissance
- **200+ API endpoint patterns**
- REST/GraphQL endpoint discovery
- API versioning detection
- Authentication testing
- JWT token analysis (500+ weak secrets)
- OpenAPI/Swagger detection
- Rate limiting detection

**Report:** `APIRecon_<domain>_<timestamp>.txt|.json`

**Helper Scripts:**
- `jwt_analyzer_pro.py` - Advanced JWT analysis with 500+ weak secret dictionary
- `api_fuzzer_pro.py` - API fuzzing with 100+ attack payloads
- `graphql_tester_pro.py` - GraphQL introspection and testing

### 11. Cloud & Hosting Exposure Analysis
- **13 cloud provider detection** (AWS, Azure, GCP, Oracle, DigitalOcean, Linode, Alibaba, IBM, Cloudflare, Vercel, Netlify, Heroku, Fastly)
- Object storage bucket discovery (S3, Azure Blob, GCS)
- Metadata endpoint detection
- Container/orchestration detection (Docker, Kubernetes, OpenShift)
- Serverless function identification
- CI/CD platform detection (Jenkins, GitLab CI, GitHub Actions, etc.)
- MLOps platform detection (MLflow, Kubeflow, SageMaker, etc.)
- Environment variable leak detection

**Report:** `CloudExposure_<domain>_<timestamp>.txt|.json`

**Helper Scripts:**
- `cloud_bucket_scanner.py` - S3/Azure/GCS bucket scanner with 30+ naming patterns
- `cloud_metadata_tester.py` - SSRF metadata endpoint testing
- `container_detector.py` - Container platform detection

---

## 🎨 Customization

### Wordlist Customization

Redlense uses customizable wordlists for directory and file discovery. The default wordlist is located at:

```
Dirb/Dir.txt
```

#### Built-in Paths (200+)

The default wordlist includes:
- Admin panels (`/admin`, `/administrator`, `/wp-admin`)
- Login pages (`/login`, `/signin`, `/auth`)
- Config files (`/config.php`, `/.env`, `/web.config`)
- Backup files (`/backup.zip`, `/site-backup.tar.gz`)
- API endpoints (`/api`, `/graphql`, `/swagger`)
- Development files (`/debug`, `/test`, `/phpinfo.php`)
- Framework-specific paths (WordPress, Django, Laravel, etc.)
- And 150+ more...

#### How to Customize

**Option 1: Edit the Default Wordlist**

```bash
nano Dirb/Dir.txt
```

Add your custom paths (one per line):
```
/custom-admin
/my-api
/special-endpoint
/hidden-panel
```

**Option 2: Use a Custom Wordlist**

Modify the module to point to your wordlist:

```python
# In modules/discovery.py (or relevant module)
WORDLIST_PATH = 'path/to/your/wordlist.txt'
```

**Option 3: Use External Wordlists**

Popular wordlists you can use:
- [SecLists](https://github.com/danielmiessler/SecLists) - Comprehensive wordlist collection
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) - Attack patterns and discovery lists
- [Assetnote Wordlists](https://wordlists.assetnote.io/) - Curated wordlists

Example:
```bash
# Download SecLists
git clone https://github.com/danielmiessler/SecLists.git

# Use specific wordlist
cp SecLists/Discovery/Web-Content/common.txt Dirb/Dir.txt
```

#### API Endpoint Customization

The API module includes **200+ built-in endpoint patterns**. To add custom patterns:

```python
# In modules/api.py, add to api_endpoints list:
'/your-custom-endpoint',
'/v1/your-api',
'/custom/route',
```

#### Cloud Provider Customization

To add custom cloud provider patterns:

```python
# In modules/cloud.py, add to cloud_providers dictionary:
'Your Cloud Provider': {
    'headers': {'X-Custom-Header': 'Provider Name'},
    'patterns': [r'\.yourcloud\.com'],
    'services': {'service': 'Service Name'}
}
```

---

## 📊 Sample Output

### Scan Summary

```
╔════════════════════════════════════════════════════════════╗
║  ✓ Scan completed in 45.23s                              ║
╚════════════════════════════════════════════════════════════╝

Statistics:
├──╼ Successful: 11
├──╼ Failed: 0
├──╼ Duration: 0m 45s
└──╼ Reports: ./Results/

[✓] Total scans completed: 11
[✓] Results saved in: ./Results/
```

### Report Files

```bash
Results/
├── PreFlight_example_com_20241228_143022.txt
├── PassiveRecon_example_com_20241228_143145.txt
├── TLSAnalysis_example_com_20241228_143301.txt
├── SecurityHeaders_example_com_20241228_143422.txt
├── TechStack_example_com_20241228_143545.txt
├── SurfaceMap_example_com_20241228_143712.txt
├── Discovery_example_com_20241228_143845.txt
├── AuthAnalysis_example_com_20241228_144012.txt
├── InputValidation_example_com_20241228_144156.txt
├── APIRecon_example_com_20241228_144334.txt
├── APIRecon_example_com_20241228_144334.json
├── CloudExposure_example_com_20241228_144512.txt
└── CloudExposure_example_com_20241228_144512.json
```

---

## 🛡️ Legal Disclaimer

**IMPORTANT: This tool is for authorized security testing only.**

- ⚖️ Only use Redlense on systems you own or have explicit permission to test
- 📋 Unauthorized scanning may be illegal in your jurisdiction
- 🎯 Respect robots.txt and rate limits
- 🔒 Be responsible - do not abuse this tool
- ⚠️ The author is not responsible for misuse or damage caused by this tool

**Always obtain written authorization before testing any system.**

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Reporting Bugs

Open an issue with:
- Description of the bug
- Steps to reproduce
- Expected vs actual behavior
- System information (OS, Python version)

### Suggesting Features

Open an issue with:
- Feature description
- Use case
- Potential implementation approach

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style

- Follow PEP 8 guidelines
- Add comments for complex logic
- Update documentation for new features
- Test your changes thoroughly

---

## 📝 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

```
GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

Copyright (C) 2024 Monish Kanna

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

### Key Points of GPL v3

- ✅ **Freedom to Use** - Use the software for any purpose
- ✅ **Freedom to Study** - Access and modify the source code
- ✅ **Freedom to Share** - Distribute copies to help others
- ✅ **Freedom to Improve** - Distribute modified versions
- ⚠️ **Copyleft** - Derivative works must also be GPL v3
- 🔒 **Patent Protection** - Protection against patent claims
- 📋 **Attribution Required** - Must preserve copyright notices

---

## 🙏 Acknowledgments

- **Security Community** - For continuous research and vulnerability discoveries
- **Open Source Projects** - For the amazing libraries and tools used in this project
- **Contributors** - For improving and expanding Redlense
- **Bug Bounty Hunters** - For testing and feedback

---

## 📞 Contact

**Monish Kanna**

- GitHub: [@TENETx0](https://github.com/TENETx0)
- Project Link: [https://github.com/TENETx0/Redlense](https://github.com/TENETx0/Redlense)

---

## ⭐ Star History

If you find Redlense useful, please consider giving it a star! ⭐

---

## 📈 Roadmap

### Upcoming Features

- [ ] AI-Powered Vulnerability Analysis (GPT-4 Vision integration)
- [ ] Automated report generation with executive summaries
- [ ] Integration with vulnerability databases (CVE, NVD)
- [ ] Web-based dashboard for scan management
- [ ] Multi-threading for faster scans
- [ ] Custom plugin system
- [ ] Docker container support
- [ ] CI/CD pipeline integration
- [ ] Webhook notifications
- [ ] Export to Burp Suite / OWASP ZAP

### Version 2.1.0 (Coming Soon)

- Enhanced cloud provider detection (20+ providers)
- Kubernetes namespace enumeration
- Container registry scanning
- Enhanced API fuzzing with AI-generated payloads
- Real-time scan progress dashboard

---

<div align="center">

### Made with ❤️ by Monish Kanna

**[⬆ Back to Top](#-redlense)**

</div>
