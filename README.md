![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

# NetVulnScanner

NetVulnScanner is a lightweight, non-intrusive vulnerability scanner written in Python. It scans a target website, domain, or IP address for exposed TCP services, common web security misconfigurations, weak TLS settings, and a small set of informational service-level risks.

The project is designed for learning, authorized security reviews, homelab auditing, and portfolio demonstration. It intentionally avoids destructive tests, exploit chains, credential attacks, spidering, heavy brute forcing, or anything that could reasonably disrupt a target.

> Use this tool only on systems you own or have explicit permission to test.

## Why I Made This

I built this project to better understand how practical vulnerability scanners work under the hood. Many security tools are powerful, but they can also hide the fundamentals behind large frameworks and plugins. This scanner focuses on the core mechanics:

- Opening TCP sockets and identifying exposed services
- Grabbing banners safely
- Checking HTTP response headers
- Inspecting TLS protocol and certificate behavior
- Sending small, controlled web probes
- Organizing findings into readable console output and structured JSON

The goal is not to replace professional tools such as Nmap, Nessus, OpenVAS, or Burp Suite. Instead, SafeVulnScanner is a transparent, readable implementation that demonstrates the building blocks of network and web security assessment.

## Features

### TCP Port Scanning

- Scans a configurable TCP port range
- Supports individual ports and ranges, such as `80,443,8080` or `1-1024`
- Uses multithreading for faster scans
- Attempts lightweight banner grabbing for open services
- Recognizes common services including HTTP, HTTPS, SSH, FTP, SMTP, SMB, Redis, MySQL, PostgreSQL, MongoDB, RDP, VNC, and more

### Web Security Checks

When HTTP or HTTPS services are discovered, the scanner performs safe checks for:

- Missing `Strict-Transport-Security`
- Missing `Content-Security-Policy`
- Missing `X-Frame-Options`
- Missing `X-Content-Type-Options`
- Missing `Referrer-Policy`
- Cookies missing the `HttpOnly` flag
- Interesting common paths such as `/admin`, `/.git/`, `/backup.zip`, `/phpinfo.php`, and `/robots.txt`
- Server headers and HTML generator tags that indicate outdated software

### TLS and Certificate Checks

For HTTPS targets, the scanner checks for:

- SSLv2 support, where available in the local Python/OpenSSL build
- SSLv3 support, where available
- TLS 1.0 support
- Expired certificates
- Certificates expiring soon
- Hostname mismatch indicators
- Self-signed certificate indicators
- Weak cipher groups such as export, NULL, RC4, DES, and 3DES where supported by the local OpenSSL build

### Non-Intrusive Vulnerability Simulators

The scanner includes small informational probes for:

- Reflected XSS indicators using a harmless dummy marker
- SQL error disclosure using a single quote parameter
- Open redirect behavior using a controlled redirect parameter

These checks do not exploit vulnerabilities. They only look for obvious response patterns that may deserve manual review.

### Service-Specific Checks

SafeVulnScanner performs limited, informational checks for:

- FTP anonymous login
- Outdated OpenSSH banners
- SMTP `VRFY` and `EXPN` support
- SMB null session exposure as a manual-review indicator
- SNMP `public` community response
- DNS zone transfer response
- Redis unauthenticated `INFO` access

### JSON Reporting

Results can be saved to a JSON file containing:

- Target and resolved IP
- Scan timestamp
- Open ports
- Service names and banners
- Vulnerability findings
- Web header, directory, software, simulator, and SSL results
- Non-critical error log

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/safevulnscanner.git
cd safevulnscanner
```

Install the only external dependency:

```bash
pip install requests
```

The scanner otherwise uses Python standard-library modules such as `socket`, `ssl`, `threading`, `argparse`, `datetime`, `json`, `queue`, `re`, and `urllib.parse`.

## Usage

Basic scan:

```bash
python vuln_scanner.py --target example.com
```

Scan specific ports:

```bash
python vuln_scanner.py --target example.com --ports 80,443,8080
```

Scan a range with custom timeout and thread count:

```bash
python vuln_scanner.py --target 192.168.1.10 --ports 1-1000 --timeout 1.5 --threads 50
```

Save results to JSON:

```bash
python vuln_scanner.py --target example.com --ports 80,443 --output scan_results.json
```

Limit directory checks:

```bash
python vuln_scanner.py --target example.com --dir-depth 5
```

## Example Output

```text
[+] Target: example.com (93.184.216.34)
[+] Scanning ports: 80,443,8080
[#] Scanning port 80...
[+] 80/tcp: open (HTTP - HTTP/1.1 200 OK Server: Apache/2.4.41)
[!] Web: Missing CSP header
[!] Web: /robots.txt returned 200 length=42
[#] Scanning port 443...
[+] 443/tcp: open (HTTPS - HTTP/1.1 200 OK Server: nginx/1.18.0)
[!] SSL: TLS 1.0 supported (Weak)
[-] Port 8080/tcp: closed or filtered
[+] Scan completed in 12.3 seconds. Results saved to scan_results.json
```

## Example JSON Structure

```json
{
  "target": "example.com",
  "resolved_ip": "93.184.216.34",
  "scan_time": "2026-05-11T14:30:00Z",
  "open_ports": [
    {
      "port": 80,
      "service": "HTTP",
      "banner": "HTTP/1.1 200 OK Server: Apache/2.4.41"
    }
  ],
  "vulnerabilities": [
    {
      "name": "Web: Missing CSP header",
      "severity": "Low",
      "description": "Content-Security-Policy was not present in the HTTP response.",
      "evidence": "http://example.com/"
    }
  ],
  "web_checks": {
    "headers": {},
    "directories": [],
    "ssl_issues": [],
    "software": [],
    "simulators": []
  },
  "error_log": []
}
```

## How It Works

SafeVulnScanner is organized around three main components:

- `PortScanner`: scans TCP ports concurrently, identifies open services, and performs safe banner grabbing.
- `WebScanner`: runs HTTP, HTTPS, header, directory, TLS, cookie, and non-intrusive web checks.
- `VulnChecker`: runs small service-specific checks against discovered ports.

The main `VulnerabilityScanner` class coordinates the full workflow:

1. Normalize and resolve the target
2. Parse the requested port list
3. Scan ports with a thread pool
4. Run web checks on discovered HTTP and HTTPS services
5. Run service-specific checks on discovered ports
6. Print readable progress to the console
7. Save structured JSON results when requested

All network operations use timeouts and exception handling so failed connections, resets, SSL errors, and unreachable services do not stop the scan.

## Safety Design

This project is intentionally conservative:

- No crawling or spidering
- No password guessing
- No exploit payloads
- No file uploads
- No destructive requests
- No high-volume brute forcing
- No persistence or post-exploitation logic

Directory checks are limited to a short built-in list by default, and web simulators only test the main page with one sample parameter.

## Limitations

SafeVulnScanner is a learning and lightweight assessment tool. It has important limitations:

- It does not replace professional vulnerability scanners
- Version-based detection can produce false positives or false negatives
- Some TLS checks depend on what the local Python/OpenSSL build supports
- Service checks are intentionally shallow and may require manual validation
- UDP scanning is not implemented except for the small SNMP community check
- It does not authenticate to applications or scan behind login pages
- It does not perform deep application security testing

Findings should be treated as indicators that require validation, not as final proof of exploitability.

## Future Features

Planned improvements include:

- Configurable path wordlists with safe rate limits
- CSV and HTML report output
- Better service fingerprinting
- Optional UDP scan mode
- CVE enrichment for detected software versions
- Severity scoring with clearer remediation guidance
- More precise TLS configuration reporting
- Robots-aware optional crawling mode for authorized tests
- Plugin-style checks for easier extension
- Unit tests and local mock services for safer validation
- GitHub Actions workflow for linting and packaging

## Responsible Use

Only scan targets where you have permission. Even lightweight scans can trigger alerts, violate acceptable-use policies, or create legal issues when run against third-party systems.

This project is provided for educational and authorized security testing purposes.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
