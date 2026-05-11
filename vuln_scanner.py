#!/usr/bin/env python3
"""
Non-intrusive website/system vulnerability scanner.

Usage:
    python vuln_scanner.py --target example.com --ports 80,443,8080 --threads 10 --output result.json

Dependencies:
    This script uses only Python standard libraries except for "requests".
    If requests is missing, install it with:
        pip install requests

Ethics and safety:
    Run this scanner only against systems you own or have explicit permission to test.
    Checks are intentionally lightweight and informational. The script does not spider,
    brute force credentials, exploit vulnerabilities, or attempt destructive actions.
"""

import argparse
import datetime
import json
import queue
import re
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests. Install with: pip install requests")
    sys.exit(1)


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    27017: "MongoDB",
}

DEFAULT_PATHS = [
    "/admin",
    "/backup.zip",
    "/.git/",
    "/phpinfo.php",
    "/robots.txt",
    "/hidden",
    "/config",
]

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"PostgreSQL.*ERROR",
    r"Microsoft SQL Server",
    r"ORA-\d{5}",
    r"SQLite/JDBCDriver",
    r"sqlite error",
    r"syntax error at or near",
    r"unclosed quotation mark",
]


class Console:
    """Small console helper for consistent, readable scan output."""

    COLORS = {
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "blue": "\033[94m",
        "reset": "\033[0m",
    }

    def __init__(self):
        """Initialize console coloring based on TTY support."""
        self.use_color = sys.stdout.isatty()
        self.lock = threading.Lock()

    def _paint(self, text, color):
        """Return colored text when stdout supports ANSI escapes."""
        if not self.use_color or color not in self.COLORS:
            return text
        return f"{self.COLORS[color]}{text}{self.COLORS['reset']}"

    def info(self, message):
        """Print a positive informational message."""
        self._print(self._paint(f"[+] {message}", "green"))

    def warn(self, message):
        """Print a warning or finding."""
        self._print(self._paint(f"[!] {message}", "yellow"))

    def error(self, message):
        """Print an error message."""
        self._print(self._paint(f"[-] {message}", "red"))

    def progress(self, message):
        """Print a neutral progress message."""
        self._print(self._paint(f"[#] {message}", "blue"))

    def _print(self, message):
        """Print from multiple threads without interleaving lines."""
        with self.lock:
            print(message, flush=True)


class ResultStore:
    """Thread-safe result accumulator for JSON output."""

    def __init__(self, target, resolved_ip):
        """Create a result store for a target."""
        self.lock = threading.Lock()
        self.data = {
            "target": target,
            "resolved_ip": resolved_ip,
            "scan_time": datetime.datetime.utcnow().isoformat() + "Z",
            "open_ports": [],
            "vulnerabilities": [],
            "web_checks": {
                "headers": {},
                "directories": [],
                "ssl_issues": [],
                "software": [],
                "simulators": [],
            },
            "error_log": [],
        }

    def add_open_port(self, port, service, banner):
        """Record an open port and its service information."""
        with self.lock:
            self.data["open_ports"].append(
                {"port": port, "service": service, "banner": banner[:500]}
            )

    def add_vulnerability(self, name, severity, description, evidence):
        """Record a vulnerability or risk finding."""
        with self.lock:
            item = {
                "name": name,
                "severity": severity,
                "description": description,
                "evidence": str(evidence)[:500],
            }
            self.data["vulnerabilities"].append(item)

    def add_web_check(self, category, item):
        """Record a web-specific check result."""
        with self.lock:
            if category in self.data["web_checks"]:
                if isinstance(self.data["web_checks"][category], list):
                    self.data["web_checks"][category].append(item)
                elif isinstance(self.data["web_checks"][category], dict):
                    self.data["web_checks"][category].update(item)

    def add_error(self, where, error):
        """Record a non-critical error."""
        with self.lock:
            self.data["error_log"].append({"where": where, "error": str(error)[:500]})

    def get_open_ports(self):
        """Return a copy of open port records."""
        with self.lock:
            return list(self.data["open_ports"])

    def save(self, path):
        """Save scan results as pretty JSON."""
        with self.lock:
            self.data["open_ports"].sort(key=lambda x: x["port"])
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(self.data, handle, indent=2)


class PortScanner:
    """Concurrent TCP port scanner with lightweight banner grabbing."""

    def __init__(self, target, timeout, threads, results, console, stop_event):
        """Initialize a scanner for one target."""
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.results = results
        self.console = console
        self.stop_event = stop_event
        self.port_queue = queue.Queue()

    def scan(self, ports):
        """Scan the supplied TCP ports concurrently."""
        for port in ports:
            self.port_queue.put(port)

        workers = []
        for _ in range(min(self.threads, len(ports) or 1)):
            worker = threading.Thread(target=self._worker, daemon=True)
            worker.start()
            workers.append(worker)

        try:
            self.port_queue.join()
        except KeyboardInterrupt:
            self.stop_event.set()

        for worker in workers:
            worker.join(timeout=0.2)

    def _worker(self):
        """Consume ports from the queue until scanning is complete."""
        while not self.stop_event.is_set():
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                return

            try:
                self.console.progress(f"Scanning port {port}...")
                is_open, banner = self._scan_port_with_retry(port)
                if is_open:
                    service = self._identify_service(port, banner)
                    self.results.add_open_port(port, service, banner)
                    detail = f"{port}/tcp: open ({service}"
                    if banner:
                        detail += f" - {banner[:80].strip()}"
                    self.console.info(detail + ")")
                else:
                    self.console.error(f"Port {port}/tcp: closed or filtered")
            finally:
                self.port_queue.task_done()

    def _scan_port_with_retry(self, port):
        """Scan a port and retry once after transient failures."""
        for attempt in range(2):
            try:
                return self._scan_port(port)
            except (socket.timeout, TimeoutError):
                if attempt == 1:
                    return False, ""
            except OSError as exc:
                if attempt == 1:
                    self.results.add_error(f"port {port}", exc)
                    return False, ""
        return False, ""

    def _scan_port(self, port):
        """Attempt a TCP connection and grab a small banner if open."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((self.target, port))
            if result != 0:
                return False, ""
            banner = self._grab_banner(sock, port)
            return True, banner
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _grab_banner(self, sock, port):
        """Grab a banner using an HTTP HEAD probe or passive read."""
        banner = ""
        try:
            if port in (80, 8080):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in (443, 8443):
                return self._grab_https_banner(port)
            elif port in (25, 110, 143, 21, 22, 23):
                pass
            else:
                sock.sendall(b"\r\n")
            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="ignore").strip()
        except (socket.timeout, OSError, ssl.SSLError):
            return ""
        return " ".join(banner.split())

    def _grab_https_banner(self, port):
        """Connect with TLS and issue a small HTTP HEAD request."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection((self.target, port), timeout=self.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=self.target) as tls_sock:
                    tls_sock.settimeout(self.timeout)
                    tls_sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = tls_sock.recv(1024)
                    return " ".join(data.decode("utf-8", errors="ignore").split())
        except (OSError, ssl.SSLError, socket.timeout):
            return ""

    def _identify_service(self, port, banner):
        """Identify service using known ports and simple banner hints."""
        service = COMMON_SERVICES.get(port, "unknown")
        lower = banner.lower()
        if "ssh" in lower:
            return "SSH"
        if "ftp" in lower:
            return "FTP"
        if "smtp" in lower:
            return "SMTP"
        if "http/" in lower or "server:" in lower:
            return "HTTPS" if port in (443, 8443) else "HTTP"
        return service


class WebScanner:
    """Non-intrusive web checks for headers, paths, TLS, and simulators."""

    def __init__(self, target, timeout, results, console, dir_depth):
        """Initialize the web scanner."""
        self.target = target
        self.timeout = timeout
        self.results = results
        self.console = console
        self.dir_depth = dir_depth
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SafeVulnScanner/1.0"})

    def run_for_port(self, port):
        """Run web checks for a discovered HTTP or HTTPS port."""
        scheme = "https" if port in (443, 8443) else "http"
        netloc = self.target if port in (80, 443) else f"{self.target}:{port}"
        base_url = f"{scheme}://{netloc}/"
        self.console.progress(f"Running web checks on {base_url}")

        try:
            response = self._request("GET", base_url)
            if response is None:
                return
            self.check_security_headers(response, base_url)
            self.check_outdated_software(response)
            self.check_cookies(response)
            self.check_directories(base_url)
            self.run_simulators(base_url)
            if scheme == "https":
                self.check_ssl_tls(port)
        except Exception as exc:
            self.results.add_error(f"web {base_url}", exc)

    def _request(self, method, url, **kwargs):
        """Make a bounded HTTP request with one retry."""
        kwargs.setdefault("timeout", self.timeout + 2)
        kwargs.setdefault("allow_redirects", True)
        for attempt in range(2):
            try:
                return self.session.request(method, url, **kwargs)
            except requests.RequestException as exc:
                if attempt == 1:
                    self.results.add_error(url, exc)
                    return None
        return None

    def check_security_headers(self, response, base_url):
        """Check for missing or weak HTTP security headers."""
        required = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing CSP header",
            "X-Frame-Options": "Missing clickjacking protection header",
            "X-Content-Type-Options": "Missing MIME-sniffing protection header",
            "Referrer-Policy": "Missing referrer policy header",
        }
        header_report = {"url": base_url, "present": {}, "missing": []}
        for header, message in required.items():
            value = response.headers.get(header)
            if value:
                header_report["present"][header] = value
            else:
                header_report["missing"].append(header)
                self.results.add_vulnerability(
                    f"Web: {message}",
                    "Low",
                    f"{header} was not present in the HTTP response.",
                    base_url,
                )
                self.console.warn(f"Web: {message}")

        xcto = response.headers.get("X-Content-Type-Options", "")
        if xcto and xcto.lower() != "nosniff":
            self.results.add_vulnerability(
                "Web: Weak X-Content-Type-Options",
                "Low",
                "X-Content-Type-Options is present but not set to nosniff.",
                xcto,
            )
        self.results.add_web_check("headers", header_report)

    def check_directories(self, base_url):
        """Probe a small built-in list of sensitive paths."""
        for path in DEFAULT_PATHS[: max(1, self.dir_depth)]:
            url = urljoin(base_url, path)
            response = self._request("GET", url, allow_redirects=False)
            if response is None:
                continue
            length = response.headers.get("Content-Length", str(len(response.content)))
            item = {"url": url, "status_code": response.status_code, "content_length": length}
            self.results.add_web_check("directories", item)
            if response.status_code in (200, 301, 302, 403):
                severity = "Medium" if path in ("/.git/", "/backup.zip", "/config") else "Low"
                self.results.add_vulnerability(
                    f"Web: Interesting path {path}",
                    severity,
                    "A common sensitive or administrative path returned an interesting status.",
                    item,
                )
                self.console.warn(
                    f"Web: {path} returned {response.status_code} length={length}"
                )

    def check_outdated_software(self, response):
        """Flag known vulnerable software versions from headers and meta tags."""
        evidence = []
        server = response.headers.get("Server", "")
        if server:
            evidence.append(server)

        generators = re.findall(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            response.text,
            flags=re.IGNORECASE,
        )
        evidence.extend(generators)
        self.results.add_web_check("software", evidence)

        for item in evidence:
            finding = self._match_vulnerable_software(item)
            if finding:
                name, description = finding
                self.results.add_vulnerability(name, "Medium", description, item)
                self.console.warn(f"Web: {name}")

    def _match_vulnerable_software(self, text):
        """Compare a software string against a small internal vulnerable-version database."""
        checks = [
            (r"Apache/?\s*2\.4\.49", "Outdated Apache 2.4.49", "Apache 2.4.49 is associated with CVE-2021-41773."),
            (r"Apache/?\s*2\.4\.50", "Outdated Apache 2.4.50", "Apache 2.4.50 is associated with CVE-2021-42013."),
            (r"nginx/?\s*1\.14\.0", "Outdated nginx 1.14.0", "nginx 1.14.0 is old and may miss important security fixes."),
            (r"PHP/?\s*5\.", "Outdated PHP 5.x", "PHP 5.x is end-of-life and no longer receives security fixes."),
            (r"WordPress\s+([0-4]\.|5\.[0-4](?:\.|$))", "Outdated WordPress < 5.5", "WordPress versions before 5.5 may lack important security fixes."),
            (r"OpenSSL/?\s*1\.0\.", "Outdated OpenSSL 1.0.x", "OpenSSL 1.0.x is end-of-life in many distributions."),
        ]
        for pattern, name, description in checks:
            if re.search(pattern, text, re.IGNORECASE):
                return name, description
        return None

    def check_ssl_tls(self, port):
        """Check weak protocol support, certificate status, and weak ciphers."""
        self._check_tls_version(port, "SSLv2", getattr(ssl, "PROTOCOL_SSLv2", None))
        self._check_tls_version(port, "SSLv3", getattr(ssl, "PROTOCOL_SSLv3", None))
        self._check_tls_version(port, "TLS 1.0", getattr(ssl, "PROTOCOL_TLSv1", None))
        self._check_certificate(port)
        self._check_weak_ciphers(port)

    def _check_tls_version(self, port, label, protocol):
        """Attempt a connection with a specific legacy TLS/SSL protocol."""
        if protocol is None:
            return
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, port), timeout=self.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=self.target):
                    issue = f"{label} supported"
                    self.results.add_web_check("ssl_issues", issue)
                    self.results.add_vulnerability(
                        f"SSL: {issue}",
                        "High" if label in ("SSLv2", "SSLv3") else "Medium",
                        f"The server accepted a connection using weak protocol {label}.",
                        f"{self.target}:{port}",
                    )
                    self.console.warn(f"SSL: {issue} (Weak)")
        except (ssl.SSLError, OSError, socket.timeout, ValueError):
            return

    def _check_certificate(self, port):
        """Check certificate expiration, hostname mismatch, and self-signed hints."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, port), timeout=self.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=self.target) as tls_sock:
                    cert = tls_sock.getpeercert()
                    not_after = cert.get("notAfter")
                    if not_after:
                        expires = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        if expires < datetime.datetime.utcnow():
                            self._ssl_issue("Certificate expired", "High", not_after)
                        elif expires < datetime.datetime.utcnow() + datetime.timedelta(days=30):
                            self._ssl_issue("Certificate expires soon", "Low", not_after)

                    issuer = cert.get("issuer", [])
                    subject = cert.get("subject", [])
                    if issuer and subject and issuer == subject:
                        self._ssl_issue("Certificate appears self-signed", "Medium", subject)
        except ssl.CertificateError as exc:
            self._ssl_issue("Certificate hostname mismatch", "High", exc)
        except ssl.SSLCertVerificationError as exc:
            self._ssl_issue("Certificate verification failed", "Medium", exc)
        except (ssl.SSLError, OSError, socket.timeout, ValueError) as exc:
            self.results.add_error(f"certificate {self.target}:{port}", exc)

    def _ssl_issue(self, name, severity, evidence):
        """Record an SSL/TLS issue in both vulnerability and web sections."""
        self.results.add_web_check("ssl_issues", name)
        self.results.add_vulnerability(f"SSL: {name}", severity, str(name), evidence)
        self.console.warn(f"SSL: {name}")

    def _check_weak_ciphers(self, port):
        """Attempt a handshake using weak cipher groups where supported by local OpenSSL."""
        weak_cipher_groups = ["EXP", "NULL", "RC4", "DES", "3DES"]
        for cipher in weak_cipher_groups:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_ciphers(cipher)
                with socket.create_connection((self.target, port), timeout=self.timeout) as raw:
                    with context.wrap_socket(raw, server_hostname=self.target) as tls_sock:
                        selected = tls_sock.cipher()
                        issue = f"Weak cipher accepted: {selected}"
                        self.results.add_web_check("ssl_issues", issue)
                        self.results.add_vulnerability(
                            "SSL: Weak cipher accepted",
                            "High",
                            "The server accepted a cipher from a weak cipher group.",
                            selected,
                        )
                        self.console.warn(f"SSL: {issue}")
            except (ssl.SSLError, OSError, socket.timeout, ValueError):
                continue

    def check_cookies(self, response):
        """Check Set-Cookie headers for missing HttpOnly flags."""
        cookies = response.headers.get("Set-Cookie", "")
        if cookies and "httponly" not in cookies.lower():
            self.results.add_vulnerability(
                "Web: Cookie missing HttpOnly",
                "Low",
                "A Set-Cookie header did not include the HttpOnly flag.",
                cookies,
            )
            self.results.add_web_check("simulators", {"cookie_httponly": False})
            self.console.warn("Web: Cookie missing HttpOnly flag")

    def run_simulators(self, base_url):
        """Run non-intrusive XSS, SQL error, and open redirect simulations."""
        self._test_reflected_xss(base_url)
        self._test_sql_error(base_url)
        self._test_open_redirect(base_url)

    def _test_reflected_xss(self, base_url):
        """Send a dummy XSS marker and report if it is reflected unchanged."""
        payload = "<script>alert('XSS')</script>"
        url = urljoin(base_url, f"?q={payload}")
        response = self._request("GET", url)
        if response is not None and payload in response.text:
            self.results.add_vulnerability(
                "Web: Reflected XSS indicator",
                "Medium",
                "A harmless dummy script marker was reflected in the response body.",
                payload,
            )
            self.results.add_web_check("simulators", {"reflected_xss": True, "url": url})
            self.console.warn("Web: Reflected XSS indicator found")

    def _test_sql_error(self, base_url):
        """Send a single quote parameter and look for common SQL error strings."""
        url = urljoin(base_url, "?id='")
        response = self._request("GET", url)
        if response is None:
            return
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, response.text, re.IGNORECASE):
                self.results.add_vulnerability(
                    "Web: SQL error disclosure indicator",
                    "Medium",
                    "A quote parameter caused a response containing a common SQL error pattern.",
                    pattern,
                )
                self.results.add_web_check("simulators", {"sql_error": True, "pattern": pattern})
                self.console.warn("Web: SQL error disclosure indicator found")
                return

    def _test_open_redirect(self, base_url):
        """Test whether a redirect parameter redirects outside the target domain."""
        test_url = urljoin(base_url, "?redirect=http://example.com")
        response = self._request("GET", test_url, allow_redirects=False)
        if response is None:
            return
        location = response.headers.get("Location", "")
        if response.status_code in (301, 302, 303, 307, 308) and location:
            target_host = urlparse(base_url).hostname
            redirect_host = urlparse(location).hostname
            if redirect_host and redirect_host != target_host:
                self.results.add_vulnerability(
                    "Web: Open redirect indicator",
                    "Medium",
                    "A redirect parameter caused an external redirect.",
                    location,
                )
                self.results.add_web_check("simulators", {"open_redirect": True, "location": location})
                self.console.warn("Web: Open redirect indicator found")


class VulnChecker:
    """Generic service-specific vulnerability checks."""

    def __init__(self, target, timeout, results, console, stop_event):
        """Initialize service checker."""
        self.target = target
        self.timeout = timeout
        self.results = results
        self.console = console
        self.stop_event = stop_event

    def run(self, open_ports, max_threads):
        """Run checks for discovered services concurrently."""
        jobs = queue.Queue()
        for item in open_ports:
            jobs.put(item)

        workers = []
        for _ in range(min(max_threads, len(open_ports) or 1)):
            worker = threading.Thread(target=self._worker, args=(jobs,), daemon=True)
            worker.start()
            workers.append(worker)

        jobs.join()
        for worker in workers:
            worker.join(timeout=0.2)

    def _worker(self, jobs):
        """Consume service check jobs."""
        while not self.stop_event.is_set():
            try:
                item = jobs.get_nowait()
            except queue.Empty:
                return
            try:
                self._check_port(item)
            finally:
                jobs.task_done()

    def _check_port(self, item):
        """Dispatch a service-specific check by port."""
        port = item["port"]
        if port == 21:
            self.check_ftp_anonymous()
        elif port == 22:
            self.check_ssh_banner(item.get("banner", ""))
        elif port == 25:
            self.check_smtp_vrfy_expn()
        elif port == 445:
            self.check_smb_null_session()
        elif port == 161:
            self.check_snmp_public()
        elif port == 53:
            self.check_dns_axfr()
        elif port == 6379:
            self.check_redis_no_auth()

    def _tcp_exchange(self, port, payloads, read_first=False):
        """Open a TCP socket and exchange a sequence of payloads."""
        responses = []
        with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            if read_first:
                try:
                    responses.append(sock.recv(1024).decode("utf-8", errors="ignore"))
                except socket.timeout:
                    pass
            for payload in payloads:
                sock.sendall(payload)
                try:
                    responses.append(sock.recv(2048).decode("utf-8", errors="ignore"))
                except socket.timeout:
                    responses.append("")
        return "\n".join(responses)

    def check_ftp_anonymous(self):
        """Check whether FTP allows anonymous login."""
        try:
            response = self._tcp_exchange(
                21,
                [b"USER anonymous\r\n", b"PASS anonymous@example.com\r\n", b"QUIT\r\n"],
                read_first=True,
            )
            if re.search(r"\b230\b", response):
                self.results.add_vulnerability(
                    "FTP: Anonymous login allowed",
                    "High",
                    "FTP accepted anonymous credentials.",
                    response,
                )
                self.console.warn("FTP: Anonymous login allowed")
        except (OSError, socket.timeout) as exc:
            self.results.add_error("ftp anonymous", exc)

    def check_ssh_banner(self, banner):
        """Check SSH banner for old OpenSSH versions."""
        try:
            if not banner:
                banner = self._tcp_exchange(22, [], read_first=True)
            match = re.search(r"OpenSSH[_-](\d+)\.(\d+)", banner)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                if (major, minor) < (7, 4):
                    self.results.add_vulnerability(
                        "SSH: Outdated OpenSSH version",
                        "Medium",
                        "OpenSSH versions before 7.4 are old and may contain known vulnerabilities.",
                        banner,
                    )
                    self.console.warn("SSH: Outdated OpenSSH version")
        except (OSError, socket.timeout) as exc:
            self.results.add_error("ssh banner", exc)

    def check_smtp_vrfy_expn(self):
        """Check if SMTP VRFY or EXPN commands are supported."""
        try:
            response = self._tcp_exchange(
                25,
                [b"HELO scanner.local\r\n", b"VRFY root\r\n", b"EXPN root\r\n", b"QUIT\r\n"],
                read_first=True,
            )
            if re.search(r"\b250\b.*(root|user|mail|OK)", response, re.IGNORECASE):
                self.results.add_vulnerability(
                    "SMTP: VRFY/EXPN supported",
                    "Low",
                    "SMTP server appears to support user enumeration commands.",
                    response,
                )
                self.console.warn("SMTP: VRFY/EXPN supported")
        except (OSError, socket.timeout) as exc:
            self.results.add_error("smtp vrfy expn", exc)

    def check_smb_null_session(self):
        """Report SMB null session as potential only without exploitation."""
        self.results.add_vulnerability(
            "SMB: Null session requires manual verification",
            "Low",
            "SMB is open. Null session exposure should be verified with approved SMB tooling.",
            f"{self.target}:445",
        )
        self.console.warn("SMB: Null session requires manual verification")

    def check_snmp_public(self):
        """Check SNMP public community with a minimal sysDescr GET request over UDP."""
        request = bytes.fromhex(
            "302602010104067075626c6963a01902043b9aca00020100020100300b300906052b06010201010500"
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(request, (self.target, 161))
            data, _ = sock.recvfrom(2048)
            if data:
                self.results.add_vulnerability(
                    "SNMP: public community accessible",
                    "Medium",
                    "SNMP responded to a sysDescr request using the public community string.",
                    data.hex()[:200],
                )
                self.console.warn("SNMP: public community accessible")
        except (OSError, socket.timeout) as exc:
            self.results.add_error("snmp public", exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def check_dns_axfr(self):
        """Attempt a DNS zone transfer for the target domain over TCP."""
        domain = self.target.rstrip(".")
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", domain):
            return
        try:
            query = self._build_axfr_query(domain)
            length = len(query).to_bytes(2, "big")
            with socket.create_connection((self.target, 53), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(length + query)
                first = sock.recv(2)
                if len(first) == 2:
                    response_len = int.from_bytes(first, "big")
                    response = sock.recv(response_len)
                    if response and len(response) > 100:
                        self.results.add_vulnerability(
                            "DNS: Zone transfer may be allowed",
                            "High",
                            "DNS server returned data to an AXFR request.",
                            response.hex()[:300],
                        )
                        self.console.warn("DNS: Zone transfer may be allowed")
        except (OSError, socket.timeout) as exc:
            self.results.add_error("dns axfr", exc)

    def _build_axfr_query(self, domain):
        """Build a minimal DNS AXFR query packet."""
        transaction_id = b"\x12\x34"
        flags = b"\x01\x00"
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in domain.split("."))
        qname += b"\x00"
        qtype_axfr = b"\x00\xfc"
        qclass_in = b"\x00\x01"
        return transaction_id + flags + counts + qname + qtype_axfr + qclass_in

    def check_redis_no_auth(self):
        """Check whether Redis responds to INFO without authentication."""
        try:
            response = self._tcp_exchange(6379, [b"*1\r\n$4\r\nINFO\r\n"])
            if "redis_version" in response.lower():
                self.results.add_vulnerability(
                    "Redis: No authentication required",
                    "High",
                    "Redis INFO command succeeded without authentication.",
                    response[:500],
                )
                self.console.warn("Redis: No authentication required")
        except (OSError, socket.timeout) as exc:
            self.results.add_error("redis info", exc)


class VulnerabilityScanner:
    """Orchestrates port scanning, web checks, service checks, and output."""

    def __init__(self, args):
        """Initialize scanner from parsed command-line arguments."""
        self.args = args
        self.console = Console()
        self.stop_event = threading.Event()
        self.target_host = normalize_target(args.target)
        self.resolved_ip = resolve_target(self.target_host)
        self.results = ResultStore(self.target_host, self.resolved_ip)

    def run(self):
        """Run the complete scan and save results if requested."""
        started = time.time()
        ports = parse_ports(self.args.ports)
        self.console.info(f"Target: {self.target_host} ({self.resolved_ip})")
        self.console.info(f"Scanning ports: {format_ports_for_display(ports)}")

        try:
            scanner = PortScanner(
                self.target_host,
                self.args.timeout,
                self.args.threads,
                self.results,
                self.console,
                self.stop_event,
            )
            scanner.scan(ports)

            open_ports = self.results.get_open_ports()
            web_ports = [
                item["port"]
                for item in open_ports
                if item["port"] in (80, 443, 8080, 8443) or item["service"] in ("HTTP", "HTTPS")
            ]

            check_threads = []
            for port in web_ports:
                thread = threading.Thread(
                    target=WebScanner(
                        self.target_host,
                        self.args.timeout,
                        self.results,
                        self.console,
                        self.args.dir_depth,
                    ).run_for_port,
                    args=(port,),
                )
                thread.start()
                check_threads.append(thread)

            VulnChecker(
                self.target_host,
                self.args.timeout,
                self.results,
                self.console,
                self.stop_event,
            ).run(open_ports, self.args.threads)

            for thread in check_threads:
                thread.join()
        except KeyboardInterrupt:
            self.stop_event.set()
            self.console.warn("Interrupted by user. Saving partial results...")
        finally:
            elapsed = time.time() - started
            if self.args.output:
                try:
                    self.results.save(self.args.output)
                    self.console.info(
                        f"Scan completed in {elapsed:.1f} seconds. Results saved to {self.args.output}"
                    )
                except OSError as exc:
                    self.console.error(f"Could not save results: {exc}")
            else:
                self.console.info(f"Scan completed in {elapsed:.1f} seconds.")


def normalize_target(target):
    """Normalize a user-supplied URL, IP address, or domain into a hostname."""
    parsed = urlparse(target if "://" in target else f"//{target}")
    return parsed.hostname or target.strip().strip("/")


def resolve_target(target):
    """Resolve a hostname to an IP address, returning a readable placeholder on failure."""
    try:
        return socket.gethostbyname(target)
    except OSError:
        return "unresolved"


def parse_ports(spec):
    """Parse comma-separated ports and ranges into a sorted unique list."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                start, end = end, start
            ports.update(range(max(1, start), min(65535, end) + 1))
        else:
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)
    if not ports:
        raise ValueError("No valid ports supplied.")
    return sorted(ports)


def format_ports_for_display(ports):
    """Return a compact display string for a port list."""
    if len(ports) > 25:
        return f"{ports[0]}-{ports[-1]} ({len(ports)} ports)"
    return ",".join(str(port) for port in ports)


def build_parser():
    """Build command-line parser."""
    parser = argparse.ArgumentParser(
        description="Non-intrusive vulnerability scanner for authorized targets."
    )
    parser.add_argument("--target", required=True, help="Target domain, URL, or IP address.")
    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Ports to scan, e.g. 1-1000 or 80,443,8080. Default: 1-1024.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds. Default: 1.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=20,
        help="Maximum concurrent worker threads. Default: 20.",
    )
    parser.add_argument(
        "--output",
        help="Optional JSON output path, e.g. scan_results.json.",
    )
    parser.add_argument(
        "--dir-depth",
        type=int,
        default=len(DEFAULT_PATHS),
        help=f"Number of built-in sensitive paths to test. Default: {len(DEFAULT_PATHS)}.",
    )
    return parser


def validate_args(args):
    """Validate command-line arguments and normalize safe bounds."""
    if args.timeout <= 0:
        raise ValueError("--timeout must be greater than 0.")
    if args.threads <= 0:
        raise ValueError("--threads must be greater than 0.")
    args.threads = min(args.threads, 200)
    args.dir_depth = max(1, min(args.dir_depth, len(DEFAULT_PATHS)))
    parse_ports(args.ports)


if __name__ == "__main__":
    try:
        parsed_args = build_parser().parse_args()
        validate_args(parsed_args)
        VulnerabilityScanner(parsed_args).run()
    except ValueError as err:
        print(f"[-] Argument error: {err}")
        sys.exit(2)
