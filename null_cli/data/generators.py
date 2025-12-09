"""Fake data generators for realistic simulation output"""
from faker import Faker
import random
import string
from typing import List, Dict, Tuple, Optional
from datetime import datetime, timedelta


fake = Faker()


# RFC 5737 test networks - safe IP ranges that won't route
TEST_NETWORKS = [
    "192.0.2",      # TEST-NET-1
    "198.51.100",   # TEST-NET-2
    "203.0.113",    # TEST-NET-3
]

# Additional safe IPv6 test network
TEST_IPV6_PREFIX = "2001:db8"


def generate_fake_ip() -> str:
    """Generate a fake IP address from test networks"""
    network = random.choice(TEST_NETWORKS)
    host = random.randint(1, 254)
    return f"{network}.{host}"


def generate_fake_ipv6() -> str:
    """Generate a fake IPv6 address from test network"""
    parts = [random.randint(0, 65535) for _ in range(6)]
    return f"{TEST_IPV6_PREFIX}:" + ":".join(f"{p:x}" for p in parts)


def generate_local_ip() -> str:
    """Generate a fake local network IP"""
    return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_mac_address() -> str:
    """Generate a fake MAC address"""
    return fake.mac_address()


def generate_hostname(target: Optional[str] = None) -> str:
    """Generate a realistic hostname based on target if provided"""
    if target and not target.replace('.', '').replace('-', '').isdigit():
        # If target looks like a domain, use it
        return target
    
    prefixes = ['web', 'mail', 'db', 'api', 'app', 'server', 'host', 'node', 'vpn', 'fw', 'gw']
    suffix = random.choice(['.local', '.corp', '.internal', ''])
    
    if random.random() < 0.3:  # 30% chance of subdomain
        subdomain = random.choice(['dev', 'staging', 'prod', 'test', 'admin'])
        return f"{subdomain}.{random.choice(prefixes)}{random.randint(1, 99)}.{fake.domain_name()}"
    
    return f"{random.choice(prefixes)}{random.randint(1, 99)}.{fake.domain_name()}"


def generate_open_ports(scan_type: str = "sS", port_range: Optional[str] = None, 
                       target_os: Optional[str] = None) -> List[Dict[str, str]]:
    """Generate realistic open ports with services based on scan type and target OS
    
    Args:
        scan_type: Type of scan (sS, sT, sU, sV, etc.)
        port_range: Port range being scanned
        target_os: Target operating system type (windows, linux, etc.)
    """
    # Comprehensive port database with OS-specific services
    windows_ports = [
        {"port": "135", "state": "open", "service": "msrpc", "version": "Microsoft Windows RPC"},
        {"port": "139", "state": "open", "service": "netbios-ssn", "version": "Microsoft Windows netbios-ssn"},
        {"port": "445", "state": "open", "service": "microsoft-ds", "version": "Windows Server 2019 microsoft-ds"},
        {"port": "3389", "state": "open", "service": "ms-wbt-server", "version": "Microsoft Terminal Services"},
        {"port": "5985", "state": "open", "service": "http", "version": "Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)"},
    ]
    
    linux_ports = [
        {"port": "22", "state": "open", "service": "ssh", "version": "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)"},
        {"port": "111", "state": "open", "service": "rpcbind", "version": "2-4 (RPC #100000)"},
    ]
    
    common_web_ports = [
        {"port": "80", "state": "open", "service": "http", "version": "Apache httpd 2.4.41 ((Ubuntu))"},
        {"port": "443", "state": "open", "service": "ssl/http", "version": "nginx 1.18.0"},
        {"port": "8080", "state": "open", "service": "http-proxy", "version": "Squid http proxy 4.13"},
        {"port": "8443", "state": "open", "service": "ssl/https-alt", "version": ""},
    ]
    
    database_ports = [
        {"port": "3306", "state": "open", "service": "mysql", "version": "MySQL 5.7.35-0ubuntu0.18.04.1"},
        {"port": "5432", "state": "open", "service": "postgresql", "version": "PostgreSQL DB 13.4 - 13.7"},
        {"port": "6379", "state": "open", "service": "redis", "version": "Redis key-value store 6.2.6"},
        {"port": "27017", "state": "open", "service": "mongodb", "version": "MongoDB 4.4.10"},
        {"port": "1433", "state": "open", "service": "ms-sql-s", "version": "Microsoft SQL Server 2019 15.00.2000.00"},
    ]
    
    other_services = [
        {"port": "21", "state": "open", "service": "ftp", "version": "vsftpd 3.0.3"},
        {"port": "23", "state": "filtered", "service": "telnet", "version": ""},
        {"port": "25", "state": "open", "service": "smtp", "version": "Postfix smtpd"},
        {"port": "53", "state": "open", "service": "domain", "version": "ISC BIND 9.16.1 (Ubuntu Linux)"},
        {"port": "110", "state": "open", "service": "pop3", "version": "Dovecot pop3d"},
        {"port": "143", "state": "open", "service": "imap", "version": "Dovecot imapd"},
    ]
    
    # Build port list based on target OS
    available_ports = []
    
    if target_os and "windows" in target_os.lower():
        available_ports.extend(windows_ports)
        available_ports.extend([p for p in database_ports if p["port"] in ["1433", "3306"]])
    elif target_os and "linux" in target_os.lower():
        available_ports.extend(linux_ports)
        available_ports.extend(database_ports)
    else:
        # Mixed environment
        if random.random() < 0.6:
            available_ports.extend(random.sample(linux_ports, min(2, len(linux_ports))))
        else:
            available_ports.extend(random.sample(windows_ports, min(3, len(windows_ports))))
    
    available_ports.extend(common_web_ports)
    available_ports.extend(other_services)
    
    # Filter by port range if specified
    if port_range:
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            available_ports = [p for p in available_ports if start <= int(p["port"]) <= end]
        elif ',' in port_range:
            specified_ports = [p.strip() for p in port_range.split(',')]
            available_ports = [p for p in available_ports if p["port"] in specified_ports]
    
    # UDP scans show different services
    if scan_type == "sU":
        udp_ports = [
            {"port": "53", "state": "open", "service": "domain", "version": "ISC BIND 9.16.1"},
            {"port": "67", "state": "open|filtered", "service": "dhcps", "version": ""},
            {"port": "123", "state": "open", "service": "ntp", "version": ""},
            {"port": "161", "state": "open", "service": "snmp", "version": "SNMPv3 server"},
        ]
        available_ports = udp_ports
    
    # Vary the state based on scan type
    if scan_type in ["sA", "sF", "sN", "sX"]:
        # ACK, FIN, NULL, Xmas scans show more filtered ports
        for port in available_ports:
            if random.random() < 0.4:
                port["state"] = "filtered"
    
    # Return random subset with variation
    if not available_ports:
        num_ports = random.randint(2, 5)
        return random.sample(other_services, min(num_ports, len(other_services)))
    
    num_ports = random.randint(3, min(10, len(available_ports)))
    return random.sample(available_ports, num_ports)


def generate_os_detection(hint: Optional[str] = None) -> Dict[str, str]:
    """Generate fake OS detection results with optional hint
    
    Args:
        hint: Hint about OS type (e.g., from open ports)
    """
    linux_variants = [
        {"name": "Linux 5.4 - 5.10", "accuracy": "95%", "cpe": "cpe:/o:linux:linux_kernel", "details": "Linux kernel 5.4.0"},
        {"name": "Ubuntu 20.04 (Linux 5.4)", "accuracy": "94%", "cpe": "cpe:/o:canonical:ubuntu_linux:20.04", "details": "Ubuntu Linux; Linux 5.4.0-88-generic"},
        {"name": "Debian 10 (Linux 4.19)", "accuracy": "93%", "cpe": "cpe:/o:debian:debian_linux:10", "details": "Debian Linux; Linux 4.19"},
        {"name": "CentOS 7 (Linux 3.10)", "accuracy": "91%", "cpe": "cpe:/o:centos:centos:7", "details": "CentOS; Linux 3.10"},
        {"name": "Red Hat Enterprise Linux 8", "accuracy": "92%", "cpe": "cpe:/o:redhat:enterprise_linux:8", "details": "RHEL 8; Linux 4.18"},
    ]
    
    windows_variants = [
        {"name": "Windows Server 2019 (1809)", "accuracy": "96%", "cpe": "cpe:/o:microsoft:windows_server_2019", "details": "Windows Server 2019 Standard 17763"},
        {"name": "Windows 10 Enterprise (1809 - 21H1)", "accuracy": "94%", "cpe": "cpe:/o:microsoft:windows_10", "details": "Windows 10 Enterprise 19041"},
        {"name": "Windows Server 2016", "accuracy": "93%", "cpe": "cpe:/o:microsoft:windows_server_2016", "details": "Windows Server 2016 Standard 14393"},
        {"name": "Windows 11 Pro (21H2)", "accuracy": "92%", "cpe": "cpe:/o:microsoft:windows_11", "details": "Windows 11 Professional 22000"},
        {"name": "Windows Server 2022", "accuracy": "95%", "cpe": "cpe:/o:microsoft:windows_server_2022", "details": "Windows Server 2022 Standard"},
    ]
    
    other_os = [
        {"name": "macOS 11.6 (Big Sur)", "accuracy": "90%", "cpe": "cpe:/o:apple:mac_os_x:11.6", "details": "macOS Big Sur 11.6"},
        {"name": "FreeBSD 12.2", "accuracy": "89%", "cpe": "cpe:/o:freebsd:freebsd:12.2", "details": "FreeBSD 12.2-RELEASE"},
        {"name": "ESXi 7.0", "accuracy": "91%", "cpe": "cpe:/o:vmware:esxi:7.0", "details": "VMware ESXi 7.0"},
    ]
    
    # Use hint to select appropriate OS
    if hint and "windows" in hint.lower():
        return random.choice(windows_variants)
    elif hint and any(x in hint.lower() for x in ["linux", "ubuntu", "debian", "centos"]):
        return random.choice(linux_variants)
    else:
        # Random selection with weighting
        all_os = linux_variants * 3 + windows_variants * 2 + other_os
        return random.choice(all_os)


def generate_vulnerabilities() -> List[Dict[str, str]]:
    """Generate fake vulnerability scan results"""
    vulns = [
        {
            "id": "CVE-2021-44228",
            "severity": "CRITICAL",
            "name": "Log4Shell - Remote Code Execution",
            "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
            "cvss": "10.0"
        },
        {
            "id": "CVE-2017-0144",
            "severity": "CRITICAL",
            "name": "EternalBlue - SMB Remote Code Execution",
            "description": "Microsoft SMBv1 server mishandles specially crafted packets",
            "cvss": "9.3"
        },
        {
            "id": "CVE-2014-0160",
            "severity": "HIGH",
            "name": "Heartbleed - Information Disclosure",
            "description": "OpenSSL TLS heartbeat extension allows remote attackers to obtain sensitive information",
            "cvss": "7.5"
        },
        {
            "id": "CVE-2020-1472",
            "severity": "CRITICAL",
            "name": "Zerologon - Privilege Escalation",
            "description": "Netlogon elevation of privilege vulnerability",
            "cvss": "10.0"
        },
        {
            "id": "CVE-2019-0708",
            "severity": "CRITICAL",
            "name": "BlueKeep - Remote Desktop RCE",
            "description": "Remote Desktop Services Remote Code Execution Vulnerability",
            "cvss": "9.8"
        },
    ]
    
    # Return 0-3 random vulnerabilities
    num_vulns = random.randint(0, 3)
    if num_vulns == 0:
        return []
    return random.sample(vulns, num_vulns)


def generate_sql_injection_data() -> List[str]:
    """Generate fake SQL injection payloads"""
    payloads = [
        "' OR '1'='1",
        "admin'--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND 1=1--",
        "' OR 1=1 LIMIT 1--",
    ]
    return payloads


def generate_user_credentials() -> List[Tuple[str, str]]:
    """Generate fake username/password combinations"""
    common_combos = [
        ("admin", "admin"),
        ("root", "toor"),
        ("admin", "password123"),
        ("user", "user"),
        ("guest", "guest"),
        ("administrator", "Administrator1"),
    ]
    return common_combos


def generate_exploit_payload() -> str:
    """Generate fake exploit payload identifier"""
    payload_types = [
        "windows/meterpreter/reverse_tcp",
        "linux/x86/meterpreter/reverse_tcp",
        "windows/shell/reverse_tcp",
        "cmd/unix/reverse_bash",
        "python/meterpreter/reverse_tcp",
    ]
    return random.choice(payload_types)


def generate_session_id() -> int:
    """Generate fake session ID"""
    return random.randint(1, 999)


def generate_metasploit_modules() -> List[Dict[str, str]]:
    """Generate fake Metasploit module list"""
    modules = [
        {
            "name": "exploit/windows/smb/ms17_010_eternalblue",
            "description": "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
            "rank": "excellent",
            "date": "2017-03-14"
        },
        {
            "name": "exploit/multi/handler",
            "description": "Generic Payload Handler",
            "rank": "manual",
            "date": "2003-07-15"
        },
        {
            "name": "exploit/unix/webapp/drupal_drupalgeddon2",
            "description": "Drupal Drupalgeddon 2 Forms API Property Injection",
            "rank": "excellent",
            "date": "2018-03-28"
        },
        {
            "name": "exploit/linux/http/apache_mod_cgi_bash_env_exec",
            "description": "Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)",
            "rank": "excellent",
            "date": "2014-09-24"
        },
    ]
    return modules


def generate_network_traffic_stats() -> Dict[str, any]:
    """Generate fake network traffic statistics"""
    duration = round(random.uniform(0.5, 60.0), 2)
    return {
        "packets_sent": random.randint(1000, 50000),
        "packets_received": random.randint(1000, 50000),
        "bytes_sent": random.randint(10000, 5000000),
        "bytes_received": random.randint(10000, 5000000),
        "duration": duration
    }


# ==== PASSWORD CRACKING GENERATORS ====

def generate_password_hash(hash_type: str = "md5") -> Tuple[str, str]:
    """Generate fake password hash and plaintext password
    
    Returns: (hash, plaintext)
    """
    passwords = [
        "password123", "admin", "letmein", "welcome1", "Password1!",
        "qwerty123", "dragon", "monkey", "123456", "iloveyou",
        "sunshine", "princess", "starwars", "batman", "trustno1"
    ]
    
    plaintext = random.choice(passwords)
    
    # Generate fake hashes (these are not real hashes, just realistic-looking strings)
    if hash_type.lower() == "md5":
        fake_hash = fake.md5()
    elif hash_type.lower() == "sha1":
        fake_hash = fake.sha1()
    elif hash_type.lower() == "sha256":
        fake_hash = fake.sha256()
    elif hash_type.lower() == "ntlm":
        fake_hash = ''.join(random.choices(string.hexdigits.upper(), k=32))
    elif hash_type.lower() == "bcrypt":
        fake_hash = "$2b$12$" + ''.join(random.choices(string.ascii_letters + string.digits + './', k=53))
    else:
        fake_hash = fake.sha256()
    
    return fake_hash, plaintext


def generate_password_list(count: int = 10) -> List[str]:
    """Generate a list of common passwords for dictionary attacks"""
    common_passwords = [
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "iloveyou", "trustno1", "1234567890",
        "superman", "qazwsx", "michael", "football", "shadow",
        "master", "jennifer", "111111", "2000", "jordan",
        "superman", "harley", "1234", "robert", "matthew",
        "password1", "password123", "admin", "root", "toor",
        "pass", "test", "guest", "info", "adm", "mysql",
        "user", "administrator", "oracle", "ftp", "pi",
        "puppet", "ansible", "ec2-user", "vagrant", "azureuser"
    ]
    return random.sample(common_passwords, min(count, len(common_passwords)))


def generate_username_list(count: int = 10) -> List[str]:
    """Generate a list of common usernames for brute force attacks"""
    usernames = [
        "admin", "root", "user", "test", "guest", "info", "adm",
        "mysql", "user", "administrator", "oracle", "ftp", "pi",
        "puppet", "ansible", "ec2-user", "vagrant", "azureuser",
        "www", "data", "www-data", "backup", "operator", "support",
        "sales", "manager", "office", "marketing", "developer",
        fake.user_name(), fake.user_name(), fake.user_name()
    ]
    return random.sample(usernames, min(count, len(usernames)))


def generate_hydra_attempt() -> Dict[str, str]:
    """Generate a single Hydra login attempt result"""
    username = random.choice(generate_username_list(5))
    password = random.choice(generate_password_list(5))
    success = random.random() < 0.05  # 5% success rate
    
    return {
        "username": username,
        "password": password,
        "success": success,
        "response_code": "200" if success else random.choice(["401", "403", "404"]),
        "response_time": round(random.uniform(0.1, 2.0), 3)
    }


def generate_hash_crack_session() -> Dict[str, any]:
    """Generate a hash cracking session with stats"""
    return {
        "hash_type": random.choice(["MD5", "SHA1", "SHA256", "NTLM", "bcrypt"]),
        "hashes_loaded": random.randint(1, 100),
        "hashes_cracked": random.randint(0, 50),
        "speed": f"{random.randint(100, 999)}k H/s",
        "progress": random.randint(0, 100),
        "time_started": datetime.now() - timedelta(seconds=random.randint(10, 300)),
        "eta": random.randint(10, 600)
    }


# ==== WEB SCANNING GENERATORS ====

def generate_web_directories() -> List[Dict[str, any]]:
    """Generate discovered web directories and files"""
    directories = [
        {"path": "/admin", "status": 200, "size": 4523, "type": "directory"},
        {"path": "/login", "status": 200, "size": 3421, "type": "page"},
        {"path": "/uploads", "status": 403, "size": 0, "type": "directory"},
        {"path": "/backup", "status": 200, "size": 0, "type": "directory"},
        {"path": "/config", "status": 403, "size": 0, "type": "directory"},
        {"path": "/api", "status": 200, "size": 1234, "type": "directory"},
        {"path": "/dashboard", "status": 302, "size": 0, "type": "redirect"},
        {"path": "/wp-admin", "status": 302, "size": 0, "type": "redirect"},
        {"path": "/phpmyadmin", "status": 200, "size": 8234, "type": "page"},
        {"path": "/test", "status": 200, "size": 523, "type": "page"},
        {"path": "/.git", "status": 403, "size": 0, "type": "directory"},
        {"path": "/.env", "status": 200, "size": 423, "type": "file"},
        {"path": "/robots.txt", "status": 200, "size": 234, "type": "file"},
        {"path": "/sitemap.xml", "status": 200, "size": 5234, "type": "file"},
    ]
    
    num_results = random.randint(3, 8)
    return random.sample(directories, num_results)


def generate_sql_injection_payloads() -> List[Dict[str, any]]:
    """Generate SQL injection test payloads and results"""
    payloads = [
        {
            "payload": "' OR '1'='1",
            "type": "boolean-based blind",
            "vulnerable": random.random() < 0.3,
            "response_time": round(random.uniform(0.1, 0.5), 3)
        },
        {
            "payload": "admin'--",
            "type": "inline comment",
            "vulnerable": random.random() < 0.2,
            "response_time": round(random.uniform(0.1, 0.5), 3)
        },
        {
            "payload": "' UNION SELECT NULL--",
            "type": "UNION query",
            "vulnerable": random.random() < 0.25,
            "response_time": round(random.uniform(0.2, 0.8), 3)
        },
        {
            "payload": "1' AND SLEEP(5)--",
            "type": "time-based blind",
            "vulnerable": random.random() < 0.15,
            "response_time": round(random.uniform(4.9, 5.2), 3) if random.random() < 0.2 else round(random.uniform(0.1, 0.3), 3)
        }
    ]
    return payloads


def generate_nikto_findings() -> List[Dict[str, any]]:
    """Generate Nikto vulnerability scan findings"""
    findings = [
        {
            "id": "000380",
            "severity": "info",
            "message": "Server may leak inodes via ETags, header found with file /, fields: 0x2b 0x5c9a2b5c "
        },
        {
            "id": "000398",
            "severity": "warning",
            "message": "Server version is outdated and may contain security vulnerabilities"
        },
        {
            "id": "000786",
            "severity": "info",
            "message": "The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS"
        },
        {
            "id": "000622",
            "severity": "warning",
            "message": "Admin login page/section found. This may allow an attacker to bruteforce the admin credentials"
        },
        {
            "id": "000190",
            "severity": "critical",
            "message": "/.git directory found. This may expose sensitive repository information"
        },
        {
            "id": "000550",
            "severity": "info",
            "message": "The anti-clickjacking X-Frame-Options header is not present"
        },
    ]
    
    num_findings = random.randint(2, 5)
    return random.sample(findings, num_findings)


def generate_wordpress_info() -> Dict[str, any]:
    """Generate WordPress installation information"""
    return {
        "version": random.choice(["5.9.3", "6.0.1", "6.1.0", "5.8.4"]),
        "theme": random.choice(["twentytwentyone", "twentytwenty", "Avada", "Divi"]),
        "plugins": random.sample([
            "akismet", "jetpack", "wordfence", "contact-form-7",
            "yoast-seo", "woocommerce", "elementor", "wpforms"
        ], random.randint(2, 5)),
        "users": random.sample([
            {"id": 1, "username": "admin", "name": "Administrator"},
            {"id": 2, "username": fake.user_name(), "name": fake.name()},
            {"id": 3, "username": fake.user_name(), "name": fake.name()},
        ], random.randint(1, 3))
    }


def generate_wifi_networks() -> List[Dict[str, any]]:
    """Generate discovered WiFi networks for aircrack-ng"""
    encryption_types = ["WPA2", "WPA", "WEP", "WPA2-Enterprise", "Open"]
    
    networks = []
    for i in range(random.randint(3, 8)):
        bssid = generate_mac_address()
        channel = random.choice([1, 6, 11, 36, 40, 44, 48])
        encryption = random.choice(encryption_types)
        power = random.randint(-90, -20)
        
        essid_prefixes = ["HOME-", "NETGEAR", "TP-Link_", "Linksys_", "ATT", "Verizon_"]
        essid = random.choice(essid_prefixes) + ''.join(random.choices(string.hexdigits.upper(), k=4))
        
        networks.append({
            "bssid": bssid,
            "channel": channel,
            "power": power,
            "encryption": encryption,
            "essid": essid,
            "beacons": random.randint(10, 500),
            "data_packets": random.randint(0, 1000)
        })
    
    return sorted(networks, key=lambda x: x["power"], reverse=True)


def generate_burp_request() -> Dict[str, any]:
    """Generate a Burp Suite HTTP request/response"""
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    paths = ["/api/users", "/login", "/admin", "/api/products", "/upload"]
    
    return {
        "method": random.choice(methods),
        "path": random.choice(paths),
        "status": random.choice([200, 201, 400, 401, 403, 404, 500]),
        "length": random.randint(200, 50000),
        "time": random.randint(50, 2000),
        "headers": {
            "Host": generate_hostname(),
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/json"
        }
    }
