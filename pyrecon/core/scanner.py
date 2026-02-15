from .compat import *
from .models import ScanType, PortState, ServiceSignature, PortResult, HostResult

class AdvancedScanner:
    """Main scanner class with enterprise features"""
    
    def __init__(self, config=None):
        self.config = config or {}
        from .packet import PacketCrafter
        self.packet_crafter = PacketCrafter()
        self.service_signatures = self._load_service_signatures()
        self.cve_db = self._load_cve_database()
        self.results = {}
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'scan_duration': 0,
            'hosts_up': 0,
            'ports_scanned': 0
        }
        
        # Rate limiting
        self.rate_limit = self.config.get('rate_limit', 1000)  # packets/second
        self.last_send_time = 0
        
        # Evasion
        self.decoys = self.config.get('decoys', [])
        self.fragment_packets = self.config.get('fragment', False)
        self.spoof_mac = self.config.get('spoof_mac', False)
        self.ttl_variation = self.config.get('ttl_variation', False)
        
        # Performance
        self.socket_pool = []
        self._init_sockets()
        
    def _init_sockets(self):
        """Initialize socket pool for performance"""
        for _ in range(10):  # Pool size
            if self.config.get('use_raw_socket', False) and os.geteuid() == 0:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.config.get('timeout', 2.0))
            self.socket_pool.append(s)
    
    def _load_service_signatures(self):
        """Load nmap-style service signatures"""
        signatures = []
        
        # HTTP signatures
        signatures.append(ServiceSignature(
            name="Apache HTTP Server",
            probe=b"GET / HTTP/1.0\r\n\r\n",
            match_pattern=b"Server: Apache",
            ports=[80, 443, 8080, 8000, 8888]
        ))
        
        signatures.append(ServiceSignature(
            name="nginx",
            probe=b"GET / HTTP/1.0\r\n\r\n",
            match_pattern=b"Server: nginx",
            ports=[80, 443, 8080]
        ))
        
        # SSH signatures
        signatures.append(ServiceSignature(
            name="OpenSSH",
            probe=b"SSH-2.0-PyRecon\r\n",
            match_pattern=b"SSH-2.0-OpenSSH",
            ports=[22]
        ))
        
        # Database signatures
        signatures.append(ServiceSignature(
            name="MySQL",
            probe=b"\x0a",
            match_pattern=b"mysql_native_password",
            ports=[3306]
        ))
        
        signatures.append(ServiceSignature(
            name="PostgreSQL",
            probe=b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
            match_pattern=b"PostgreSQL",
            ports=[5432]
        ))
        
        # Custom protocol probes
        signatures.append(ServiceSignature(
            name="Redis",
            probe=b"INFO\r\n",
            match_pattern=b"redis_version",
            ports=[6379]
        ))
        
        signatures.append(ServiceSignature(
            name="Memcached",
            probe=b"stats\r\n",
            match_pattern=b"STAT pid",
            ports=[11211]
        ))
        
        signatures.append(ServiceSignature(
            name="MongoDB",
            probe=b"\x3a\x00\x00\x00\xa7\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00!isMaster\x00\x00\x00\x00\x00\x00\x00\xf0?",
            match_pattern=b"ismaster",
            soft_match=True,
            ports=[27017]
        ))
        
        signatures.append(ServiceSignature(
            name="Elasticsearch",
            probe=b"GET / HTTP/1.0\r\n\r\n",
            match_pattern=b"\"tagline\" : \"You Know, for Search\"",
            ports=[9200, 9300]
        ))
        
        signatures.append(ServiceSignature(
            name="Docker Registry",
            probe=b"GET /v2/ HTTP/1.0\r\n\r\n",
            match_pattern=b"Docker-Distribution-Api-Version",
            ports=[5000]
        ))
        
        signatures.append(ServiceSignature(
            name="Kubernetes API",
            probe=b"GET /api HTTP/1.0\r\n\r\n",
            match_pattern=b"\"kind\": \"APIVersions\"",
            ports=[6443, 8080]
        ))
        
        return signatures
    
    def _load_cve_database(self):
        """Load CVE database for vulnerability assessment"""
        # In production, use actual CVE database
        # This is a simplified version
        return {
            "vsftpd_2.3.4": "CVE-2011-2523",
            "apache_2.4.7": ["CVE-2014-0098", "CVE-2014-0117"],
            "openssh_7.2": "CVE-2016-0777",
            "proftpd_1.3.5": "CVE-2015-3306",
            "mysql_5.5": ["CVE-2016-6662", "CVE-2016-6663"],
            "redis_3.2": "CVE-2015-8080",
            "elasticsearch_1.4": "CVE-2015-1427",
            "docker_1.12": "CVE-2019-5736",
            "kubernetes_1.16": "CVE-2019-11253",
        }
    
    def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        elapsed = current_time - self.last_send_time
        if elapsed < 1.0 / self.rate_limit:
            time.sleep(1.0 / self.rate_limit - elapsed)
        self.last_send_time = time.time()
    
    def syn_scan(self, target_ip, ports, timeout=2.0):
        """Real SYN scan with Scapy"""
        if not SCAPY_AVAILABLE:
            print("[!] Scapy required for SYN scan. Use --scan-type connect")
            return self.connect_scan(target_ip, ports, timeout)
        
        if os.geteuid() != 0:
            print("[!] SYN scan requires root privileges")
            return self.connect_scan(target_ip, ports, timeout)
        
        results = {}
        
        for port in ports:
            self._rate_limit()
            
            # Create SYN packet
            packet = self.packet_crafter.create_tcp_packet(
                target_ip, port, flags="S", 
                ttl=random.randint(30, 255) if self.ttl_variation else 64
            )
            
            # Add decoys
            if self.decoys:
                for decoy in self.decoys:
                    decoy_packet = packet.copy()
                    decoy_packet[IP].src = decoy
                    send(decoy_packet, verbose=0)
            
            # Send packet
            response = sr1(packet, timeout=timeout, verbose=0)
            self.stats['packets_sent'] += 1
            
            if response:
                self.stats['packets_received'] += 1
                
                if response.haslayer(TCP):
                    tcp_layer = response[TCP]
                    
                    # SYN-ACK response
                    if tcp_layer.flags & 0x12:  # SYN-ACK
                        results[port] = PortState.OPEN
                        
                        # Send RST to close connection
                        rst_packet = self.packet_crafter.create_tcp_packet(
                            target_ip, port, flags="R"
                        )
                        send(rst_packet, verbose=0)
                    
                    # RST response
                    elif tcp_layer.flags & 0x04:  # RST
                        results[port] = PortState.CLOSED
                    
                    # No response or ICMP unreachable
                    elif response.haslayer(ICMP):
                        icmp_type = response[ICMP].type
                        if icmp_type == 3 and response[ICMP].code in [1, 2, 3, 9, 10, 13]:
                            results[port] = PortState.FILTERED
                        else:
                            results[port] = PortState.FILTERED
                    else:
                        results[port] = PortState.FILTERED
                else:
                    results[port] = PortState.FILTERED
            else:
                results[port] = PortState.FILTERED
        
        return results
    
    def connect_scan(self, target_ip, ports, timeout=2.0):
        """Enhanced TCP connect scan with socket reuse"""
        results = {}
        
        def scan_port(port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            
            # Set socket options for performance
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                start_time = time.time()
                s.connect((target_ip, port))
                response_time = time.time() - start_time
                
                # Get service info
                banner = self._grab_banner(s, port)
                service_info = self._detect_service(port, banner)
                
                result = PortResult(
                    port=port,
                    state=PortState.OPEN,
                    protocol="tcp",
                    service=service_info.get('name'),
                    service_version=service_info.get('version'),
                    banner=banner,
                    response_time=response_time
                )
                
                # Check for vulnerabilities
                result.cves = self._check_vulnerabilities(result)
                
                return port, result
                
            except socket.timeout:
                return port, PortResult(port=port, state=PortState.FILTERED, protocol="tcp")
            except ConnectionRefusedError:
                return port, PortResult(port=port, state=PortState.CLOSED, protocol="tcp")
            except Exception as e:
                return port, PortResult(port=port, state=PortState.FILTERED, protocol="tcp")
            finally:
                s.close()
        
        # Parallel scanning
        with ThreadPoolExecutor(max_workers=self.config.get('max_threads', 200)) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    port_result = future.result()
                    if isinstance(port_result, tuple):
                        results[port_result[0]] = port_result[1]
                except Exception as e:
                    print(f"[!] Error scanning port {port}: {e}")
        
        return results
    
    def advanced_udp_scan(self, target_ip, ports, timeout=2.0):
        """Intelligent UDP scan with protocol-specific probes"""
        results = {}
        
        for port in ports:
            # Use different probes based on port
            probe = self._get_udp_probe(port)
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            
            try:
                s.sendto(probe, (target_ip, port))
                self.stats['packets_sent'] += 1
                
                try:
                    data, addr = s.recvfrom(1024)
                    self.stats['packets_received'] += 1
                    
                    # Analyze response
                    service_info = self._analyze_udp_response(port, data)
                    
                    result = PortResult(
                        port=port,
                        state=PortState.OPEN,
                        protocol="udp",
                        service=service_info.get('name'),
                        banner=data[:500].decode('utf-8', errors='ignore')
                    )
                    
                    results[port] = result
                    
                except socket.timeout:
                    # Could be open or filtered
                    # Send ICMP probe to check
                    icmp_result = self._icmp_probe(target_ip, port)
                    if icmp_result:
                        results[port] = PortResult(
                            port=port,
                            state=PortState.FILTERED,
                            protocol="udp"
                        )
                    else:
                        results[port] = PortResult(
                            port=port,
                            state=PortState.OPEN_FILTERED,
                            protocol="udp"
                        )
                        
            except Exception as e:
                print(f"[!] UDP scan error for port {port}: {e}")
            finally:
                s.close()
        
        return results
    
    def _get_udp_probe(self, port):
        """Get appropriate UDP probe for port"""
        probes = {
            53: b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',  # DNS
            161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x02\x3a\x69\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP
            123: b'\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3',  # NTP
            137: b'\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01',  # NetBIOS
            500: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # ISAKMP
            1900: b'M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',  # SSDP
            5353: b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01',  # mDNS
        }
        
        return probes.get(port, b'')
    
    def _analyze_udp_response(self, port, data):
        """Analyze UDP response"""
        service_info = {}
        
        if port == 53:  # DNS
            if len(data) > 12:
                service_info['name'] = 'DNS'
                # Parse DNS response
                try:
                    qr = (data[2] >> 7) & 0x01
                    if qr == 1:  # Response
                        service_info['version'] = 'DNS server'
                except:
                    pass
                    
        elif port == 161:  # SNMP
            if data.startswith(b'\x30'):  # ASN.1 BER encoded
                service_info['name'] = 'SNMP'
                
        elif port == 123:  # NTP
            if len(data) >= 48:
                service_info['name'] = 'NTP'
                
        elif port == 137:  # NetBIOS
            if len(data) > 12:
                service_info['name'] = 'NetBIOS'
                
        return service_info
    
    def _grab_banner(self, sock, port, timeout=2.0):
        """Advanced banner grabbing"""
        banners = []
        
        # Protocol-specific probes
        probes = [
            # HTTP/S
            b'GET / HTTP/1.0\r\n\r\n',
            b'HEAD / HTTP/1.0\r\n\r\n',
            b'OPTIONS / HTTP/1.0\r\n\r\n',
            
            # FTP
            b'USER anonymous\r\n',
            
            # SMTP
            b'EHLO example.com\r\n',
            
            # SSH
            b'SSH-2.0-PyRecon\r\n',
            
            # MySQL
            b'\x0a',
            
            # Redis
            b'INFO\r\n',
            
            # Memcached
            b'stats\r\n',
            
            # Generic
            b'\r\n',
            b'\r\n\r\n',
        ]
        
        for probe in probes:
            try:
                sock.settimeout(timeout)
                sock.send(probe)
                
                # Try to receive response
                start_time = time.time()
                data = b''
                while time.time() - start_time < timeout:
                    try:
                        chunk = sock.recv(4096)
                        if chunk:
                            data += chunk
                            # Check if we have enough data
                            if len(data) > 1024:
                                break
                        else:
                            break
                    except socket.timeout:
                        break
                    except BlockingIOError:
                        time.sleep(0.01)
                
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
                    if banner and banner not in banners:
                        banners.append(banner)
                        
            except (socket.timeout, socket.error, OSError):
                continue
        
        # Try SSL/TLS if regular probes fail
        if not banners and port in [443, 8443, 993, 995, 465, 636, 989, 990]:
            ssl_banner = self._grab_ssl_banner(sock, port, timeout)
            if ssl_banner:
                banners.append(ssl_banner)
        
        return '\n'.join(banners[:3]) if banners else None
    
    def _grab_ssl_banner(self, sock, port, timeout):
        """Grab SSL/TLS banner"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with context.wrap_socket(sock, server_hostname='') as ssock:
                ssock.settimeout(timeout)
                return str(ssock.version())
        except:
            return None
    
    def _detect_service(self, port, banner):
        """Advanced service detection"""
        service_info = {}
        
        # Check signatures
        for signature in self.service_signatures:
            if port in signature.ports or not signature.ports:
                if signature.probe:  # We already sent probe in banner grab
                    if signature.match_pattern:
                        if signature.match_pattern in banner.encode() if banner else False:
                            service_info['name'] = signature.name
                            break
        
        # If no signature match, use common ports
        if not service_info.get('name'):
            common_services = {
                21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
                53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
                443: 'https', 445: 'smb', 465: 'smtps',
                993: 'imaps', 995: 'pop3s', 3306: 'mysql',
                3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
                6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
                9200: 'elasticsearch', 27017: 'mongodb'
            }
            service_info['name'] = common_services.get(port)
        
        # Try to extract version from banner
        if banner and not service_info.get('version'):
            version_patterns = [
                r'(\d+\.\d+(?:\.\d+)?)',  # X.X.X
                r'v(\d+\.\d+)',  # vX.X
                r'version[\s:]*(\d+\.\d+)',  # version: X.X
                r'(\d{4}[\.\-]\d{1,2}[\.\-]\d{1,2})',  # YYYY-MM-DD
            ]
            
            for pattern in version_patterns:
                import re
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    service_info['version'] = match.group(1)
                    break
        
        return service_info
    
    def _check_vulnerabilities(self, port_result):
        """Check for known vulnerabilities"""
        cves = []
        
        if port_result.service and port_result.service_version:
            # Check CVE database
            service_key = f"{port_result.service}_{port_result.service_version}"
            if service_key in self.cve_db:
                cves = self.cve_db[service_key] if isinstance(self.cve_db[service_key], list) else [self.cve_db[service_key]]
            
            # Check for specific vulnerabilities
            if port_result.banner:
                banner_lower = port_result.banner.lower()
                
                # FTP anonymous login
                if port_result.service == 'ftp' and '220' in port_result.banner:
                    cves.append('FTP_ANONYMOUS_ACCESS')
                
                # SSH weak algorithms
                if port_result.service == 'ssh':
                    weak_algorithms = ['ssh-dss', 'diffie-hellman-group1-sha1', 
                                     'hmac-md5', 'hmac-md5-96']
                    if any(alg in banner_lower for alg in weak_algorithms):
                        cves.append('SSH_WEAK_ALGORITHMS')
                
                # HTTP security headers missing
                if port_result.service in ['http', 'https']:
                    security_headers = ['X-Frame-Options:', 'X-Content-Type-Options:',
                                      'Content-Security-Policy:', 'Strict-Transport-Security:']
                    missing = [h for h in security_headers if h not in port_result.banner]
                    if missing:
                        cves.append('MISSING_SECURITY_HEADERS')
        
        return cves
    
    def os_fingerprint(self, target_ip):
        """TCP/IP stack fingerprinting for OS detection"""
        if not SCAPY_AVAILABLE:
            return None
        
        results = {}
        
        # TCP options fingerprinting
        tests = [
            # SYN packet with various options
            IP(dst=target_ip)/TCP(dport=80, flags="S", 
                options=[('MSS', 1460), ('NOP', None), ('WScale', 10), 
                        ('NOP', None), ('NOP', None), ('Timestamp', (123, 0)),
                        ('SAckOK', b''), ('EOL', None)]),
            
            # FIN packet
            IP(dst=target_ip)/TCP(dport=80, flags="F"),
            
            # NULL packet
            IP(dst=target_ip)/TCP(dport=80, flags=0),
            
            # XMAS packet
            IP(dst=target_ip)/TCP(dport=80, flags="FPU"),
        ]
        
        for test in tests:
            resp = sr1(test, timeout=2, verbose=0)
            if resp and resp.haslayer(TCP):
                # Analyze response
                pass
        
        # Compare with known fingerprints
        # This is simplified - real implementation would have extensive DB
        
        return results
    
    def run_scan(self, target, ports, scan_type=ScanType.SYN, 
                output_format='json', output_file=None):
        """Main scan execution"""
        start_time = time.time()
        
        # Parse target
        if '/' in target:  # CIDR range
            network = ipaddress.ip_network(target, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        elif ',' in target:  # List of targets
            targets = [t.strip() for t in target.split(',')]
        else:  # Single target
            targets = [target]
        
        all_results = {}
        
        for target_ip in targets:
            print(f"[*] Scanning {target_ip}")
            
            # Resolve hostname
            try:
                hostname = socket.gethostbyaddr(target_ip)[0]
            except:
                hostname = None
            
            host_result = HostResult(ip=target_ip, hostname=hostname)
            
            # Perform scan
            if scan_type == ScanType.SYN:
                port_results = self.syn_scan(target_ip, ports)
            elif scan_type == ScanType.UDP:
                port_results = self.advanced_udp_scan(target_ip, ports)
            else:
                port_results = self.connect_scan(target_ip, ports)
            
            # Add results to host
            for port, result in port_results.items():
                if isinstance(result, PortResult):
                    host_result.add_port(result)
                else:
                    host_result.add_port(PortResult(
                        port=port, 
                        state=result, 
                        protocol="tcp" if scan_type != ScanType.UDP else "udp"
                    ))
            
            # OS fingerprinting
            if self.config.get('os_detection', False):
                os_info = self.os_fingerprint(target_ip)
                if os_info:
                    host_result.os_family = os_info.get('os_family')
                    host_result.os_version = os_info.get('os_version')
                    host_result.os_accuracy = os_info.get('accuracy', 0)
            
            host_result.end_time = datetime.now()
            all_results[target_ip] = host_result
            
            # Print results
            open_ports = host_result.get_open_ports()
            if open_ports:
                print(f"[+] {target_ip} has {len(open_ports)} open ports:")
                for port in open_ports:
                    vuln_str = f" [CVEs: {', '.join(port.cves)}]" if port.cves else ""
                    print(f"    {port.port}/{port.protocol} open {port.service or ''}{vuln_str}")
        
        # Generate report
        self._generate_report(all_results, output_format, output_file)
        
        self.stats['scan_duration'] = time.time() - start_time
        self.stats['hosts_up'] = len([h for h in all_results.values() if h.get_open_ports()])
        self.stats['ports_scanned'] = sum(len(h.ports) for h in all_results.values())
        
        print(f"\n[*] Scan completed in {self.stats['scan_duration']:.2f} seconds")
        print(f"[*] Hosts up: {self.stats['hosts_up']}")
        print(f"[*] Packets sent: {self.stats['packets_sent']}")
        print(f"[*] Packets received: {self.stats['packets_received']}")
        
        return all_results
    
    def _generate_report(self, results, format='json', filename=None):
        """Generate comprehensive report"""
        if format == 'json':
            report_data = {}
            for ip, host in results.items():
                host_dict = asdict(host)
                # Convert datetime to string
                host_dict['start_time'] = host_dict['start_time'].isoformat()
                host_dict['end_time'] = host_dict['end_time'].isoformat() if host_dict['end_time'] else None
                report_data[ip] = host_dict
            
            report = json.dumps(report_data, indent=2)
        
        elif format == 'nmap':
            # Generate nmap-style XML output
            report = '<?xml version="1.0"?>\n'
            report += '<!DOCTYPE nmaprun>\n'
            report += f'<nmaprun scanner="PyRecon" start="{int(time.time())}" version="2.0">\n'
            
            for ip, host in results.items():
                report += f'  <host><address addr="{ip}" addrtype="ipv4"/>\n'
                if host.hostname:
                    report += f'    <hostnames><hostname name="{host.hostname}" type="user"/></hostnames>\n'
                
                report += '    <ports>\n'
                for port_num, port in host.ports.items():
                    report += f'      <port protocol="{port.protocol}" portid="{port_num}">\n'
                    report += f'        <state state="{port.state.value}"/>\n'
                    if port.service:
                        report += f'        <service name="{port.service}">\n'
                        if port.service_version:
                            report += f'          <cpe>cpe:/a:{port.service}:{port.service_version}</cpe>\n'
                        report += '        </service>\n'
                    report += '      </port>\n'
                report += '    </ports>\n'
                report += '  </host>\n'
            
            report += '</nmaprun>'
        
        else:  # text format
            report = f"PyRecon Scan Report\n"
            report += f"Generated: {datetime.now().isoformat()}\n"
            report += "=" * 80 + "\n\n"
            
            for ip, host in results.items():
                report += f"Host: {ip}"
                if host.hostname:
                    report += f" ({host.hostname})"
                report += "\n"
                
                if host.os_family:
                    report += f"OS: {host.os_family}"
                    if host.os_version:
                        report += f" {host.os_version}"
                    report += f" (accuracy: {host.os_accuracy}%)\n"
                
                open_ports = host.get_open_ports()
                if open_ports:
                    report += f"Open ports: {len(open_ports)}\n"
                    for port in open_ports:
                        report += f"  {port.port}/{port.protocol} {port.state.value} {port.service or ''}"
                        if port.service_version:
                            report += f" {port.service_version}"
                        if port.banner:
                            banner_preview = port.banner[:100].replace('\n', '\\n')
                            report += f"\n    Banner: {banner_preview}"
                        if port.cves:
                            report += f"\n    CVEs: {', '.join(port.cves)}"
                        report += "\n"
                else:
                    report += "No open ports found\n"
                
                report += "\n"
        
        if filename:
            with open(filename, 'w') as f:
                f.write(report)
            print(f"[*] Report saved to {filename}")
        else:
            print(report)
        
        return report
