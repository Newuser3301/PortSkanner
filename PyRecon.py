import socket
import struct
import sys
import os
import time
import json
import ipaddress
import threading
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import random
import signal
import ctypes
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set, Any
from dataclasses import dataclass, field, asdict
from enum import Enum, IntEnum
from queue import Queue, Empty
import select
import ssl
import hashlib
import base64
import zlib

# Third-party imports
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.http import HTTP
    from scapy.sendrecv import sr, sr1, srp, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. Advanced features disabled.")
    print("[!] Install: pip install scapy")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Constants
class ScanType(IntEnum):
    """Advanced scan types with TCP flag combinations"""
    SYN = 1          # SYN scan
    CONNECT = 2      # TCP connect
    ACK = 3          # ACK scan (firewall testing)
    FIN = 4          # FIN scan
    NULL = 5         # NULL scan (no flags)
    XMAS = 6         # XMAS scan (FIN,URG,PSH)
    MAIMON = 7       # Maimon scan (FIN,ACK)
    WINDOW = 8       # Window scan
    UDP = 9          # UDP scan
    SCTP = 10        # SCTP scan
    IPPROTO = 11     # IP protocol scan
    IDLE = 12        # Idle/zombie scan
    FTP_BOUNCE = 13  # FTP bounce scan

class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"

@dataclass
class ServiceSignature:
    """Service detection signature"""
    name: str
    probe: bytes
    match_pattern: bytes
    soft_match: bool = False
    rarity: int = 1  # 1-9, lower is more common
    ports: List[int] = field(default_factory=list)
    ssl_ports: List[int] = field(default_factory=list)

@dataclass
class PortResult:
    """Enhanced port result"""
    port: int
    state: PortState
    protocol: str
    service: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    banner_hash: Optional[str] = None
    response_time: Optional[float] = None
    cves: List[str] = field(default_factory=list)
    extra_info: Dict[str, Any] = field(default_factory=dict)
    script_results: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.banner:
            self.banner_hash = hashlib.md5(self.banner.encode()).hexdigest()

@dataclass 
class HostResult:
    """Host with advanced fingerprinting"""
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    os_accuracy: int = 0  # 0-100
    uptime_guess: Optional[int] = None
    tcp_sequence: Dict[str, Any] = field(default_factory=dict)
    ports: Dict[int, PortResult] = field(default_factory=dict)
    traceroute: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    
    def add_port(self, result: PortResult):
        self.ports[result.port] = result
    
    def get_open_ports(self) -> List[PortResult]:
        return [p for p in self.ports.values() if p.state == PortState.OPEN]

class PacketCrafter:
    """Advanced packet crafting with Scapy"""
    
    def __init__(self, use_ipv6=False, source_ip=None, source_port=None, 
                 interface=None, mtu=1500):
        self.use_ipv6 = use_ipv6
        self.source_ip = source_ip or self._get_local_ip()
        self.source_port = source_port or random.randint(1024, 65535)
        self.interface = interface
        self.mtu = mtu
        self.seq = random.randint(0, 2**32 - 1)
        self.ip_id = random.randint(0, 65535)
        
    def _get_local_ip(self):
        """Get local IP for routing"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip
    
    def create_tcp_packet(self, target_ip, target_port, flags="S", 
                         ttl=64, window=1024, options=None, 
                         payload=b'', bad_checksum=False):
        """Create TCP packet with full control"""
        
        if self.use_ipv6:
            ip_layer = IPv6(src=self.source_ip, dst=target_ip)
        else:
            ip_layer = IP(src=self.source_ip, dst=target_ip, ttl=ttl, id=self.ip_id)
        
        # TCP flags
        flag_dict = {
            'S': 'S',  # SYN
            'A': 'A',  # ACK
            'F': 'F',  # FIN
            'R': 'R',  # RST
            'P': 'P',  # PSH
            'U': 'U',  # URG
            'E': 'E',  # ECE
            'C': 'C',  # CWR
        }
        
        tcp_flags = 0
        for f in flags:
            if f in flag_dict:
                tcp_flags |= getattr(TCP, flag_dict[f])
        
        tcp_layer = TCP(sport=self.source_port, dport=target_port,
                       flags=tcp_flags, seq=self.seq, window=window)
        
        self.seq += 1
        self.ip_id += 1
        
        # TCP options
        if options:
            tcp_layer.options = options
        
        # Bad checksum for evasion
        if bad_checksum:
            tcp_layer.chksum = random.randint(0, 65535)
        
        packet = ip_layer / tcp_layer / payload
        
        # Fragmentation
        if len(packet) > self.mtu:
            packet = fragment(packet, fragsize=self.mtu)
        
        return packet
    
    def create_udp_packet(self, target_ip, target_port, payload=b''):
        """Create UDP packet with protocol-specific probes"""
        if self.use_ipv6:
            ip_layer = IPv6(src=self.source_ip, dst=target_ip)
        else:
            ip_layer = IP(src=self.source_ip, dst=target_ip)
        
        udp_layer = UDP(sport=random.randint(1024, 65535), dport=target_port)
        
        # Common UDP service probes
        if target_port == 53:  # DNS
            payload = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'
        elif target_port == 161:  # SNMP
            payload = b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x02\x3a\x69\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
        elif target_port == 123:  # NTP
            payload = b'\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3'
        
        return ip_layer / udp_layer / payload

class AdvancedScanner:
    """Main scanner class with enterprise features"""
    
    def __init__(self, config=None):
        self.config = config or {}
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

class NSELikeScriptEngine:
    """Nmap Scripting Engine-like functionality"""
    
    def __init__(self):
        self.scripts = self._load_scripts()
    
    def _load_scripts(self):
        """Load security assessment scripts"""
        scripts = {}
        
        # HTTP scripts
        scripts['http-enum'] = self.http_enum
        scripts['http-vuln-cve'] = self.http_vuln_check
        scripts['http-headers'] = self.http_headers
        scripts['http-methods'] = self.http_methods
        
        # SSH scripts
        scripts['ssh-auth-methods'] = self.ssh_auth_methods
        scripts['ssh-hostkey'] = self.ssh_hostkey
        
        # FTP scripts
        scripts['ftp-anon'] = self.ftp_anonymous
        
        # SMB scripts
        scripts['smb-os-discovery'] = self.smb_os_discovery
        scripts['smb-vuln-ms17-010'] = self.smb_ms17_010
        
        # Database scripts
        scripts['mysql-audit'] = self.mysql_audit
        scripts['redis-info'] = self.redis_info
        
        return scripts
    
    def http_enum(self, target, port):
        """Enumerate HTTP directories and files"""
        import requests
        
        common_paths = [
            '/admin/', '/login/', '/wp-admin/', '/phpmyadmin/',
            '/server-status', '/.git/', '/backup/', '/config/',
            '/api/', '/swagger/', '/graphql', '/.env',
        ]
        
        results = []
        for path in common_paths:
            try:
                url = f"http://{target}:{port}{path}"
                resp = requests.get(url, timeout=2, verify=False)
                if resp.status_code < 400:
                    results.append({
                        'path': path,
                        'status': resp.status_code,
                        'title': self._extract_title(resp.text),
                        'length': len(resp.content)
                    })
            except:
                continue
        
        return results
    
    def http_vuln_check(self, target, port):
        """Check for common HTTP vulnerabilities"""
        vulns = []
        
        # Check for common vulnerabilities
        checks = [
            ('/../../../../etc/passwd', 'Path Traversal'),
            ('/cgi-bin/test.cgi', 'CGI Vulnerability'),
            ('/wp-content/debug.log', 'WordPress Debug Log'),
            ('/.git/HEAD', 'Git Repository Exposure'),
        ]
        
        for path, vuln_name in checks:
            try:
                url = f"http://{target}:{port}{path}"
                resp = requests.get(url, timeout=2, verify=False)
                if resp.status_code == 200 and 'root:' in resp.text:
                    vulns.append({'vulnerability': vuln_name, 'path': path})
            except:
                continue
        
        return vulns
    
    def ssh_auth_methods(self, target, port):
        """Check SSH authentication methods"""
        import paramiko
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target, port=port, username='invalid', 
                          password='invalid', timeout=2)
        except paramiko.ssh_exception.AuthenticationException as e:
            # Extract auth methods from error
            error_str = str(e)
            methods = []
            if 'password' in error_str:
                methods.append('password')
            if 'publickey' in error_str:
                methods.append('publickey')
            if 'keyboard-interactive' in error_str:
                methods.append('keyboard-interactive')
            
            return {'auth_methods': methods}
        except:
            pass
        
        return {'auth_methods': []}
    
    def ftp_anonymous(self, target, port):
        """Check for anonymous FTP access"""
        try:
            from ftplib import FTP
            
            ftp = FTP()
            ftp.connect(target, port, timeout=2)
            ftp.login('anonymous', 'anonymous@example.com')
            
            # Try to list directory
            files = ftp.nlst()
            ftp.quit()
            
            return {
                'anonymous_access': True,
                'files_count': len(files),
                'files': files[:10]  # Limit output
            }
        except:
            return {'anonymous_access': False}
    
    def run_scripts(self, target, port, service):
        """Run appropriate scripts based on service"""
        results = {}
        
        # Determine which scripts to run
        scripts_to_run = []
        
        if service in ['http', 'https']:
            scripts_to_run.extend(['http-enum', 'http-headers', 'http-methods'])
            if 'apache' in service or 'nginx' in service:
                scripts_to_run.append('http-vuln-cve')
        
        elif service == 'ssh':
            scripts_to_run.extend(['ssh-auth-methods', 'ssh-hostkey'])
        
        elif service == 'ftp':
            scripts_to_run.append('ftp-anon')
        
        elif service == 'smb' or port == 445:
            scripts_to_run.extend(['smb-os-discovery', 'smb-vuln-ms17-010'])
        
        elif service == 'mysql':
            scripts_to_run.append('mysql-audit')
        
        elif service == 'redis':
            scripts_to_run.append('redis-info')
        
        # Run scripts
        for script_name in scripts_to_run:
            if script_name in self.scripts:
                try:
                    result = self.scripts[script_name](target, port)
                    if result:
                        results[script_name] = result
                except Exception as e:
                    results[script_name] = {'error': str(e)}
        
        return results

def main():
    parser = argparse.ArgumentParser(
        description="PyRecon v2.0 - Advanced Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # SYN scan top 1000 ports
  %(prog)s 192.168.1.1 -s syn -p top1000
  
  # Full scan with OS detection and scripts
  %(prog)s 192.168.1.0/24 -s syn -p 1-65535 -O -A
  
  # UDP scan for common services
  %(prog)s target.com -s udp -p 53,161,123,137,500
  
  # Stealth scan with decoys
  %(prog)s 10.0.0.1 -s syn --decoys 1.2.3.4,5.6.7.8 --timing 2
  
  # Output to Elasticsearch
  %(prog)s 192.168.1.1 -o elastic --elastic-host http://localhost:9200
        """
    )
    
    parser.add_argument("target", help="Target IP, range (CIDR), or hostname")
    parser.add_argument("-p", "--ports", default="top1000",
                       help="Ports to scan (e.g., '1-1000,443,8080', 'top100', 'all')")
    parser.add_argument("-s", "--scan-type", default="syn",
                       choices=["syn", "connect", "udp", "ack", "fin", "null", "xmas", "maimon", "window", "idle"],
                       help="Scan type")
    parser.add_argument("-t", "--threads", type=int, default=200,
                       help="Maximum threads (default: 200)")
    parser.add_argument("-T", "--timeout", type=float, default=2.0,
                       help="Socket timeout (default: 2.0)")
    parser.add_argument("--timing", type=int, default=3, choices=range(0, 6),
                       help="Timing template (0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    parser.add_argument("-O", "--os-detection", action="store_true",
                       help="Enable OS detection")
    parser.add_argument("-A", "--aggressive", action="store_true",
                       help="Aggressive mode (OS detection, version detection, script scanning)")
    parser.add_argument("--scripts", help="Comma-separated list of scripts to run")
    parser.add_argument("--decoys", help="Comma-separated list of decoy IPs")
    parser.add_argument("--spoof-mac", help="Spoof MAC address")
    parser.add_argument("--data-length", type=int, help="Append random data to packets")
    parser.add_argument("--fragment", action="store_true", help="Fragment packets")
    parser.add_argument("-o", "--output", choices=["text", "json", "nmap", "csv", "elastic"],
                       default="text", help="Output format")
    parser.add_argument("-f", "--output-file", help="Output file")
    parser.add_argument("--elastic-host", help="Elasticsearch host for output")
    parser.add_argument("--rate-limit", type=int, default=1000,
                       help="Packets per second (default: 1000)")
    
    args = parser.parse_args()
    
    # Parse ports
    if args.ports == "top1000":
        # Common 1000 ports (simplified)
        ports = list(range(1, 1001))
    elif args.ports == "top100":
        ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443]
        ports.extend(range(8000, 8100))
    elif args.ports == "all":
        ports = list(range(1, 65536))
    else:
        # Parse port string
        ports = set()
        for part in args.ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        ports = sorted(ports)
    
    # Configure scanner
    config = {
        'max_threads': args.threads,
        'timeout': args.timeout,
        'os_detection': args.os_detection or args.aggressive,
        'rate_limit': args.rate_limit,
        'fragment': args.fragment,
    }
    
    if args.decoys:
        config['decoys'] = [d.strip() for d in args.decoys.split(',')]
    
    # Timing templates
    timing_configs = {
        0: {'rate_limit': 10, 'timeout': 5.0},    # Paranoid
        1: {'rate_limit': 50, 'timeout': 4.0},    # Sneaky
        2: {'rate_limit': 100, 'timeout': 3.0},   # Polite
        3: {'rate_limit': 500, 'timeout': 2.0},   # Normal
        4: {'rate_limit': 1000, 'timeout': 1.5},  # Aggressive
        5: {'rate_limit': 5000, 'timeout': 1.0},  # Insane
    }
    
    if args.timing in timing_configs:
        config.update(timing_configs[args.timing])
    
    # Create scanner
    scanner = AdvancedScanner(config)
    
    # Determine scan type
    scan_type_map = {
        'syn': ScanType.SYN,
        'connect': ScanType.CONNECT,
        'udp': ScanType.UDP,
        'ack': ScanType.ACK,
        'fin': ScanType.FIN,
        'null': ScanType.NULL,
        'xmas': ScanType.XMAS,
        'maimon': ScanType.MAIMON,
        'window': ScanType.WINDOW,
        'idle': ScanType.IDLE,
    }
    
    scan_type = scan_type_map.get(args.scan_type, ScanType.SYN)
    
    # Run scan
    try:
        results = scanner.run_scan(
            target=args.target,
            ports=ports[:10000],  # Limit for demo
            scan_type=scan_type,
            output_format=args.output,
            output_file=args.output_file
        )
        
        # Run scripts if aggressive mode
        if args.aggressive or args.scripts:
            print("\n[*] Running security scripts...")
            script_engine = NSELikeScriptEngine()
            
            for ip, host in results.items():
                for port_result in host.get_open_ports():
                    if port_result.service:
                        script_results = script_engine.run_scripts(
                            ip, port_result.port, port_result.service
                        )
                        if script_results:
                            port_result.script_results = script_results
                            print(f"[+] Script results for {ip}:{port_result.port}:")
                            for script, result in script_results.items():
                                print(f"    {script}: {result}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Check for root if needed
    if len(sys.argv) > 1 and 'syn' in sys.argv and os.geteuid() != 0:
        print("[!] SYN scan requires root privileges. Use sudo or --scan-type connect")
        sys.exit(1)
    
    main()
