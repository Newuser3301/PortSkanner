from .compat import *

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
