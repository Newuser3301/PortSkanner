from .compat import *

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
