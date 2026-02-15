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
    from .core.scanner import AdvancedScanner
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
            from .engines.scripts import NSELikeScriptEngine
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
