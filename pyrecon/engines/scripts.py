from ..core.compat import *
from ..core.models import *

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
