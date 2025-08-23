"""
Deep Packet Inspection (DPI) Module
Analyzes packet payloads to detect application-layer attacks
"""

import re
import base64
import urllib.parse
import logging
from datetime import datetime
import dpkt
import socket

logger = logging.getLogger(__name__)

class DeepPacketInspector:
    def __init__(self):
        """Initialize Deep Packet Inspector"""
        self.sql_injection_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # SQL injection
            r"(\%27)|(\')|(union)|(select)|(insert)|(delete)|(update)|(drop)|(create)|(alter)",
            r"(exec(\s|\+)+(s|x)p\w+)",  # SQL Server stored procedures
            r"(script.*?src)",  # Script injection
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",  # Script tags
            r"javascript:",  # JavaScript protocol
            r"on\w+\s*=",  # Event handlers
            r"<iframe[^>]*>.*?</iframe>",  # Iframe tags
            r"<object[^>]*>.*?</object>",  # Object tags
            r"<embed[^>]*>.*?</embed>",  # Embed tags
            r"<link[^>]*>",  # Link tags
            r"<meta[^>]*>",  # Meta tags with refresh
        ]
        
        self.command_injection_patterns = [
            r"(;|\||&|`|\$\(|\$\{)",  # Command separators
            r"(nc|netcat|telnet|wget|curl)",  # Network tools
            r"(cat|ls|ps|id|whoami|uname)",  # System commands
            r"(\.\./){2,}",  # Directory traversal
            r"(cmd\.exe|powershell|bash|sh)",  # Shell executables
        ]
        
        self.malware_signatures = [
            r"(eval\s*\()",  # Eval functions
            r"(base64_decode|gzinflate|str_rot13)",  # PHP obfuscation
            r"(document\.write|innerHTML)",  # DOM manipulation
            r"(CreateObject|WScript\.Shell)",  # Windows scripting
            r"(\x90{4,})",  # NOP sleds
        ]
        
        self.botnet_patterns = [
            r"(bot|zombie|slave)",  # Bot keywords
            r"(c&c|command.*control)",  # C&C references
            r"(beacon|heartbeat|checkin)",  # Communication patterns
            r"(download.*execute|exec.*download)",  # Download and execute
        ]
        
        # Compile patterns for better performance
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance"""
        self.compiled_sql_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_injection_patterns]
        self.compiled_xss_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns]
        self.compiled_cmd_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.command_injection_patterns]
        self.compiled_malware_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.malware_signatures]
        self.compiled_botnet_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.botnet_patterns]
    
    def inspect_packet(self, packet_data):
        """
        Perform deep packet inspection on packet data
        
        Args:
            packet_data: Raw packet data or scapy packet
            
        Returns:
            dict: Inspection results
        """
        results = {
            'timestamp': datetime.now(),
            'threats_detected': [],
            'payload_analysis': {},
            'protocol_info': {},
            'suspicious_patterns': []
        }
        
        try:
            # Extract payload based on packet type
            payload = self._extract_payload(packet_data)
            
            if payload:
                # Analyze payload for various threats
                results['payload_analysis'] = self._analyze_payload(payload)
                
                # Check for specific attack patterns
                sql_threats = self._detect_sql_injection(payload)
                xss_threats = self._detect_xss(payload)
                cmd_threats = self._detect_command_injection(payload)
                malware_threats = self._detect_malware_signatures(payload)
                botnet_threats = self._detect_botnet_communication(payload)
                
                # Combine all threats
                all_threats = sql_threats + xss_threats + cmd_threats + malware_threats + botnet_threats
                results['threats_detected'] = all_threats
                
                # Extract protocol information
                results['protocol_info'] = self._extract_protocol_info(packet_data)
                
        except Exception as e:
            logger.error(f"Error during packet inspection: {e}")
            results['error'] = str(e)
        
        return results
    
    def _extract_payload(self, packet_data):
        """Extract payload from packet data"""
        try:
            # If it's a scapy packet
            if hasattr(packet_data, 'load'):
                return packet_data.load
            
            # If it's raw bytes, try to parse with dpkt
            if isinstance(packet_data, bytes):
                try:
                    eth = dpkt.ethernet.Ethernet(packet_data)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                            return ip.data.data
                except:
                    pass
                
                # Return raw data if parsing fails
                return packet_data
            
            return None
            
        except Exception as e:
            logger.error(f"Error extracting payload: {e}")
            return None
    
    def _analyze_payload(self, payload):
        """Analyze payload characteristics"""
        if not payload:
            return {}
        
        try:
            # Convert to string for analysis
            if isinstance(payload, bytes):
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                except:
                    payload_str = str(payload)
            else:
                payload_str = str(payload)
            
            analysis = {
                'size': len(payload),
                'entropy': self._calculate_entropy(payload),
                'printable_ratio': self._calculate_printable_ratio(payload_str),
                'contains_urls': bool(re.search(r'https?://', payload_str, re.IGNORECASE)),
                'contains_base64': self._detect_base64(payload_str),
                'contains_hex': bool(re.search(r'[0-9a-fA-F]{20,}', payload_str)),
                'suspicious_strings': self._find_suspicious_strings(payload_str)
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing payload: {e}")
            return {}
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Count byte frequencies
            byte_counts = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            # Calculate entropy
            entropy = 0
            data_len = len(data)
            for count in byte_counts.values():
                probability = count / data_len
                if probability > 0:
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
            
        except Exception:
            return 0
    
    def _calculate_printable_ratio(self, text):
        """Calculate ratio of printable characters"""
        if not text:
            return 0
        
        printable_count = sum(1 for char in text if char.isprintable())
        return printable_count / len(text)
    
    def _detect_base64(self, text):
        """Detect potential base64 encoded content"""
        # Look for base64 patterns
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, text)
        
        for match in matches:
            try:
                decoded = base64.b64decode(match)
                # Check if decoded content looks suspicious
                if len(decoded) > 10 and self._calculate_printable_ratio(decoded.decode('utf-8', errors='ignore')) > 0.7:
                    return True
            except:
                continue
        
        return False
    
    def _find_suspicious_strings(self, text):
        """Find suspicious strings in payload"""
        suspicious = []
        
        # Common attack strings
        attack_strings = [
            'eval(', 'exec(', 'system(', 'shell_exec(',
            'passthru(', 'file_get_contents(', 'fopen(',
            'include(', 'require(', 'document.cookie',
            'window.location', 'document.write'
        ]
        
        for attack_str in attack_strings:
            if attack_str.lower() in text.lower():
                suspicious.append(attack_str)
        
        return suspicious
    
    def _detect_sql_injection(self, payload):
        """Detect SQL injection patterns"""
        threats = []
        
        if not payload:
            return threats
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore') if isinstance(payload, bytes) else str(payload)
            
            # URL decode the payload
            decoded_payload = urllib.parse.unquote(payload_str)
            
            for i, pattern in enumerate(self.compiled_sql_patterns):
                if pattern.search(decoded_payload):
                    threats.append({
                        'type': 'SQL Injection',
                        'pattern_id': i,
                        'pattern': self.sql_injection_patterns[i],
                        'severity': 'High',
                        'description': 'Potential SQL injection attack detected'
                    })
            
        except Exception as e:
            logger.error(f"Error detecting SQL injection: {e}")
        
        return threats
    
    def _detect_xss(self, payload):
        """Detect Cross-Site Scripting (XSS) patterns"""
        threats = []
        
        if not payload:
            return threats
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore') if isinstance(payload, bytes) else str(payload)
            
            # URL decode the payload
            decoded_payload = urllib.parse.unquote(payload_str)
            
            for i, pattern in enumerate(self.compiled_xss_patterns):
                if pattern.search(decoded_payload):
                    threats.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'pattern_id': i,
                        'pattern': self.xss_patterns[i],
                        'severity': 'Medium',
                        'description': 'Potential XSS attack detected'
                    })
            
        except Exception as e:
            logger.error(f"Error detecting XSS: {e}")
        
        return threats
    
    def _detect_command_injection(self, payload):
        """Detect command injection patterns"""
        threats = []
        
        if not payload:
            return threats
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore') if isinstance(payload, bytes) else str(payload)
            
            # URL decode the payload
            decoded_payload = urllib.parse.unquote(payload_str)
            
            for i, pattern in enumerate(self.compiled_cmd_patterns):
                if pattern.search(decoded_payload):
                    threats.append({
                        'type': 'Command Injection',
                        'pattern_id': i,
                        'pattern': self.command_injection_patterns[i],
                        'severity': 'High',
                        'description': 'Potential command injection attack detected'
                    })
            
        except Exception as e:
            logger.error(f"Error detecting command injection: {e}")
        
        return threats
    
    def _detect_malware_signatures(self, payload):
        """Detect malware signatures"""
        threats = []
        
        if not payload:
            return threats
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore') if isinstance(payload, bytes) else str(payload)
            
            for i, pattern in enumerate(self.compiled_malware_patterns):
                if pattern.search(payload_str):
                    threats.append({
                        'type': 'Malware Signature',
                        'pattern_id': i,
                        'pattern': self.malware_signatures[i],
                        'severity': 'High',
                        'description': 'Potential malware signature detected'
                    })
            
        except Exception as e:
            logger.error(f"Error detecting malware signatures: {e}")
        
        return threats
    
    def _detect_botnet_communication(self, payload):
        """Detect botnet communication patterns"""
        threats = []
        
        if not payload:
            return threats
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore') if isinstance(payload, bytes) else str(payload)
            
            for i, pattern in enumerate(self.compiled_botnet_patterns):
                if pattern.search(payload_str):
                    threats.append({
                        'type': 'Botnet Communication',
                        'pattern_id': i,
                        'pattern': self.botnet_patterns[i],
                        'severity': 'High',
                        'description': 'Potential botnet communication detected'
                    })
            
        except Exception as e:
            logger.error(f"Error detecting botnet communication: {e}")
        
        return threats
    
    def _extract_protocol_info(self, packet_data):
        """Extract protocol information from packet"""
        info = {}
        
        try:
            # If it's a scapy packet
            if hasattr(packet_data, 'summary'):
                info['summary'] = packet_data.summary()
            
            # Extract layer information
            if hasattr(packet_data, 'layers'):
                info['layers'] = [layer.name for layer in packet_data.layers()]
            
            # Extract specific protocol fields
            if hasattr(packet_data, 'src') and hasattr(packet_data, 'dst'):
                info['src_ip'] = packet_data.src
                info['dst_ip'] = packet_data.dst
            
            if hasattr(packet_data, 'sport') and hasattr(packet_data, 'dport'):
                info['src_port'] = packet_data.sport
                info['dst_port'] = packet_data.dport
            
        except Exception as e:
            logger.error(f"Error extracting protocol info: {e}")
        
        return info

# Test function
if __name__ == "__main__":
    # Create DPI instance
    dpi = DeepPacketInspector()
    
    # Test with sample payloads
    test_payloads = [
        b"GET /index.php?id=1' OR '1'='1 HTTP/1.1",  # SQL injection
        b"<script>alert('XSS')</script>",  # XSS
        b"normal web traffic content",  # Normal
        b"; cat /etc/passwd",  # Command injection
    ]
    
    for i, payload in enumerate(test_payloads):
        print(f"\nTest {i+1}:")
        result = dpi.inspect_packet(payload)
        print(f"Threats detected: {len(result['threats_detected'])}")
        for threat in result['threats_detected']:
            print(f"  - {threat['type']}: {threat['description']}")

