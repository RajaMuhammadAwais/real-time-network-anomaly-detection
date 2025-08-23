"""
Botnet and Malware Communication Detection Module
Detects C&C server communication, DNS tunneling, and malware behavior patterns
"""

import re
import dns.resolver
import dns.message
import dns.query
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import base64
import struct
import socket
import threading
import time

logger = logging.getLogger(__name__)

class BotnetDetector:
    def __init__(self):
        """Initialize botnet detection engine"""
        self.dns_cache = {}
        self.communication_patterns = defaultdict(list)
        self.beacon_patterns = defaultdict(list)
        self.suspicious_domains = set()
        self.c2_indicators = {
            'domain_patterns': [
                r'^[a-z0-9]{8,16}\.(com|net|org|info)$',  # Random domain names
                r'^[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}\.',  # IP-like domains
                r'\.tk$|\.ml$|\.ga$|\.cf$',  # Free TLD domains
                r'^[a-f0-9]{32}\.',  # MD5-like domains
            ],
            'suspicious_tlds': [
                '.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.ws', '.to'
            ],
            'dga_patterns': [
                r'^[bcdfghjklmnpqrstvwxyz]{6,}[aeiou][bcdfghjklmnpqrstvwxyz]{6,}\.',
                r'^[a-z]{20,}\.',  # Very long random strings
                r'^[0-9a-f]{16,32}\.',  # Hex patterns
            ]
        }
        
        # Known C&C port patterns
        self.suspicious_ports = {
            1337, 31337, 6667, 6668, 6669,  # IRC ports
            8080, 8443, 9999, 4444, 5555,   # Common C&C ports
            53, 443, 80, 8000, 8888         # Legitimate ports used by malware
        }
        
        # DNS tunneling detection
        self.dns_tunnel_indicators = {
            'max_subdomain_length': 63,
            'max_query_length': 253,
            'suspicious_record_types': ['TXT', 'NULL', 'CNAME'],
            'entropy_threshold': 4.5,
            'base64_pattern': r'[A-Za-z0-9+/]{20,}={0,2}'
        }
        
        self.start_monitoring()
    
    def start_monitoring(self):
        """Start background monitoring threads"""
        # Start beacon detection thread
        beacon_thread = threading.Thread(target=self._beacon_detection_loop, daemon=True)
        beacon_thread.start()
        
        # Start pattern analysis thread
        pattern_thread = threading.Thread(target=self._pattern_analysis_loop, daemon=True)
        pattern_thread.start()
        
        logger.info("Botnet detection monitoring started")
    
    def analyze_communication(self, packet_info):
        """
        Analyze network communication for botnet indicators
        
        Args:
            packet_info (dict): Packet information
            
        Returns:
            dict: Analysis results
        """
        results = {
            'timestamp': datetime.now(),
            'is_suspicious': False,
            'indicators': [],
            'threat_score': 0.0,
            'communication_type': 'normal'
        }
        
        try:
            # Check for C&C communication patterns
            c2_score = self._detect_c2_communication(packet_info)
            if c2_score > 0:
                results['indicators'].append('C&C Communication')
                results['threat_score'] += c2_score
            
            # Check for beacon patterns
            beacon_score = self._detect_beacon_pattern(packet_info)
            if beacon_score > 0:
                results['indicators'].append('Beacon Pattern')
                results['threat_score'] += beacon_score
            
            # Check for DGA domains
            dga_score = self._detect_dga_domain(packet_info)
            if dga_score > 0:
                results['indicators'].append('DGA Domain')
                results['threat_score'] += dga_score
            
            # Check for suspicious ports
            port_score = self._check_suspicious_ports(packet_info)
            if port_score > 0:
                results['indicators'].append('Suspicious Port')
                results['threat_score'] += port_score
            
            # Normalize threat score
            results['threat_score'] = min(results['threat_score'], 1.0)
            
            # Determine if suspicious
            if results['threat_score'] > 0.3:
                results['is_suspicious'] = True
                results['communication_type'] = 'botnet'
            
            # Store communication pattern for analysis
            self._store_communication_pattern(packet_info, results)
            
        except Exception as e:
            logger.error(f"Error analyzing communication: {e}")
        
        return results
    
    def _detect_c2_communication(self, packet_info):
        """Detect Command & Control server communication"""
        score = 0.0
        
        try:
            dst_ip = packet_info.get('dst_ip')
            dst_port = packet_info.get('dst_port')
            
            if not dst_ip or not dst_port:
                return score
            
            # Check for communication to suspicious IPs
            if self._is_suspicious_ip(dst_ip):
                score += 0.4
            
            # Check for non-standard ports with high traffic
            if dst_port not in [80, 443, 53, 22, 21, 25]:
                score += 0.2
            
            # Check for encrypted traffic on non-standard ports
            if dst_port not in [443, 22] and packet_info.get('flags') == 'PSH':
                score += 0.3
            
            # Check for regular communication intervals (potential beacons)
            src_ip = packet_info.get('src_ip')
            if src_ip and dst_ip:
                connection_key = f"{src_ip}:{dst_ip}:{dst_port}"
                current_time = packet_info.get('timestamp', datetime.now())
                
                if connection_key in self.communication_patterns:
                    last_times = self.communication_patterns[connection_key]
                    if len(last_times) > 3:
                        intervals = [
                            (current_time - last_times[i]).total_seconds()
                            for i in range(-3, 0)
                        ]
                        
                        # Check for regular intervals (beacon behavior)
                        if self._is_regular_interval(intervals):
                            score += 0.5
                
                self.communication_patterns[connection_key].append(current_time)
                
                # Keep only recent communications
                cutoff_time = current_time - timedelta(hours=1)
                self.communication_patterns[connection_key] = [
                    t for t in self.communication_patterns[connection_key]
                    if t > cutoff_time
                ]
        
        except Exception as e:
            logger.error(f"Error detecting C&C communication: {e}")
        
        return score
    
    def _detect_beacon_pattern(self, packet_info):
        """Detect beacon communication patterns"""
        score = 0.0
        
        try:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            packet_size = packet_info.get('packet_size', 0)
            
            if not src_ip or not dst_ip:
                return score
            
            beacon_key = f"{src_ip}:{dst_ip}"
            current_time = packet_info.get('timestamp', datetime.now())
            
            # Store beacon information
            beacon_info = {
                'timestamp': current_time,
                'packet_size': packet_size,
                'port': packet_info.get('dst_port')
            }
            
            self.beacon_patterns[beacon_key].append(beacon_info)
            
            # Keep only recent beacons (last 2 hours)
            cutoff_time = current_time - timedelta(hours=2)
            self.beacon_patterns[beacon_key] = [
                b for b in self.beacon_patterns[beacon_key]
                if b['timestamp'] > cutoff_time
            ]
            
            beacons = self.beacon_patterns[beacon_key]
            
            if len(beacons) >= 5:
                # Analyze beacon patterns
                intervals = []
                sizes = []
                
                for i in range(1, len(beacons)):
                    interval = (beacons[i]['timestamp'] - beacons[i-1]['timestamp']).total_seconds()
                    intervals.append(interval)
                    sizes.append(beacons[i]['packet_size'])
                
                # Check for regular intervals
                if self._is_regular_interval(intervals):
                    score += 0.6
                
                # Check for consistent packet sizes
                if len(set(sizes)) <= 3:  # Very few different sizes
                    score += 0.3
                
                # Check for high frequency beacons
                avg_interval = np.mean(intervals)
                if 30 <= avg_interval <= 300:  # 30 seconds to 5 minutes
                    score += 0.4
        
        except Exception as e:
            logger.error(f"Error detecting beacon pattern: {e}")
        
        return score
    
    def _detect_dga_domain(self, packet_info):
        """Detect Domain Generation Algorithm (DGA) domains"""
        score = 0.0
        
        try:
            # Extract domain from packet info (this would need to be enhanced
            # to actually parse DNS queries from packet payload)
            domain = packet_info.get('domain')
            if not domain:
                return score
            
            # Check against DGA patterns
            for pattern in self.c2_indicators['dga_patterns']:
                if re.search(pattern, domain, re.IGNORECASE):
                    score += 0.4
                    break
            
            # Check domain characteristics
            domain_parts = domain.split('.')
            if len(domain_parts) >= 2:
                subdomain = domain_parts[0]
                tld = '.' + domain_parts[-1]
                
                # Check for suspicious TLD
                if tld in self.c2_indicators['suspicious_tlds']:
                    score += 0.3
                
                # Check subdomain entropy
                entropy = self._calculate_entropy(subdomain)
                if entropy > 4.0:  # High entropy indicates randomness
                    score += 0.4
                
                # Check for very long subdomains
                if len(subdomain) > 20:
                    score += 0.2
                
                # Check for numeric patterns
                if re.match(r'^[0-9a-f]{16,}$', subdomain):
                    score += 0.5
        
        except Exception as e:
            logger.error(f"Error detecting DGA domain: {e}")
        
        return score
    
    def _check_suspicious_ports(self, packet_info):
        """Check for communication on suspicious ports"""
        score = 0.0
        
        try:
            dst_port = packet_info.get('dst_port')
            if dst_port in self.suspicious_ports:
                score += 0.3
                
                # Higher score for known C&C ports
                if dst_port in [1337, 31337, 6667]:
                    score += 0.4
        
        except Exception as e:
            logger.error(f"Error checking suspicious ports: {e}")
        
        return score
    
    def detect_dns_tunneling(self, dns_query):
        """
        Detect DNS tunneling attempts
        
        Args:
            dns_query (dict): DNS query information
            
        Returns:
            dict: Detection results
        """
        results = {
            'is_tunneling': False,
            'indicators': [],
            'threat_score': 0.0,
            'tunnel_type': None
        }
        
        try:
            query_name = dns_query.get('query_name', '')
            query_type = dns_query.get('query_type', 'A')
            query_data = dns_query.get('query_data', '')
            
            score = 0.0
            
            # Check query length
            if len(query_name) > self.dns_tunnel_indicators['max_query_length']:
                score += 0.4
                results['indicators'].append('Excessive query length')
            
            # Check subdomain length
            subdomains = query_name.split('.')
            for subdomain in subdomains:
                if len(subdomain) > self.dns_tunnel_indicators['max_subdomain_length']:
                    score += 0.3
                    results['indicators'].append('Long subdomain')
                    break
            
            # Check for suspicious record types
            if query_type in self.dns_tunnel_indicators['suspicious_record_types']:
                score += 0.3
                results['indicators'].append(f'Suspicious record type: {query_type}')
            
            # Check for base64 encoding in query
            if re.search(self.dns_tunnel_indicators['base64_pattern'], query_name):
                score += 0.5
                results['indicators'].append('Base64 encoding detected')
                results['tunnel_type'] = 'base64'
            
            # Check entropy of query name
            entropy = self._calculate_entropy(query_name)
            if entropy > self.dns_tunnel_indicators['entropy_threshold']:
                score += 0.4
                results['indicators'].append('High entropy query')
            
            # Check for hex encoding
            if re.match(r'^[0-9a-f]{20,}', query_name.replace('.', '')):
                score += 0.4
                results['indicators'].append('Hex encoding detected')
                results['tunnel_type'] = 'hex'
            
            # Check for repeated queries to same domain
            domain = '.'.join(query_name.split('.')[-2:])
            if domain in self.dns_cache:
                self.dns_cache[domain] += 1
                if self.dns_cache[domain] > 50:  # Many queries to same domain
                    score += 0.3
                    results['indicators'].append('Excessive queries to domain')
            else:
                self.dns_cache[domain] = 1
            
            results['threat_score'] = min(score, 1.0)
            results['is_tunneling'] = score > 0.5
            
        except Exception as e:
            logger.error(f"Error detecting DNS tunneling: {e}")
        
        return results
    
    def _is_suspicious_ip(self, ip):
        """Check if IP address is suspicious"""
        try:
            # Check for private IP ranges communicating externally
            ip_parts = ip.split('.')
            if len(ip_parts) != 4:
                return False
            
            first_octet = int(ip_parts[0])
            second_octet = int(ip_parts[1])
            
            # Check for suspicious IP ranges
            suspicious_ranges = [
                (1, 1),      # 1.1.x.x (sometimes used by malware)
                (8, 8),      # 8.8.x.x (Google DNS - suspicious if used for C&C)
                (185, 0),    # Some bulletproof hosting ranges
                (46, 0),     # Some bulletproof hosting ranges
            ]
            
            for range_start, range_end in suspicious_ranges:
                if first_octet == range_start and (range_end == 0 or second_octet == range_end):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _is_regular_interval(self, intervals):
        """Check if intervals show regular beacon pattern"""
        if len(intervals) < 3:
            return False
        
        try:
            # Calculate coefficient of variation
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            
            if mean_interval == 0:
                return False
            
            cv = std_interval / mean_interval
            
            # Regular intervals have low coefficient of variation
            return cv < 0.3
            
        except Exception:
            return False
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        try:
            # Count character frequencies
            char_counts = Counter(data.lower())
            data_len = len(data)
            
            # Calculate entropy
            entropy = 0
            for count in char_counts.values():
                probability = count / data_len
                if probability > 0:
                    entropy -= probability * np.log2(probability)
            
            return entropy
            
        except Exception:
            return 0
    
    def _store_communication_pattern(self, packet_info, analysis_results):
        """Store communication pattern for future analysis"""
        try:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            
            if src_ip and dst_ip and analysis_results['is_suspicious']:
                pattern_key = f"{src_ip}:{dst_ip}"
                
                pattern_info = {
                    'timestamp': packet_info.get('timestamp', datetime.now()),
                    'threat_score': analysis_results['threat_score'],
                    'indicators': analysis_results['indicators'],
                    'packet_size': packet_info.get('packet_size', 0),
                    'port': packet_info.get('dst_port')
                }
                
                self.communication_patterns[pattern_key].append(pattern_info)
        
        except Exception as e:
            logger.error(f"Error storing communication pattern: {e}")
    
    def _beacon_detection_loop(self):
        """Background loop for beacon detection"""
        while True:
            try:
                # Clean up old beacon patterns every 5 minutes
                cutoff_time = datetime.now() - timedelta(hours=2)
                
                for key in list(self.beacon_patterns.keys()):
                    self.beacon_patterns[key] = [
                        b for b in self.beacon_patterns[key]
                        if b['timestamp'] > cutoff_time
                    ]
                    
                    if not self.beacon_patterns[key]:
                        del self.beacon_patterns[key]
                
                time.sleep(300)  # 5 minutes
                
            except Exception as e:
                logger.error(f"Error in beacon detection loop: {e}")
                time.sleep(60)
    
    def _pattern_analysis_loop(self):
        """Background loop for pattern analysis"""
        while True:
            try:
                # Analyze communication patterns every 10 minutes
                self._analyze_stored_patterns()
                time.sleep(600)  # 10 minutes
                
            except Exception as e:
                logger.error(f"Error in pattern analysis loop: {e}")
                time.sleep(60)
    
    def _analyze_stored_patterns(self):
        """Analyze stored communication patterns for botnet behavior"""
        try:
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(hours=1)
            
            # Group patterns by source IP
            source_patterns = defaultdict(list)
            
            for pattern_key, patterns in self.communication_patterns.items():
                src_ip = pattern_key.split(':')[0]
                recent_patterns = [p for p in patterns if p['timestamp'] > cutoff_time]
                
                if recent_patterns:
                    source_patterns[src_ip].extend(recent_patterns)
            
            # Analyze each source IP for botnet behavior
            for src_ip, patterns in source_patterns.items():
                if len(patterns) >= 10:  # Minimum patterns for analysis
                    botnet_score = self._calculate_botnet_score(patterns)
                    
                    if botnet_score > 0.7:
                        logger.warning(f"Potential botnet activity detected from {src_ip} (score: {botnet_score:.2f})")
        
        except Exception as e:
            logger.error(f"Error analyzing stored patterns: {e}")
    
    def _calculate_botnet_score(self, patterns):
        """Calculate botnet likelihood score for a set of patterns"""
        try:
            if not patterns:
                return 0.0
            
            score = 0.0
            
            # Check for multiple destinations (potential C&C servers)
            destinations = set()
            for pattern in patterns:
                if 'dst_ip' in pattern:
                    destinations.add(pattern['dst_ip'])
            
            if len(destinations) > 3:
                score += 0.3
            
            # Check for regular communication intervals
            timestamps = [p['timestamp'] for p in patterns]
            timestamps.sort()
            
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            if self._is_regular_interval(intervals):
                score += 0.4
            
            # Check average threat score
            threat_scores = [p.get('threat_score', 0) for p in patterns]
            avg_threat_score = np.mean(threat_scores)
            score += avg_threat_score * 0.5
            
            return min(score, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating botnet score: {e}")
            return 0.0
    
    def get_botnet_statistics(self):
        """Get current botnet detection statistics"""
        try:
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(hours=24)
            
            stats = {
                'active_beacons': 0,
                'suspicious_communications': 0,
                'potential_c2_servers': set(),
                'dns_tunneling_attempts': 0,
                'top_suspicious_ips': []
            }
            
            # Count active beacons
            for beacon_key, beacons in self.beacon_patterns.items():
                recent_beacons = [b for b in beacons if b['timestamp'] > cutoff_time]
                if len(recent_beacons) >= 5:
                    stats['active_beacons'] += 1
            
            # Count suspicious communications
            for pattern_key, patterns in self.communication_patterns.items():
                recent_patterns = [p for p in patterns if p['timestamp'] > cutoff_time]
                suspicious_patterns = [p for p in recent_patterns if p.get('threat_score', 0) > 0.5]
                
                if suspicious_patterns:
                    stats['suspicious_communications'] += len(suspicious_patterns)
                    
                    # Extract potential C&C servers
                    dst_ip = pattern_key.split(':')[1]
                    stats['potential_c2_servers'].add(dst_ip)
            
            # Convert set to list for JSON serialization
            stats['potential_c2_servers'] = list(stats['potential_c2_servers'])
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting botnet statistics: {e}")
            return {}

# Test function
if __name__ == "__main__":
    # Create botnet detector
    detector = BotnetDetector()
    
    # Test with sample communication
    test_packet = {
        'timestamp': datetime.now(),
        'src_ip': '192.168.1.100',
        'dst_ip': '185.10.20.30',
        'dst_port': 8080,
        'packet_size': 64,
        'flags': 'PSH'
    }
    
    result = detector.analyze_communication(test_packet)
    print("Botnet analysis result:", result)
    
    # Test DNS tunneling detection
    test_dns = {
        'query_name': 'aGVsbG93b3JsZA.example.com',
        'query_type': 'TXT',
        'query_data': 'base64data'
    }
    
    dns_result = detector.detect_dns_tunneling(test_dns)
    print("DNS tunneling result:", dns_result)
    
    # Get statistics
    stats = detector.get_botnet_statistics()
    print("Botnet statistics:", stats)

