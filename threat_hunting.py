"""
Threat Hunting Module
Provides searchable data logs and threat intelligence integration
"""

import sqlite3
import json
import requests
import logging
from datetime import datetime, timedelta
import pandas as pd
import re
import hashlib
import threading
import time

logger = logging.getLogger(__name__)

class ThreatHuntingEngine:
    def __init__(self, db_path='threat_hunting.db'):
        """Initialize threat hunting engine"""
        self.db_path = db_path
        self.threat_intel_sources = {
            'malware_domains': 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt',
            'phishing_domains': 'https://openphish.com/feed.txt',
            'tor_exit_nodes': 'https://check.torproject.org/torbulkexitlist',
        }
        self.ioc_cache = {}
        self.last_intel_update = None
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for storing network logs"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create network logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    packet_size INTEGER,
                    flags TEXT,
                    payload_hash TEXT,
                    threat_score REAL,
                    attack_type TEXT,
                    dpi_results TEXT,
                    lstm_prediction TEXT
                )
            ''')
            
            # Create threat intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT,
                    ioc_value TEXT,
                    source TEXT,
                    threat_type TEXT,
                    confidence REAL,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    description TEXT
                )
            ''')
            
            # Create alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    alert_type TEXT,
                    severity TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    description TEXT,
                    raw_data TEXT,
                    investigated BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Create indexes for better search performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON network_logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON network_logs(src_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dst_ip ON network_logs(dst_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol ON network_logs(protocol)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_value ON threat_intelligence(ioc_value)')
            
            conn.commit()
            conn.close()
            logger.info("Threat hunting database initialized")
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
    
    def log_network_event(self, packet_info, threat_analysis=None):
        """Log network event to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Calculate payload hash if payload exists
            payload_hash = None
            if 'payload' in packet_info and packet_info['payload']:
                payload_hash = hashlib.md5(str(packet_info['payload']).encode()).hexdigest()
            
            # Extract threat information
            threat_score = 0.0
            attack_type = 'normal'
            dpi_results = None
            lstm_prediction = None
            
            if threat_analysis:
                if 'threat_score' in threat_analysis:
                    threat_score = threat_analysis['threat_score']
                if 'attack_type' in threat_analysis:
                    attack_type = threat_analysis['attack_type']
                if 'dpi_results' in threat_analysis:
                    dpi_results = json.dumps(threat_analysis['dpi_results'])
                if 'lstm_prediction' in threat_analysis:
                    lstm_prediction = json.dumps(threat_analysis['lstm_prediction'])
            
            cursor.execute('''
                INSERT INTO network_logs 
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, 
                 packet_size, flags, payload_hash, threat_score, attack_type, 
                 dpi_results, lstm_prediction)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet_info.get('timestamp', datetime.now()),
                packet_info.get('src_ip'),
                packet_info.get('dst_ip'),
                packet_info.get('src_port'),
                packet_info.get('dst_port'),
                packet_info.get('protocol'),
                packet_info.get('packet_size'),
                packet_info.get('flags'),
                payload_hash,
                threat_score,
                attack_type,
                dpi_results,
                lstm_prediction
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging network event: {e}")
    
    def search_logs(self, filters=None, limit=1000):
        """
        Search network logs with various filters
        
        Args:
            filters (dict): Search filters
            limit (int): Maximum number of results
            
        Returns:
            list: Matching log entries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Build query based on filters
            query = "SELECT * FROM network_logs WHERE 1=1"
            params = []
            
            if filters:
                if 'src_ip' in filters:
                    query += " AND src_ip = ?"
                    params.append(filters['src_ip'])
                
                if 'dst_ip' in filters:
                    query += " AND dst_ip = ?"
                    params.append(filters['dst_ip'])
                
                if 'protocol' in filters:
                    query += " AND protocol = ?"
                    params.append(filters['protocol'])
                
                if 'port' in filters:
                    query += " AND (src_port = ? OR dst_port = ?)"
                    params.extend([filters['port'], filters['port']])
                
                if 'attack_type' in filters:
                    query += " AND attack_type = ?"
                    params.append(filters['attack_type'])
                
                if 'start_time' in filters:
                    query += " AND timestamp >= ?"
                    params.append(filters['start_time'])
                
                if 'end_time' in filters:
                    query += " AND timestamp <= ?"
                    params.append(filters['end_time'])
                
                if 'min_threat_score' in filters:
                    query += " AND threat_score >= ?"
                    params.append(filters['min_threat_score'])
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            df = pd.read_sql_query(query, conn, params=params)
            conn.close()
            
            return df.to_dict('records')
            
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
            return []
    
    def get_statistics(self, time_range_hours=24):
        """Get network statistics for the specified time range"""
        try:
            conn = sqlite3.connect(self.db_path)
            
            start_time = datetime.now() - timedelta(hours=time_range_hours)
            
            # Basic statistics
            stats_query = '''
                SELECT 
                    COUNT(*) as total_events,
                    COUNT(DISTINCT src_ip) as unique_src_ips,
                    COUNT(DISTINCT dst_ip) as unique_dst_ips,
                    AVG(packet_size) as avg_packet_size,
                    SUM(packet_size) as total_bytes,
                    COUNT(CASE WHEN attack_type != 'normal' THEN 1 END) as threats_detected
                FROM network_logs 
                WHERE timestamp >= ?
            '''
            
            stats_df = pd.read_sql_query(stats_query, conn, params=[start_time])
            
            # Top source IPs
            top_src_query = '''
                SELECT src_ip, COUNT(*) as count 
                FROM network_logs 
                WHERE timestamp >= ? 
                GROUP BY src_ip 
                ORDER BY count DESC 
                LIMIT 10
            '''
            
            top_src_df = pd.read_sql_query(top_src_query, conn, params=[start_time])
            
            # Attack type distribution
            attack_query = '''
                SELECT attack_type, COUNT(*) as count 
                FROM network_logs 
                WHERE timestamp >= ? AND attack_type != 'normal'
                GROUP BY attack_type 
                ORDER BY count DESC
            '''
            
            attack_df = pd.read_sql_query(attack_query, conn, params=[start_time])
            
            conn.close()
            
            return {
                'basic_stats': stats_df.to_dict('records')[0] if not stats_df.empty else {},
                'top_source_ips': top_src_df.to_dict('records'),
                'attack_distribution': attack_df.to_dict('records')
            }
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
    
    def update_threat_intelligence(self):
        """Update threat intelligence from external sources"""
        try:
            logger.info("Updating threat intelligence...")
            
            for source_name, url in self.threat_intel_sources.items():
                try:
                    response = requests.get(url, timeout=30)
                    if response.status_code == 200:
                        self._process_threat_feed(source_name, response.text)
                        logger.info(f"Updated threat intelligence from {source_name}")
                    else:
                        logger.warning(f"Failed to fetch {source_name}: {response.status_code}")
                        
                except Exception as e:
                    logger.error(f"Error fetching {source_name}: {e}")
            
            self.last_intel_update = datetime.now()
            logger.info("Threat intelligence update completed")
            
        except Exception as e:
            logger.error(f"Error updating threat intelligence: {e}")
    
    def _process_threat_feed(self, source_name, feed_data):
        """Process threat intelligence feed data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            lines = feed_data.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Determine IOC type and extract value
                ioc_type = 'domain'
                ioc_value = line
                
                if source_name == 'tor_exit_nodes':
                    ioc_type = 'ip'
                elif 'phishing' in source_name:
                    ioc_type = 'url'
                    # Extract domain from URL
                    if line.startswith('http'):
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(line)
                            ioc_value = parsed.netloc
                            ioc_type = 'domain'
                        except:
                            continue
                
                # Insert or update IOC
                cursor.execute('''
                    INSERT OR REPLACE INTO threat_intelligence 
                    (ioc_type, ioc_value, source, threat_type, confidence, 
                     first_seen, last_seen, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ioc_type,
                    ioc_value,
                    source_name,
                    self._get_threat_type(source_name),
                    0.8,  # Default confidence
                    datetime.now(),
                    datetime.now(),
                    f"IOC from {source_name}"
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error processing threat feed {source_name}: {e}")
    
    def _get_threat_type(self, source_name):
        """Map source name to threat type"""
        mapping = {
            'malware_domains': 'malware',
            'phishing_domains': 'phishing',
            'tor_exit_nodes': 'anonymization'
        }
        return mapping.get(source_name, 'unknown')
    
    def check_ioc(self, ioc_value, ioc_type='auto'):
        """
        Check if an IOC (Indicator of Compromise) is known
        
        Args:
            ioc_value (str): The IOC value to check
            ioc_type (str): Type of IOC (ip, domain, url, hash)
            
        Returns:
            dict: IOC information if found
        """
        try:
            # Auto-detect IOC type if not specified
            if ioc_type == 'auto':
                ioc_type = self._detect_ioc_type(ioc_value)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM threat_intelligence 
                WHERE ioc_value = ? AND ioc_type = ?
            ''', (ioc_value, ioc_type))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, result))
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking IOC: {e}")
            return None
    
    def _detect_ioc_type(self, value):
        """Auto-detect IOC type based on value format"""
        # IP address pattern
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if re.match(ip_pattern, value):
            return 'ip'
        
        # Domain pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if re.match(domain_pattern, value):
            return 'domain'
        
        # URL pattern
        if value.startswith(('http://', 'https://')):
            return 'url'
        
        # Hash patterns
        if len(value) == 32 and re.match(r'^[a-fA-F0-9]+$', value):
            return 'md5'
        elif len(value) == 40 and re.match(r'^[a-fA-F0-9]+$', value):
            return 'sha1'
        elif len(value) == 64 and re.match(r'^[a-fA-F0-9]+$', value):
            return 'sha256'
        
        return 'unknown'
    
    def create_alert(self, alert_type, severity, src_ip, dst_ip, description, raw_data=None):
        """Create a new security alert"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts 
                (timestamp, alert_type, severity, src_ip, dst_ip, description, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now(),
                alert_type,
                severity,
                src_ip,
                dst_ip,
                description,
                json.dumps(raw_data) if raw_data else None
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Alert created: {alert_type} - {description}")
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
    
    def get_alerts(self, limit=100, investigated=None):
        """Get security alerts"""
        try:
            conn = sqlite3.connect(self.db_path)
            
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if investigated is not None:
                query += " AND investigated = ?"
                params.append(investigated)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            df = pd.read_sql_query(query, conn, params=params)
            conn.close()
            
            return df.to_dict('records')
            
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []
    
    def start_background_intel_update(self, update_interval_hours=24):
        """Start background thread for threat intelligence updates"""
        def update_loop():
            while True:
                try:
                    self.update_threat_intelligence()
                    time.sleep(update_interval_hours * 3600)  # Convert hours to seconds
                except Exception as e:
                    logger.error(f"Error in background intel update: {e}")
                    time.sleep(3600)  # Wait 1 hour before retrying
        
        thread = threading.Thread(target=update_loop, daemon=True)
        thread.start()
        logger.info("Background threat intelligence update started")

# Test function
if __name__ == "__main__":
    # Create threat hunting engine
    engine = ThreatHuntingEngine()
    
    # Test logging a network event
    packet_info = {
        'timestamp': datetime.now(),
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'packet_size': 1024,
        'flags': 'SYN'
    }
    
    threat_analysis = {
        'threat_score': 0.8,
        'attack_type': 'port_scan'
    }
    
    engine.log_network_event(packet_info, threat_analysis)
    
    # Test searching logs
    results = engine.search_logs({'src_ip': '192.168.1.100'})
    print(f"Found {len(results)} matching logs")
    
    # Test IOC checking
    ioc_result = engine.check_ioc('malicious-domain.com', 'domain')
    print(f"IOC check result: {ioc_result}")
    
    # Get statistics
    stats = engine.get_statistics()
    print(f"Statistics: {stats}")
    
    print("Threat hunting engine test completed")

