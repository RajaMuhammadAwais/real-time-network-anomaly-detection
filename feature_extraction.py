"""
Feature Extraction Module
Extracts features from network traffic data for anomaly detection
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class FeatureExtractor:
    def __init__(self, time_window=60):
        """
        Initialize feature extractor
        
        Args:
            time_window (int): Time window in seconds for feature aggregation
        """
        self.time_window = time_window
        
    def extract_basic_features(self, packets_df):
        """Extract basic statistical features from packets"""
        if packets_df.empty:
            return {}
        
        features = {
            # Packet count features
            'packet_count': len(packets_df),
            'unique_src_ips': packets_df['src_ip'].nunique(),
            'unique_dst_ips': packets_df['dst_ip'].nunique(),
            'unique_src_ports': packets_df['src_port'].nunique(),
            'unique_dst_ports': packets_df['dst_port'].nunique(),
            
            # Packet size features
            'avg_packet_size': packets_df['packet_size'].mean(),
            'max_packet_size': packets_df['packet_size'].max(),
            'min_packet_size': packets_df['packet_size'].min(),
            'std_packet_size': packets_df['packet_size'].std(),
            'total_bytes': packets_df['packet_size'].sum(),
            
            # Protocol distribution
            'tcp_ratio': len(packets_df[packets_df['protocol'] == 6]) / len(packets_df),
            'udp_ratio': len(packets_df[packets_df['protocol'] == 17]) / len(packets_df),
            'icmp_ratio': len(packets_df[packets_df['protocol'] == 1]) / len(packets_df),
        }
        
        return features
    
    def extract_temporal_features(self, packets_df):
        """Extract time-based features"""
        if packets_df.empty or len(packets_df) < 2:
            return {}
        
        # Convert timestamp to datetime if it's not already
        if not pd.api.types.is_datetime64_any_dtype(packets_df['timestamp']):
            packets_df['timestamp'] = pd.to_datetime(packets_df['timestamp'])
        
        # Sort by timestamp
        packets_df = packets_df.sort_values('timestamp')
        
        # Calculate inter-arrival times
        time_diffs = packets_df['timestamp'].diff().dt.total_seconds().dropna()
        
        features = {
            'avg_inter_arrival_time': time_diffs.mean(),
            'std_inter_arrival_time': time_diffs.std(),
            'max_inter_arrival_time': time_diffs.max(),
            'min_inter_arrival_time': time_diffs.min(),
        }
        
        return features
    
    def extract_connection_features(self, packets_df):
        """Extract connection-based features"""
        if packets_df.empty:
            return {}
        
        # Create connection pairs
        packets_df['connection'] = packets_df['src_ip'].astype(str) + ':' + packets_df['src_port'].astype(str) + '->' + packets_df['dst_ip'].astype(str) + ':' + packets_df['dst_port'].astype(str)
        
        connection_counts = packets_df['connection'].value_counts()
        
        features = {
            'unique_connections': len(connection_counts),
            'avg_packets_per_connection': connection_counts.mean(),
            'max_packets_per_connection': connection_counts.max(),
            'std_packets_per_connection': connection_counts.std(),
        }
        
        return features
    
    def detect_port_scan_features(self, packets_df):
        """Extract features that might indicate port scanning"""
        if packets_df.empty:
            return {}
        
        features = {}
        
        # Group by source IP
        src_groups = packets_df.groupby('src_ip')
        
        for src_ip, group in src_groups:
            if len(group) < 5:  # Skip if too few packets
                continue
                
            unique_dst_ports = group['dst_port'].nunique()
            unique_dst_ips = group['dst_ip'].nunique()
            
            # Potential port scan indicators
            if unique_dst_ports > 10 and len(group) > 20:
                features[f'potential_port_scan_{src_ip}'] = {
                    'unique_ports_accessed': unique_dst_ports,
                    'unique_ips_accessed': unique_dst_ips,
                    'total_packets': len(group),
                    'port_scan_ratio': unique_dst_ports / len(group)
                }
        
        return features
    
    def detect_dos_features(self, packets_df):
        """Extract features that might indicate DoS attacks"""
        if packets_df.empty:
            return {}
        
        features = {}
        
        # High packet rate from single source
        src_counts = packets_df['src_ip'].value_counts()
        total_packets = len(packets_df)
        
        for src_ip, count in src_counts.head(5).items():
            packet_ratio = count / total_packets
            if packet_ratio > 0.3:  # More than 30% of traffic from single source
                features[f'potential_dos_{src_ip}'] = {
                    'packet_count': count,
                    'packet_ratio': packet_ratio,
                    'avg_packet_size': packets_df[packets_df['src_ip'] == src_ip]['packet_size'].mean()
                }
        
        return features
    
    def extract_all_features(self, packets_df):
        """Extract all features from packets dataframe"""
        if packets_df.empty:
            return {}
        
        all_features = {}
        
        # Extract different types of features
        all_features.update(self.extract_basic_features(packets_df))
        all_features.update(self.extract_temporal_features(packets_df))
        all_features.update(self.extract_connection_features(packets_df))
        
        # Attack-specific features
        port_scan_features = self.detect_port_scan_features(packets_df)
        dos_features = self.detect_dos_features(packets_df)
        
        all_features['port_scan_indicators'] = port_scan_features
        all_features['dos_indicators'] = dos_features
        
        # Add timestamp
        all_features['extraction_timestamp'] = datetime.now()
        
        return all_features
    
    def create_feature_vector(self, features_dict):
        """Convert features dictionary to a numerical vector for ML"""
        # Define the features we want to use for ML
        ml_features = [
            'packet_count', 'unique_src_ips', 'unique_dst_ips', 
            'avg_packet_size', 'std_packet_size', 'total_bytes',
            'tcp_ratio', 'udp_ratio', 'icmp_ratio',
            'avg_inter_arrival_time', 'std_inter_arrival_time',
            'unique_connections', 'avg_packets_per_connection'
        ]
        
        feature_vector = []
        for feature in ml_features:
            value = features_dict.get(feature, 0)
            # Handle NaN values
            if pd.isna(value):
                value = 0
            feature_vector.append(float(value))
        
        return np.array(feature_vector)

# Test function
if __name__ == "__main__":
    # Create sample data for testing
    sample_data = {
        'timestamp': [datetime.now() - timedelta(seconds=i) for i in range(100, 0, -1)],
        'src_ip': ['192.168.1.1'] * 50 + ['192.168.1.2'] * 50,
        'dst_ip': ['192.168.1.100'] * 100,
        'protocol': [6] * 80 + [17] * 20,  # TCP and UDP
        'packet_size': np.random.normal(500, 100, 100),
        'src_port': np.random.randint(1024, 65535, 100),
        'dst_port': [80] * 50 + [443] * 30 + [22] * 20,
        'flags': ['S'] * 100
    }
    
    df = pd.DataFrame(sample_data)
    
    extractor = FeatureExtractor()
    features = extractor.extract_all_features(df)
    
    print("Extracted Features:")
    for key, value in features.items():
        if key not in ['port_scan_indicators', 'dos_indicators']:
            print(f"{key}: {value}")
    
    # Test feature vector creation
    feature_vector = extractor.create_feature_vector(features)
    print(f"\nFeature Vector: {feature_vector}")
    print(f"Feature Vector Shape: {feature_vector.shape}")

