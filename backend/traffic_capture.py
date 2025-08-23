"""
Network Traffic Capture Module
Handles real-time network traffic capture using Scapy
"""

import scapy.all as scapy
import threading
import time
import pandas as pd
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TrafficCapture:
    def __init__(self, interface='eth0'):
        self.interface = interface
        self.is_capturing = False
        self.capture_thread = None
        self.packets_data = []
        self.max_packets = 1000  # Limit to prevent memory overflow
        
    def packet_handler(self, packet):
        """Process each captured packet and extract features"""
        try:
            # Extract basic packet information
            packet_info = {
                'timestamp': datetime.now(),
                'src_ip': packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'N/A',
                'dst_ip': packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'N/A',
                'protocol': packet[scapy.IP].proto if packet.haslayer(scapy.IP) else 'N/A',
                'packet_size': len(packet),
                'src_port': packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else (packet[scapy.UDP].sport if packet.haslayer(scapy.UDP) else 'N/A'),
                'dst_port': packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else (packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) else 'N/A'),
                'flags': packet[scapy.TCP].flags if packet.haslayer(scapy.TCP) else 'N/A'
            }
            
            # Add to packets data
            self.packets_data.append(packet_info)
            
            # Maintain maximum packet limit
            if len(self.packets_data) > self.max_packets:
                self.packets_data.pop(0)
                
            logger.debug(f"Captured packet: {packet_info['src_ip']} -> {packet_info['dst_ip']}")
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.is_capturing:
            logger.warning("Capture is already running")
            return
            
        self.is_capturing = True
        logger.info(f"Starting packet capture on interface: {self.interface}")
        
        def capture_packets():
            try:
                scapy.sniff(iface=self.interface, prn=self.packet_handler, stop_filter=lambda x: not self.is_capturing)
            except Exception as e:
                logger.error(f"Error during packet capture: {e}")
                self.is_capturing = False
        
        self.capture_thread = threading.Thread(target=capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop packet capture"""
        if not self.is_capturing:
            logger.warning("Capture is not running")
            return
            
        self.is_capturing = False
        logger.info("Stopping packet capture")
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
    
    def get_recent_packets(self, count=100):
        """Get recent packets data"""
        return self.packets_data[-count:] if len(self.packets_data) >= count else self.packets_data
    
    def get_packets_dataframe(self):
        """Convert packets data to pandas DataFrame"""
        if not self.packets_data:
            return pd.DataFrame()
        
        return pd.DataFrame(self.packets_data)
    
    def get_traffic_stats(self):
        """Get basic traffic statistics"""
        if not self.packets_data:
            return {}
        
        df = self.get_packets_dataframe()
        
        stats = {
            'total_packets': len(df),
            'unique_src_ips': df['src_ip'].nunique(),
            'unique_dst_ips': df['dst_ip'].nunique(),
            'avg_packet_size': df['packet_size'].mean(),
            'total_traffic': df['packet_size'].sum(),
            'protocols': df['protocol'].value_counts().to_dict(),
            'top_src_ips': df['src_ip'].value_counts().head(5).to_dict(),
            'top_dst_ips': df['dst_ip'].value_counts().head(5).to_dict()
        }
        
        return stats

# Test function for development
if __name__ == "__main__":
    # Create a traffic capture instance
    capture = TrafficCapture(interface='lo')  # Use loopback for testing
    
    try:
        # Start capture
        capture.start_capture()
        
        # Let it run for a few seconds
        time.sleep(10)
        
        # Get stats
        stats = capture.get_traffic_stats()
        print("Traffic Stats:", stats)
        
    except KeyboardInterrupt:
        print("Stopping capture...")
    finally:
        capture.stop_capture()

