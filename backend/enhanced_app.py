"""
Enhanced Network Traffic Anomaly Detection System
Main Flask application with advanced threat detection capabilities
"""

import os
import json
import logging
import threading
import time
import sys
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Add the backend directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our enhanced modules
from traffic_capture import TrafficCapture
from feature_extraction import FeatureExtractor
from anomaly_detector import AnomalyDetector
from deep_learning_detector import LSTMAttackDetector
from deep_packet_inspector import DeepPacketInspector
from threat_hunting import ThreatHuntingEngine
from botnet_detector import BotnetDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, 
           template_folder='../frontend',
           static_folder='../frontend')
app.config['SECRET_KEY'] = 'enhanced-network-anomaly-detector-secret-key'

# Enable CORS for all routes
CORS(app, origins="*")

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize enhanced components
traffic_capture = TrafficCapture()
feature_extractor = FeatureExtractor()
anomaly_detector = AnomalyDetector()
lstm_detector = LSTMAttackDetector()
dpi_inspector = DeepPacketInspector()
threat_hunting = ThreatHuntingEngine()
botnet_detector = BotnetDetector()

# Global variables for enhanced monitoring
monitoring_active = False
current_stats = {
    'total_packets': 0,
    'anomalies_detected': 0,
    'protocols': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0},
    'top_sources': {},
    'top_destinations': {},
    'threat_level': 'Low',
    'last_update': datetime.now().isoformat(),
    'advanced_threats': {
        'lstm_detections': 0,
        'dpi_threats': 0,
        'botnet_communications': 0,
        'dns_tunneling': 0
    },
    'threat_hunting_stats': {
        'total_events_logged': 0,
        'alerts_generated': 0,
        'iocs_checked': 0
    }
}

packet_buffer = []
sequence_buffer = []
SEQUENCE_LENGTH = 50

class EnhancedNetworkMonitor:
    def __init__(self):
        self.is_running = False
        self.alerts = []
        self.max_alerts = 1000
        self.packet_count = 0
        
    def start_monitoring(self, interface='lo'):
        """Start enhanced network monitoring"""
        if self.is_running:
            return False
            
        try:
            self.is_running = True
            logger.info(f"Starting enhanced network monitoring on interface: {interface}")
            
            # Start background threat intelligence updates
            threat_hunting.start_background_intel_update()
            
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self._monitoring_loop, args=(interface,))
            monitor_thread.daemon = True
            monitor_thread.start()
            
            return True
        except Exception as e:
            logger.error(f"Error starting monitoring: {e}")
            self.is_running = False
            return False
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_running = False
        logger.info("Network monitoring stopped")
    
    def _monitoring_loop(self, interface):
        """Enhanced monitoring loop with all detection capabilities"""
        
        try:
            # Initialize LSTM detector if not already trained
            if not lstm_detector.is_trained:
                logger.info("Training LSTM detector...")
                lstm_detector.train_model(epochs=20)
            
            while self.is_running:
                try:
                    # Simulate packet capture (in real implementation, this would capture actual packets)
                    packet_data = self._simulate_packet_capture()
                    
                    if packet_data:
                        self.packet_count += 1
                        
                        # Extract features using existing FeatureExtractor APIs
                        # Convert packet_data to a one-row DataFrame with expected columns
                        proto_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
                        packet_df = pd.DataFrame([{
                            'timestamp': packet_data.get('timestamp', datetime.now()),
                            'src_ip': packet_data.get('src_ip'),
                            'dst_ip': packet_data.get('dst_ip'),
                            'protocol': proto_map.get(packet_data.get('protocol', 'TCP'), 6),
                            'packet_size': packet_data.get('packet_size', packet_data.get('size', 0)),
                            'src_port': packet_data.get('src_port'),
                            'dst_port': packet_data.get('dst_port'),
                            'flags': packet_data.get('flags', '')
                        }])
                        
                        features = feature_extractor.extract_all_features(packet_df)
                        feature_vector = feature_extractor.create_feature_vector(features)
                        
                        # Traditional anomaly detection
                        anomaly_result = anomaly_detector.predict(feature_vector)
                        
                        # Deep packet inspection
                        dpi_result = dpi_inspector.inspect_packet(packet_data)
                        
                        # Botnet detection (ensure packet_size is available)
                        packet_data_for_botnet = dict(packet_data)
                        if 'packet_size' not in packet_data_for_botnet:
                            packet_data_for_botnet['packet_size'] = packet_data_for_botnet.get('size', 0)
                        botnet_result = botnet_detector.analyze_communication(packet_data_for_botnet)
                        
                        # Build sequence for LSTM
                        sequence_buffer.append(feature_vector.tolist())
                        if len(sequence_buffer) > SEQUENCE_LENGTH:
                            sequence_buffer.pop(0)
                        
                        # LSTM prediction (when we have enough data)
                        lstm_result = None
                        if len(sequence_buffer) == SEQUENCE_LENGTH:
                            try:
                                sequence_array = np.array(sequence_buffer).reshape(1, SEQUENCE_LENGTH, -1)
                                lstm_result = lstm_detector.predict_sequence(sequence_array)
                            except Exception as e:
                                logger.error(f"LSTM prediction error: {e}")
                        
                        # Combine all analysis results
                        combined_analysis = self._combine_analysis_results(
                            anomaly_result, dpi_result, botnet_result, lstm_result
                        )
                        
                        # Log to threat hunting database
                        threat_hunting.log_network_event(packet_data, combined_analysis)
                        
                        # Update statistics
                        self._update_statistics(packet_data, combined_analysis)
                        
                        # Generate alerts if necessary
                        self._check_and_generate_alerts(packet_data, combined_analysis)
                        
                        # Emit real-time updates
                        socketio.emit('packet_update', {
                            'packet_data': packet_data,
                            'analysis': combined_analysis,
                            'stats': current_stats
                        })
                        
                        # Add to packet buffer for dashboard
                        packet_buffer.append({
                            'timestamp': packet_data.get('timestamp', datetime.now()).isoformat(),
                            'src_ip': packet_data.get('src_ip'),
                            'dst_ip': packet_data.get('dst_ip'),
                            'protocol': packet_data.get('protocol'),
                            'packet_size': packet_data.get('packet_size', packet_data.get('size', 0)),
                            'threat_score': combined_analysis.get('threat_score', 0),
                            'attack_type': combined_analysis.get('attack_type', 'normal')
                        })
                        
                        # Keep buffer size manageable
                        if len(packet_buffer) > 1000:
                            packet_buffer.pop(0)
                    
                    time.sleep(0.1)  # Small delay to prevent overwhelming
                    
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(1)
                    
        except Exception as e:
            logger.error(f"Fatal error in monitoring loop: {e}")
            self.is_running = False
    
    def _simulate_packet_capture(self):
        """Simulate packet capture for testing (replace with real capture in production)"""
        import random
        import numpy as np
        
        # Simulate different types of network traffic
        packet_types = ['normal', 'dos', 'port_scan', 'apt', 'sql_injection', 'xss', 'botnet']
        weights = [0.7, 0.05, 0.05, 0.02, 0.03, 0.03, 0.12]  # Normal traffic is most common
        
        packet_type = np.random.choice(packet_types, p=weights)
        
        # Generate packet data based on type
        if packet_type == 'normal':
            return {
                'timestamp': datetime.now(),
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"10.0.0.{random.randint(1, 254)}",
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 21, 25]),
                'protocol': random.choice(['TCP', 'UDP']),
                'packet_size': random.randint(64, 1500),
                'flags': random.choice(['SYN', 'ACK', 'PSH', 'FIN']),
                'payload': b'normal web traffic data'
            }
        elif packet_type == 'dos':
            return {
                'timestamp': datetime.now(),
                'src_ip': f"192.168.1.{random.randint(1, 10)}",  # Few source IPs
                'dst_ip': "10.0.0.1",  # Single target
                'src_port': random.randint(1024, 65535),
                'dst_port': 80,
                'protocol': 'TCP',
                'packet_size': 64,  # Small packets
                'flags': 'SYN',
                'payload': b'SYN flood attack'
            }
        elif packet_type == 'sql_injection':
            return {
                'timestamp': datetime.now(),
                'src_ip': f"192.168.1.{random.randint(100, 200)}",
                'dst_ip': "10.0.0.5",
                'src_port': random.randint(1024, 65535),
                'dst_port': 80,
                'protocol': 'TCP',
                'packet_size': random.randint(800, 1200),
                'flags': 'PSH',
                'payload': b"GET /login.php?id=1' OR '1'='1 HTTP/1.1"
            }
        elif packet_type == 'botnet':
            return {
                'timestamp': datetime.now(),
                'src_ip': f"192.168.1.{random.randint(50, 100)}",
                'dst_ip': f"185.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([8080, 8443, 1337, 31337]),
                'protocol': 'TCP',
                'packet_size': random.randint(100, 300),
                'flags': 'PSH',
                'payload': b'beacon checkin data'
            }
        else:
            # Generate other attack types similarly
            return {
                'timestamp': datetime.now(),
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"10.0.0.{random.randint(1, 254)}",
                'src_port': random.randint(1024, 65535),
                'dst_port': random.randint(1, 65535),
                'protocol': random.choice(['TCP', 'UDP']),
                'packet_size': random.randint(64, 1500),
                'flags': random.choice(['SYN', 'ACK', 'PSH', 'FIN']),
                'payload': f'{packet_type} attack payload'.encode()
            }
    
    def _combine_analysis_results(self, anomaly_result, dpi_result, botnet_result, lstm_result):
        """Combine results from all detection methods"""
        combined = {
            'timestamp': datetime.now(),
            'threat_score': 0.0,
            'attack_type': 'normal',
            'is_anomaly': False,
            'detection_methods': [],
            'details': {}
        }
        
        # Traditional anomaly detection
        if anomaly_result and anomaly_result.get('is_anomaly', False):
            combined['threat_score'] += 0.3
            combined['is_anomaly'] = True
            combined['detection_methods'].append('Traditional ML')
            combined['details']['anomaly_score'] = anomaly_result.get('anomaly_score', 0)
        
        # Deep packet inspection
        if dpi_result and dpi_result.get('threats_detected'):
            threat_count = len(dpi_result['threats_detected'])
            combined['threat_score'] += min(threat_count * 0.2, 0.6)
            combined['detection_methods'].append('Deep Packet Inspection')
            combined['details']['dpi_threats'] = dpi_result['threats_detected']
            
            # Set attack type based on DPI results
            if dpi_result['threats_detected']:
                combined['attack_type'] = dpi_result['threats_detected'][0]['type'].lower().replace(' ', '_')
        
        # Botnet detection
        if botnet_result and botnet_result.get('is_suspicious', False):
            combined['threat_score'] += botnet_result.get('threat_score', 0) * 0.4
            combined['detection_methods'].append('Botnet Detection')
            combined['details']['botnet_indicators'] = botnet_result.get('indicators', [])
            
            if botnet_result.get('communication_type') == 'botnet':
                combined['attack_type'] = 'botnet'
        
        # LSTM prediction
        if lstm_result and lstm_result.get('is_attack', False):
            lstm_confidence = lstm_result.get('confidence', 0)
            combined['threat_score'] += lstm_confidence * 0.5
            combined['detection_methods'].append('LSTM Deep Learning')
            combined['details']['lstm_prediction'] = lstm_result
            
            if lstm_confidence > 0.7:
                combined['attack_type'] = lstm_result.get('attack_type', 'unknown')
        
        # Normalize threat score
        combined['threat_score'] = min(combined['threat_score'], 1.0)
        
        # Determine if this is an attack
        if combined['threat_score'] > 0.3:
            combined['is_anomaly'] = True
        
        return combined
    
    def _update_statistics(self, packet_data, analysis):
        """Update global statistics"""
        
        current_stats['total_packets'] += 1
        current_stats['last_update'] = datetime.now().isoformat()
        
        # Update protocol stats
        protocol = packet_data.get('protocol', 'Other')
        if protocol in current_stats['protocols']:
            current_stats['protocols'][protocol] += 1
        else:
            current_stats['protocols']['Other'] += 1
        
        # Update anomaly count
        if analysis.get('is_anomaly', False):
            current_stats['anomalies_detected'] += 1
        
        # Update advanced threat stats
        if 'Deep Packet Inspection' in analysis.get('detection_methods', []):
            current_stats['advanced_threats']['dpi_threats'] += 1
        
        if 'LSTM Deep Learning' in analysis.get('detection_methods', []):
            current_stats['advanced_threats']['lstm_detections'] += 1
        
        if 'Botnet Detection' in analysis.get('detection_methods', []):
            current_stats['advanced_threats']['botnet_communications'] += 1
        
        # Update threat level
        threat_ratio = current_stats['anomalies_detected'] / max(current_stats['total_packets'], 1)
        if threat_ratio > 0.1:
            current_stats['threat_level'] = 'High'
        elif threat_ratio > 0.05:
            current_stats['threat_level'] = 'Medium'
        else:
            current_stats['threat_level'] = 'Low'
        
        # Update top sources and destinations
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        
        if src_ip:
            current_stats['top_sources'][src_ip] = current_stats['top_sources'].get(src_ip, 0) + 1
        
        if dst_ip:
            current_stats['top_destinations'][dst_ip] = current_stats['top_destinations'].get(dst_ip, 0) + 1
    
    def _check_and_generate_alerts(self, packet_data, analysis):
        """Generate alerts for significant threats"""
        if analysis.get('threat_score', 0) > 0.7:
            alert = {
                'id': len(self.alerts) + 1,
                'timestamp': datetime.now().isoformat(),
                'alert_type': 'High Threat Detected',
                'severity': 'High',
                'src_ip': packet_data.get('src_ip'),
                'dst_ip': packet_data.get('dst_ip'),
                'description': f"High threat score ({analysis['threat_score']:.2f}) detected. Methods: {', '.join(analysis.get('detection_methods', []))}",
                'attack_type': analysis.get('attack_type', 'unknown'),
                'raw_data': packet_data
            }
            
            self.alerts.append(alert)
            
            # Keep alerts list manageable
            if len(self.alerts) > self.max_alerts:
                self.alerts.pop(0)
            
            # Create alert in threat hunting database
            threat_hunting.create_alert(
                alert['alert_type'],
                alert['severity'],
                alert['src_ip'],
                alert['dst_ip'],
                alert['description'],
                alert['raw_data']
            )
            
            # Emit alert to connected clients
            socketio.emit('new_alert', alert)
            
            logger.warning(f"High threat alert: {alert['description']}")

# Initialize monitor
network_monitor = EnhancedNetworkMonitor()

# Routes
@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/threat_hunting.html')
def threat_hunting_page():
    """Threat hunting interface"""
    return render_template('threat_hunting.html')

@app.route('/api/start_monitoring', methods=['POST'])
def start_monitoring():
    """Start network monitoring"""
    try:
        interface = request.json.get('interface', 'lo') if request.json else 'lo'
        success = network_monitor.start_monitoring(interface)
        
        if success:
            global monitoring_active
            monitoring_active = True
            return jsonify({'status': 'success', 'message': 'Monitoring started'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to start monitoring'}), 500
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring"""
    try:
        network_monitor.stop_monitoring()
        global monitoring_active
        monitoring_active = False
        return jsonify({'status': 'success', 'message': 'Monitoring stopped'})
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/status')
def get_status():
    """Get current monitoring status and statistics"""
    
    status = {
        'monitoring_active': monitoring_active,
        'stats': current_stats,
        'recent_packets': packet_buffer[-10:] if packet_buffer else [],
        'recent_alerts': network_monitor.alerts[-5:] if network_monitor.alerts else []
    }
    
    return jsonify(status)

# Threat Hunting API Routes
@app.route('/api/threat_hunting/search', methods=['POST'])
def threat_hunting_search():
    """Search network logs"""
    try:
        filters = request.json or {}
        results = threat_hunting.search_logs(filters)
        statistics = threat_hunting.get_statistics()
        
        return jsonify({
            'results': results,
            'statistics': statistics
        })
    except Exception as e:
        logger.error(f"Error in threat hunting search: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat_hunting/event/<int:event_id>')
def get_event_details(event_id):
    """Get detailed information about a specific event"""
    try:
        # This would fetch from the database in a real implementation
        event = {'id': event_id, 'details': 'Event details would be here'}
        return jsonify(event)
    except Exception as e:
        logger.error(f"Error getting event details: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat_hunting/check_ioc', methods=['POST'])
def check_ioc():
    """Check an Indicator of Compromise"""
    try:
        data = request.json
        ioc_value = data.get('ioc_value')
        ioc_type = data.get('ioc_type', 'auto')
        
        result = threat_hunting.check_ioc(ioc_value, ioc_type)
        
        if result:
            return jsonify({
                'found': True,
                'threat_type': result.get('threat_type'),
                'source': result.get('source'),
                'confidence': result.get('confidence'),
                'first_seen': result.get('first_seen'),
                'description': result.get('description')
            })
        else:
            return jsonify({'found': False})
            
    except Exception as e:
        logger.error(f"Error checking IOC: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat_hunting/alerts')
def get_alerts():
    """Get security alerts"""
    try:
        investigated = request.args.get('investigated')
        investigated = investigated.lower() == 'true' if investigated else None
        
        alerts = threat_hunting.get_alerts(investigated=investigated)
        return jsonify(alerts)
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat_hunting/intel_stats')
def get_intel_stats():
    """Get threat intelligence statistics"""
    try:
        # This would get actual stats from the database
        stats = {
            'malware_domains': 1250,
            'phishing_domains': 890,
            'tor_exit_nodes': 1100,
            'last_update': threat_hunting.last_intel_update.isoformat() if threat_hunting.last_intel_update else None
        }
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting intel stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat_hunting/update_intel', methods=['POST'])
def update_threat_intel():
    """Update threat intelligence"""
    try:
        threat_hunting.update_threat_intelligence()
        return jsonify({'status': 'success', 'message': 'Threat intelligence updated'})
    except Exception as e:
        logger.error(f"Error updating threat intelligence: {e}")
        return jsonify({'error': str(e)}), 500

# Botnet Detection API Routes
@app.route('/api/botnet/stats')
def get_botnet_stats():
    """Get botnet detection statistics"""
    try:
        stats = botnet_detector.get_botnet_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting botnet stats: {e}")
        return jsonify({'error': str(e)}), 500

# WebSocket Events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info('Client connected')
    emit('status', {'monitoring_active': monitoring_active, 'stats': current_stats})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info('Client disconnected')

@socketio.on('request_stats')
def handle_stats_request():
    """Handle request for current statistics"""
    emit('stats_update', current_stats)

if __name__ == '__main__':
    logger.info("Starting Enhanced Network Anomaly Detection System...")
    
    # Import numpy for LSTM operations
    import numpy as np
    
    # Start the application
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
# End of file

