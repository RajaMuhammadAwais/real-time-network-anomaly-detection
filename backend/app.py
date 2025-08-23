"""
Main Flask Application for Network Traffic Anomaly Detection
Provides REST API and real-time WebSocket communication
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time
import json
from datetime import datetime
import logging
import os
import sys

# Add the backend directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from traffic_capture import TrafficCapture
from feature_extraction import FeatureExtractor
from anomaly_detector import AnomalyDetector

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, template_folder='../frontend', static_folder='../frontend/static')
app.config['SECRET_KEY'] = 'network_anomaly_detector_secret_key'

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
traffic_capture = None
feature_extractor = FeatureExtractor()
anomaly_detector = AnomalyDetector()
monitoring_thread = None
is_monitoring = False

class NetworkMonitor:
    def __init__(self):
        self.capture = None
        self.is_running = False
        self.alerts = []
        self.max_alerts = 100
        
    def start_monitoring(self, interface='lo'): 
    """Start network monitoring"""
    if self.is_running:
        return  # prevent starting twice

    self.is_running = True
    self.interface = interface
    # your capture/monitoring logic here
