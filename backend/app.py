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

# Global components
feature_extractor = FeatureExtractor()
anomaly_detector = AnomalyDetector()


class NetworkMonitor:
    def __init__(self):
        self.capture = None
        self.is_running = False
        self.interface = "lo"
        self.alerts = []
        self.max_alerts = 100

    def start_monitoring(self, interface="lo"):
        """Start network monitoring"""
        if self.is_running:
            return  # prevent starting twice

        self.is_running = True
        self.interface = interface
        self.capture = TrafficCapture(interface)

        def run():
            for packet in self.capture.capture_packets():
                features = feature_extractor.extract(packet)
                if features is None:
                    continue

                result = anomaly_detector.predict(features)
                if result.get("anomaly"):
                    alert = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "details": result,
                    }
                    self.alerts.append(alert)
                    if len(self.alerts) > self.max_alerts:
                        self.alerts.pop(0)

                    socketio.emit("new_alert", alert)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_running = False
        if self.capture:
            self.capture.stop()
        logger.info("Monitoring stopped")

    def get_alerts(self):
        """Return collected alerts"""
        return self.alerts


# Instantiate monitor
monitor = NetworkMonitor()


# -------------------------
# Flask routes
# -------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    return jsonify(monitor.get_alerts())


@app.route("/api/start", methods=["POST"])
def start():
    data = request.json or {}
    interface = data.get("interface", "lo")
    monitor.start_monitoring(interface)
    return jsonify({"status": "monitoring started", "interface": interface})


@app.route("/api/stop", methods=["POST"])
def stop():
    monitor.stop_monitoring()
    return jsonify({"status": "monitoring stopped"})


# -------------------------
# Main entry point
# -------------------------
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
