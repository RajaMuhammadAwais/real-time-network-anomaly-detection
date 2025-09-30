"""
Main Flask entry-point that runs the enhanced application.
This delegates to enhanced_app.py where all APIs and detectors are implemented.
"""

import logging

# Reuse the enhanced application components
from enhanced_app import app, socketio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logger.info("Starting Enhanced Network Anomaly Detection Flask app...")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
