# Network Anomaly Detection System
<!-- badges:start -->
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/Python-3.11-blue.svg)
![Version](https://img.shields.io/badge/Version-0.0.1-blue.svg)
<!-- badges:end -->

A modern, full-stack network security monitoring platform with real-time simulation/capture, multiple detection engines (ML + deep learning + DPI + botnet analysis), a live web dashboard, and a threat hunting interface.

## Features

- Real-time monitoring with Socket.IO updates and live charts
- Multi-engine detection:
  - Isolation Forest anomaly detection
  - LSTM sequence-based deep learning detector
  - Deep Packet Inspection (DPI) for payload signatures
  - Botnet communication heuristics
- Threat Hunting Engine:
  - IOC checks, alert storage, intel updates (simulated)
  - Search and statistics APIs
- Interactive Dashboard (frontend/index.html)
  - Start/Stop Monitoring
  - Retrain Model
  - Interface selection
  - Real-time charts and alerts
- Protocol and IP analytics (top sources/destinations, protocol distribution)
- Docker support with docker-compose

## Architecture

1. Backend (Flask + Flask-SocketIO)
   - Entry point: backend/app.py (delegates to backend/enhanced_app.py)
   - WebSockets via Socket.IO
   - REST API for control and status
   - Detectors:
     - anomaly_detector.py (IsolationForest)
     - deep_learning_detector.py (LSTMAttackDetector)
     - deep_packet_inspector.py (DPI)
     - botnet_detector.py (heuristics)
   - Feature extraction: feature_extraction.py
   - Threat hunting: threat_hunting.py

2. Frontend (HTML/CSS/JS)
   - Dashboard: frontend/index.html, script.js, style.css
   - Threat Hunting UI: frontend/threat_hunting.html, threat_hunting.js, threat_hunting.css
   - Charts: Chart.js
   - Live updates: Socket.IO

3. Optional Capture (Scapy/PyShark)
   - Simulated traffic in enhanced_app.py for local testing
   - Real capture can be integrated via traffic_capture.py (may require elevated privileges)

## Prerequisites

- Python 3.11+
- Modern browser (Chrome/Firefox)
- Optional: Docker and docker-compose

## Installation

### Using Python

```bash
python3.11 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Using Docker

```bash
docker-compose up --build
```

This builds and runs the backend at http://localhost:5000.

## Running

### Option A: Local Python

```bash
source venv/bin/activate
python backend/app.py
```

- Backend listens on http://localhost:5000
- Dashboard: http://localhost:5000
- Threat Hunting: http://localhost:5000/threat_hunting.html

### Option B: Docker

```bash
docker-compose up
```

- Backend: http://localhost:5000
- Logs are mounted at ./logs

## Configuration (Frontend runtime)

If the frontend is served from a different origin than the backend, set runtime parameters so the JS knows where to call:

- URL parameters:
  - ?apiBase=http://localhost:5000&socketUrl=http://localhost:5000
- Or via localStorage:
  - localStorage.setItem('apiBase', 'http://localhost:5000')
  - localStorage.setItem('socketUrl', 'http://localhost:5000')

Example:
```
http://your-frontend-host/index.html?apiBase=http://localhost:5000&socketUrl=http://localhost:5000
```

## Dashboard Overview

- Controls:
  - Network Interface: lo, eth0, wlan0 (select)
  - Start Monitoring: POST /api/start_monitoring
  - Stop Monitoring: POST /api/stop_monitoring
  - Retrain Model: POST /api/train_model
- Status:
  - Connection indicator (Socket.IO)
  - Monitoring state, total packets, alerts
- Charts:
  - Real-Time Traffic (line)
  - Protocol Distribution (doughnut)
- Anomaly Status:
  - Circle indicator (Normal/Anomaly)
  - Confidence score and threat level
- Alerts:
  - Recent alerts with severity, confidence, recommendations
- Top Source IPs:
  - Top talkers list

## API Endpoints

Core:
- POST /api/start_monitoring
  - Body: { "interface": "lo" } (optional; defaults to "lo")
- POST /api/stop_monitoring
- GET  /api/status
- POST /api/train_model

Threat Hunting:
- POST /api/threat_hunting/search
- GET  /api/threat_hunting/alerts?investigated=true|false
- GET  /api/threat_hunting/intel_stats
- POST /api/threat_hunting/update_intel
- POST /api/threat_hunting/check_ioc
  - Body: { "ioc_value": "...", "ioc_type": "auto" }

Botnet:
- GET  /api/botnet/stats

WebSocket:
- event: connect/disconnect
- emitted: status, stats_update, packet_update, new_alert

## Troubleshooting

- Buttons don’t work / Disconnected indicator:
  - Ensure backend is running at http://localhost:5000
  - If hosting frontend elsewhere, set apiBase/socketUrl as above
  - Check browser devtools (Network tab) for /api/* request failures
- Permission errors (for real capture):
  - Use sudo or grant NET_ADMIN/CAP_NET_RAW if capturing inside Docker
- Port 5000 already in use:
  ```bash
  lsof -i :5000
  kill -9 <PID>
  ```
- CORS:
  - Flask-CORS is enabled; most issues stem from incorrect base URL

## Development Notes

- Simulation is enabled by default for ease of testing (enhanced_app.py)
- LSTM is trained on startup if not already trained (lightweight demo config)
- Packet/alert buffers are size-limited to avoid memory bloat

## Machine Learning Algorithms Used

- Isolation Forest (scikit-learn)
  - Purpose: traditional anomaly detection over engineered features
  - Usage: anomaly_detector.py predicts is_anomaly and anomaly_score
  - Strengths: robust to outliers, no heavy training data requirement
  - Limitations: less effective on complex temporal patterns without sequence context
- LSTM-based Sequence Model (Keras/TensorFlow)
  - Purpose: detect sequential attack patterns (e.g., slow port scans, beaconing)
  - Usage: deep_learning_detector.py (LSTMAttackDetector) trains/predicts over sliding windows
  - Input: feature vectors aggregated into sequences of length SEQUENCE_LENGTH
  - Output: { is_attack, confidence, attack_type }
- Deep Packet Inspection (rules/signatures)
  - Purpose: payload/content-based indicators (SQLi strings, suspicious headers)
  - Usage: deep_packet_inspector.py returns threats_detected with types and details
  - Note: signature/rule-based, complementary to ML; not strictly a learning algorithm
- Botnet Communication Heuristics
  - Purpose: detect beaconing, unusual destinations/ports, low-and-slow patterns
  - Usage: botnet_detector.py returns is_suspicious, threat_score, indicators
  - Note: heuristic scoring acts like a lightweight model; pairs well with ML outputs
- Feature Engineering
  - Source: feature_extraction.py
  - Examples: protocol counts/ratios, packet sizes, unique IP counts, temporal/spatial stats
  - These features feed Isolation Forest and form the basis of LSTM sequences

## Future Enhancements

- Advanced Deep Learning
  - Transformer-based time series models for long-range dependencies
  - Temporal Convolutional Networks (TCN) for efficient sequence modeling
  - Autoencoders/VAEs for unsupervised anomaly detection
- Graph-Based Detection
  - Graph neural networks (GNNs) over communication graphs (IP/port nodes, edges)
  - Community detection for lateral movement and C2 patterns
- Online/Continual Learning
  - Incremental updates to Isolation Forest or streaming anomaly detectors
  - Drift detection and adaptive thresholds
- Semi-supervised and Weakly-supervised Methods
  - Leverage small labeled sets + large unlabeled traffic
  - Pseudo-labeling and consistency regularization
- Threat Intelligence Integration
  - Live feeds (MISP, Open Threat Intel) with scoring/fusion
  - IOC enrichment and automated blocklists
- Explainability and Analyst UX
  - SHAP/feature importance for anomaly rationale
  - Rich alert context: packet traces, related sessions, timelines
- MLOps and Reproducibility
  - Versioned datasets/models, experiment tracking
  - Scheduled retraining, evaluation dashboards
- Real Capture and Scale
  - High-performance capture (DPDK/libpcap) and batching
  - Distributed deployment, message bus (Kafka), and long-term storage
- Integrations
  - SIEM connectors, alert forwarding (email/Slack/Webhooks)
  - Firewall/IDS orchestration hooks

## License

MIT

## Contributing

PRs welcome. Please follow standard Python/JS styling and keep changes minimal, tested, and focused.

## Support

Open an issue or check Troubleshooting above.

