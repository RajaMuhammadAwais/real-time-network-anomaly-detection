# Network Traffic Anomaly Detection with Real-Time Dashboard
<!-- badges:start -->
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/Python-3.11-blue.svg)
![Version](https://img.shields.io/badge/Version-0.0.1-blue.svg)
<!-- badges:end -->

A comprehensive network security monitoring system that captures real-time network traffic, detects anomalies using machine learning, and provides a web-based dashboard for visualization and alerting.

## 🚀 Features

- **Real-time Network Traffic Capture**: Uses Scapy to capture and analyze network packets in real-time
- **Machine Learning Anomaly Detection**: Employs Isolation Forest algorithm to detect suspicious network behavior
- **Interactive Web Dashboard**: Modern, responsive web interface with real-time updates
- **Attack Type Detection**: Identifies specific attack patterns including DoS, Port Scanning, and unusual traffic patterns
- **Real-time Alerts**: Instant notifications when anomalies or attacks are detected
- **Traffic Visualization**: Charts and graphs showing network statistics and trends
- **Protocol Analysis**: Breakdown of network protocols and traffic patterns

## 🏗️ Architecture

The system consists of three main components:

1. **Backend (Python/Flask)**
   - Traffic capture using Scapy
   - Feature extraction from network packets
   - Machine learning-based anomaly detection
   - REST API and WebSocket communication

2. **Frontend (HTML/CSS/JavaScript)**
   - Real-time dashboard with Chart.js visualizations
   - WebSocket client for live updates
   - Responsive design for desktop and mobile

3. **Machine Learning Pipeline**
   - Feature engineering from network traffic
   - Isolation Forest for anomaly detection
   - Attack pattern recognition

## 📋 Prerequisites

- Python 3.11 or higher
- Network interface access (may require sudo for packet capture)
- Modern web browser with JavaScript enabled

## 🛠️ Installation

### 1. Clone or Download the Project

```bash
# If you have the project files, navigate to the project directory
cd to project
```

### 2. Create Virtual Environment

```bash
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install Flask Flask-SocketIO scapy pyshark scikit-learn pandas
```

### 4. Verify Installation

```bash
python test_backend.py
```

## 🚀 Quick Start

### 1. Start the Application

```bash
# Navigate to the backend directory
cd backend

# Activate virtual environment
source ../venv/bin/activate

# Start the Flask application
python app.py
```

The application will start on `http://localhost:5000`

### 2. Access the Dashboard

Open your web browser and navigate to:
```
http://localhost:5000
```

### 3. Start Monitoring

1. Select your network interface from the dropdown (default: loopback)
2. Click "Start Monitoring" to begin traffic capture
3. View real-time traffic statistics and anomaly detection results

## 📊 Dashboard Features

### Control Panel
- **Network Interface Selection**: Choose which network interface to monitor
- **Start/Stop Monitoring**: Control traffic capture
- **Model Retraining**: Retrain the anomaly detection model with new data

### Real-Time Visualizations
- **Traffic Overview**: Line chart showing packet flow over time
- **Protocol Distribution**: Pie chart of network protocols (TCP, UDP, ICMP)
- **Network Statistics**: Key metrics including packet count, unique IPs, and traffic volume

### Anomaly Detection
- **Status Indicator**: Visual indicator of current network health
- **Threat Level**: Current threat assessment (Low, Medium, High)
- **Confidence Score**: ML model confidence in predictions

### Alerts System
- **Real-time Alerts**: Instant notifications of detected anomalies
- **Attack Type Classification**: Identification of specific attack patterns
- **Recommendations**: Suggested actions for detected threats

## 🔧 Configuration

### Network Interface Selection

The application supports monitoring different network interfaces:

- **Loopback (lo)**: For testing and development
- **Ethernet (eth0)**: For wired network monitoring
- **WiFi (wlan0)**: For wireless network monitoring

### Machine Learning Model

The system uses an Isolation Forest algorithm with the following default parameters:

- **Contamination**: 0.1 (10% expected anomaly rate)
- **Estimators**: 100 trees
- **Features**: 13 extracted features including packet statistics, protocol ratios, and temporal patterns

### Feature Engineering

The system extracts the following features from network traffic:

1. **Basic Statistics**
   - Packet count
   - Unique source/destination IPs
   - Average packet size
   - Protocol distribution

2. **Temporal Features**
   - Inter-arrival times
   - Traffic patterns over time

3. **Connection Features**
   - Unique connections
   - Packets per connection

4. **Attack Indicators**
   - Port scan detection
   - DoS attack patterns
   - Unusual traffic behaviors

## 🛡️ Security Considerations

### Permissions

Network packet capture typically requires elevated privileges:

```bash
# Run with sudo if needed
sudo python app.py
```

### Network Access

The application binds to `0.0.0.0:5000` to allow external access. In production:

- Use a reverse proxy (nginx)
- Enable HTTPS/TLS
- Implement authentication
- Configure firewall rules

### Data Privacy

- Network traffic data is stored in memory only
- No persistent storage of captured packets
- Consider data retention policies for alerts

## 🧪 Testing

### Run Unit Tests

```bash
python test_backend.py
```

### Test Coverage

The test suite covers:
- Feature extraction functionality
- Anomaly detection algorithms
- Model training and prediction
- End-to-end pipeline integration

### Manual Testing

1. Start the application
2. Generate network traffic (web browsing, file downloads)
3. Verify dashboard updates in real-time
4. Test alert generation with unusual traffic patterns

## 📈 Performance Optimization

### Memory Management

- Packet buffer limited to 1000 packets
- Automatic cleanup of old data
- Efficient data structures for real-time processing

### CPU Optimization

- Background thread for packet capture
- Asynchronous WebSocket communication
- Optimized feature extraction algorithms

### Network Performance

- Minimal impact on network performance
- Configurable capture filters
- Efficient packet processing pipeline

## 🔍 Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Solution: Run with sudo
   sudo python app.py
   ```

2. **Interface Not Found**
   ```bash
   # List available interfaces
   ip link show
   # or
   ifconfig
   ```

3. **Port Already in Use**
   ```bash
   # Find process using port 5000
   lsof -i :5000
   # Kill the process
   kill -9 <PID>
   ```

4. **WebSocket Connection Failed**
   - Check firewall settings
   - Verify browser JavaScript is enabled
   - Try different browser

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Performance Issues

- Reduce packet capture rate
- Increase monitoring interval
- Optimize feature extraction

## 🚀 Deployment

### Local Deployment

The application is designed for local network monitoring. For production deployment:

1. **Use Production WSGI Server**
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

2. **Configure Reverse Proxy**
   ```nginx
   server {
       listen 80;
       location / {
           proxy_pass http://localhost:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

3. **Enable HTTPS**
   ```bash
   # Use Let's Encrypt or configure SSL certificates
   certbot --nginx -d yourdomain.com
   ```

### Docker Deployment

Create a Dockerfile for containerized deployment:

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python", "backend/app.py"]
```

## 🔮 Future Enhancements

### Planned Features

1. **Advanced ML Models**
   - Deep learning for complex pattern recognition
   - Ensemble methods for improved accuracy
   - Online learning for adaptive detection

2. **Enhanced Visualizations**
   - Network topology mapping
   - Geographic IP visualization
   - Historical trend analysis

3. **Integration Capabilities**
   - SIEM system integration
   - Email/SMS notifications
   - API for external tools

4. **Advanced Analytics**
   - Behavioral analysis
   - Threat intelligence integration
   - Custom rule engine

### Scalability Improvements

- Distributed processing
- Database integration
- Cloud deployment options
- Multi-node monitoring

## 📝 License

This project is open source and available under the MIT License.

## 🤝 Contributing

We welcome contributions from developers, data scientists, security researchers, and DevOps engineers. Please read the full guidelines in [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request.

## 📞 Support

For support and questions:
- Check the troubleshooting section
- Review the documentation
- Open an issue on the project repository

---

**Note**: This system is designed for educational and research purposes. For production security monitoring, consider additional hardening and professional security tools.

