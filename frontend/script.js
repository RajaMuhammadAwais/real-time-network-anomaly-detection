// Network Traffic Anomaly Detection Dashboard JavaScript

// Simple runtime config to make local development work when frontend and backend run on different ports.
// You can set ?apiBase=http://localhost:5000&socketUrl=http://localhost:5000 in the URL,
// or set localStorage.apiBase / localStorage.socketUrl.
const RuntimeConfig = (() => {
    const url = new URL(window.location.href);
    const apiBase = url.searchParams.get('apiBase') || localStorage.getItem('apiBase') || '';
    const socketUrl = url.searchParams.get('socketUrl') || localStorage.getItem('socketUrl') || '';
    const base = apiBase || '';
    const sock = socketUrl || '';
    const withBase = (path) => (base ? `${base}${path}` : path);
    return { apiBase: base, socketUrl: sock, withBase };
})();

class NetworkDashboard {
    constructor() {
        this.socket = null;
        this.trafficChart = null;
        this.protocolChart = null;
        this.isConnected = false;
        this.isMonitoring = false;
        
        this.init();
    }
    
    init() {
        this.initializeSocketIO();
        this.initializeCharts();
        this.bindEventListeners();
        this.updateStatus();
    }
    
    initializeSocketIO() {
        try {
            this.socket = RuntimeConfig.socketUrl ? io(RuntimeConfig.socketUrl) : io();
        } catch (e) {
            this.showNotification('Socket connection failed. Ensure backend is running.', 'error');
            return;
        }
        
        this.socket.on('connect', () => {
            this.isConnected = true;
            this.updateConnectionStatus();
            this.showNotification('Connected to server', 'success');
            this.socket.emit('request_stats');
        });
        
        this.socket.on('disconnect', () => {
            this.isConnected = false;
            this.updateConnectionStatus();
            this.showNotification('Disconnected from server', 'error');
        });
        
        // Support enhanced_app.py event names
        this.socket.on('status', (data) => {
            // Normalize payload for UI
            this.updateMonitoringStatus({
                is_monitoring: !!data.monitoring_active,
                total_packets: data.stats?.total_packets || 0,
                total_alerts: data.stats?.anomalies_detected || 0
            });
        });
        
        this.socket.on('packet_update', (data) => {
            // Normalize packet_update payload to the expected shape
            const normalized = {
                stats: {
                    total_packets: data.stats?.total_packets || 0,
                    unique_src_ips: Object.keys(data.stats?.top_sources || {}).length,
                    unique_dst_ips: Object.keys(data.stats?.top_destinations || {}).length,
                    avg_packet_size: data.packet_data?.packet_size || data.packet_data?.size || 0,
                    total_traffic: 0, // not tracked; leave 0
                    protocols: {
                        '6': data.stats?.protocols?.TCP || 0,  // TCP
                        '17': data.stats?.protocols?.UDP || 0, // UDP
                        '1': data.stats?.protocols?.ICMP || 0  // ICMP
                    },
                    top_src_ips: data.stats?.top_sources || {}
                },
                features: {
                    packet_count: data.stats?.total_packets || 0
                },
                prediction: {
                    is_anomaly: !!data.analysis?.is_anomaly,
                    confidence: data.analysis?.threat_score || 0
                },
                analysis: {
                    severity: (data.stats?.threat_level || 'Low')
                }
            };
            this.updateTrafficData(normalized);
        });
        
        // Backward compatibility with older event names if used
        this.socket.on('status_update', (data) => {
            this.updateMonitoringStatus(data);
        });
        
        this.socket.on('traffic_update', (data) => {
            this.updateTrafficData(data);
        });
        
        this.socket.on('new_alert', (alert) => {
            this.addAlert(alert);
            this.showNotification(`New Alert: ${alert.type || alert.alert_type || 'Alert'}`, 'warning');
        });
    }
    
    initializeCharts() {
        // Traffic Chart
        const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
        this.trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets per Minute',
                    data: [],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
        
        // Protocol Chart
        const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
        this.protocolChart = new Chart(protocolCtx, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        '#667eea',
                        '#764ba2',
                        '#f093fb',
                        '#f5576c'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }
    
    bindEventListeners() {
        // Start monitoring button
        document.getElementById('start-monitoring').addEventListener('click', () => {
            this.startMonitoring();
        });

        // Stop monitoring button
        document.getElementById('stop-monitoring').addEventListener('click', () => {
            this.stopMonitoring();
        });
        
        // Retrain model button
        document.getElementById('retrain-model').addEventListener('click', () => {
            this.retrainModel();
        });
    }
    
    async startMonitoring() {
        const interface = document.getElementById('interface-select').value;
        this.showLoading(true);
        
        try {
            const response = await fetch(RuntimeConfig.withBase('/api/start_monitoring'), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ interface })
            });
            
            const result = await response.json();
            
            if ((result.status || '').toLowerCase() === 'success') {
                this.showNotification(result.message || 'Monitoring started', 'success');
                this.isMonitoring = true;
                this.updateButtonStates();
            } else {
                this.showNotification(result.message || 'Failed to start monitoring', 'error');
            }
        } catch (error) {
            this.showNotification('Error starting monitoring', 'error');
            console.error('Error:', error);
        } finally {
            this.showLoading(false);
        }
    }
    
    async stopMonitoring() {
        this.showLoading(true);
        
        try {
            const response = await fetch(RuntimeConfig.withBase('/api/stop_monitoring'), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const result = await response.json();
            
            if ((result.status || '').toLowerCase() === 'success') {
                this.showNotification(result.message || 'Monitoring stopped', 'success');
                this.isMonitoring = false;
                this.updateButtonStates();
            } else {
                this.showNotification(result.message || 'Failed to stop monitoring', 'error');
            }
        } catch (error) {
            this.showNotification('Error stopping monitoring', 'error');
            console.error('Error:', error);
        } finally {
            this.showLoading(false);
        }
    }
    
    async retrainModel() {
        this.showLoading(true);
        
        try {
            const response = await fetch(RuntimeConfig.withBase('/api/train_model'), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const result = await response.json();
            
            if ((result.status || '').toLowerCase() === 'success') {
                this.showNotification(result.message || 'Models retrained', 'success');
            } else {
                this.showNotification(result.message || 'Failed to retrain models', 'error');
            }
        } catch (error) {
            this.showNotification('Error retraining model', 'error');
            console.error('Error:', error);
        } finally {
            this.showLoading(false);
        }
    }
    
    updateConnectionStatus() {
        const statusDot = document.getElementById('connection-status');
        const statusText = document.getElementById('connection-text');
        
        if (this.isConnected) {
            statusDot.className = 'status-dot online';
            statusText.textContent = 'Connected';
        } else {
            statusDot.className = 'status-dot offline';
            statusText.textContent = 'Disconnected';
        }
    }
    
    updateMonitoringStatus(data) {
        this.isMonitoring = data.is_monitoring;
        
        document.getElementById('monitoring-status').textContent = 
            data.is_monitoring ? 'Running' : 'Stopped';
        document.getElementById('total-packets').textContent = data.total_packets || 0;
        document.getElementById('total-alerts').textContent = data.total_alerts || 0;
        
        this.updateButtonStates();
    }
    
    updateButtonStates() {
        const startBtn = document.getElementById('start-monitoring');
        const stopBtn = document.getElementById('stop-monitoring');
        
        startBtn.disabled = this.isMonitoring;
        stopBtn.disabled = !this.isMonitoring;
    }
    
    updateTrafficData(data) {
        // Update statistics
        if (data.stats) {
            document.getElementById('packet-count').textContent = data.stats.total_packets || 0;
            document.getElementById('unique-ips').textContent = 
                (data.stats.unique_src_ips || 0) + (data.stats.unique_dst_ips || 0);
            document.getElementById('avg-packet-size').textContent = 
                Math.round(data.stats.avg_packet_size || 0);
            document.getElementById('total-traffic').textContent = 
                Math.round((data.stats.total_traffic || 0) / 1024);
        }
        
        // Update traffic chart
        if (this.trafficChart) {
            const now = new Date().toLocaleTimeString();
            const packetCount = data.features?.packet_count || 0;
            
            this.trafficChart.data.labels.push(now);
            this.trafficChart.data.datasets[0].data.push(packetCount);
            
            // Keep only last 20 data points
            if (this.trafficChart.data.labels.length > 20) {
                this.trafficChart.data.labels.shift();
                this.trafficChart.data.datasets[0].data.shift();
            }
            
            this.trafficChart.update('none');
        }
        
        // Update protocol chart
        if (this.protocolChart && data.stats?.protocols) {
            const protocols = data.stats.protocols;
            const tcpCount = protocols['6'] || 0;  // TCP
            const udpCount = protocols['17'] || 0; // UDP
            const icmpCount = protocols['1'] || 0; // ICMP
            const otherCount = Object.values(protocols).reduce((sum, count) => sum + count, 0) - 
                              tcpCount - udpCount - icmpCount;
            
            this.protocolChart.data.datasets[0].data = [tcpCount, udpCount, icmpCount, otherCount];
            this.protocolChart.update('none');
        }
        
        // Update anomaly status
        if (data.prediction) {
            this.updateAnomalyStatus(data.prediction, data.analysis);
        }
        
        // Update top IPs
        if (data.stats?.top_src_ips) {
            this.updateTopIPs(data.stats.top_src_ips);
        }
    }
    
    updateAnomalyStatus(prediction, analysis) {
        const statusCircle = document.getElementById('anomaly-status');
        const anomalyText = document.getElementById('anomaly-text');
        const confidenceScore = document.getElementById('confidence-score');
        const threatLevel = document.getElementById('threat-level');
        
        if (prediction.is_anomaly) {
            statusCircle.className = 'status-circle danger';
            anomalyText.textContent = 'Anomaly Detected';
        } else {
            statusCircle.className = 'status-circle normal';
            anomalyText.textContent = 'Normal Traffic';
        }
        
        confidenceScore.textContent = `Confidence: ${(prediction.confidence * 100).toFixed(1)}%`;
        
        if (analysis) {
            threatLevel.textContent = analysis.severity || 'Low';
            threatLevel.className = `threat-badge ${(analysis.severity || 'low').toLowerCase()}`;
        }
    }
    
    updateTopIPs(topIPs) {
        const container = document.getElementById('top-ips');
        
        if (Object.keys(topIPs).length === 0) {
            container.innerHTML = '<div class="no-data">No data available</div>';
            return;
        }
        
        const ipItems = Object.entries(topIPs)
            .slice(0, 5)
            .map(([ip, count]) => `
                <div class="ip-item">
                    <span class="ip-address">${ip}</span>
                    <span class="ip-count">${count}</span>
                </div>
            `).join('');
        
        container.innerHTML = ipItems;
    }
    
    addAlert(alert) {
        const container = document.getElementById('alerts-container');
        
        // Remove "no alerts" message if present
        const noAlerts = container.querySelector('.no-alerts');
        if (noAlerts) {
            noAlerts.remove();
        }
        
        const alertElement = document.createElement('div');
        alertElement.className = `alert-item ${alert.severity.toLowerCase()}`;
        
        const attackTypes = alert.attack_types.length > 0 ? 
            alert.attack_types.join(', ') : 'Unknown';
        
        const recommendations = alert.recommendations.length > 0 ?
            alert.recommendations.join('. ') : 'Monitor the situation';
        
        alertElement.innerHTML = `
            <div class="alert-header">
                <span class="alert-title">${alert.type}</span>
                <span class="alert-time">${new Date(alert.timestamp).toLocaleTimeString()}</span>
            </div>
            <div class="alert-details">
                <strong>Attack Types:</strong> ${attackTypes}<br>
                <strong>Severity:</strong> ${alert.severity}<br>
                <strong>Confidence:</strong> ${(alert.confidence * 100).toFixed(1)}%
            </div>
            <div class="alert-recommendations">
                <strong>Recommendations:</strong> ${recommendations}
            </div>
        `;
        
        // Add to top of container
        container.insertBefore(alertElement, container.firstChild);
        
        // Keep only last 10 alerts
        const alerts = container.querySelectorAll('.alert-item');
        if (alerts.length > 10) {
            alerts[alerts.length - 1].remove();
        }
    }
    
    showNotification(message, type = 'info') {
        const container = document.getElementById('notification-container');
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        container.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);
    }
    
    showLoading(show) {
        const overlay = document.getElementById('loading-overlay');
        overlay.style.display = show ? 'flex' : 'none';
    }
    
    async updateStatus() {
        try {
            const response = await fetch(RuntimeConfig.withBase('/api/status'));
            const data = await response.json();
            // Normalize enhanced_app.py status payload
            if (data && data.stats) {
                this.updateMonitoringStatus({
                    is_monitoring: !!data.monitoring_active,
                    total_packets: data.stats?.total_packets || 0,
                    total_alerts: data.stats?.anomalies_detected || 0
                });
                // Also push a synthetic traffic update to seed charts
                const normalized = {
                    stats: {
                        total_packets: data.stats?.total_packets || 0,
                        unique_src_ips: Object.keys(data.stats?.top_sources || {}).length,
                        unique_dst_ips: Object.keys(data.stats?.top_destinations || {}).length,
                        avg_packet_size: 0,
                        total_traffic: 0,
                        protocols: {
                            '6': data.stats?.protocols?.TCP || 0,
                            '17': data.stats?.protocols?.UDP || 0,
                            '1': data.stats?.protocols?.ICMP || 0
                        },
                        top_src_ips: data.stats?.top_sources || {}
                    },
                    features: {
                        packet_count: data.stats?.total_packets || 0
                    },
                    prediction: {
                        is_anomaly: false,
                        confidence: 0
                    },
                    analysis: {
                        severity: (data.stats?.threat_level || 'Low')
                    }
                };
                this.updateTrafficData(normalized);
            } else {
                this.updateMonitoringStatus(data);
            }
        } catch (error) {
            console.error('Error fetching status:', error);
            this.showNotification('Backend not reachable. Set apiBase parameter or start backend.', 'error');
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new NetworkDashboard();
});

