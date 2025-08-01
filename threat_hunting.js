// Threat Hunting Interface JavaScript

class ThreatHuntingInterface {
    constructor() {
        this.currentPage = 1;
        this.resultsPerPage = 25;
        this.totalResults = 0;
        this.currentResults = [];
        
        this.init();
    }
    
    init() {
        this.bindEventListeners();
        this.loadAlerts();
        this.loadThreatIntelStats();
        this.setDefaultTimeRange();
    }
    
    bindEventListeners() {
        // Search functionality
        document.getElementById('search-btn').addEventListener('click', () => {
            this.performSearch();
        });
        
        document.getElementById('clear-btn').addEventListener('click', () => {
            this.clearFilters();
        });
        
        document.getElementById('export-btn').addEventListener('click', () => {
            this.exportResults();
        });
        
        // IOC checker
        document.getElementById('check-ioc-btn').addEventListener('click', () => {
            this.checkIOC();
        });
        
        // Enter key support for IOC input
        document.getElementById('ioc-value').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.checkIOC();
            }
        });
        
        // Pagination
        document.getElementById('prev-page').addEventListener('click', () => {
            if (this.currentPage > 1) {
                this.currentPage--;
                this.displayResults();
            }
        });
        
        document.getElementById('next-page').addEventListener('click', () => {
            const totalPages = Math.ceil(this.totalResults / this.resultsPerPage);
            if (this.currentPage < totalPages) {
                this.currentPage++;
                this.displayResults();
            }
        });
        
        document.getElementById('results-per-page').addEventListener('change', (e) => {
            this.resultsPerPage = parseInt(e.target.value);
            this.currentPage = 1;
            this.displayResults();
        });
        
        // Alerts
        document.getElementById('refresh-alerts').addEventListener('click', () => {
            this.loadAlerts();
        });
        
        document.getElementById('show-investigated').addEventListener('change', () => {
            this.loadAlerts();
        });
        
        // Threat intelligence
        document.getElementById('update-intel').addEventListener('click', () => {
            this.updateThreatIntelligence();
        });
        
        // Modal
        document.querySelector('.close').addEventListener('click', () => {
            this.closeModal();
        });
        
        window.addEventListener('click', (e) => {
            const modal = document.getElementById('detail-modal');
            if (e.target === modal) {
                this.closeModal();
            }
        });
    }
    
    setDefaultTimeRange() {
        // Set default time range to last 24 hours
        const now = new Date();
        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        
        document.getElementById('start-time').value = this.formatDateTimeLocal(yesterday);
        document.getElementById('end-time').value = this.formatDateTimeLocal(now);
    }
    
    formatDateTimeLocal(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        
        return `${year}-${month}-${day}T${hours}:${minutes}`;
    }
    
    async performSearch() {
        this.showLoading(true);
        
        try {
            const filters = this.getSearchFilters();
            
            const response = await fetch('/api/threat_hunting/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(filters)
            });
            
            if (response.ok) {
                const data = await response.json();
                this.currentResults = data.results || [];
                this.totalResults = this.currentResults.length;
                this.currentPage = 1;
                
                this.displayResults();
                this.updateStatistics(data.statistics);
                this.showNotification('Search completed successfully', 'success');
            } else {
                this.showNotification('Error performing search', 'error');
            }
        } catch (error) {
            console.error('Search error:', error);
            this.showNotification('Error performing search', 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    getSearchFilters() {
        const filters = {};
        
        const srcIp = document.getElementById('src-ip').value.trim();
        if (srcIp) filters.src_ip = srcIp;
        
        const dstIp = document.getElementById('dst-ip').value.trim();
        if (dstIp) filters.dst_ip = dstIp;
        
        const protocol = document.getElementById('protocol').value;
        if (protocol) filters.protocol = protocol;
        
        const port = document.getElementById('port').value;
        if (port) filters.port = parseInt(port);
        
        const attackType = document.getElementById('attack-type').value;
        if (attackType) filters.attack_type = attackType;
        
        const startTime = document.getElementById('start-time').value;
        if (startTime) filters.start_time = startTime;
        
        const endTime = document.getElementById('end-time').value;
        if (endTime) filters.end_time = endTime;
        
        const threatScore = document.getElementById('threat-score').value;
        if (threatScore) filters.min_threat_score = parseFloat(threatScore);
        
        return filters;
    }
    
    displayResults() {
        const tbody = document.getElementById('results-tbody');
        const startIndex = (this.currentPage - 1) * this.resultsPerPage;
        const endIndex = startIndex + this.resultsPerPage;
        const pageResults = this.currentResults.slice(startIndex, endIndex);
        
        if (pageResults.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="no-results">No results found</td></tr>';
        } else {
            tbody.innerHTML = pageResults.map(result => this.createResultRow(result)).join('');
        }
        
        // Update pagination info
        const totalPages = Math.ceil(this.totalResults / this.resultsPerPage);
        document.getElementById('results-count').textContent = `${this.totalResults} results found`;
        document.getElementById('page-info').textContent = `Page ${this.currentPage} of ${totalPages}`;
        
        // Update pagination buttons
        document.getElementById('prev-page').disabled = this.currentPage <= 1;
        document.getElementById('next-page').disabled = this.currentPage >= totalPages;
    }
    
    createResultRow(result) {
        const timestamp = new Date(result.timestamp).toLocaleString();
        const threatScoreClass = this.getThreatScoreClass(result.threat_score);
        const attackTypeClass = result.attack_type.replace('_', '');
        
        return `
            <tr>
                <td>${timestamp}</td>
                <td>${result.src_ip || 'N/A'}</td>
                <td>${result.dst_ip || 'N/A'}</td>
                <td>${result.protocol || 'N/A'}</td>
                <td>${result.src_port || 'N/A'}:${result.dst_port || 'N/A'}</td>
                <td><span class="attack-type ${attackTypeClass}">${result.attack_type}</span></td>
                <td><span class="threat-score ${threatScoreClass}">${(result.threat_score || 0).toFixed(2)}</span></td>
                <td>
                    <button class="btn btn-small" onclick="threatHunting.showEventDetails(${result.id})">
                        Details
                    </button>
                </td>
            </tr>
        `;
    }
    
    getThreatScoreClass(score) {
        if (score >= 0.7) return 'high';
        if (score >= 0.4) return 'medium';
        return 'low';
    }
    
    async showEventDetails(eventId) {
        try {
            const response = await fetch(`/api/threat_hunting/event/${eventId}`);
            if (response.ok) {
                const event = await response.json();
                this.displayEventModal(event);
            } else {
                this.showNotification('Error loading event details', 'error');
            }
        } catch (error) {
            console.error('Error loading event details:', error);
            this.showNotification('Error loading event details', 'error');
        }
    }
    
    displayEventModal(event) {
        const detailsContainer = document.getElementById('event-details');
        
        const details = [
            { label: 'Event ID', value: event.id },
            { label: 'Timestamp', value: new Date(event.timestamp).toLocaleString() },
            { label: 'Source IP', value: event.src_ip || 'N/A' },
            { label: 'Destination IP', value: event.dst_ip || 'N/A' },
            { label: 'Source Port', value: event.src_port || 'N/A' },
            { label: 'Destination Port', value: event.dst_port || 'N/A' },
            { label: 'Protocol', value: event.protocol || 'N/A' },
            { label: 'Packet Size', value: event.packet_size || 'N/A' },
            { label: 'Flags', value: event.flags || 'N/A' },
            { label: 'Attack Type', value: event.attack_type || 'N/A' },
            { label: 'Threat Score', value: (event.threat_score || 0).toFixed(3) },
            { label: 'Payload Hash', value: event.payload_hash || 'N/A' }
        ];
        
        detailsContainer.innerHTML = details.map(detail => `
            <div class="detail-item">
                <span class="detail-label">${detail.label}:</span>
                <span class="detail-value">${detail.value}</span>
            </div>
        `).join('');
        
        // Add DPI results if available
        if (event.dpi_results) {
            try {
                const dpiResults = JSON.parse(event.dpi_results);
                if (dpiResults.threats_detected && dpiResults.threats_detected.length > 0) {
                    detailsContainer.innerHTML += `
                        <div class="detail-item">
                            <span class="detail-label">DPI Threats:</span>
                            <span class="detail-value">${dpiResults.threats_detected.map(t => t.type).join(', ')}</span>
                        </div>
                    `;
                }
            } catch (e) {
                console.error('Error parsing DPI results:', e);
            }
        }
        
        // Add LSTM prediction if available
        if (event.lstm_prediction) {
            try {
                const lstmPrediction = JSON.parse(event.lstm_prediction);
                detailsContainer.innerHTML += `
                    <div class="detail-item">
                        <span class="detail-label">LSTM Prediction:</span>
                        <span class="detail-value">${lstmPrediction.attack_type} (${(lstmPrediction.confidence * 100).toFixed(1)}%)</span>
                    </div>
                `;
            } catch (e) {
                console.error('Error parsing LSTM prediction:', e);
            }
        }
        
        document.getElementById('detail-modal').style.display = 'block';
    }
    
    closeModal() {
        document.getElementById('detail-modal').style.display = 'none';
    }
    
    async checkIOC() {
        const iocValue = document.getElementById('ioc-value').value.trim();
        const iocType = document.getElementById('ioc-type').value;
        
        if (!iocValue) {
            this.showNotification('Please enter an IOC value', 'warning');
            return;
        }
        
        this.showLoading(true);
        
        try {
            const response = await fetch('/api/threat_hunting/check_ioc', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    ioc_value: iocValue,
                    ioc_type: iocType
                })
            });
            
            if (response.ok) {
                const result = await response.json();
                this.displayIOCResult(result);
            } else {
                this.showIOCError('Error checking IOC');
            }
        } catch (error) {
            console.error('IOC check error:', error);
            this.showIOCError('Error checking IOC');
        } finally {
            this.showLoading(false);
        }
    }
    
    displayIOCResult(result) {
        const resultContainer = document.getElementById('ioc-result');
        
        if (result.found) {
            resultContainer.className = 'ioc-result found';
            resultContainer.innerHTML = `
                <h4>⚠️ Threat Detected</h4>
                <p><strong>Type:</strong> ${result.threat_type}</p>
                <p><strong>Source:</strong> ${result.source}</p>
                <p><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</p>
                <p><strong>First Seen:</strong> ${new Date(result.first_seen).toLocaleString()}</p>
                <p><strong>Description:</strong> ${result.description}</p>
            `;
        } else {
            resultContainer.className = 'ioc-result not-found';
            resultContainer.innerHTML = `
                <h4>✅ No Threat Found</h4>
                <p>This IOC is not found in our threat intelligence database.</p>
            `;
        }
    }
    
    showIOCError(message) {
        const resultContainer = document.getElementById('ioc-result');
        resultContainer.className = 'ioc-result error';
        resultContainer.innerHTML = `
            <h4>❌ Error</h4>
            <p>${message}</p>
        `;
    }
    
    clearFilters() {
        document.getElementById('src-ip').value = '';
        document.getElementById('dst-ip').value = '';
        document.getElementById('protocol').value = '';
        document.getElementById('port').value = '';
        document.getElementById('attack-type').value = '';
        document.getElementById('threat-score').value = '';
        this.setDefaultTimeRange();
        
        // Clear results
        this.currentResults = [];
        this.totalResults = 0;
        this.displayResults();
        this.updateStatistics({});
        
        this.showNotification('Filters cleared', 'success');
    }
    
    updateStatistics(stats) {
        document.getElementById('total-events').textContent = stats.total_events || 0;
        document.getElementById('unique-sources').textContent = stats.unique_sources || 0;
        document.getElementById('threats-found').textContent = stats.threats_found || 0;
        document.getElementById('avg-threat-score').textContent = (stats.avg_threat_score || 0).toFixed(2);
    }
    
    async loadAlerts() {
        try {
            const showInvestigated = document.getElementById('show-investigated').checked;
            const response = await fetch(`/api/threat_hunting/alerts?investigated=${showInvestigated}`);
            
            if (response.ok) {
                const alerts = await response.json();
                this.displayAlerts(alerts);
            } else {
                this.showNotification('Error loading alerts', 'error');
            }
        } catch (error) {
            console.error('Error loading alerts:', error);
            this.showNotification('Error loading alerts', 'error');
        }
    }
    
    displayAlerts(alerts) {
        const container = document.getElementById('alerts-container');
        
        if (alerts.length === 0) {
            container.innerHTML = '<div class="no-alerts">No alerts found</div>';
            return;
        }
        
        container.innerHTML = alerts.map(alert => `
            <div class="alert-item ${alert.investigated ? 'investigated' : ''}">
                <div class="alert-header">
                    <span class="alert-type">${alert.alert_type}</span>
                    <span class="alert-severity ${alert.severity.toLowerCase()}">${alert.severity}</span>
                    <span class="alert-time">${new Date(alert.timestamp).toLocaleString()}</span>
                </div>
                <div class="alert-description">${alert.description}</div>
                <div class="alert-ips">
                    ${alert.src_ip} → ${alert.dst_ip}
                </div>
            </div>
        `).join('');
    }
    
    async loadThreatIntelStats() {
        try {
            const response = await fetch('/api/threat_hunting/intel_stats');
            if (response.ok) {
                const stats = await response.json();
                this.displayThreatIntelStats(stats);
            }
        } catch (error) {
            console.error('Error loading threat intel stats:', error);
        }
    }
    
    displayThreatIntelStats(stats) {
        document.getElementById('malware-count').textContent = stats.malware_domains || 0;
        document.getElementById('phishing-count').textContent = stats.phishing_domains || 0;
        document.getElementById('tor-count').textContent = stats.tor_exit_nodes || 0;
        
        if (stats.last_update) {
            document.getElementById('last-update').textContent = 
                `Last update: ${new Date(stats.last_update).toLocaleString()}`;
        }
    }
    
    async updateThreatIntelligence() {
        this.showLoading(true);
        
        try {
            const response = await fetch('/api/threat_hunting/update_intel', {
                method: 'POST'
            });
            
            if (response.ok) {
                this.showNotification('Threat intelligence updated successfully', 'success');
                this.loadThreatIntelStats();
            } else {
                this.showNotification('Error updating threat intelligence', 'error');
            }
        } catch (error) {
            console.error('Error updating threat intelligence:', error);
            this.showNotification('Error updating threat intelligence', 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    exportResults() {
        if (this.currentResults.length === 0) {
            this.showNotification('No results to export', 'warning');
            return;
        }
        
        // Convert results to CSV
        const headers = ['Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Source Port', 'Dest Port', 'Attack Type', 'Threat Score'];
        const csvContent = [
            headers.join(','),
            ...this.currentResults.map(result => [
                new Date(result.timestamp).toISOString(),
                result.src_ip || '',
                result.dst_ip || '',
                result.protocol || '',
                result.src_port || '',
                result.dst_port || '',
                result.attack_type || '',
                result.threat_score || 0
            ].join(','))
        ].join('\n');
        
        // Download CSV file
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `threat_hunting_results_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        this.showNotification('Results exported successfully', 'success');
    }
    
    showLoading(show) {
        const overlay = document.getElementById('loading-overlay');
        overlay.style.display = show ? 'flex' : 'none';
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
}

// Initialize threat hunting interface when DOM is loaded
let threatHunting;
document.addEventListener('DOMContentLoaded', () => {
    threatHunting = new ThreatHuntingInterface();
});

