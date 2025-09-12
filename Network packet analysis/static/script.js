class NetworkAnalysisApp {
    constructor() {
        this.websocket = null;
        this.isConnected = false;
        this.currentSession = null;
        this.packets = [];
        this.selectedPacket = null;
        this.protocolFilter = 'all';
        this.ipFilter = '';
        this.sessionStartTime = null;
        this.durationInterval = null;
        this.trafficData = Array(20).fill(0);
        
        this.initializeElements();
        this.bindEvents();
        this.connectWebSocket();
        this.createSession();
        this.initTrafficChart();
    }

    initializeElements() {
        // Buttons
        this.startBtn = document.getElementById('startBtn');
        this.stopBtn = document.getElementById('stopBtn');
        this.exportBtn = document.getElementById('exportBtn');
        this.clearBtn = document.getElementById('clearBtn');
        
        // Status elements
        this.statusIndicator = document.getElementById('statusIndicator');
        this.sessionDuration = document.getElementById('sessionDuration');
        this.totalPacketsEl = document.getElementById('totalPackets');
        this.packetsPerSecondEl = document.getElementById('packetsPerSecond');
        this.anomaliesEl = document.getElementById('anomalies');
        
        // Filters
        this.protocolFilterEl = document.getElementById('protocolFilter');
        this.ipFilterEl = document.getElementById('ipFilter');
        
        // Lists and content areas
        this.packetList = document.getElementById('packetList');
        this.emptyState = document.getElementById('emptyState');
        this.detailsContent = document.getElementById('detailsContent');
        this.connectionStatus = document.getElementById('connectionStatus');
        this.toastContainer = document.getElementById('toastContainer');
        
        // Stats
        this.statTotalPackets = document.getElementById('statTotalPackets');
        this.statDataVolume = document.getElementById('statDataVolume');
        this.statAnomalies = document.getElementById('statAnomalies');
        this.statUniqueIPs = document.getElementById('statUniqueIPs');
        this.topSources = document.getElementById('topSources');
        this.protocolChart = document.getElementById('protocolChart');
        this.trafficChart = document.getElementById('trafficChart');
        this.currentRate = document.getElementById('currentRate');
    }

    bindEvents() {
        this.startBtn.addEventListener('click', () => this.startCapture());
        this.stopBtn.addEventListener('click', () => this.stopCapture());
        this.exportBtn.addEventListener('click', () => this.exportData());
        this.clearBtn.addEventListener('click', () => this.clearData());
        
        this.protocolFilterEl.addEventListener('change', (e) => {
            this.protocolFilter = e.target.value;
            this.filterPackets();
        });
        
        this.ipFilterEl.addEventListener('input', (e) => {
            this.ipFilter = e.target.value;
            this.filterPackets();
        });
    }

    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        this.websocket = new WebSocket(wsUrl);
        
        this.websocket.onopen = () => {
            console.log('Connected to WebSocket');
            this.isConnected = true;
            this.connectionStatus.classList.add('hidden');
        };
        
        this.websocket.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.handleWebSocketMessage(message);
            } catch (error) {
                console.error('Failed to parse WebSocket message:', error);
            }
        };
        
        this.websocket.onclose = () => {
            console.log('Disconnected from WebSocket');
            this.isConnected = false;
            this.connectionStatus.classList.remove('hidden');
            // Attempt to reconnect after 3 seconds
            setTimeout(() => this.connectWebSocket(), 3000);
        };
        
        this.websocket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'packet':
                this.addPacket(message.data);
                break;
            case 'stats':
                this.updateStats(message.data);
                break;
            case 'session':
                this.updateSession(message.data);
                break;
        }
    }

    async createSession() {
        try {
            const response = await fetch('/api/sessions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: `Session ${new Date().toLocaleString()}`
                })
            });
            
            if (!response.ok) throw new Error('Failed to create session');
            
            this.currentSession = await response.json();
            this.exportBtn.disabled = false;
            this.showToast('Session Created', 'New session created successfully', 'success');
        } catch (error) {
            this.showToast('Error', 'Failed to create new session', 'error');
        }
    }

    async startCapture() {
        if (!this.currentSession) return;
        
        try {
            const response = await fetch(`/api/sessions/${this.currentSession.id}/start`, {
                method: 'POST'
            });
            
            if (!response.ok) throw new Error('Failed to start capture');
            
            this.statusIndicator.classList.add('active');
            this.startBtn.disabled = true;
            this.stopBtn.disabled = false;
            this.sessionStartTime = Date.now();
            this.startDurationTimer();
            this.showToast('Capture Started', 'Network packet capture has begun', 'success');
        } catch (error) {
            this.showToast('Error', 'Failed to start packet capture', 'error');
        }
    }

    async stopCapture() {
        if (!this.currentSession) return;
        
        try {
            const response = await fetch(`/api/sessions/${this.currentSession.id}/stop`, {
                method: 'POST'
            });
            
            if (!response.ok) throw new Error('Failed to stop capture');
            
            this.statusIndicator.classList.remove('active');
            this.startBtn.disabled = false;
            this.stopBtn.disabled = true;
            this.stopDurationTimer();
            this.showToast('Capture Stopped', 'Network packet capture has been stopped', 'success');
        } catch (error) {
            this.showToast('Error', 'Failed to stop packet capture', 'error');
        }
    }

    exportData() {
        if (!this.currentSession) return;
        
        const link = document.createElement('a');
        link.href = `/api/sessions/${this.currentSession.id}/export`;
        link.download = `session-${this.currentSession.id}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        this.showToast('Export Started', 'Session data export has begun', 'success');
    }

    clearData() {
        this.packets = [];
        this.selectedPacket = null;
        this.renderPacketList();
        this.renderPacketDetails();
        this.resetStats();
        this.showToast('Session Cleared', 'All packet data has been cleared', 'success');
    }

    addPacket(packetData) {
        const packet = {
            ...packetData,
            timestamp: new Date(packetData.timestamp),
            anomalyScore: packetData.anomalyScore || 0
        };
        
        this.packets.unshift(packet);
        
        // Keep only last 1000 packets
        if (this.packets.length > 1000) {
            this.packets = this.packets.slice(0, 1000);
        }
        
        this.filterPackets();
        this.updateTrafficChart(packet);
    }

    updateStats(stats) {
        this.totalPacketsEl.textContent = stats.totalPackets.toLocaleString();
        this.packetsPerSecondEl.textContent = stats.packetsPerSecond.toFixed(1);
        this.anomaliesEl.textContent = stats.anomalies.toString();
        
        this.statTotalPackets.textContent = stats.totalPackets.toLocaleString();
        this.statDataVolume.textContent = stats.dataVolume;
        this.statAnomalies.textContent = stats.anomalies.toString();
        this.statUniqueIPs.textContent = stats.uniqueIPs.toString();
        this.currentRate.textContent = stats.packetsPerSecond.toFixed(1);
        
        this.updateProtocolChart(stats.protocolDistribution);
        this.updateTopSources(stats.topSources);
    }

    updateSession(sessionData) {
        this.currentSession = {
            ...sessionData,
            startTime: new Date(sessionData.startTime),
            endTime: sessionData.endTime ? new Date(sessionData.endTime) : null
        };
    }

    filterPackets() {
        const filteredPackets = this.packets.filter(packet => {
            if (this.protocolFilter && this.protocolFilter !== 'all' && packet.protocol !== this.protocolFilter) {
                return false;
            }
            if (this.ipFilter && !packet.sourceIp.includes(this.ipFilter) && !packet.destinationIp.includes(this.ipFilter)) {
                return false;
            }
            return true;
        });
        
        this.renderPacketList(filteredPackets);
    }

    renderPacketList(packets = this.packets) {
        if (packets.length === 0) {
            this.emptyState.style.display = 'flex';
            this.packetList.innerHTML = '';
            this.packetList.appendChild(this.emptyState);
            return;
        }
        
        this.emptyState.style.display = 'none';
        
        const fragment = document.createDocumentFragment();
        
        packets.forEach((packet, index) => {
            const row = document.createElement('div');
            row.className = `packet-row ${this.selectedPacket?.id === packet.id ? 'selected' : ''}`;
            
            if (packet.anomalyScore > 0.7) {
                row.classList.add('anomaly-high');
            } else if (packet.anomalyScore > 0.5) {
                row.classList.add('anomaly-medium');
            }
            
            row.innerHTML = `
                <div class="packet-col">${index + 1}</div>
                <div class="packet-col" style="font-family: monospace; font-size: 0.75rem;">
                    ${this.formatTimestamp(packet.timestamp)}
                </div>
                <div class="packet-col" style="font-family: monospace; font-size: 0.75rem;">
                    ${packet.sourceIp}
                </div>
                <div class="packet-col" style="font-family: monospace; font-size: 0.75rem;">
                    ${packet.destinationIp}
                </div>
                <div class="packet-col">
                    <span class="protocol-tag protocol-${packet.protocol.toLowerCase()}">
                        ${packet.protocol}
                    </span>
                </div>
                <div class="packet-col" style="font-family: monospace; font-size: 0.75rem;">
                    ${packet.size.toLocaleString()}
                </div>
                <div class="packet-col" style="font-size: 0.75rem;">
                    ${packet.info || '-'}
                </div>
                <div class="packet-col">
                    <span class="${this.getScoreClass(packet.anomalyScore)}" style="font-size: 0.75rem;">
                        ${packet.anomalyScore.toFixed(2)}
                    </span>
                </div>
            `;
            
            row.addEventListener('click', () => {
                this.selectPacket(packet);
            });
            
            fragment.appendChild(row);
        });
        
        this.packetList.innerHTML = '';
        this.packetList.appendChild(fragment);
    }

    selectPacket(packet) {
        this.selectedPacket = packet;
        this.filterPackets(); // Re-render to update selection
        this.renderPacketDetails();
    }

    renderPacketDetails() {
        if (!this.selectedPacket) {
            this.detailsContent.innerHTML = `
                <div class="no-selection">
                    <div class="no-selection-icon">📋</div>
                    <p>Select a packet to view details</p>
                </div>
            `;
            return;
        }
        
        const packet = this.selectedPacket;
        const anomalyScore = packet.anomalyScore || 0;
        const isHighAnomaly = anomalyScore > 0.7;
        const isMediumAnomaly = anomalyScore > 0.5;
        
        let anomalyAlert = '';
        if (isHighAnomaly || isMediumAnomaly) {
            anomalyAlert = `
                <div class="anomaly-alert ${isHighAnomaly ? 'high' : 'medium'}">
                    <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                        <span style="margin-right: 0.5rem;">⚠️</span>
                        <span style="font-weight: 600;">
                            ${isHighAnomaly ? 'High Anomaly Score' : 'Medium Anomaly Score'}
                        </span>
                    </div>
                    <p style="font-size: 0.875rem; opacity: 0.8;">
                        ${isHighAnomaly ? 'Potential security threat detected.' : 'Unusual traffic pattern detected.'} 
                        Score: ${anomalyScore.toFixed(2)}
                    </p>
                </div>
            `;
        }
        
        let headersSection = '';
        if (packet.headers && typeof packet.headers === 'object') {
            const headerEntries = Object.entries(packet.headers)
                .map(([key, value]) => `<div><span style="color: var(--muted-foreground);">${key}:</span> ${value}</div>`)
                .join('');
            headersSection = `
                <div class="details-section">
                    <h4>Headers</h4>
                    <div class="code-block">${headerEntries}</div>
                </div>
            `;
        }
        
        let payloadSection = '';
        if (packet.payload) {
            payloadSection = `
                <div class="details-section">
                    <h4>Payload</h4>
                    <div class="code-block">${packet.payload}</div>
                </div>
            `;
        }
        
        let actionButtons = '';
        if (isHighAnomaly || isMediumAnomaly) {
            actionButtons = `
                <div class="action-buttons">
                    <button class="btn btn-danger" style="width: 100%;">
                        🚫 Block Source IP
                    </button>
                    <button class="btn btn-secondary" style="width: 100%;">
                        🛡️ Add to Whitelist
                    </button>
                </div>
            `;
        }
        
        this.detailsContent.innerHTML = `
            <div style="font-size: 0.875rem; color: var(--muted-foreground); margin-bottom: 1rem;">
                ID: <span style="font-family: monospace;">${packet.id}</span>
            </div>
            
            ${anomalyAlert}
            
            <div class="details-section">
                <h4>Basic Information</h4>
                <div class="detail-row">
                    <span class="detail-label">Timestamp:</span>
                    <span class="detail-value">${this.formatTimestamp(packet.timestamp, true)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Source IP:</span>
                    <span class="detail-value">${packet.sourceIp}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Destination IP:</span>
                    <span class="detail-value">${packet.destinationIp}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Protocol:</span>
                    <span class="protocol-tag protocol-${packet.protocol.toLowerCase()}">${packet.protocol}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Length:</span>
                    <span class="detail-value">${packet.size.toLocaleString()} bytes</span>
                </div>
                ${packet.info ? `
                    <div class="detail-row">
                        <span class="detail-label">Info:</span>
                        <span class="detail-value" style="font-size: 0.75rem;">${packet.info}</span>
                    </div>
                ` : ''}
            </div>
            
            ${headersSection}
            ${payloadSection}
            
            <div class="details-section">
                <h4>ML Analysis</h4>
                <div class="detail-row" style="align-items: center;">
                    <span class="detail-label">Anomaly Score:</span>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${anomalyScore * 100}%;"></div>
                        </div>
                        <span class="${this.getScoreClass(anomalyScore)}" style="font-family: monospace; font-size: 0.875rem;">
                            ${anomalyScore.toFixed(2)}
                        </span>
                    </div>
                </div>
                <div style="font-size: 0.75rem; color: var(--muted-foreground); margin-top: 0.5rem;">
                    <div><strong>Detection:</strong> ${
                        isHighAnomaly ? 'High threat probability' :
                        isMediumAnomaly ? 'Moderate anomaly detected' :
                        'Normal traffic pattern'
                    }</div>
                    <div style="margin-top: 0.25rem;"><strong>Confidence:</strong> ${(anomalyScore * 100).toFixed(1)}%</div>
                </div>
            </div>
            
            ${actionButtons}
        `;
    }

    updateProtocolChart(protocolDistribution) {
        const total = Object.values(protocolDistribution).reduce((sum, count) => sum + count, 0);
        
        if (total === 0) {
            this.protocolChart.innerHTML = '<div class="no-data">No data available</div>';
            return;
        }
        
        const protocolEntries = Object.entries(protocolDistribution)
            .sort(([, a], [, b]) => b - a)
            .map(([protocol, count]) => {
                const percentage = (count / total) * 100;
                return `
                    <div class="protocol-item">
                        <span>${protocol}</span>
                        <div class="protocol-progress">
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${percentage}%;"></div>
                            </div>
                            <span style="font-family: monospace; font-size: 0.75rem; width: 2rem; text-align: right;">
                                ${percentage.toFixed(0)}%
                            </span>
                        </div>
                    </div>
                `;
            })
            .join('');
        
        this.protocolChart.innerHTML = protocolEntries;
    }

    updateTopSources(topSources) {
        if (!topSources || topSources.length === 0) {
            this.topSources.innerHTML = '<div class="no-data">No data available</div>';
            return;
        }
        
        const sourcesHtml = topSources
            .map(source => `
                <div class="source-item">
                    <span class="source-ip">${source.ip}</span>
                    <span class="source-count">${source.count.toLocaleString()} pkts</span>
                </div>
            `)
            .join('');
        
        this.topSources.innerHTML = sourcesHtml;
    }

    updateTrafficChart(packet) {
        // Add current packet rate to traffic data
        this.trafficData.shift();
        this.trafficData.push(Math.floor(Math.random() * 50) + 10); // Mock rate
        
        const maxRate = Math.max(...this.trafficData);
        
        const barsHtml = this.trafficData
            .map(rate => {
                const height = maxRate > 0 ? (rate / maxRate) * 100 : 0;
                return `<div class="traffic-bar" style="height: ${height}%;" title="${rate} packets"></div>`;
            })
            .join('');
        
        this.trafficChart.innerHTML = barsHtml;
    }

    initTrafficChart() {
        this.updateTrafficChart();
    }

    resetStats() {
        this.totalPacketsEl.textContent = '0';
        this.packetsPerSecondEl.textContent = '0.0';
        this.anomaliesEl.textContent = '0';
        
        this.statTotalPackets.textContent = '0';
        this.statDataVolume.textContent = '0 MB';
        this.statAnomalies.textContent = '0';
        this.statUniqueIPs.textContent = '0';
        this.currentRate.textContent = '0.0';
        
        this.protocolChart.innerHTML = '<div class="no-data">No data available</div>';
        this.topSources.innerHTML = '<div class="no-data">No data available</div>';
        this.trafficData = Array(20).fill(0);
        this.updateTrafficChart();
    }

    startDurationTimer() {
        this.durationInterval = setInterval(() => {
            if (this.sessionStartTime) {
                const elapsed = Date.now() - this.sessionStartTime;
                const hours = Math.floor(elapsed / 3600000);
                const minutes = Math.floor((elapsed % 3600000) / 60000);
                const seconds = Math.floor((elapsed % 60000) / 1000);
                
                this.sessionDuration.textContent = 
                    `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            }
        }, 1000);
    }

    stopDurationTimer() {
        if (this.durationInterval) {
            clearInterval(this.durationInterval);
            this.durationInterval = null;
        }
    }

    formatTimestamp(timestamp, detailed = false) {
        const date = new Date(timestamp);
        if (detailed) {
            return date.toLocaleString('en-US', {
                hour12: false,
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                fractionalSecondDigits: 3
            });
        } else {
            return date.toLocaleTimeString('en-US', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                fractionalSecondDigits: 3
            });
        }
    }

    getScoreClass(score) {
        if (score > 0.7) return 'score-high';
        if (score > 0.5) return 'score-medium';
        return 'score-low';
    }

    showToast(title, description, type = 'success') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div class="toast-title">${title}</div>
            <div class="toast-description">${description}</div>
        `;
        
        this.toastContainer.appendChild(toast);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 5000);
        
        // Remove on click
        toast.addEventListener('click', () => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        });
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new NetworkAnalysisApp();
});