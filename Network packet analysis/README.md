# Network Traffic Analysis



## Features

- **Real-time packet visualization** with WebSocket connections
- **Interactive packet list** with filtering by protocol and IP address
- **Detailed packet inspection** with headers and payload analysis
- **Statistics dashboard** with traffic charts and protocol distribution
- **Session management** with start/stop controls and duration tracking
- **Export functionality** for captured data
- **Responsive design** that works on desktop and mobile


## Setup

1. Place all files in your web server directory
2. Ensure your Python scapy backend provides the following API endpoints:
   - `POST /api/sessions` - Create new session
   - `POST /api/sessions/:id/start` - Start packet capture
   - `POST /api/sessions/:id/stop` - Stop packet capture
   - `GET /api/sessions/:id/export` - Export session data
   - WebSocket endpoint at `/ws` for real-time updates

## WebSocket Message Format

The frontend expects WebSocket messages in this format:

```json
{
  "type": "packet",
  "data": {
    "id": "packet-id",
    "sessionId": "session-id",
    "timestamp": "2024-01-01T12:00:00.000Z",
    "sourceIp": "192.168.1.100",
    "destinationIp": "8.8.8.8",
    "protocol": "TCP",
    "size": 1500,
    "info": "HTTP GET request",
    "headers": {
      "frame": 1,
      "ethernet": "192.168.1.100 -> 8.8.8.8"
    },
    "payload": "GET / HTTP/1.1..."
  }
}
```

```json
{
  "type": "stats",
  "data": {
    "totalPackets": 1500,
    "packetsPerSecond": 25.3,
    "anomalies": 12,
    "dataVolume": "2.3 MB",
    "uniqueIPs": 45,
    "protocolDistribution": {
      "TCP": 800,
      "UDP": 500,
      "ICMP": 200
    },
    "topSources": [
      {"ip": "192.168.1.100", "count": 250},
      {"ip": "10.0.0.1", "count": 180}
    ]
  }
}
```

## Browser Compatibility

- Modern browsers with WebSocket support
- Chrome 16+, Firefox 11+, Safari 7+, Edge 12+

## Usage

1. Open `index.html` in your web browser
2. Click "Start" to begin packet capture
3. View real-time packets in the main list
4. Click on any packet to see detailed information
5. Use filters to narrow down the packet display
6. Monitor statistics and charts in the bottom dashboard
7. Click "Export PCAP" to download session data

## Customization

The interface can be customized by modifying:

- **Colors**: Edit CSS custom properties in `:root`
- **Layout**: Adjust grid layouts and responsive breakpoints
- **Features**: Add new packet analysis features in JavaScript
- **Styling**: Modify the dark theme or create light theme variants

