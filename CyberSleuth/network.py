from flask import Flask, render_template, jsonify,request
from flask_sock import Sock
from scapy.all import AsyncSniffer, IP
import threading
import queue
import time
import random
import json

app = Flask(__name__)
sock = Sock(app)

packet_id = 0
packet_queue = queue.Queue()
sniffer = None        # Global sniffer object
sniffing = False      # Control flag

stats = {
    "totalPackets": 0,
    "packetsPerSecond": 0,
    "anomalies": 0,
    "dataVolume": 0,
    "uniqueIPs": set(),
    "protocolDistribution": {},
    "topSources": []
}

IP_PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

def packet_handler(packet):
    global packet_id, stats
    packet_id += 1
    timestamp = time.time()

    proto = "Other"
    size = len(packet)
    src = "?"
    dst = "?"
    info = ""
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto_num = packet[IP].proto
        proto = IP_PROTO_MAP.get(proto_num, str(proto_num))
        info = packet.summary()

    pkt = {
        "id": packet_id,
        "timestamp": timestamp,
        "sourceIp": src,
        "destinationIp": dst,
        "protocol": proto,
        "size": size,
        "info": info,
        "anomalyScore": round(size % 100 / 100, 2)
    }
    packet_queue.put(pkt)
    stats["totalPackets"] += 1
    stats["dataVolume"] += size
    stats["anomalies"] += 1 if pkt["anomalyScore"] > 0.7 else 0
    stats["uniqueIPs"].update([src, dst])
    stats["protocolDistribution"][proto] = stats["protocolDistribution"].get(proto, 0) + 1
    stats["topSources"].append({"ip": src, "count": 1})

@app.route("/")
def index():
    return render_template("index.html")

sessions = {}
next_session_id = 1

@app.route("/api/sessions", methods=["POST"])
def create_session():
    global next_session_id
    data = request.get_json()
    session_id = next_session_id
    next_session_id += 1

    session = {
        "id": session_id,
        "name": data.get("name", f"Session {session_id}"),
        "startTime": None,
        "endTime": None
    }
    sessions[session_id] = session

    return jsonify(session), 201

@app.route("/api/sessions/<int:sid>/start", methods=["POST"])
def start_capture(sid):
    global sniffer, sniffing, stats, packet_id  # Also clear data here if needed
    if not sniffing:
        # Optionally reset stats and packet_id
        stats = {
            "totalPackets": 0,
            "packetsPerSecond": 0,
            "anomalies": 0,
            "dataVolume": 0,
            "uniqueIPs": set(),
            "protocolDistribution": {},
            "topSources": []
        }
        packet_id = 0
        with packet_queue.mutex:
            packet_queue.queue.clear()
        sniffer = AsyncSniffer(prn=packet_handler, store=False)
        sniffer.start()
        sniffing = True
    return jsonify({"result": "started"})

@app.route("/api/sessions/<int:sid>/stop", methods=["POST"])
def stop_capture(sid):
    global sniffer, sniffing
    if sniffing and sniffer is not None:
        sniffer.stop()
        sniffer = None
        sniffing = False
    return jsonify({"result": "stopped"})

@sock.route("/ws")
def ws(ws):
    while True:
        try:
            while not packet_queue.empty():
                pkt = packet_queue.get()
                ws.send(json.dumps({"type": "packet", "data": pkt}))

            stats_data = {
                "totalPackets": stats["totalPackets"],
                "packetsPerSecond": random.randint(5, 50),
                "anomalies": stats["anomalies"],
                "dataVolume": f"{stats['dataVolume']//1024} KB",
                "uniqueIPs": len(stats["uniqueIPs"]),
                "protocolDistribution": stats["protocolDistribution"],
                "topSources": stats["topSources"][-5:]
            }
            ws.send(json.dumps({"type": "stats", "data": stats_data}))
            time.sleep(2)
        except Exception as e:
            print("WebSocket closed:", e)
            break

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
