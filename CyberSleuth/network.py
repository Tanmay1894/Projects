import threading
import queue
import time
import json
import math
import pickle
import os
from collections import defaultdict, deque
from scapy.utils import wrpcap

import numpy as np
import pandas as pd
from flask import Flask, render_template, jsonify, request, Response, send_file
from flask_sock import Sock
from scapy.all import AsyncSniffer, IP, TCP, UDP

app = Flask(__name__)
sock = Sock(app)

# --- 1. Machine Learning Model & Feature Configuration ---
MODEL_PATH = 'random_forest_model.pkl'
SCALER_PATH = 'scaler.pkl'
model = None
scaler = None

# This list MUST be in the exact same order as the columns used for training the model.
# Transcribed from your provided image.
FEATURE_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1', # Note: Likely a duplicate column
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]
captured_packets = []


def load_ml_model():
    """Loads the ML model and scaler from disk."""
    global model, scaler
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        print(f"Loading model from {MODEL_PATH} and scaler from {SCALER_PATH}...")
        with open(MODEL_PATH, 'rb') as f_model, open(SCALER_PATH, 'rb') as f_scaler:
            model = pickle.load(f_model)
            scaler = pickle.load(f_scaler)
        print("Model and scaler loaded successfully.")
    else:
        print("--- WARNING: Model or scaler file not found. Anomaly scores will be 0. ---")
        print("Please ensure 'model.pkl' and 'scaler.pkl' are in the same directory.")

# --- Global State ---
sniffer = None
sniffing = False
flow_state = {}
sessions = {}
session_id_counter = 0
flow_id_counter = 0

completed_flows_queue = queue.Queue()
packet_count_since_last_stat = 0
last_stat_time = time.time()

# --- Configuration & Mappings ---
FLOW_TIMEOUT = 120  # Increased timeout for more accurate feature calculation
TCP_FIN_RST_TIMEOUT = 5
IP_PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

# --- Helper Functions ---
def get_service_name(port):
    services = {80: "http", 21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 443: "https"}
    return services.get(port, "-")

def safe_division(numerator, denominator):
    return numerator / denominator if denominator else 0

def calculate_std(values, mean):
    if len(values) < 2:
        return 0
    return math.sqrt(sum([(x - mean) ** 2 for x in values]) / (len(values) - 1))

# --- Core Packet & Flow Processing ---
def packet_handler(packet):

    global flow_id_counter, flow_state, packet_count_since_last_stat, captured_packets
    if not IP in packet: 
        return

    packet_count_since_last_stat += 1
    current_time = time.time()

    # Append raw packet for full capture PCAP save
    captured_packets.append(packet)

    # Basic packet info
    packet_size = len(packet)
    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    proto_num = packet[IP].proto
    proto_name = IP_PROTO_MAP.get(proto_num, "Other")

    src_port, dst_port, flags = None, None, None
    if TCP in packet:
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
        flags = packet[TCP].flags
    elif UDP in packet:
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport

    flow_tuple_forward = (src_ip, src_port, dst_ip, dst_port, proto_name)
    flow_tuple_backward = (dst_ip, dst_port, src_ip, src_port, proto_name)

    flow = flow_state.get(flow_tuple_forward) or flow_state.get(flow_tuple_backward)
    is_forward = True if flow_state.get(flow_tuple_forward) else False

    if not flow:
        flow_id_counter += 1
        flow = {
            "id": flow_id_counter, "flow_tuple": flow_tuple_forward,
            "srcip": src_ip, "dstip": dst_ip, "sport": src_port, "dsport": dst_port, "proto": proto_name,
            "packets": [], "start_time": current_time, "last_time": current_time, "has_fin_rst": False
        }
        flow_state[flow_tuple_forward] = flow

    flow["last_time"] = current_time
    
    # Store detailed packet info for feature calculation later
    packet_info = {
        "timestamp": current_time,
        "size": packet_size,
        "is_forward": is_forward,
        "header_len": packet[IP].ihl * 4 + (packet[TCP].dataofs * 4 if TCP in packet else 8),
        "flags": flags,
        "is_active_data": TCP in packet and len(packet[TCP].payload) > 0
    }
    
    # Capture initial window sizes
    if TCP in packet:
        if 'init_win_bytes_forward' not in flow and is_forward:
            flow['init_win_bytes_forward'] = packet[TCP].window
        if 'init_win_bytes_backward' not in flow and not is_forward:
            flow['init_win_bytes_backward'] = packet[TCP].window
    
    if flags and (flags.F or flags.R):
        flow["has_fin_rst"] = True

    flow["packets"].append(packet_info)


def calculate_and_predict_flow(flow):
    """
    The core function to calculate all 79 features for a completed flow
    and then use the ML model to predict its anomaly score.
    """
    # --- Feature Calculation ---
    features = {}
    packets = flow["packets"]
    if not packets: return None

    fwd_packets = [p for p in packets if p["is_forward"]]
    bwd_packets = [p for p in packets if not p["is_forward"]]
    
    # Durations and Timestamps
    features['Flow Duration'] = (flow["last_time"] - flow["start_time"]) * 1_000_000 # to microseconds

    all_ts = sorted([p['timestamp'] for p in packets])
    fwd_ts = sorted([p['timestamp'] for p in fwd_packets])
    bwd_ts = sorted([p['timestamp'] for p in bwd_packets])
    
    flow_iats = [j - i for i, j in zip(all_ts[:-1], all_ts[1:])]
    fwd_iats = [j - i for i, j in zip(fwd_ts[:-1], fwd_ts[1:])]
    bwd_iats = [j - i for i, j in zip(bwd_ts[:-1], bwd_ts[1:])]

    # Packet counts and lengths
    features['Total Fwd Packets'] = len(fwd_packets)
    features['Total Backward Packets'] = len(bwd_packets)
    
    fwd_pkt_lengths = [p['size'] for p in fwd_packets]
    bwd_pkt_lengths = [p['size'] for p in bwd_packets]
    all_pkt_lengths = fwd_pkt_lengths + bwd_pkt_lengths

    features['Total Length of Fwd Packets'] = sum(fwd_pkt_lengths)
    features['Total Length of Bwd Packets'] = sum(bwd_pkt_lengths)
    
    # Min, Max, Mean, Std for Packet Lengths
    features['Fwd Packet Length Max'] = max(fwd_pkt_lengths) if fwd_pkt_lengths else 0
    features['Fwd Packet Length Min'] = min(fwd_pkt_lengths) if fwd_pkt_lengths else 0
    features['Fwd Packet Length Mean'] = np.mean(fwd_pkt_lengths) if fwd_pkt_lengths else 0
    features['Fwd Packet Length Std'] = np.std(fwd_pkt_lengths) if len(fwd_pkt_lengths) > 1 else 0
    
    features['Bwd Packet Length Max'] = max(bwd_pkt_lengths) if bwd_pkt_lengths else 0
    features['Bwd Packet Length Min'] = min(bwd_pkt_lengths) if bwd_pkt_lengths else 0
    features['Bwd Packet Length Mean'] = np.mean(bwd_pkt_lengths) if bwd_pkt_lengths else 0
    features['Bwd Packet Length Std'] = np.std(bwd_pkt_lengths) if len(bwd_pkt_lengths) > 1 else 0

    features['Min Packet Length'] = min(all_pkt_lengths) if all_pkt_lengths else 0
    features['Max Packet Length'] = max(all_pkt_lengths) if all_pkt_lengths else 0
    features['Packet Length Mean'] = np.mean(all_pkt_lengths) if all_pkt_lengths else 0
    features['Packet Length Std'] = np.std(all_pkt_lengths) if len(all_pkt_lengths) > 1 else 0
    features['Packet Length Variance'] = np.var(all_pkt_lengths) if len(all_pkt_lengths) > 1 else 0

    # IAT Statistics
    for prefix, iats in [('Flow', flow_iats), ('Fwd', fwd_iats), ('Bwd', bwd_iats)]:
        iats_us = [i * 1_000_000 for i in iats]
        features[f'{prefix} IAT Mean'] = np.mean(iats_us) if iats_us else 0
        features[f'{prefix} IAT Std'] = np.std(iats_us) if len(iats_us) > 1 else 0
        features[f'{prefix} IAT Max'] = max(iats_us) if iats_us else 0
        features[f'{prefix} IAT Min'] = min(iats_us) if iats_us else 0
    
    features['Fwd IAT Total'] = sum(fwd_iats) * 1_000_000
    features['Bwd IAT Total'] = sum(bwd_iats) * 1_000_000

    # Rates
    duration_sec = features['Flow Duration'] / 1_000_000
    features['Flow Bytes/s'] = safe_division(sum(all_pkt_lengths), duration_sec)
    features['Flow Packets/s'] = safe_division(len(packets), duration_sec)
    features['Fwd Packets/s'] = safe_division(len(fwd_packets), duration_sec)
    features['Bwd Packets/s'] = safe_division(len(bwd_packets), duration_sec)

    # Flag Counts
    flags_all = [p['flags'] for p in packets if p['flags'] is not None]
    fwd_flags = [p['flags'] for p in fwd_packets if p['flags'] is not None]
    bwd_flags = [p['flags'] for p in bwd_packets if p['flags'] is not None]
    
    features['Fwd PSH Flags'] = sum(1 for f in fwd_flags if f.P)
    features['Bwd PSH Flags'] = sum(1 for f in bwd_flags if f.P)
    features['Fwd URG Flags'] = sum(1 for f in fwd_flags if f.U)
    features['Bwd URG Flags'] = sum(1 for f in bwd_flags if f.U)
    features['FIN Flag Count'] = sum(1 for f in flags_all if f.F)
    features['SYN Flag Count'] = sum(1 for f in flags_all if f.S)
    features['RST Flag Count'] = sum(1 for f in flags_all if f.R)
    features['PSH Flag Count'] = sum(1 for f in flags_all if f.P)
    features['ACK Flag Count'] = sum(1 for f in flags_all if f.A)
    features['URG Flag Count'] = sum(1 for f in flags_all if f.U)
    features['CWE Flag Count'] = sum(1 for f in flags_all if f.C)
    features['ECE Flag Count'] = sum(1 for f in flags_all if f.E)

    # Header Lengths and Segment Sizes
    features['Fwd Header Length'] = sum(p['header_len'] for p in fwd_packets)
    features['Bwd Header Length'] = sum(p['header_len'] for p in bwd_packets)
    features['Fwd Header Length.1'] = features['Fwd Header Length'] # Duplicate column

    features['Down/Up Ratio'] = safe_division(len(bwd_packets), len(fwd_packets))
    features['Average Packet Size'] = features['Packet Length Mean']
    features['Avg Fwd Segment Size'] = features['Fwd Packet Length Mean']
    features['Avg Bwd Segment Size'] = features['Bwd Packet Length Mean']
    
    # Subflow and Other Features
    features['Init_Win_bytes_forward'] = flow.get('init_win_bytes_forward', -1)
    features['Init_Win_bytes_backward'] = flow.get('init_win_bytes_backward', -1)
    features['act_data_pkt_fwd'] = sum(1 for p in fwd_packets if p['is_active_data'])
    min_fwd_header_len = min(p['header_len'] for p in fwd_packets) if fwd_packets else 0
    features['min_seg_size_forward'] = min_fwd_header_len

    # Subflows are typically 1-to-1 in this context
    features['Subflow Fwd Packets'] = len(fwd_packets)
    features['Subflow Fwd Bytes'] = sum(fwd_pkt_lengths)
    features['Subflow Bwd Packets'] = len(bwd_packets)
    features['Subflow Bwd Bytes'] = sum(bwd_pkt_lengths)
    
    # Placeholder features - not feasible to calculate from raw packets without ambiguity
    for key in ['Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
                'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
                'Active Mean', 'Active Std', 'Active Max', 'Active Min',
                'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']:
        features[key] = 0
        
    features['Destination Port'] = flow.get('dsport', 0)

    # --- Prediction ---
    score = 0.0
    if model and scaler:
        try:
            # Ensure features are in the correct order
            feature_vector = [features.get(col, 0) for col in FEATURE_COLUMNS]
            df = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)
            
            # Scale and predict
            scaled_features = scaler.transform(df)
            prediction_proba = model.predict_proba(scaled_features)
            
            # Score is the probability of the 'attack' class (usually index 1)
            score = prediction_proba[0][1] 
        except Exception as e:
            print(f"Error during prediction for flow {flow['id']}: {e}")
            score = 0.0 # Default to non-anomalous on error

    # --- Format for Frontend ---
    dur = duration_sec
    service = get_service_name(flow.get("dsport"))
    total_bytes = sum(all_pkt_lengths)
    info = f"Pkts: {len(fwd_packets)}+{len(bwd_packets)} | Dur: {dur:.2f}s"
    
    return {
        "id": flow["id"], "timestamp": flow["start_time"] * 1000,
        "sourceIp": flow["srcip"], "destinationIp": flow["dstip"],
        "protocol": flow["proto"], "size": total_bytes, "info": info,
        "anomalyScore": score,
        "headers": {"Source Port": flow.get("sport"), "Destination Port": flow.get("dsport"), "Service": service},
        "payload": "Payload data not inspected."
    }

def flow_monitor():
    while sniffing:
        flows_to_remove = []
        current_time = time.time()
        for flow_tuple, flow in list(flow_state.items()):
            timeout = TCP_FIN_RST_TIMEOUT if flow.get("has_fin_rst") else FLOW_TIMEOUT
            if current_time - flow["last_time"] > timeout:
                final_metrics = calculate_and_predict_flow(flow)
                if final_metrics:
                    completed_flows_queue.put(final_metrics)
                flows_to_remove.append(flow_tuple)
        
        for flow_tuple in flows_to_remove:
            if flow_tuple in flow_state: del flow_state[flow_tuple]
        time.sleep(1)

# --- Flask Routes & WebSocket (largely unchanged) ---
@app.route("/")
def home():
    return render_template("homepage.html")

@app.route("/network_packet_analyser")
def index():
    return render_template("index.html")

@app.route("/api/sessions", methods=["POST"])
def create_session():
    global session_id_counter
    session_id_counter += 1
    session_name = request.json.get("name", f"Session {session_id_counter}")
    
    session = {
        "id": session_id_counter,
        "name": session_name,
        "startTime": time.time() * 1000, # in milliseconds
        "endTime": None,
        "packets": [],
    }
    sessions[session_id_counter] = session
    return jsonify(session)

@app.route("/api/sessions/<int:sid>/start", methods=["POST"])
def start_capture(sid):
    global sniffer, sniffing, flow_state, flow_id_counter, packet_count_since_last_stat, last_stat_time, captured_packets

    if not sniffing:
        flow_state.clear()
        flow_id_counter = 0
        packet_count_since_last_stat = 0
        last_stat_time = time.time()
        captured_packets = []  # Clear packets list on start

        with completed_flows_queue.mutex:
            completed_flows_queue.queue.clear()

        sniffer = AsyncSniffer(prn=packet_handler, store=False)
        sniffer.start()
        sniffing = True
        threading.Thread(target=flow_monitor, daemon=True).start()
    return jsonify({"result": "started"})


@app.route("/api/sessions/<int:sid>/stop", methods=["POST"])
def stop_capture(sid):
    global sniffer, sniffing, captured_packets

    if sniffing and sniffer is not None:
        sniffer.stop()
        sniffing = False

        # Process remaining flows
        for flow in list(flow_state.values()):
            final_metrics = calculate_and_predict_flow(flow)
            if final_metrics:
                completed_flows_queue.put(final_metrics)
        flow_state.clear()

        os.makedirs("sessions", exist_ok=True)
        if captured_packets:
            wrpcap(f"sessions/session_{sid}.pcap", captured_packets)
        else:
            print("No packets captured to save.")

    return jsonify({"result": "stopped"})



@app.route("/api/sessions/<int:sid>/export.pcap", methods=["GET"])
def export_pcap(sid):
    pcap_path = f"sessions/session_{sid}.pcap"
    if not os.path.exists(pcap_path):
        return jsonify({"error": "PCAP file not available"}), 404
    return send_file(pcap_path, as_attachment=True, download_name=f"session-{sid}.pcap")

@sock.route("/ws")
def ws(ws):
    global packet_count_since_last_stat, last_stat_time
    session_flows = deque(maxlen=5000) # Use deque for efficient appends
    
    while True:
        try:
            while not completed_flows_queue.empty():
                flow = completed_flows_queue.get()
                session_flows.append(flow)
                ws.send(json.dumps({"type": "packet", "data": flow}))

            current_time = time.time()
            time_delta = current_time - last_stat_time
            if time_delta >= 2:
                pps = packet_count_since_last_stat / time_delta
                
                # Stats calculation (can be optimized if needed)
                anomalies = sum(1 for f in session_flows if f.get('anomalyScore', 0) > 0.7)
                unique_ips = len(set(f['sourceIp'] for f in session_flows) | set(f['destinationIp'] for f in session_flows))
                proto_dist = defaultdict(int)
                top_sources_agg = defaultdict(int)
                for f in session_flows:
                    proto_dist[f['protocol']] += 1
                    top_sources_agg[f['sourceIp']] += 1
                
                top_sources_list = [{"ip": ip, "count": count} for ip, count in sorted(top_sources_agg.items(), key=lambda i: i[1], reverse=True)[:5]]

                stats_data = {
                    "totalPackets": len(session_flows), "packetsPerSecond": round(pps, 1),
                    "anomalies": anomalies, "dataVolume": f"{(sum(f.get('size', 0) for f in session_flows) / 1024**2):.2f} MB",
                    "uniqueIPs": unique_ips, "protocolDistribution": dict(proto_dist), "topSources": top_sources_list
                }
                ws.send(json.dumps({"type": "stats", "data": stats_data}))
                
                packet_count_since_last_stat = 0; last_stat_time = current_time
            
            time.sleep(0.2)
        except Exception as e:
            print(f"WebSocket closed or error: {e}"); break

# Other routes like /api/sessions and /export remain unchanged
# ... (You can paste the old code for those routes here if needed) ...

if __name__ == "__main__":
    load_ml_model() # Load the model on startup
    app.run(debug=True, host="0.0.0.0", port=5000)
