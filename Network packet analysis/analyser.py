from scapy.all import sniff, IP
import threading, time
import queue

packet_queue = queue.Queue()
packet_id = 0

def packet_handler(packet):
    global packet_id
    packet_id += 1
    timestamp = time.strftime("%H:%M:%S", time.localtime())

    proto = "OTHER"
    size = len(packet)
    src, dst = "?", "?"
    info = ""

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        info = packet.summary()

    pkt = {
        "id": packet_id,
        "timestamp": timestamp,
        "source": src,
        "destination": dst,
        "protocol": proto,
        "size": size,
        "info": info,
        "score": round(size % 100 / 10, 2)  # dummy anomaly score
    }

    packet_queue.put(pkt)

def start_sniffer(iface=None):
    sniff(prn=packet_handler, store=False, iface=iface)

def run_sniffer_background():
    thread = threading.Thread(target=start_sniffer, daemon=True)
    thread.start()
