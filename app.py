from flask import Flask, jsonify, render_template, request, Response
import csv, os, threading, json
from datetime import datetime
from collections import deque

app = Flask(__name__)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

SNIFF_MODE = True

if SNIFF_MODE:
    from sniffer import sniffer as packet_sniffer

monitoring_active = False
packets           = []
displayed_index   = 0
lock              = threading.Lock()
event_log         = deque(maxlen=100)

PORT_SERVICES = {
    20:"FTP-DATA", 
    21:"FTP", 22:"SSH", 23:"TELNET", 25:"SMTP",
    53:"DNS", 67:"DHCP", 68:"DHCP", 69:"TFTP", 80:"HTTP",
    110:"POP3", 119:"NNTP", 123:"NTP", 135:"RPC", 137:"NetBIOS",
    138:"NetBIOS", 139:"NetBIOS", 143:"IMAP", 161:"SNMP", 162:"SNMP",
    179:"BGP", 194:"IRC", 389:"LDAP", 443:"HTTPS", 445:"SMB",
    465:"SMTPS", 514:"SYSLOG", 515:"LPD", 587:"SMTP", 636:"LDAPS",
    993:"IMAPS", 995:"POP3S", 1080:"SOCKS", 1194:"OpenVPN",
    1433:"MSSQL", 1521:"Oracle", 1723:"PPTP", 3000:"Dev-Server",
    3306:"MySQL", 3389:"RDP", 4444:"Metasploit", 5000:"Flask",
    5432:"PostgreSQL", 5900:"VNC", 6379:"Redis", 6881:"BitTorrent",
    8080:"HTTP-Alt", 8443:"HTTPS-Alt", 8888:"Jupyter",
    9200:"Elasticsearch", 27017:"MongoDB", 32400:"Plex"
}

def load_dataset():
    global packets
    packets = []
    csv_path = os.path.join(os.path.dirname(__file__), "dataset.csv")
    if not os.path.exists(csv_path):
        log_event("dataset.csv not found!", "error")
        return
    with open(csv_path, newline="", encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f)):
            protocol = row.get("Protocol", "").upper().strip()
            try: src_port = int(row.get("Source_Port") or 0)
            except ValueError: src_port = 0
            try: dst_port = int(row.get("Destination_Port") or 0)
            except ValueError: dst_port = 0
            try: packet_size = int(row.get("Packet_Size") or 0)
            except ValueError: packet_size = 64
            if protocol == "ICMP":
                service = "ICMP-PING"
            else:
                service = (PORT_SERVICES.get(dst_port) or
                           PORT_SERVICES.get(src_port) or
                           row.get("Service", "UNKNOWN"))
            packets.append({
                "id":          i + 1,
                "time":        row.get("Time", ""),
                "src_ip":      row.get("Source_IP", ""),
                "dst_ip":      row.get("Destination_IP", ""),
                "protocol":    protocol,
                "src_port":    src_port,
                "dst_port":    dst_port,
                "packet_size": packet_size,
                "service":     service,
                "ttl":         row.get("TTL", ""),
                "flags":       row.get("Flags", "---"),
            })
    log_event(f"Dataset loaded: {len(packets)} packets ready.", "info")

def log_event(message, level="info"):
    event_log.append({
        "time":    datetime.now().strftime("%H:%M:%S"),
        "message": message,
        "level":   level
    })

def compute_stats(packet_list):
    if not packet_list:
        return {"total":0,"tcp":0,"udp":0,"icmp":0,"avg_size":0,
                "total_bytes":0,"top_src_ip":"N/A","top_dst_ip":"N/A","top_service":"N/A"}
    tcp  = sum(1 for p in packet_list if p["protocol"] == "TCP")
    udp  = sum(1 for p in packet_list if p["protocol"] == "UDP")
    icmp = sum(1 for p in packet_list if p["protocol"] == "ICMP")
    total_bytes = sum(p["packet_size"] for p in packet_list)
    avg_size    = round(total_bytes / len(packet_list), 2)
    sc, dc, svc = {}, {}, {}
    for p in packet_list:
        sc[p["src_ip"]]   = sc.get(p["src_ip"],   0) + 1
        dc[p["dst_ip"]]   = dc.get(p["dst_ip"],   0) + 1
        svc[p["service"]] = svc.get(p["service"],  0) + 1
    return {"total":len(packet_list),"tcp":tcp,"udp":udp,"icmp":icmp,
            "avg_size":avg_size,"total_bytes":total_bytes,
            "top_src_ip":  max(sc,  key=sc.get)  if sc  else "N/A",
            "top_dst_ip":  max(dc,  key=dc.get)  if dc  else "N/A",
            "top_service": max(svc, key=svc.get) if svc else "N/A"}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start", methods=["POST"])
def start_monitoring():
    global monitoring_active, displayed_index
    with lock:
        monitoring_active = True
        displayed_index   = 0
    if SNIFF_MODE:
        packet_sniffer.start()
        log_event("Live sniffing started", "success")
    else:
        log_event("Monitoring started", "success")
    return jsonify({"status": "started"})

@app.route("/stop", methods=["POST"])
def stop_monitoring():
    global monitoring_active
    with lock:
        monitoring_active = False
    if SNIFF_MODE:
        packet_sniffer.stop()
    log_event("Monitoring stopped", "warning")
    return jsonify({"status": "stopped"})

@app.route("/packets")
def get_packets():
    global displayed_index
    since_id = int(request.args.get("since_id", 0))

    if SNIFF_MODE:
        with packet_sniffer.lock:
            snapshot = list(packet_sniffer.packets)
        total_captured = len(snapshot)
        result = [p for p in snapshot if p["id"] > since_id]
    else:
        with lock:
            if monitoring_active:
                displayed_index = min(displayed_index + 10, len(packets))
            visible = packets[:displayed_index]
        total_captured = displayed_index
        result = [p for p in visible if p["id"] > since_id]

    return jsonify({"packets": result, "total_captured": total_captured,
                    "monitoring": monitoring_active})

@app.route("/stats")
def get_stats():
    if SNIFF_MODE:
        with packet_sniffer.lock:
            visible = list(packet_sniffer.packets)
    else:
        with lock:
            visible = packets[:displayed_index]
    return jsonify(compute_stats(visible))

@app.route("/logs")
def get_logs():
    return jsonify({"logs": list(event_log)})

@app.route("/save", methods=["POST"])
def save_packets():
    data = request.get_json(silent=True)
    if data and "packets" in data:
        to_save = data["packets"]
    elif SNIFF_MODE:
        with packet_sniffer.lock:
            to_save = list(packet_sniffer.packets)
    else:
        with lock:
            to_save = list(packets[:displayed_index])

    if not to_save:
        return jsonify({"error": "No packets to save"}), 400
    filename  = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    save_path = os.path.join(os.path.dirname(__file__), "saves", filename)
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    with open(save_path, "w") as f:
        json.dump(to_save, f, indent=2)
    log_event(f"Saved {len(to_save)} packets to {filename}", "success")
    return jsonify({"status": "saved", "filename": filename, "count": len(to_save)})

@app.route("/saves")
def list_saves():
    saves_dir = os.path.join(os.path.dirname(__file__), "saves")
    if not os.path.exists(saves_dir):
        return jsonify({"files": []})
    files = []
    for f in sorted(os.listdir(saves_dir), reverse=True):
        if f.endswith(".json"):
            full_path = os.path.join(saves_dir, f)
            files.append({"name": f, "size": os.path.getsize(full_path)})
    return jsonify({"files": files})

@app.route("/load/<filename>")
def load_packets(filename):
    if ".." in filename or "/" in filename or "\\" in filename:
        return jsonify({"error": "Invalid filename"}), 400
    save_path = os.path.join(os.path.dirname(__file__), "saves", filename)
    if not os.path.exists(save_path):
        return jsonify({"error": "File not found"}), 404
    with open(save_path, "r") as f:
        loaded = json.load(f)
    log_event(f"Loaded {len(loaded)} packets from {filename}", "info")
    return jsonify({"packets": loaded, "count": len(loaded)})

@app.route("/export")
def export_csv():
    if SNIFF_MODE:
        with packet_sniffer.lock:
            visible = list(packet_sniffer.packets)
    else:
        with lock:
            visible = packets[:displayed_index]
    if not visible:
        return jsonify({"error": "No packets to export"}), 400
    headers = ["id","time","src_ip","dst_ip","protocol",
               "src_port","dst_port","packet_size","service","ttl","flags"]
    lines = [",".join(headers)]
    for p in visible:
        lines.append(",".join(str(p.get(h, "")) for h in headers))
    return Response("\n".join(lines), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=capture.csv"})

if __name__ == "__main__":
    print("=" * 50)
    print("  Network Traffic Monitor")
    print("=" * 50)
    if not SNIFF_MODE:
        load_dataset()
        print(f"  Loaded {len(packets)} packets from dataset.csv")
    print(f"  Mode: {'LIVE' if SNIFF_MODE else 'SIMULATED'}")
    print(f"  Open: http://localhost:5000")
    print("=" * 50)
    app.run(debug=False, port=5000)