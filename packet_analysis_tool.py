# packet_analyzer.py
#!/usr/bin/env python3
"""
Packet Analysis Tool using Scapy
Captures network packets, analyzes for malicious activity, and generates reports.
"""

import os
import time
import json
import argparse
import threading
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw, ICMP
import pandas as pd
from jinja2 import Template

DEFAULT_RULES = "detection_rules.json"

def load_rules(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Rules file not found: {path}")
    with open(path, "r") as f:
        return json.load(f)

events = []
packet_stats = defaultdict(int)
bytes_stats = defaultdict(int)
recent_ports_by_src = defaultdict(lambda: deque())
pkts_by_src = defaultdict(lambda: deque())
lock = threading.Lock()

def is_malicious_ip(ip, rules):
    return ip in rules.get("malicious_ips", [])

def check_payload_sigs(payload, rules):
    sigs = rules.get("suspicious_payload_signatures", [])
    lower = payload.lower()
    for s in sigs:
        if s.lower() in lower:
            return s
    return None

def register_event(kind, details):
    ts = datetime.utcnow().isoformat() + "Z"
    entry = {"timestamp": ts, "kind": kind}
    entry.update(details)
    with lock:
        events.append(entry)

def analyze_packet(pkt, rules):
    if not pkt.haslayer(IP):
        return
    ip = pkt[IP]
    src = ip.src
    dst = ip.dst
    proto = ip.proto
    size = len(pkt)
    ts = time.time()

    packet_stats['total'] += 1
    packet_stats[f"proto_{proto}"] += 1
    bytes_stats[src] += size
    bytes_stats[dst] += 0

    if is_malicious_ip(src, rules):
        register_event("malicious_ip", {"src": src, "dst": dst, "proto": proto, "size": size, "info": "source in blacklist"})
    if is_malicious_ip(dst, rules):
        register_event("malicious_ip", {"src": src, "dst": dst, "proto": proto, "size": size, "info": "destination in blacklist"})

    sport = dport = None
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        flags = None
    elif pkt.haslayer(ICMP):
        flags = "ICMP"
    else:
        flags = None

    s_ports = rules.get("suspicious_ports", [])
    if dport in s_ports or sport in s_ports:
        register_event("suspicious_port", {"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto})

    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw]).decode(errors="ignore")
        found = check_payload_sigs(payload, rules)
        if found:
            register_event("suspicious_payload", {"src": src, "dst": dst, "proto": proto, "signature": found, "snippet": payload[:200]})

    if dport:
        window = rules["port_scan"]["time_window_seconds"]
        threshold = rules["port_scan"]["port_threshold"]
        q = recent_ports_by_src[src]
        q.append((ts, dport))
        while q and (ts - q[0][0]) > window:
            q.popleft()
        unique_ports = {p for _, p in q}
        if len(unique_ports) >= threshold:
            register_event("port_scan", {"src": src, "unique_ports": len(unique_ports), "window": window})
            q.clear()

    pkts_q = pkts_by_src[src]
    pkts_q.append(ts)
    hwindow = rules["high_rate"]["time_window_seconds"]
    while pkts_q and (ts - pkts_q[0]) > hwindow:
        pkts_q.popleft()
    if len(pkts_q) >= rules["high_rate"]["packets_per_sec_threshold"]:
        register_event("high_rate", {"src": src, "count": len(pkts_q), "window": hwindow})
        pkts_q.clear()

def save_csv_reports(outdir):
    os.makedirs(outdir, exist_ok=True)
    events_df = pd.DataFrame(events)
    summary = {
        "total_packets": packet_stats.get('total', 0),
        "by_protocol": {k:v for k,v in packet_stats.items() if k.startswith("proto_")},
        "top_talkers": sorted(bytes_stats.items(), key=lambda x: x[1], reverse=True)[:10]
    }
    events_df.to_csv(os.path.join(outdir, "events.csv"), index=False)
    summary_rows = []
    summary_rows.append({"metric":"total_packets", "value": summary["total_packets"]})
    for k,v in summary["by_protocol"].items():
        summary_rows.append({"metric":k, "value":v})
    for ip,count in summary["top_talkers"]:
        summary_rows.append({"metric":"top_talker", "value": f"{ip}:{count}"})
    pd.DataFrame(summary_rows).to_csv(os.path.join(outdir, "summary.csv"), index=False)
    return summary

HTML_TEMPLATE = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Packet Analysis Report</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:20px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:6px;text-align:left;font-size:13px}
h1,h2{color:#222}
.event-kind{font-weight:bold}
.small{font-size:12px;color:#555}
</style>
</head>
<body>
<h1>Packet Analysis Report</h1>
<p class="small">Generated: {{created}}</p>
<h2>Summary</h2>
<ul>
  <li>Total packets processed: {{summary.total_packets}}</li>
  {% for k,v in summary.by_protocol.items() %}
    <li>{{k}} : {{v}}</li>
  {% endfor %}
</ul>
<h2>Top Talkers (by bytes)</h2>
<table>
<tr><th>IP</th><th>Bytes Sent</th></tr>
{% for ip,bytes in summary.top_talkers %}
<tr><td>{{ip}}</td><td>{{bytes}}</td></tr>
{% endfor %}
</table>
<h2>Events</h2>
<table>
<tr><th>Time (UTC)</th><th>Type</th><th>Details</th></tr>
{% for e in events %}
<tr>
  <td>{{e.timestamp}}</td>
  <td class="event-kind">{{e.kind}}</td>
  <td>
    {% for k,v in e.items() %}
      {% if k not in ['timestamp','kind'] %}
        <div><strong>{{k}}:</strong> {{v}}</div>
      {% endif %}
    {% endfor %}
  </td>
</tr>
{% endfor %}
</table>
</body>
</html>
"""

def save_html_report(outdir, summary, events):
    tpl = Template(HTML_TEMPLATE)
    rendered = tpl.render(created=datetime.utcnow().isoformat() + "Z",
                          summary=summary,
                          events=events)
    path = os.path.join(outdir, "report.html")
    with open(path, "w") as f:
        f.write(rendered)
    return path

def start_sniff(interface, rules, duration=None, bpf_filter=None):
    print(f"[+] Starting sniff on {interface} filter='{bpf_filter}'")
    def prn(pkt):
        try:
            analyze_packet(pkt, rules)
        except Exception as e:
            print("Error analyzing packet:", e)
    sniff(iface=interface, prn=prn, store=False, timeout=duration, filter=bpf_filter)

def main():
    parser = argparse.ArgumentParser(description="Packet Analysis Tool (Scapy)")
    parser.add_argument("--interface", "-i", default=None, help="Network interface to sniff (required)", required=True)
    parser.add_argument("--rules", "-r", default=DEFAULT_RULES, help="Path to detection rules JSON")
    parser.add_argument("--duration", "-d", type=int, default=None, help="Sniff duration in seconds (optional)")
    parser.add_argument("--bpf", default=None, help="BPF filter string (e.g., 'tcp and port 80')")
    parser.add_argument("--outdir", "-o", default="output", help="Output directory for reports")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    try:
        start_sniff(args.interface, rules, duration=args.duration, bpf_filter=args.bpf)
    except PermissionError:
        print("Permission denied: run as root or use sudo.")
        return

    summary = save_csv_reports(args.outdir)
    html_path = save_html_report(args.outdir, summary, events)
    print(f"[+] Saved CSV & HTML reports to {args.outdir}")
    print(f"[+] HTML report: {html_path}")

if __name__ == "__main__":
    main()
