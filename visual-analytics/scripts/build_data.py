import csv
import datetime as dt
import json
import re
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parents[1] / "data" / "va_data.json"


def top(counter, n=12):
    return [{"key": str(k), "value": int(v)} for k, v in counter.most_common(n)]


def hour_key(ts):
    return ts.strftime("%Y-%m-%d %H:00")


def minute_key(ts):
    return ts.strftime("%Y-%m-%d %H:%M")


def parse_firewall():
    path = ROOT / "firewall_log_1.csv"
    ops = Counter()
    proto = Counter()
    direction = Counter()
    src = Counter()
    dst = Counter()
    sport = Counter()
    dport = Counter()
    services = Counter()
    flows = Counter()
    hourly = defaultdict(Counter)
    rows = blank = 0
    first = last = None

    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows += 1
            if not any((v or "").strip() for v in row.values()):
                blank += 1
                continue

            date_text = row.get("Date/time", "")
            try:
                ts = dt.datetime.strptime(date_text, "%d/%m/%Y %H:%M")
            except ValueError:
                ts = None
            if ts:
                first = ts if first is None or ts < first else first
                last = ts if last is None or ts > last else last
                hourly[hour_key(ts)][row.get("Operation") or "(empty)"] += 1

            op = row.get("Operation") or "(empty)"
            pr = row.get("Protocol") or "(empty)"
            s = row.get("Source IP") or "(empty)"
            d = row.get("Destination IP") or "(empty)"
            sp = row.get("Source port") or "(empty)"
            dp = row.get("Destination port") or "(empty)"
            svc = row.get("Destination service") or "(empty)"
            ops[op] += 1
            proto[pr] += 1
            direction[row.get("Direction") or "(empty)"] += 1
            src[s] += 1
            dst[d] += 1
            sport[sp] += 1
            dport[dp] += 1
            services[svc] += 1
            if s not in ("", "(empty)") and d not in ("", "(empty)"):
                flows[(s, d, dp)] += 1

    return {
        "rows_total": rows,
        "rows_nonempty": rows - blank,
        "blank_rows": blank,
        "first": first.isoformat() if first else None,
        "last": last.isoformat() if last else None,
        "operations": top(ops),
        "protocols": top(proto),
        "directions": top(direction),
        "top_sources": top(src),
        "top_destinations": top(dst),
        "top_source_ports": top(sport, 15),
        "top_ports": top(dport, 15),
        "top_services": top(services, 15),
        "top_flows": [
            {"source": s, "target": d, "port": p, "value": int(v)}
            for (s, d, p), v in flows.most_common(30)
        ],
        "timeline": [
            {"time": k, **{op: int(v) for op, v in c.items()}}
            for k, c in sorted(hourly.items())
        ],
    }


def parse_ids():
    path = ROOT / "IDS.txt"
    alert_re = re.compile(r"\[\*\*\] \[(.*?)\] (.*?) \[\*\*\]")
    flow_re = re.compile(r"^(\d\d/\d\d-\d\d:\d\d:\d\d\.\d+)\s+(\S+)\s+->\s+(\S+)")
    alerts = Counter()
    src = Counter()
    dst = Counter()
    pairs = Counter()
    hourly = defaultdict(Counter)
    current = None
    first = last = None
    total = 0

    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            m = alert_re.search(line)
            if m:
                current = m.group(2)
                alerts[current] += 1
                total += 1
                continue
            m = flow_re.search(line)
            if m and current:
                raw_ts, s, d = m.groups()
                try:
                    ts = dt.datetime.strptime("2011/" + raw_ts, "%Y/%m/%d-%H:%M:%S.%f")
                except ValueError:
                    ts = None
                if ts:
                    first = ts if first is None or ts < first else first
                    last = ts if last is None or ts > last else last
                    hourly[hour_key(ts)][current] += 1
                src[s] += 1
                dst[d] += 1
                pairs[(s, d)] += 1
                current = None

    return {
        "alerts": total,
        "first": first.isoformat() if first else None,
        "last": last.isoformat() if last else None,
        "types": top(alerts, 10),
        "top_sources": top(src),
        "top_destinations": top(dst),
        "top_pairs": [
            {"source": s, "target": d, "value": int(v)}
            for (s, d), v in pairs.most_common(25)
        ],
        "timeline": [
            {"time": k, "alerts": int(sum(c.values()))}
            for k, c in sorted(hourly.items())
        ],
    }


def parse_security_xml():
    path = ROOT / "SecurityLog.xml"
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    event_ids = Counter()
    users = Counter()
    ips = Counter()
    computers = Counter()
    statuses = Counter()
    hourly = defaultdict(Counter)
    events = 0
    first = last = None

    for _, elem in ET.iterparse(path, events=("end",)):
        if elem.tag != ns + "Event":
            continue
        events += 1
        ts = None
        event_id = None
        system = elem.find(ns + "System")
        if system is not None:
            eid_el = system.find(ns + "EventID")
            if eid_el is not None:
                event_id = eid_el.text or "(empty)"
                event_ids[event_id] += 1
            comp = system.find(ns + "Computer")
            if comp is not None:
                computers[comp.text or "(empty)"] += 1
            tc = system.find(ns + "TimeCreated")
            if tc is not None and "SystemTime" in tc.attrib:
                ts_text = tc.attrib["SystemTime"].replace("Z", "+00:00")
                try:
                    ts = dt.datetime.fromisoformat(ts_text)
                except ValueError:
                    ts = None
                if ts:
                    first = ts if first is None or ts < first else first
                    last = ts if last is None or ts > last else last
                    hourly[hour_key(ts.replace(tzinfo=None))][event_id or "(empty)"] += 1

        data = elem.find(ns + "EventData")
        if data is not None:
            for d in data.findall(ns + "Data"):
                name = d.attrib.get("Name")
                text = d.text or ""
                if name in ("TargetUserName", "SubjectUserName") and text and text != "-":
                    users[text] += 1
                elif name == "IpAddress" and text and text != "-":
                    ips[text] += 1
                elif name == "Status" and text:
                    statuses[text] += 1
        elem.clear()

    return {
        "events": events,
        "first": first.isoformat() if first else None,
        "last": last.isoformat() if last else None,
        "event_ids": top(event_ids, 12),
        "top_users": top(users, 15),
        "top_ips": top(ips, 15),
        "computers": top(computers),
        "statuses": top(statuses),
        "timeline": [
            {"time": k, "events": int(sum(c.values())), **{eid: int(v) for eid, v in c.items()}}
            for k, c in sorted(hourly.items())
        ],
    }


def parse_pcap():
    path = ROOT / "pcap_1.pcap"
    eth_types = Counter()
    ip_proto = Counter()
    src = Counter()
    dst = Counter()
    pairs = Counter()
    src_ports = Counter()
    ports = Counter()
    minute = defaultdict(lambda: {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0})
    packets = 0
    total_incl = 0
    first = last = None

    with path.open("rb") as f:
        gh = f.read(24)
        magic = gh[:4]
        endian = "<" if magic == bytes.fromhex("d4c3b2a1") else ">"
        _, _, _, _, snaplen, linktype = struct.unpack(endian + "HHiiii", gh[4:24])
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl, _ = struct.unpack(endian + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                break
            packets += 1
            total_incl += incl
            ts = dt.datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000, dt.UTC).replace(tzinfo=None)
            first = ts if first is None or ts < first else first
            last = ts if last is None or ts > last else last
            if linktype != 1 or incl < 14:
                continue
            et = struct.unpack("!H", data[12:14])[0]
            eth_types[f"0x{et:04x}"] += 1
            if et != 0x0800 or incl < 34:
                continue
            ihl = (data[14] & 0x0F) * 4
            proto = data[23]
            s = ".".join(map(str, data[26:30]))
            d = ".".join(map(str, data[30:34]))
            ip_proto[str(proto)] += 1
            src[s] += 1
            dst[d] += 1
            pairs[(s, d)] += 1
            label = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "Other")
            minute[minute_key(ts)][label] += 1
            if proto in (6, 17) and incl >= 14 + ihl + 4:
                sp, dp = struct.unpack("!HH", data[14 + ihl : 14 + ihl + 4])
                src_ports[("TCP" if proto == 6 else "UDP", sp)] += 1
                ports[("TCP" if proto == 6 else "UDP", dp)] += 1

    return {
        "packets": packets,
        "bytes_included": total_incl,
        "snaplen": snaplen,
        "linktype": linktype,
        "first": first.isoformat() if first else None,
        "last": last.isoformat() if last else None,
        "eth_types": top(eth_types),
        "ip_protocols": top(ip_proto),
        "top_sources": top(src),
        "top_destinations": top(dst),
        "top_pairs": [
            {"source": s, "target": d, "value": int(v)}
            for (s, d), v in pairs.most_common(25)
        ],
        "top_source_ports": [
            {"key": f"{proto}/{port}", "value": int(v)}
            for (proto, port), v in src_ports.most_common(15)
        ],
        "top_ports": [
            {"key": f"{proto}/{port}", "value": int(v)}
            for (proto, port), v in ports.most_common(15)
        ],
        "timeline": [{"time": k, **v} for k, v in sorted(minute.items())],
    }


def export_nessus_csv():
    src = ROOT / "Nessus.xls"
    temp = Path(tempfile.gettempdir()) / "va_nessus_export.csv"
    ps = f"""
$ErrorActionPreference='Stop'
$excel=New-Object -ComObject Excel.Application
$excel.Visible=$false
$excel.DisplayAlerts=$false
$wb=$excel.Workbooks.Open('{src}', $null, $true)
try {{ $wb.SaveAs('{temp}', 6) }} finally {{ $wb.Close($false); try {{ $excel.Quit() }} catch {{}} }}
"""
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True, capture_output=True, text=True)
    return temp


def parse_nessus():
    risk = Counter()
    hosts = Counter()
    plugins = Counter()
    ports = Counter()
    synopsis = Counter()
    markers = []
    result_rows = 0
    host_count = 0
    try:
        csv_path = export_nessus_csv()
        with csv_path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
            for row in csv.reader(f):
                row += [""] * 7
                if row[0] == "timestamps":
                    if row[3] == "host_start":
                        host_count += 1
                    if row[3] in ("scan_start", "scan_end"):
                        markers.append({"type": row[3], "time": row[4]})
                if row[0] == "results":
                    result_rows += 1
                    hosts[row[2]] += 1
                    ports[row[3]] += 1
                    plugins[row[4]] += 1
                    risk[row[5] or "(empty)"] += 1
                    m = re.search(r"Synopsis :\\n\\n(.*?)\\n\\nDescription", row[6], re.S)
                    if m:
                        synopsis[m.group(1).replace("\\n", " ")[:150]] += 1
    except Exception as exc:
        markers.append({"type": "parse_warning", "time": str(exc)})

    return {
        "host_count": host_count,
        "result_rows": result_rows,
        "markers": markers,
        "risk": top(risk),
        "top_hosts": top(hosts),
        "top_plugins": top(plugins),
        "top_ports": top(ports),
        "top_synopsis": top(synopsis, 15),
    }


def build_story(data):
    return [
        {
            "phase": "1. Vulnerability surface",
            "time": "2011-04-11 10:16-10:19",
            "source": "Nessus.xls",
            "finding": "Nessus scan exposes many Security Hole findings on workstations 192.168.2.171-175, including SMB/CIFS and Microsoft Office/IE RCE.",
            "visual": "Risk matrix, ranked host bars, vulnerability table",
            "severity": "high",
        },
        {
            "phase": "2. Reconnaissance",
            "time": "2011-04-13 07:54+",
            "source": "IDS.txt",
            "finding": "IDS records TCP Portscan/Portsweep from 192.168.2.x workstations toward servers 192.168.1.2, 192.168.1.14 and 192.168.1.6.",
            "visual": "Alert timeline, source-target graph, heatmap",
            "severity": "high",
        },
        {
            "phase": "3. Connection attempts",
            "time": "2011-04-13 08:52-11:41",
            "source": "firewall_log_1.csv",
            "finding": "Cisco ASA shows Built/Teardown/Deny sessions; SMB/RPC/Kerberos/LDAP and HTTP directions are prominent.",
            "visual": "Firewall flow map, operation stacked bars, port ranking",
            "severity": "medium",
        },
        {
            "phase": "4. Packet-level burst",
            "time": "2011-04-13 20:12-20:15 UTC",
            "source": "pcap_1.pcap",
            "finding": "PCAP contains a short high-volume network slice: HTTP to 172.20.1.5, syslog UDP/514 and TCP sessions to internal services.",
            "visual": "Protocol streamgraph, top talkers, packet Sankey",
            "severity": "medium",
        },
        {
            "phase": "5. Domain activity",
            "time": "2011-04-13 14:57 - 2011-04-14 15:03 UTC",
            "source": "SecurityLog.xml",
            "finding": "DC01 records successful network logons, Kerberos tickets and privileged logon events that connect IP addresses with domain accounts.",
            "visual": "Event timeline, account-IP table, authentication heatmap",
            "severity": "medium",
        },
    ]


def main():
    data = {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "summary": {
            "dataset": "VA security fusion dataset",
            "question": "Which visualization methods fit different cyber-data types?",
        },
        "visualization_catalog": [
            {"data_type": "Firewall/session logs", "visuals": ["flow map", "port ranking", "stacked operation timeline", "deny hotspot heatmap"]},
            {"data_type": "IDS alerts", "visuals": ["alert timeline", "attack-type bars", "source-target graph", "severity matrix"]},
            {"data_type": "Windows event XML", "visuals": ["event-id timeline", "account-IP table", "Kerberos/authentication heatmap", "privilege event cards"]},
            {"data_type": "PCAP headers", "visuals": ["protocol streamgraph", "top talkers", "packet flow Sankey", "port distribution"]},
            {"data_type": "Vulnerability scan", "visuals": ["risk matrix", "host ranking", "vulnerability table", "asset exposure map"]},
            {"data_type": "Raw syslog", "visuals": ["parser quality view", "message-code bars", "raw-to-normalized drilldown"]},
        ],
    }
    data["firewall"] = parse_firewall()
    data["ids"] = parse_ids()
    data["security"] = parse_security_xml()
    data["pcap"] = parse_pcap()
    data["nessus"] = parse_nessus()
    data["story"] = build_story(data)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
