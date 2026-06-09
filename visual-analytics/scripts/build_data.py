import csv
import datetime as dt
import json
import re
import struct
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FOL = ROOT / "FOL"
OUT = Path(__file__).resolve().parents[1] / "data" / "va_data.json"


TIME_FORMATS = (
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
)

NETWORK_NODES = [
    {"ip": "10.200.150.1", "name": "Firewall Internet interface", "type": "firewall", "priority": "high"},
    {"ip": "172.20.1.1", "name": "Firewall external web interface", "type": "firewall", "priority": "high"},
    {"ip": "172.20.1.5", "name": "External Web Server", "type": "server", "priority": "high"},
    {"ip": "192.168.1.1", "name": "Firewall data center VLAN interface", "type": "firewall", "priority": "high"},
    {"ip": "192.168.1.2", "name": "DC / DNS / DHCP server", "type": "server", "priority": "high"},
    {"ip": "192.168.1.3", "name": "HR Database Server", "type": "server", "priority": "high"},
    {"ip": "192.168.1.4", "name": "Shipping / Routing Database Server", "type": "server", "priority": "high"},
    {"ip": "192.168.1.5", "name": "Internal Web Server", "type": "server", "priority": "high"},
    {"ip": "192.168.1.6", "name": "Mail Server", "type": "server", "priority": "high"},
    {"ip": "192.168.1.7", "name": "File Server", "type": "server", "priority": "high"},
    {"ip": "192.168.1.14", "name": "DC / DNS server", "type": "server", "priority": "high"},
    {"ip": "192.168.1.16", "name": "Snort IDS", "type": "ids", "priority": "high"},
    {"ip": "192.168.1.50", "name": "Firewall log server", "type": "log_server", "priority": "high"},
    {"ip": "192.168.2.1", "name": "Firewall office VLAN interface", "type": "firewall", "priority": "high"},
    {"ip": "192.168.2.10-250", "name": "Office workstations", "type": "workstation_range", "priority": "normal"},
]


def top(counter, n=12):
    return [{"key": str(k), "value": int(v)} for k, v in counter.most_common(n)]


def hour_key(ts):
    return ts.strftime("%Y-%m-%d %H:00")


def minute_key(ts):
    return ts.strftime("%Y-%m-%d %H:%M")


def day_from_path(path):
    match = re.search(r"(201104\d\d)", str(path))
    if not match:
        return "unknown"
    raw = match.group(1)
    return f"{raw[:4]}-{raw[4:6]}-{raw[6:]}"


def parse_time(value):
    value = str(value or "").strip()
    if not value:
        return None
    normalized = (
        value.replace("/Jan/", "/01/")
        .replace("/Feb/", "/02/")
        .replace("/Mar/", "/03/")
        .replace("/Apr/", "/04/")
        .replace("/May/", "/05/")
        .replace("/Jun/", "/06/")
        .replace("/Jul/", "/07/")
        .replace("/Aug/", "/08/")
        .replace("/Sep/", "/09/")
        .replace("/Oct/", "/10/")
        .replace("/Nov/", "/11/")
        .replace("/Dec/", "/12/")
    )
    for fmt in TIME_FORMATS:
        try:
            return dt.datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return dt.datetime.fromisoformat(value)
    except ValueError:
        return None


def split_endpoint(value):
    value = str(value or "").strip()
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        return host, port
    return value, ""


def clean_process_name(value):
    value = str(value or "").strip()
    if value in {"", "-", "(empty)", "0x0"}:
        return ""
    value = value.replace("\\", "/")
    return value.rsplit("/", 1)[-1]


def empty(value):
    value = str(value or "").strip()
    return value in {"", "(empty)", "empty", "EMPTY", "null", "NULL", "none", "None", "N/A", "n/a", "-", "--"}


def norm(value, fallback="(empty)"):
    value = str(value or "").strip()
    return fallback if empty(value) else value


def extract_cves(text):
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text or "")))


def extract_first(pattern, text):
    match = re.search(pattern, text or "", re.I)
    return match.group(1).strip() if match else ""


def extract_exploit_available(text):
    text = text or ""
    match = re.search(r"Exploit(?:s)? available\s*:\s*(yes|no|true|false)", text, re.I)
    if match:
        return match.group(1)
    if re.search(r"exploit", text, re.I):
        return "mentioned"
    return ""


def extract_section(text, title):
    text = text or ""
    match = re.search(rf"{re.escape(title)} :\\n\\n(.*?)(?:\\n\\n[A-Z][A-Za-z ]+ :|$)", text, re.S)
    if not match:
        return ""
    return match.group(1).replace("\\n", " ").strip()[:260]


def parse_firewall():
    paths = sorted(FOL.glob("201104*/firewall/csv/*.csv"))
    ops = Counter()
    priorities = Counter()
    proto = Counter()
    direction = Counter()
    src = Counter()
    dst = Counter()
    sport = Counter()
    dport = Counter()
    services = Counter()
    flows = Counter()
    source_port_matrix = Counter()
    day_counts = Counter()
    hourly = defaultdict(Counter)
    detail_rows = []
    detail_rows_by_day = Counter()
    rows = blank = parsed_files = 0
    first = last = None

    for path in paths:
        parsed_files += 1
        day = day_from_path(path)
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for line_no, row in enumerate(reader, start=2):
                rows += 1
                if not any((v or "").strip() for v in row.values()):
                    blank += 1
                    continue
                day_counts[day] += 1
                ts = parse_time(row.get("Date/time", ""))
                if ts:
                    first = ts if first is None or ts < first else first
                    last = ts if last is None or ts > last else last
                    hourly[hour_key(ts)][norm(row.get("Operation"))] += 1

                op = norm(row.get("Operation"))
                prio = norm(row.get("Syslog priority"))
                pr = norm(row.get("Protocol"))
                s = norm(row.get("Source IP"))
                d = norm(row.get("Destination IP"))
                sp = norm(row.get("Source port"))
                dp = norm(row.get("Destination port"))
                svc = norm(row.get("Destination service"))
                msg = norm(row.get("Message code"))
                dirn = norm(row.get("Direction"))

                ops[op] += 1
                priorities[prio] += 1
                proto[pr] += 1
                direction[dirn] += 1
                src[s] += 1
                dst[d] += 1
                sport[sp] += 1
                dport[dp] += 1
                services[svc] += 1
                if s != "(empty)" and d != "(empty)":
                    flows[(s, d, dp)] += 1
                if s != "(empty)" and dp != "(empty)":
                    source_port_matrix[(s, dp, pr)] += 1

                is_sensitive = dp in {"21", "22", "23", "25", "53", "80", "88", "135", "139", "389", "443", "445", "3389", "43025", "43032"}
                is_suspicious = op == "Deny" or is_sensitive
                if is_suspicious and detail_rows_by_day[day] < 600:
                    detail_rows.append(
                        {
                            "time": ts.isoformat() if ts else row.get("Date/time", ""),
                            "source_ip": s,
                            "destination_ip": d,
                            "source_port": sp,
                            "destination_port": dp,
                            "protocol": pr,
                            "direction": dirn,
                            "action": op,
                            "operation": op,
                            "destination_service": svc,
                            "message_code": msg,
                            "raw_ref": f"{path.name}:{line_no}",
                            "day": day,
                        }
                    )
                    detail_rows_by_day[day] += 1

    return {
        "source_files": [str(p.relative_to(ROOT)) for p in paths],
        "files": parsed_files,
        "rows_total": rows,
        "rows_nonempty": rows - blank,
        "blank_rows": blank,
        "first": first.isoformat() if first else None,
        "last": last.isoformat() if last else None,
        "by_day": top(day_counts, 10),
        "operations": top(ops),
        "priorities": top(priorities),
        "protocols": top(proto),
        "directions": top(direction),
        "top_sources": top(src),
        "top_destinations": top(dst),
        "top_source_ports": top(sport, 20),
        "top_ports": top(dport, 20),
        "top_services": top(services, 20),
        "top_flows": [
            {"source": s, "target": d, "port": p, "value": int(v)}
            for (s, d, p), v in flows.most_common(60)
        ],
        "source_port_matrix": [
            {"source": s, "port": p, "protocol": pr, "value": int(v)}
            for (s, p, pr), v in source_port_matrix.most_common(150)
        ],
        "suspicious_connections": detail_rows,
        "timeline": [
            {"time": k, **{op: int(v) for op, v in c.items()}}
            for k, c in sorted(hourly.items())
        ],
    }


def parse_ids():
    paths = sorted(FOL.glob("201104*/IDS/*.txt*"))
    alert_re = re.compile(r"\[\*\*\] \[(.*?)\] (.*?) \[\*\*\]")
    meta_re = re.compile(r"(?:\[Classification:\s*(.*?)\]\s*)?\[Priority:\s*(\d+)\]")
    flow_re = re.compile(r"^(\d\d/\d\d-\d\d:\d\d:\d\d\.\d+)\s+(\S+)\s+->\s+(\S+)")

    alerts = Counter()
    classifications = Counter()
    priorities = Counter()
    src = Counter()
    dst = Counter()
    pairs = Counter()
    source_port_matrix = Counter()
    hourly = defaultdict(Counter)
    hourly_signature = defaultdict(Counter)
    day_counts = Counter()
    sample = []
    sample_by_day = Counter()
    first = last = None
    total = 0
    current = None

    for path in paths:
        day_raw = re.search(r"(201104\d\d)", str(path)).group(1)
        day = f"{day_raw[:4]}-{day_raw[4:6]}-{day_raw[6:]}"
        with path.open(encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                m = alert_re.search(line)
                if m:
                    signature = m.group(2).strip()
                    current = {
                        "signature": signature,
                        "classification": "(empty)",
                        "priority": "(empty)",
                        "day": day,
                        "line": line_no,
                    }
                    alerts[signature] += 1
                    total += 1
                    day_counts[day] += 1
                    continue

                if current:
                    m = meta_re.search(line)
                    if m:
                        current["classification"] = norm(m.group(1))
                        current["priority"] = norm(m.group(2))
                        classifications[current["classification"]] += 1
                        priorities[current["priority"]] += 1
                        continue

                    m = flow_re.search(line)
                    if m:
                        raw_ts, s_endpoint, d_endpoint = m.groups()
                        ts = None
                        try:
                            ts = dt.datetime.strptime("2011/" + raw_ts, "%Y/%m/%d-%H:%M:%S.%f")
                        except ValueError:
                            pass
                        signature = current["signature"]
                        if ts:
                            first = ts if first is None or ts < first else first
                            last = ts if last is None or ts > last else last
                            hourly[hour_key(ts)]["alerts"] += 1
                            hourly_signature[hour_key(ts)][signature] += 1
                        src[s_endpoint] += 1
                        dst[d_endpoint] += 1
                        pairs[(s_endpoint, d_endpoint)] += 1
                        clean_src, _ = split_endpoint(s_endpoint)
                        _, dst_port = split_endpoint(d_endpoint)
                        if clean_src and dst_port:
                            source_port_matrix[(clean_src, dst_port, signature)] += 1
                        if sample_by_day[day] < 600:
                            sample.append(
                                {
                                    "time": ts.isoformat() if ts else "",
                                    "source": s_endpoint,
                                    "destination": d_endpoint,
                                    "signature": signature,
                                    "classification": current["classification"],
                                    "priority": current["priority"],
                                    "day": day,
                                    "raw_ref": f"{path.name}:{current['line']}",
                                }
                            )
                            sample_by_day[day] += 1
                        current = None

    return {
        "source_files": [str(p.relative_to(ROOT)) for p in paths],
        "files": len(paths),
        "alerts": total,
        "first": first.isoformat() if first else None,
        "last": last.isoformat() if last else None,
        "by_day": top(day_counts, 10),
        "types": top(alerts, 15),
        "classifications": top(classifications, 15),
        "priorities": top(priorities, 10),
        "top_sources": top(src, 20),
        "top_destinations": top(dst, 20),
        "top_pairs": [
            {"source": s, "target": d, "value": int(v)}
            for (s, d), v in pairs.most_common(60)
        ],
        "source_port_matrix": [
            {"source": s, "port": p, "signature": sig, "value": int(v)}
            for (s, p, sig), v in source_port_matrix.most_common(150)
        ],
        "sample_alerts": sample,
        "timeline": [
            {"time": k, "alerts": int(c["alerts"])}
            for k, c in sorted(hourly.items())
        ],
        "timeline_by_signature": [
            {"time": k, **{sig: int(v) for sig, v in c.most_common(6)}}
            for k, c in sorted(hourly_signature.items())
        ],
    }


def parse_security_xml():
    paths = sorted(FOL.glob("201104*/security/*.xml"))
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    event_ids = Counter()
    users = Counter()
    ips = Counter()
    computers = Counter()
    statuses = Counter()
    user_host_matrix = Counter()
    users_by_hour = defaultdict(Counter)
    ips_by_hour = defaultdict(Counter)
    user_host_by_hour = defaultdict(Counter)
    processes = Counter()
    process_edges = Counter()
    hourly = defaultdict(Counter)
    day_counts = Counter()
    process_details = []
    events = 0
    first = last = None

    for path in paths:
        day = day_from_path(path)
        for _, elem in ET.iterparse(path, events=("end",)):
            if elem.tag != ns + "Event":
                continue
            events += 1
            day_counts[day] += 1
            ts = None
            event_id = "(empty)"
            computer_name = "(empty)"
            system = elem.find(ns + "System")
            if system is not None:
                eid_el = system.find(ns + "EventID")
                if eid_el is not None:
                    event_id = eid_el.text or "(empty)"
                    event_ids[event_id] += 1
                comp = system.find(ns + "Computer")
                if comp is not None:
                    computer_name = comp.text or "(empty)"
                    computers[computer_name] += 1
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
                        hourly[hour_key(ts.replace(tzinfo=None))][event_id] += 1

            data = elem.find(ns + "EventData")
            event_fields = {}
            hour = hour_key(ts.replace(tzinfo=None)) if ts else None
            if data is not None:
                for d in data.findall(ns + "Data"):
                    name = d.attrib.get("Name")
                    text = d.text or ""
                    if name:
                        event_fields[name] = text
                    if name in ("TargetUserName", "SubjectUserName") and not empty(text):
                        users[text] += 1
                        if hour:
                            users_by_hour[hour][text] += 1
                    elif name in ("IpAddress", "ClientAddress", "SourceAddress") and not empty(text):
                        ips[text] += 1
                        if hour:
                            ips_by_hour[hour][text] += 1
                    elif name == "Status" and text:
                        statuses[text] += 1

            user = event_fields.get("TargetUserName") or event_fields.get("SubjectUserName") or ""
            host_or_ip = (
                event_fields.get("WorkstationName")
                or event_fields.get("IpAddress")
                or event_fields.get("ClientAddress")
                or ""
            )
            if not empty(user) and not empty(host_or_ip):
                user_host_matrix[(user, host_or_ip, event_id)] += 1
                if hour:
                    user_host_by_hour[hour][(user, host_or_ip, event_id)] += 1

            proc = event_fields.get("ProcessName") or event_fields.get("Image") or event_fields.get("ProcessNameBuffer") or ""
            parent = event_fields.get("ParentProcessName") or event_fields.get("ParentImage") or event_fields.get("CreatorProcessName") or ""
            command = event_fields.get("CommandLine") or event_fields.get("ProcessCommandLine") or ""
            proc_clean = clean_process_name(proc)
            parent_clean = clean_process_name(parent)
            if proc_clean:
                processes[proc_clean] += 1
            if proc_clean and parent_clean:
                process_edges[(parent_clean, proc_clean)] += 1
            if proc_clean and len(process_details) < 500:
                process_details.append(
                    {
                        "time": ts.isoformat() if ts else "",
                        "computer": computer_name,
                        "user": user,
                        "process_name": proc_clean,
                        "parent_process_name": parent_clean,
                        "command_line": command,
                        "image": proc,
                        "hash": event_fields.get("Hash") or event_fields.get("Hashes") or "",
                        "event_id": event_id,
                        "day": day,
                    }
                )
            elem.clear()

    return {
        "source_files": [str(p.relative_to(ROOT)) for p in paths],
        "files": len(paths),
        "events": events,
        "first": first.isoformat() if first else None,
        "last": last.isoformat() if last else None,
        "by_day": top(day_counts, 10),
        "event_ids": top(event_ids, 15),
        "top_users": top(users, 20),
        "top_ips": top(ips, 20),
        "computers": top(computers),
        "statuses": top(statuses),
        "user_host_matrix": [
            {"user": u, "host": h, "event_id": eid, "value": int(v)}
            for (u, h, eid), v in user_host_matrix.most_common(180)
        ],
        "top_users_by_hour": [
            {"time": hour, "key": user, "value": int(value)}
            for hour, counter in sorted(users_by_hour.items())
            for user, value in counter.most_common(20)
        ],
        "top_ips_by_hour": [
            {"time": hour, "key": ip, "value": int(value)}
            for hour, counter in sorted(ips_by_hour.items())
            for ip, value in counter.most_common(20)
        ],
        "user_host_matrix_by_hour": [
            {"time": hour, "user": u, "host": h, "event_id": eid, "value": int(value)}
            for hour, counter in sorted(user_host_by_hour.items())
            for (u, h, eid), value in counter.most_common(80)
        ],
        "top_processes": top(processes, 25),
        "process_edges": [
            {"source": p, "target": c, "value": int(v)}
            for (p, c), v in process_edges.most_common(80)
        ],
        "process_details": process_details,
        "timeline": [
            {"time": k, "events": int(sum(c.values())), **{eid: int(v) for eid, v in c.items()}}
            for k, c in sorted(hourly.items())
        ],
    }


def parse_pcap():
    paths = sorted(FOL.glob("PCAP/PCAP/201104*/*.pcap"))
    eth_types = Counter()
    ip_proto = Counter()
    src = Counter()
    dst = Counter()
    pairs = Counter()
    src_ports = Counter()
    ports = Counter()
    source_port_matrix = Counter()
    minute = defaultdict(lambda: {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0})
    day_counts = Counter()
    file_summaries = []
    packet_details = []
    packet_details_by_day = Counter()
    packets = 0
    sampled_packets = 0
    total_incl = 0
    first = last = None
    snaplens = Counter()
    linktypes = Counter()

    for path in paths:
        file_packets = 0
        file_sampled = 0
        file_first = file_last = None
        file_eth_types = Counter()
        file_ip_proto = Counter()
        file_src = Counter()
        file_dst = Counter()
        file_pairs = Counter()
        file_src_ports = Counter()
        file_ports = Counter()
        file_source_port_matrix = Counter()
        file_minute = defaultdict(lambda: {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0})
        with path.open("rb") as f:
            gh = f.read(24)
            if len(gh) < 24:
                continue
            magic = gh[:4]
            endian = "<" if magic in (bytes.fromhex("d4c3b2a1"), bytes.fromhex("4d3cb2a1")) else ">"
            try:
                _, _, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", gh[4:24])
            except struct.error:
                continue
            snaplens[snaplen] += 1
            linktypes[linktype] += 1
            first_header = f.read(16)
            if len(first_header) < 16:
                continue
            _, _, first_incl, _ = struct.unpack(endian + "IIII", first_header)
            record_size = 16 + first_incl
            if record_size <= 16:
                continue
            estimated_packets = max(1, (path.stat().st_size - 24) // record_size)
            sample_target = min(90_000, estimated_packets)
            windows = []
            window_size = max(1, sample_target // 3)
            for start in [0, max(0, estimated_packets // 2 - window_size // 2), max(0, estimated_packets - window_size)]:
                windows.append((start, min(estimated_packets, start + window_size)))
            merged_windows = []
            for start, end in sorted(windows):
                if not merged_windows or start > merged_windows[-1][1]:
                    merged_windows.append([start, end])
                else:
                    merged_windows[-1][1] = max(merged_windows[-1][1], end)

            for start, end in merged_windows:
                f.seek(24 + start * record_size)
                for packet_index in range(start, end):
                    ph = f.read(16)
                    if len(ph) < 16:
                        break
                    ts_sec, ts_usec, incl, _ = struct.unpack(endian + "IIII", ph)
                    data = f.read(incl)
                    if len(data) < incl:
                        break
                    file_sampled += 1
                    ts = dt.datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000, dt.UTC).replace(tzinfo=None)
                    file_first = ts if file_first is None or ts < file_first else file_first
                    file_last = ts if file_last is None or ts > file_last else file_last
                    if linktype != 1 or incl < 14:
                        continue
                    et = struct.unpack("!H", data[12:14])[0]
                    file_eth_types[f"0x{et:04x}"] += 1
                    if et != 0x0800 or incl < 34:
                        continue
                    ihl = (data[14] & 0x0F) * 4
                    proto = data[23]
                    s = ".".join(map(str, data[26:30]))
                    d = ".".join(map(str, data[30:34]))
                    file_ip_proto[str(proto)] += 1
                    file_src[s] += 1
                    file_dst[d] += 1
                    file_pairs[(s, d)] += 1
                    label = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "Other")
                    file_minute[minute_key(ts)][label] += 1
                    if proto in (6, 17) and incl >= 14 + ihl + 4:
                        sp, dp = struct.unpack("!HH", data[14 + ihl : 14 + ihl + 4])
                        proto_name = "TCP" if proto == 6 else "UDP"
                        file_src_ports[(proto_name, sp)] += 1
                        file_ports[(proto_name, dp)] += 1
                        file_source_port_matrix[(s, dp, proto_name)] += 1
                        packet_day = ts.strftime("%Y-%m-%d")
                        if packet_details_by_day[packet_day] < 600 and (
                            dp in {25, 53, 80, 88, 135, 139, 389, 443, 445, 514, 3389, 43025, 43032}
                            or packet_index == start
                        ):
                            packet_details.append(
                                {
                                    "no": packets + packet_index,
                                    "time": ts.isoformat(),
                                    "source": s,
                                    "destination": d,
                                    "protocol": proto_name,
                                    "length": incl,
                                    "source_port": sp,
                                    "destination_port": dp,
                                    "file": path.name,
                                }
                            )
                            packet_details_by_day[packet_day] += 1
                    elif proto == 1 and packet_index == start:
                        packet_day = ts.strftime("%Y-%m-%d")
                        if packet_details_by_day[packet_day] >= 600:
                            continue
                        packet_details.append(
                            {
                                "no": packets + packet_index,
                                "time": ts.isoformat(),
                                "source": s,
                                "destination": d,
                                "protocol": label,
                                "length": incl,
                                "source_port": "",
                                "destination_port": "",
                                "file": path.name,
                            }
                        )
                        packet_details_by_day[packet_day] += 1
        file_packets = estimated_packets
        packets += estimated_packets
        sampled_packets += file_sampled
        total_incl += estimated_packets * first_incl
        first = file_first if first is None or (file_first and file_first < first) else first
        last = file_last if last is None or (file_last and file_last > last) else last
        if file_first:
            day_counts[file_first.strftime("%Y-%m-%d")] += estimated_packets
        scale = estimated_packets / max(file_sampled, 1)
        for key, value in file_eth_types.items():
            eth_types[key] += round(value * scale)
        for key, value in file_ip_proto.items():
            ip_proto[key] += round(value * scale)
        for key, value in file_src.items():
            src[key] += round(value * scale)
        for key, value in file_dst.items():
            dst[key] += round(value * scale)
        for key, value in file_pairs.items():
            pairs[key] += round(value * scale)
        for key, value in file_src_ports.items():
            src_ports[key] += round(value * scale)
        for key, value in file_ports.items():
            ports[key] += round(value * scale)
        for key, value in file_source_port_matrix.items():
            source_port_matrix[key] += round(value * scale)
        for key, values in file_minute.items():
            for proto_key, value in values.items():
                minute[key][proto_key] += round(value * scale)
        file_summaries.append(
            {
                "file": str(path.relative_to(ROOT)),
                "packets": file_packets,
                "sampled_packets": file_sampled,
                "first": file_first.isoformat() if file_first else None,
                "last": file_last.isoformat() if file_last else None,
            }
        )

    return {
        "source_files": [str(p.relative_to(ROOT)) for p in paths],
        "files": len(paths),
        "packets": packets,
        "sampled_packets": sampled_packets,
        "sampling_note": "PCAP dashboard aggregates are estimated from deterministic header samples across the beginning, middle and end of each PCAP file. File-level packet counts are estimated from PCAP record size because VAST PCAP evidence is optional and very large.",
        "bytes_included": total_incl,
        "snaplen": snaplens.most_common(1)[0][0] if snaplens else None,
        "linktype": linktypes.most_common(1)[0][0] if linktypes else None,
        "first": first.isoformat() if first else None,
        "last": last.isoformat() if last else None,
        "by_day": top(day_counts, 10),
        "file_summaries": file_summaries,
        "eth_types": top(eth_types),
        "ip_protocols": top(ip_proto),
        "top_sources": top(src, 20),
        "top_destinations": top(dst, 20),
        "top_pairs": [
            {"source": s, "target": d, "value": int(v)}
            for (s, d), v in pairs.most_common(80)
        ],
        "top_source_ports": [
            {"key": f"{proto}/{port}", "value": int(v)}
            for (proto, port), v in src_ports.most_common(20)
        ],
        "top_ports": [
            {"key": f"{proto}/{port}", "value": int(v)}
            for (proto, port), v in ports.most_common(20)
        ],
        "source_port_matrix": [
            {"source": s, "port": p, "protocol": proto, "value": int(v)}
            for (s, p, proto), v in source_port_matrix.most_common(160)
        ],
        "packet_details": packet_details,
        "timeline": [{"time": k, **v} for k, v in sorted(minute.items())],
    }


def parse_nessus():
    path = FOL / "Nessus" / "20110411_VAST11MiC2_Nessus.nbe"
    risk = Counter()
    hosts = Counter()
    plugins = Counter()
    ports = Counter()
    synopsis = Counter()
    cve_or_plugin = Counter()
    markers = []
    details = []
    result_rows = 0
    host_count = 0

    with path.open(encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.rstrip("\r\n")
            parts = line.split("|", 6)
            if not parts:
                continue
            if parts[0] == "timestamps":
                parts += [""] * 5
                if parts[3] == "host_start":
                    host_count += 1
                if parts[3] in {"scan_start", "scan_end", "host_start", "host_end"} and len(markers) < 600:
                    markers.append({"type": parts[3], "host": parts[2], "time": parts[4]})
                continue
            if parts[0] != "results":
                continue
            parts += [""] * 7
            _, subnet, host, port, plugin_id, severity, body = parts[:7]
            severity = norm(severity)
            result_rows += 1
            hosts[host] += 1
            ports[port] += 1
            plugins[plugin_id] += 1
            risk[severity] += 1
            cves = extract_cves(body)
            if cves:
                for cve in cves[:5]:
                    cve_or_plugin[cve] += 1
            else:
                cve_or_plugin[plugin_id or "(empty)"] += 1
            synopsis_text = extract_section(body, "Synopsis")
            if synopsis_text:
                synopsis[synopsis_text[:150]] += 1
            if len(details) < 900:
                details.append(
                    {
                        "host": host,
                        "ip_address": host,
                        "subnet": subnet,
                        "port": port,
                        "service": port,
                        "plugin_id": plugin_id,
                        "plugin_name": synopsis_text or plugin_id,
                        "severity": severity,
                        "cvss": extract_first(r"CVSS(?: Base Score)?\s*:\\n\\n\s*([0-9.]+)", body)
                        or extract_first(r"CVSS(?: Base Score)?\s*:\s*([0-9.]+)", body),
                        "cve": ", ".join(cves[:8]),
                        "exploit_available": extract_exploit_available(body),
                        "solution": extract_section(body, "Solution"),
                        "raw_ref": f"{path.name}:{line_no}",
                    }
                )

    return {
        "source_files": [str(path.relative_to(ROOT)), str((FOL / "Nessus" / "20110411_VAST11MC2_Nessus.xls").relative_to(ROOT))],
        "host_count": host_count,
        "result_rows": result_rows,
        "markers": markers,
        "risk": top(risk),
        "top_hosts": top(hosts, 20),
        "top_plugins": top(plugins, 20),
        "top_cve_plugin": top(cve_or_plugin, 25),
        "top_ports": top(ports, 20),
        "top_synopsis": top(synopsis, 20),
        "details": details,
    }


def build_story(data):
    vuln_hosts = ", ".join(item["key"] for item in data["nessus"].get("top_hosts", [])[:5])
    ids_targets = ", ".join(item["key"] for item in data["ids"].get("top_destinations", [])[:3])
    fw_dest = data["firewall"].get("top_destinations", [{}])[0].get("key", "unknown")
    pcap_dest = data["pcap"].get("top_destinations", [{}])[0].get("key", "unknown")
    top_events = ", ".join(item["key"] for item in data["security"].get("event_ids", [])[:4])
    return [
        {
            "phase": "1. Vulnerability surface",
            "time": "2011-04-11",
            "source": "FOL/Nessus",
            "finding": f"Nessus identifies concentrated vulnerability exposure on hosts {vuln_hosts}.",
            "visual": "Nessus severity treemap, host-service heatmap, host-plugin scatterplot",
            "severity": "high",
        },
        {
            "phase": "2. Reconnaissance and IDS detections",
            "time": f"{data['ids'].get('first')} - {data['ids'].get('last')}",
            "source": "FOL/*/IDS",
            "finding": f"Snort IDS alerts show recurrent detections toward {ids_targets}, including portscan/portsweep-style signatures.",
            "visual": "IDS timeline, source-target heatmap, IDS parallel coordinates",
            "severity": "high",
        },
        {
            "phase": "3. Firewall-observed connection activity",
            "time": f"{data['firewall'].get('first')} - {data['firewall'].get('last')}",
            "source": "FOL/*/firewall/csv",
            "finding": f"Cisco ASA firewall logs show Built/Teardown/Deny activity, with {fw_dest} as the highest-volume destination.",
            "visual": "Firewall timeline, Source IP x Destination IP heatmap, Time x Destination Port scatterplot",
            "severity": "medium",
        },
        {
            "phase": "4. Domain and authentication context",
            "time": f"{data['security'].get('first')} - {data['security'].get('last')}",
            "source": "FOL/*/security",
            "finding": f"Windows Security logs provide domain activity context through EventIDs {top_events}.",
            "visual": "Windows EventID timeline, User x Host heatmap",
            "severity": "medium",
        },
        {
            "phase": "5. Packet-level confirmation",
            "time": f"{data['pcap'].get('first')} - {data['pcap'].get('last')}",
            "source": "FOL/PCAP",
            "finding": f"PCAP captures packet-level traffic structure; the highest-volume destination is {pcap_dest}.",
            "visual": "PCAP timeline, IP x IP heatmap, Time x Destination Port scatterplot",
            "severity": "medium",
        },
    ]


def build_catalog():
    return [
        {"data_type": "Firewall/session logs", "visuals": ["operation timeline", "source-target heatmap", "time-port scatterplot", "parallel coordinates", "raw syslog drilldown"]},
        {"data_type": "IDS alerts", "visuals": ["alert timeline", "signature ranking", "source-target heatmap", "source-port matrix", "parallel coordinates"]},
        {"data_type": "Windows Security XML", "visuals": ["EventID timeline", "user-host heatmap", "account/IP ranking", "process graph when process fields exist"]},
        {"data_type": "PCAP headers", "visuals": ["protocol timeline", "top talkers", "source-target heatmap", "source-port matrix", "parallel coordinates"]},
        {"data_type": "Nessus vulnerability scan", "visuals": ["severity treemap", "host-service heatmap", "host-CVE/plugin scatterplot", "parallel coordinates"]},
        {"data_type": "Raw firewall syslog", "visuals": ["on-demand evidence retrieval", "raw-to-normalized validation"]},
    ]


def main():
    if not FOL.exists():
        raise SystemExit(f"FOL directory not found: {FOL}")

    data = {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "summary": {
            "dataset": "VAST 2011 Mini-Challenge 2: All Freight Corporation official data",
            "question": "Which visualization methods fit different cyber-data types and support attack-story reasoning?",
            "source_root": str(FOL.relative_to(ROOT)),
            "description_file": "VAST11MC2_Network Description.doc",
            "official_data_note": "The network description states that the earlier examples were not the actual challenge data; this analytical layer is rebuilt from FOL.",
            "pcap_note": "PCAP files are optional evidence in the challenge and contain header-limited packet capture data.",
        },
        "network": {
            "nodes": NETWORK_NODES,
            "internal_ranges": ["172.x.x.x", "192.x.x.x"],
            "external_rule": "Nodes outside 172.x.x.x and 192.x.x.x are external to the All Freight network.",
            "common_ports": [
                {"port": 25, "service": "email traffic"},
                {"port": 53, "service": "domain name service"},
                {"port": 80, "service": "web traffic"},
            ],
        },
        "visualization_catalog": build_catalog(),
    }
    print("Parsing firewall CSV files...", flush=True)
    data["firewall"] = parse_firewall()
    print("Parsing IDS text logs...", flush=True)
    data["ids"] = parse_ids()
    print("Parsing Windows Security XML logs...", flush=True)
    data["security"] = parse_security_xml()
    print("Parsing PCAP files...", flush=True)
    data["pcap"] = parse_pcap()
    print("Parsing Nessus NBE report...", flush=True)
    data["nessus"] = parse_nessus()
    data["story"] = build_story(data)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {OUT}", flush=True)


if __name__ == "__main__":
    main()
