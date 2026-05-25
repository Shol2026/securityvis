import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%d/%m/%Y %H:%M",
    "%m/%d-%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
)


@dataclass
class NormalizedEvent:
    source: str
    timestamp: str | None = None
    category: str | None = None
    event_type: str | None = None
    severity: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: str | None = None
    dst_port: str | None = None
    protocol: str | None = None
    account: str | None = None
    host: str | None = None
    risk: str | None = None
    label: str | None = None
    raw_ref: str | None = None
    attrs: dict = field(default_factory=dict)

    def as_dict(self):
        return {k: v for k, v in self.__dict__.items() if v not in (None, "", {}, [])}


def read_csv(path: Path):
    if not path or not path.exists():
        return []
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as fh:
        return list(csv.DictReader(fh))


def first(row, names, default=""):
    lower = {k.lower().strip(): k for k in row.keys()}
    for name in names:
        key = lower.get(name.lower())
        if key is not None:
            value = row.get(key, "")
            if value is not None and str(value).strip() != "":
                return str(value).strip()
    return default


def parse_time(value):
    value = str(value or "").strip()
    if not value:
        return None
    if value.endswith("Z") and "." not in value:
        value = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.astimezone(timezone.utc).replace(tzinfo=None).isoformat()
    except ValueError:
        pass
    for fmt in TIME_FORMATS:
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=None).isoformat()
        except ValueError:
            continue
    return None


def hour_bucket(timestamp):
    if not timestamp:
        return "unknown"
    try:
        return datetime.fromisoformat(timestamp).strftime("%Y-%m-%d %H:00")
    except ValueError:
        return "unknown"


def normalize_firewall(rows):
    events = []
    for i, row in enumerate(rows, start=2):
        if not any(str(v or "").strip() for v in row.values()):
            continue
        operation = first(row, ["Operation", "action", "ASA action", "event_type"])
        src_ip = first(row, ["Source IP", "src_ip", "source", "sourceIP"])
        dst_ip = first(row, ["Destination IP", "dst_ip", "destination", "destIP"])
        ev = NormalizedEvent(
            source="firewall",
            timestamp=parse_time(first(row, ["Date/time", "timestamp", "time"])),
            category="traffic",
            event_type=operation or "firewall_event",
            severity=severity_from_firewall(operation),
            src_ip=empty_to_none(src_ip),
            dst_ip=empty_to_none(dst_ip),
            src_port=empty_to_none(first(row, ["Source port", "src_port", "sourcePort"])),
            dst_port=empty_to_none(first(row, ["Destination port", "dst_port", "destPort"])),
            protocol=empty_to_none(first(row, ["Protocol", "proto"])),
            label=empty_to_none(first(row, ["Message code", "label", "signature"])),
            raw_ref=f"firewall_csv_line:{i}",
            attrs={
                "direction": first(row, ["Direction"]),
                "service": first(row, ["Destination service", "service"]),
            },
        )
        events.append(ev)
    return events


def normalize_ids(rows):
    events = []
    for i, row in enumerate(rows, start=2):
        alert = first(row, ["alert", "Alert", "signature", "classification", "label", "event_type"])
        ev = NormalizedEvent(
            source="ids",
            timestamp=parse_time(first(row, ["timestamp", "time", "Date/time"])),
            category="reconnaissance" if "scan" in alert.lower() else "detection",
            event_type=alert or "ids_alert",
            severity=first(row, ["priority", "Priority", "severity"], "medium"),
            src_ip=empty_to_none(strip_port(first(row, ["src_ip", "Source IP", "source", "sourceIP"]))),
            dst_ip=empty_to_none(strip_port(first(row, ["dst_ip", "Destination IP", "destination", "destIP"]))),
            src_port=empty_to_none(extract_port(first(row, ["src_port", "sourcePort", "source"]))),
            dst_port=empty_to_none(extract_port(first(row, ["dst_port", "destPort", "destination"]))),
            protocol=empty_to_none(first(row, ["protocol", "Protocol", "proto"])),
            label=empty_to_none(alert),
            raw_ref=f"ids_csv_line:{i}",
        )
        events.append(ev)
    return events


def normalize_security(rows):
    events = []
    for i, row in enumerate(rows, start=2):
        event_id = first(row, ["EventID", "event_id", "eventId"])
        account = first(row, ["TargetUserName", "SubjectUserName", "account", "user", "username"])
        ev = NormalizedEvent(
            source="windows_security",
            timestamp=parse_time(first(row, ["SystemTime", "TimeCreated", "timestamp", "time"])),
            category="identity",
            event_type=event_id_name(event_id),
            severity=severity_from_event_id(event_id),
            src_ip=empty_to_none(first(row, ["IpAddress", "src_ip", "Source IP", "ClientAddress"])),
            account=empty_to_none(account),
            host=empty_to_none(first(row, ["Computer", "host", "hostname", "WorkstationName"])),
            label=empty_to_none(event_id),
            raw_ref=f"security_csv_line:{i}",
            attrs={
                "event_id": event_id,
                "logon_type": first(row, ["LogonType"]),
                "service": first(row, ["ServiceName"]),
                "status": first(row, ["Status"]),
            },
        )
        events.append(ev)
    return events


def normalize_pcap(rows):
    events = []
    for i, row in enumerate(rows, start=2):
        proto = first(row, ["protocol", "Protocol", "ip_proto", "proto"])
        ev = NormalizedEvent(
            source="pcap",
            timestamp=parse_time(first(row, ["timestamp", "time", "Date/time"])),
            category="packet",
            event_type="packet_flow",
            severity="info",
            src_ip=empty_to_none(first(row, ["src_ip", "Source IP", "source", "sourceIP"])),
            dst_ip=empty_to_none(first(row, ["dst_ip", "Destination IP", "destination", "destIP"])),
            src_port=empty_to_none(first(row, ["src_port", "Source port", "sourcePort"])),
            dst_port=empty_to_none(first(row, ["dst_port", "Destination port", "destPort"])),
            protocol=empty_to_none(proto),
            label=empty_to_none(first(row, ["packet_info", "info", "label"])),
            raw_ref=f"pcap_csv_line:{i}",
            attrs={
                "packets": first(row, ["packets", "packet_count", "count"], "1"),
                "bytes": first(row, ["bytes", "length", "size"]),
            },
        )
        events.append(ev)
    return events


def normalize_nessus(rows):
    events = []
    for i, row in enumerate(rows, start=2):
        risk = first(row, ["Risk", "risk", "severity", "risk_factor"])
        host = first(row, ["Host", "host", "IP", "ip", "host_ip"])
        ev = NormalizedEvent(
            source="nessus",
            timestamp=parse_time(first(row, ["timestamp", "time", "scan_time"])),
            category="vulnerability",
            event_type="vulnerability_finding",
            severity=severity_from_risk(risk),
            src_ip=None,
            dst_ip=empty_to_none(host),
            dst_port=empty_to_none(first(row, ["Port", "port", "service_port"])),
            protocol=empty_to_none(first(row, ["Protocol", "protocol"])),
            host=empty_to_none(host),
            risk=empty_to_none(risk),
            label=empty_to_none(first(row, ["Plugin", "plugin_id", "Synopsis", "finding", "label"])),
            raw_ref=f"nessus_csv_line:{i}",
            attrs={
                "plugin_id": first(row, ["Plugin ID", "plugin_id", "plugin"]),
                "service": first(row, ["Service", "service", "Port"]),
                "synopsis": first(row, ["Synopsis", "synopsis", "finding"]),
            },
        )
        events.append(ev)
    return events


def build_unified_layer(events):
    event_dicts = [event.as_dict() for event in events]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "schema": {
            "event_keys": [
                "source",
                "timestamp",
                "category",
                "event_type",
                "severity",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "account",
                "host",
                "risk",
                "label",
                "raw_ref",
                "attrs",
            ],
            "entity_types": ["ip", "host", "account", "port"],
            "join_dimensions": ["time", "ip", "host", "account", "source_target", "port", "protocol", "risk"],
        },
        "summary": summarize(events),
        "events": event_dicts,
        "entities": build_entities(events),
        "flows": build_flows(events),
        "timelines": build_timelines(events),
        "risk": build_risk(events),
        "story_candidates": build_story_candidates(events),
    }


def summarize(events):
    return {
        "total_events": len(events),
        "by_source": counter_dict(event.source for event in events),
        "by_category": counter_dict(event.category for event in events),
        "by_severity": counter_dict(event.severity for event in events),
        "time_range": {
            "first": min((e.timestamp for e in events if e.timestamp), default=None),
            "last": max((e.timestamp for e in events if e.timestamp), default=None),
        },
    }


def build_entities(events):
    entities = {
        "ip": defaultdict(new_entity),
        "host": defaultdict(new_entity),
        "account": defaultdict(new_entity),
        "port": defaultdict(new_entity),
    }

    for event in events:
        for ip in [event.src_ip, event.dst_ip]:
            if ip:
                touch_entity(entities["ip"][ip], event)
        if event.host:
            touch_entity(entities["host"][event.host], event)
        if event.account:
            touch_entity(entities["account"][event.account], event)
        for port in [event.src_port, event.dst_port]:
            if port:
                touch_entity(entities["port"][str(port)], event)

        if event.src_ip and event.dst_ip:
            entities["ip"][event.src_ip]["related"].add(event.dst_ip)
            entities["ip"][event.dst_ip]["related"].add(event.src_ip)
        if event.account and event.src_ip:
            entities["account"][event.account]["related"].add(event.src_ip)
            entities["ip"][event.src_ip]["related"].add(event.account)
        if event.host and event.dst_ip:
            entities["host"][event.host]["related"].add(event.dst_ip)
            entities["ip"][event.dst_ip]["related"].add(event.host)

    return {
        kind: {
            key: finalize_entity(value)
            for key, value in sorted(group.items(), key=lambda item: item[1]["count"], reverse=True)
        }
        for kind, group in entities.items()
    }


def new_entity():
    return {
        "count": 0,
        "sources": Counter(),
        "categories": Counter(),
        "severities": Counter(),
        "risks": Counter(),
        "ports": Counter(),
        "related": set(),
        "first_seen": None,
        "last_seen": None,
    }


def touch_entity(entity, event):
    entity["count"] += 1
    entity["sources"][event.source] += 1
    if event.category:
        entity["categories"][event.category] += 1
    if event.severity:
        entity["severities"][event.severity] += 1
    if event.risk:
        entity["risks"][event.risk] += 1
    for port in [event.src_port, event.dst_port]:
        if port:
            entity["ports"][str(port)] += 1
    if event.timestamp:
        entity["first_seen"] = min(filter(None, [entity["first_seen"], event.timestamp]))
        entity["last_seen"] = max(filter(None, [entity["last_seen"], event.timestamp]))


def finalize_entity(entity):
    return {
        "count": entity["count"],
        "sources": dict(entity["sources"]),
        "categories": dict(entity["categories"]),
        "severities": dict(entity["severities"]),
        "risks": dict(entity["risks"]),
        "top_ports": top_list(entity["ports"]),
        "related": sorted(entity["related"])[:30],
        "first_seen": entity["first_seen"],
        "last_seen": entity["last_seen"],
    }


def build_flows(events):
    flows = Counter()
    by_source = defaultdict(Counter)
    for event in events:
        if event.src_ip and event.dst_ip:
            key = (event.src_ip, event.dst_ip, event.dst_port or "", event.protocol or "")
            flows[key] += 1
            by_source[event.source][key] += 1
    return {
        "top": [
            {"src_ip": s, "dst_ip": d, "dst_port": p, "protocol": proto, "count": c}
            for (s, d, p, proto), c in flows.most_common(100)
        ],
        "by_source": {
            source: [
                {"src_ip": s, "dst_ip": d, "dst_port": p, "protocol": proto, "count": c}
                for (s, d, p, proto), c in counter.most_common(50)
            ]
            for source, counter in by_source.items()
        },
    }


def build_timelines(events):
    by_hour = defaultdict(Counter)
    for event in events:
        bucket = hour_bucket(event.timestamp)
        by_hour[bucket][f"source:{event.source}"] += 1
        if event.category:
            by_hour[bucket][f"category:{event.category}"] += 1
        if event.severity:
            by_hour[bucket][f"severity:{event.severity}"] += 1
    return {
        "hourly": [
            {"time": bucket, **dict(counter)}
            for bucket, counter in sorted(by_hour.items())
        ]
    }


def build_risk(events):
    risks = Counter(e.risk for e in events if e.risk)
    risky_hosts = Counter()
    for event in events:
        if event.risk and (event.host or event.dst_ip):
            risky_hosts[event.host or event.dst_ip] += 1
    return {
        "by_risk": top_list(risks, 20),
        "top_assets": top_list(risky_hosts, 30),
    }


def build_story_candidates(events):
    candidates = []
    by_ip = defaultdict(list)
    for event in events:
        for ip in [event.src_ip, event.dst_ip, event.host]:
            if ip:
                by_ip[ip].append(event)

    for ip, related_events in by_ip.items():
        sources = {e.source for e in related_events}
        categories = {e.category for e in related_events}
        if len(sources) >= 2 or {"vulnerability", "reconnaissance"} <= categories:
            candidates.append(
                {
                    "entity": ip,
                    "event_count": len(related_events),
                    "sources": sorted(sources),
                    "categories": sorted(c for c in categories if c),
                    "first_seen": min((e.timestamp for e in related_events if e.timestamp), default=None),
                    "last_seen": max((e.timestamp for e in related_events if e.timestamp), default=None),
                }
            )
    return sorted(candidates, key=lambda x: x["event_count"], reverse=True)[:50]


def severity_from_firewall(operation):
    op = (operation or "").lower()
    if "deny" in op:
        return "medium"
    if "built" in op or "teardown" in op:
        return "info"
    return "info"


def severity_from_event_id(event_id):
    if str(event_id) in {"4672", "1102"}:
        return "high"
    if str(event_id) in {"4625", "4648"}:
        return "medium"
    return "info"


def severity_from_risk(risk):
    risk = (risk or "").lower()
    if "hole" in risk or "critical" in risk or "high" in risk:
        return "high"
    if "warning" in risk or "medium" in risk:
        return "medium"
    if "note" in risk or "low" in risk:
        return "low"
    return "info"


def event_id_name(event_id):
    names = {
        "4624": "successful_logon",
        "4634": "logoff",
        "4672": "special_privileges",
        "4768": "kerberos_tgt_request",
        "4769": "kerberos_service_ticket",
        "4770": "kerberos_ticket_renewed",
        "4776": "credential_validation",
        "1102": "audit_log_cleared",
    }
    return names.get(str(event_id), f"windows_event_{event_id or 'unknown'}")


def strip_port(value):
    value = str(value or "")
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def extract_port(value):
    value = str(value or "")
    if value.count(":") == 1:
        return value.split(":", 1)[1]
    return ""


def empty_to_none(value):
    value = str(value or "").strip()
    if value in {"", "(empty)", "-", "None", "null"}:
        return None
    return value


def counter_dict(values):
    return dict(Counter(v for v in values if v))


def top_list(counter, limit=15):
    return [{"key": str(k), "value": int(v)} for k, v in counter.most_common(limit)]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Build a unified analytical layer from separate cyber-security CSV files."
    )
    parser.add_argument("--firewall", type=Path, help="CSV with firewall/session events")
    parser.add_argument("--ids", type=Path, help="CSV with IDS alerts")
    parser.add_argument("--security", type=Path, help="CSV with Windows Security events")
    parser.add_argument("--pcap", type=Path, help="CSV with PCAP-derived packet/flow rows")
    parser.add_argument("--nessus", type=Path, help="CSV with Nessus findings")
    parser.add_argument("--out", type=Path, default=Path("unified_layer.json"), help="Output JSON path")
    return parser.parse_args()


def main():
    args = parse_args()
    events = []
    events.extend(normalize_firewall(read_csv(args.firewall)))
    events.extend(normalize_ids(read_csv(args.ids)))
    events.extend(normalize_security(read_csv(args.security)))
    events.extend(normalize_pcap(read_csv(args.pcap)))
    events.extend(normalize_nessus(read_csv(args.nessus)))

    layer = build_unified_layer(events)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(layer, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {args.out} with {len(events)} normalized events")


if __name__ == "__main__":
    main()
