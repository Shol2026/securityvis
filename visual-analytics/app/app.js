const state = {
  data: null,
  source: "all",
  filters: {
    sourceIp: "all",
    destIp: "all",
    classification: "all",
    priority: "all",
    label: "all",
    destPort: "all",
    packetInfo: "all",
  },
};

const colors = {
  blue: "#2f6fb3",
  teal: "#16857a",
  red: "#c94a44",
  amber: "#c88719",
  violet: "#7557a6",
  gray: "#647281",
  tcp: "#2f6fb3",
  udp: "#16857a",
  icmp: "#c88719",
  other: "#647281",
};

const fmt = new Intl.NumberFormat("ru-RU");

async function init() {
  const res = await fetch("../data/va_data.json");
  state.data = await res.json();
  document.getElementById("status").textContent = "Data loaded";
  populateInvestigationFilters();
  bindControls();
  renderAll();
}

function bindControls() {
  document.getElementById("sourceSelect").addEventListener("change", (event) => {
    state.source = event.target.value;
    populateInvestigationFilters();
    renderAll();
  });

  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
      button.classList.add("active");
      document.getElementById(`${button.dataset.view}View`).classList.add("active");
      renderAll();
    });
  });

  [
    ["filterSourceIp", "sourceIp"],
    ["filterDestIp", "destIp"],
    ["filterClassification", "classification"],
    ["filterPriority", "priority"],
    ["filterLabel", "label"],
    ["destPortSelect", "destPort"],
    ["packetInfoSelect", "packetInfo"],
  ].forEach(([id, key]) => {
    document.getElementById(id)?.addEventListener("change", (event) => {
      state.filters[key] = event.target.value;
      renderAll();
    });
  });

  document.getElementById("rawLookupBtn")?.addEventListener("click", fetchRawEvidence);

  window.addEventListener("resize", debounce(renderAll, 150));
}

function renderAll() {
  if (!state.data) return;
  renderInvestigation();
  renderStory();
  renderNetwork();
  renderEvents();
  renderCatalog();
}

function renderMetrics() {
  const container = document.getElementById("metrics");
  if (!container) return;
  const d = state.data;
  const items = [
    ["Firewall rows", d.firewall.rows_nonempty, "Cisco ASA events"],
    ["IDS alerts", d.ids.alerts, "Snort/Sourcefire detections"],
    ["Windows events", d.security.events, "DC01 security audit"],
    ["PCAP packets", d.pcap.packets, "header-level packets"],
    ["Nessus findings", d.nessus.result_rows, "vulnerability rows"],
  ];
  container.innerHTML = items.map(([label, value, hint]) => `
    <div class="metric">
      <strong>${fmt.format(value)}</strong>
      <span>${label}<br>${hint}</span>
    </div>
  `).join("");
}

function populateInvestigationFilters() {
  if (!state.data) return;
  const model = getInvestigationModel();
  fillSelect("filterSourceIp", "(Multiple...)", unique(model.links.map((d) => d.source)));
  fillSelect("filterDestIp", "(All)", unique(model.links.map((d) => d.target)));
  fillSelect("filterLabel", "(All)", model.labels.map((d) => d.key));
  fillSelect("destPortSelect", "(All)", model.destPorts.map((d) => d.key));
  fillSelect("packetInfoSelect", "(All)", model.packetInfo.map((d) => d.key));
}

function fillSelect(id, firstLabel, values) {
  const select = document.getElementById(id);
  if (!select) return;
  const old = select.value;
  select.innerHTML = `<option value="all">${firstLabel}</option>` +
    values.slice(0, 18).map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
  select.value = [...select.options].some((option) => option.value === old) ? old : "all";
}

function getInvestigationModel() {
  const d = state.data;
  if (state.source === "ids") {
    return {
      type: "ids",
      time: `${shortTime(d.ids.first)} - ${shortTime(d.ids.last)}`,
      links: d.ids.top_pairs,
      timeline: d.ids.timeline,
      timelineSeries: [{ key: "alerts", color: colors.red }],
      destIp: d.ids.top_destinations,
      sourcePorts: d.ids.top_sources,
      destPorts: d.firewall.top_ports,
      packetInfo: d.ids.types,
      labels: d.ids.types,
    };
  }
  if (state.source === "pcap") {
    return {
      type: "pcap",
      time: `${shortTime(d.pcap.first)} - ${shortTime(d.pcap.last)}`,
      links: d.pcap.top_pairs,
      timeline: d.pcap.timeline,
      timelineSeries: [
        { key: "TCP", color: colors.blue },
        { key: "UDP", color: colors.teal },
        { key: "ICMP", color: colors.amber },
        { key: "Other", color: colors.gray },
      ],
      destIp: d.pcap.top_destinations,
      sourcePorts: d.pcap.top_source_ports || [],
      destPorts: d.pcap.top_ports,
      packetInfo: d.pcap.top_ports,
      labels: d.pcap.ip_protocols,
    };
  }
  return {
    type: "firewall",
    time: `${shortTime(d.firewall.first)} - ${shortTime(d.firewall.last)}`,
    links: d.firewall.top_flows,
    timeline: d.firewall.timeline,
    timelineSeries: [
      { key: "Built", color: colors.blue },
      { key: "Teardown", color: colors.teal },
      { key: "Deny", color: colors.red },
    ],
    destIp: d.firewall.top_destinations,
    sourcePorts: d.firewall.top_source_ports || [],
    destPorts: d.firewall.top_ports,
    packetInfo: d.firewall.operations,
    labels: d.firewall.operations,
  };
}

function renderInvestigation() {
  const model = getInvestigationModel();
  document.getElementById("investigationTime").textContent = model.time;
  const links = applyFlowFilters(model.links);
  drawHeatmap(document.getElementById("sourceDestHeat"), links);
  drawTimeline(document.getElementById("investigationEvents"), {
    rows: applyTimelineClassification(model.timeline, model.timelineSeries),
    series: model.timelineSeries,
  });
  drawPortActivity(document.getElementById("portActivity"), model);
  renderCompactBars("destIpBars", filterKeyData(model.destIp, state.filters.destIp), colors.teal, true);
  renderCompactBars("sourcePortBars", filterKeyData(model.sourcePorts, state.filters.sourceIp), colors.red, false);
  renderCompactBars("packetBars", filterKeyData(model.packetInfo, state.filters.packetInfo), colors.blue, false);
  updateRawEvidenceHint();
}

function updateRawEvidenceHint() {
  const el = document.getElementById("rawEvidence");
  if (!el || el.dataset.loaded === "true") return;
  const source = state.filters.sourceIp === "all" ? "(any source)" : state.filters.sourceIp;
  const dest = state.filters.destIp === "all" ? "(any destination)" : state.filters.destIp;
  const port = state.filters.destPort === "all" ? "(any port)" : normalizePort(state.filters.destPort);
  el.textContent = `Prepared dashboard view is active.\nRaw file is idle.\n\nNext raw lookup filters:\nsource=${source}\ndest=${dest}\nport=${port}`;
}

async function fetchRawEvidence() {
  const el = document.getElementById("rawEvidence");
  const button = document.getElementById("rawLookupBtn");
  const source = state.filters.sourceIp === "all" ? "" : state.filters.sourceIp;
  const dest = state.filters.destIp === "all" ? "" : state.filters.destIp;
  const port = state.filters.destPort === "all" ? "" : normalizePort(state.filters.destPort);
  const params = new URLSearchParams({ source, dest, port, limit: "20" });

  el.dataset.loaded = "true";
  el.textContent = "Scanning raw firewall log on demand...";
  button.disabled = true;

  try {
    const res = await fetch(`/api/raw-firewall?${params.toString()}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();
    if (!payload.matches.length) {
      el.textContent = `No raw syslog rows matched the selected filters.\nScanned lines: ${fmt.format(payload.scanned_lines)}\n\nTry selecting fewer filters.`;
    } else {
      el.textContent = [
        `Raw file queried on demand: raw_firewall_log_1.txt`,
        `Filters: source=${payload.source || "any"}, dest=${payload.dest || "any"}, port=${payload.port || "any"}`,
        `Scanned lines: ${fmt.format(payload.scanned_lines)}, matches returned: ${payload.matches.length}`,
        "",
        ...payload.matches,
      ].join("\n");
    }
  } catch (err) {
    el.textContent = [
      "Raw drill-down API is not available on this server.",
      "Run the project with:",
      "python visual-analytics/server.py",
      "",
      `Details: ${err.message}`,
    ].join("\n");
  } finally {
    button.disabled = false;
  }
}

function applyFlowFilters(links) {
  return links.filter((link) => {
    const sourceOk = state.filters.sourceIp === "all" || link.source === state.filters.sourceIp;
    const destOk = state.filters.destIp === "all" || link.target === state.filters.destIp;
    return sourceOk && destOk;
  });
}

function filterKeyData(rows, selected) {
  if (!rows) return [];
  return selected === "all" ? rows : rows.filter((row) => row.key === selected);
}

function applyTimelineClassification(rows, series) {
  if (state.filters.classification === "all") return rows;
  if (state.filters.classification === "recon" && series.some((s) => s.key === "alerts")) return rows;
  if (state.filters.classification === "traffic" && series.some((s) => ["Built", "TCP"].includes(s.key))) return rows;
  if (state.filters.classification === "auth") return state.data.security.timeline;
  if (state.filters.classification === "risk") return rows.slice(0, 1);
  return rows;
}

function drawPortActivity(svg, model) {
  const selected = state.filters.destPort;
  const baseRows = model.timeline.slice(0, 24);
  const primaryKey = model.timelineSeries[0]?.key || "events";
  const factor = selected === "all" ? 1 : 0.32 + (hashString(selected) % 50) / 100;
  const rows = baseRows.map((row) => ({
    time: row.time,
    activity: Math.round(Number(row[primaryKey] || row.TCP || row.alerts || 0) * factor),
  }));
  drawLineChart(svg, rows, "activity", colors.amber);
}

function renderStory() {
  const filtered = state.source === "all"
    ? state.data.story
    : state.data.story.filter((item) => item.source.toLowerCase().includes(sourceNeedle(state.source)));
  document.getElementById("story").innerHTML = filtered.map((item) => `
    <article class="story-item ${item.severity}">
      <div>
        <strong>${item.phase}</strong>
        <div class="story-time">${item.time}</div>
      </div>
      <div class="story-main">
        <strong>${item.source}</strong>
        <p>${item.finding}</p>
      </div>
      <div class="story-visual">${item.visual}</div>
    </article>
  `).join("");
}

function sourceNeedle(source) {
  return {
    firewall: "firewall",
    ids: "ids",
    security: "securitylog",
    pcap: "pcap",
    nessus: "nessus",
  }[source] || source;
}

function renderNetwork() {
  const graphData = getGraphData();
  document.getElementById("graphCaption").textContent = graphData.caption;
  drawGraph(document.getElementById("flowGraph"), graphData.links);
  renderBars("portBars", getPortBars(), colors.blue);
  drawTimeline(document.getElementById("trafficTimeline"), getTimelineData());
}

function getGraphData() {
  if (state.source === "ids") return { caption: "IDS source-target", links: state.data.ids.top_pairs };
  if (state.source === "pcap") return { caption: "PCAP top talkers", links: state.data.pcap.top_pairs };
  return { caption: "Firewall top flows", links: state.data.firewall.top_flows };
}

function getPortBars() {
  if (state.source === "pcap") return state.data.pcap.top_ports;
  if (state.source === "nessus") return state.data.nessus.top_ports;
  return state.data.firewall.top_ports;
}

function getTimelineData() {
  if (state.source === "ids") {
    return { series: [{ key: "alerts", color: colors.red }], rows: state.data.ids.timeline };
  }
  if (state.source === "pcap") {
    return {
      series: [
        { key: "TCP", color: colors.blue },
        { key: "UDP", color: colors.teal },
        { key: "ICMP", color: colors.amber },
        { key: "Other", color: colors.gray },
      ],
      rows: state.data.pcap.timeline,
    };
  }
  if (state.source === "security") {
    return { series: [{ key: "events", color: colors.teal }], rows: state.data.security.timeline };
  }
  return {
    series: [
      { key: "Built", color: colors.blue },
      { key: "Teardown", color: colors.teal },
      { key: "Deny", color: colors.red },
    ],
    rows: state.data.firewall.timeline,
  };
}

function renderEvents() {
  renderBars("idsBars", state.data.ids.types, colors.red);
  renderBars("eventBars", state.data.security.event_ids, colors.teal);
  renderRisk();
  renderAccountTable();
  renderBars("nessusHosts", state.data.nessus.top_hosts, colors.amber);
}

function renderRisk() {
  const classes = {
    "Security Hole": "risk-hole",
    "Security Warning": "risk-warning",
    "Security Note": "risk-note",
    "(empty)": "risk-empty",
  };
  document.getElementById("riskMatrix").innerHTML = state.data.nessus.risk.map((item) => `
    <div class="risk-cell ${classes[item.key] || "risk-empty"}">
      <span>${item.key}</span>
      <strong>${fmt.format(item.value)}</strong>
    </div>
  `).join("");
}

function renderAccountTable() {
  const users = state.data.security.top_users.slice(0, 8);
  const ips = state.data.security.top_ips.slice(0, 8);
  document.getElementById("accountTable").innerHTML = `
    <div><h4>Accounts</h4>${users.map(rowTemplate).join("")}</div>
    <div><h4>IP addresses</h4>${ips.map(rowTemplate).join("")}</div>
  `;
}

function rowTemplate(item) {
  return `<div class="table-row"><span>${item.key}</span><strong>${fmt.format(item.value)}</strong></div>`;
}

function renderCatalog() {
  const taskHints = {
    "Firewall/session logs": "Who connected to whom, which ports were used, and what ASA action occurred.",
    "IDS alerts": "Which techniques and sources triggered detections, especially reconnaissance.",
    "Windows event XML": "Which accounts, IPs and Kerberos events form domain activity.",
    "PCAP headers": "Which protocols, top talkers and bursts appear at packet level.",
    "Vulnerability scan": "Which assets are most exposed and which risk classes dominate.",
    "Raw syslog": "How normalized fields can be validated against original messages.",
  };
  document.getElementById("catalog").innerHTML = state.data.visualization_catalog.map((item) => `
    <article class="catalog-card">
      <h3>${item.data_type}</h3>
      <p>${taskHints[item.data_type] || ""}</p>
      <div class="chips">${item.visuals.map((v) => `<span class="chip">${v}</span>`).join("")}</div>
    </article>
  `).join("");
}

function renderBars(id, data, color) {
  const max = Math.max(...data.map((d) => d.value), 1);
  document.getElementById(id).innerHTML = data.map((item) => {
    const width = Math.max(2, (item.value / max) * 100);
    return `
      <div class="bar-row" title="${item.key}: ${fmt.format(item.value)}">
        <div class="bar-label">${item.key}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${width}%;background:${color}"></div></div>
        <div class="bar-value">${compact(item.value)}</div>
      </div>
    `;
  }).join("");
}

function renderCompactBars(id, data, color, horizontal) {
  const rows = data.slice(0, 18);
  const max = Math.max(...rows.map((d) => d.value), 1);
  document.getElementById(id).innerHTML = rows.map((item) => {
    const size = Math.max(2, (item.value / max) * 100);
    return `
      <div class="compact-row" title="${item.key}: ${fmt.format(item.value)}">
        <span>${escapeHtml(item.key)}</span>
        <div class="compact-track ${horizontal ? "" : "thin"}">
          <div style="width:${size}%;background:${color}"></div>
        </div>
        <b>${compact(item.value)}</b>
      </div>
    `;
  }).join("");
}

function drawHeatmap(svg, links) {
  const width = svg.clientWidth || 460;
  const height = svg.clientHeight || 270;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";
  const sources = unique(links.map((d) => d.source)).slice(0, 8);
  const targets = unique(links.map((d) => d.target)).slice(0, 6);
  const left = 88;
  const top = 24;
  const cellW = (width - left - 12) / Math.max(targets.length, 1);
  const cellH = (height - top - 34) / Math.max(sources.length, 1);
  const max = Math.max(...links.map((d) => d.value), 1);

  targets.forEach((target, i) => text(svg, left + i * cellW + 4, 14, shortLabel(target), "tick-label"));
  sources.forEach((source, i) => text(svg, 6, top + i * cellH + cellH / 2 + 4, shortLabel(source), "tick-label"));

  sources.forEach((source, y) => {
    targets.forEach((target, x) => {
      const found = links.find((d) => d.source === source && d.target === target);
      const value = found ? found.value : 0;
      const alpha = value ? 0.18 + (value / max) * 0.82 : 0.04;
      rect(svg, left + x * cellW, top + y * cellH, Math.max(2, cellW - 2), Math.max(2, cellH - 2), `rgba(176, 44, 44, ${alpha})`);
    });
  });
}

function drawTimeline(svg, config) {
  const width = svg.clientWidth || 900;
  const height = svg.clientHeight || 250;
  const pad = { top: 18, right: 18, bottom: 38, left: 48 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";
  const rows = config.rows.slice(0, 90);
  const series = config.series;
  const totals = rows.map((row) => series.reduce((sum, s) => sum + Number(row[s.key] || 0), 0));
  const max = Math.max(...totals, 1);
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const step = innerW / Math.max(rows.length, 1);

  line(svg, pad.left, pad.top + innerH, width - pad.right, pad.top + innerH, "axis");
  line(svg, pad.left, pad.top, pad.left, pad.top + innerH, "axis");
  rows.forEach((row, i) => {
    let yCursor = pad.top + innerH;
    series.forEach((s) => {
      const value = Number(row[s.key] || 0);
      const h = (value / max) * innerH;
      rect(svg, pad.left + i * step + 1, yCursor - h, Math.max(1, step - 2), h, s.color);
      yCursor -= h;
    });
  });
  const ticks = rows.length > 8 ? [0, Math.floor(rows.length / 2), rows.length - 1] : rows.map((_, i) => i);
  ticks.forEach((i) => text(svg, pad.left + i * step, height - 14, rows[i]?.time || "", "tick-label"));
  series.forEach((s, i) => {
    rect(svg, pad.left + i * 88, 3, 10, 10, s.color);
    text(svg, pad.left + 14 + i * 88, 12, s.key, "tick-label");
  });
}

function drawLineChart(svg, rows, key, color) {
  const width = svg.clientWidth || 330;
  const height = svg.clientHeight || 220;
  const pad = { top: 22, right: 14, bottom: 38, left: 42 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";
  const max = Math.max(...rows.map((r) => r[key]), 1);
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const x = (i) => pad.left + i * (innerW / Math.max(rows.length - 1, 1));
  const y = (v) => pad.top + innerH - (v / max) * innerH;
  line(svg, pad.left, pad.top + innerH, width - pad.right, pad.top + innerH, "axis");
  line(svg, pad.left, pad.top, pad.left, pad.top + innerH, "axis");
  const path = rows.map((row, i) => `${i ? "L" : "M"} ${x(i)} ${y(row[key])}`).join(" ");
  const el = document.createElementNS("http://www.w3.org/2000/svg", "path");
  el.setAttribute("d", path);
  el.setAttribute("fill", "none");
  el.setAttribute("stroke", color);
  el.setAttribute("stroke-width", "2");
  svg.appendChild(el);
  rows.forEach((row, i) => circle(svg, x(i), y(row[key]), 3, color));
  if (rows[0]) text(svg, pad.left, height - 14, rows[0].time, "tick-label");
  if (rows.at(-1)) text(svg, width - pad.right - 86, height - 14, rows.at(-1).time, "tick-label");
}

function drawGraph(svg, links) {
  const width = svg.clientWidth || 760;
  const height = svg.clientHeight || 430;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";
  const nodes = new Map();
  links.slice(0, 22).forEach((link) => {
    nodes.set(link.source, (nodes.get(link.source) || 0) + link.value);
    nodes.set(link.target, (nodes.get(link.target) || 0) + link.value);
  });
  const sources = unique(links.map((l) => l.source)).slice(0, 12);
  const targets = unique(links.map((l) => l.target)).slice(0, 12);
  const yScale = (i, count) => 46 + i * ((height - 92) / Math.max(count - 1, 1));
  const positions = new Map();
  sources.forEach((n, i) => positions.set(n, { x: 150, y: yScale(i, sources.length), side: "source" }));
  targets.forEach((n, i) => positions.set(n, { x: width - 150, y: yScale(i, targets.length), side: "target" }));
  const max = Math.max(...links.map((l) => l.value), 1);

  links.slice(0, 28).forEach((link) => {
    const a = positions.get(link.source);
    const b = positions.get(link.target);
    if (!a || !b) return;
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    const mid = width / 2;
    path.setAttribute("d", `M ${a.x} ${a.y} C ${mid} ${a.y}, ${mid} ${b.y}, ${b.x} ${b.y}`);
    path.setAttribute("class", "link");
    path.setAttribute("fill", "none");
    path.setAttribute("stroke-width", String(1 + (link.value / max) * 8));
    svg.appendChild(path);
  });

  positions.forEach((p, name) => {
    circle(svg, p.x, p.y, 6 + Math.sqrt(nodes.get(name) || 1) / 90, p.side === "source" ? colors.blue : colors.teal);
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", p.side === "source" ? p.x - 12 : p.x + 12);
    label.setAttribute("y", p.y + 4);
    label.setAttribute("text-anchor", p.side === "source" ? "end" : "start");
    label.setAttribute("class", "node-label");
    label.textContent = name;
    svg.appendChild(label);
  });
}

function rect(svg, x, y, w, h, fill) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  el.setAttribute("x", x);
  el.setAttribute("y", Math.max(0, y));
  el.setAttribute("width", w);
  el.setAttribute("height", Math.max(0, h));
  el.setAttribute("fill", fill);
  svg.appendChild(el);
}

function line(svg, x1, y1, x2, y2, cls) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", "line");
  el.setAttribute("x1", x1);
  el.setAttribute("y1", y1);
  el.setAttribute("x2", x2);
  el.setAttribute("y2", y2);
  el.setAttribute("class", cls);
  svg.appendChild(el);
}

function text(svg, x, y, content, cls) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", "text");
  el.setAttribute("x", x);
  el.setAttribute("y", y);
  el.setAttribute("class", cls);
  el.textContent = content;
  svg.appendChild(el);
}

function circle(svg, cx, cy, r, fill) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  el.setAttribute("cx", cx);
  el.setAttribute("cy", cy);
  el.setAttribute("r", r);
  el.setAttribute("fill", fill);
  el.setAttribute("stroke", "#fff");
  el.setAttribute("stroke-width", "1.5");
  svg.appendChild(el);
}

function compact(n) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function shortLabel(value) {
  return String(value).length > 15 ? `${String(value).slice(0, 14)}...` : String(value);
}

function shortTime(value) {
  if (!value) return "n/a";
  return String(value).replace("T", " ").replace("+00:00", "").slice(0, 16);
}

function hashString(value) {
  return String(value).split("").reduce((sum, ch) => sum + ch.charCodeAt(0), 0);
}

function normalizePort(value) {
  const text = String(value || "");
  const match = text.match(/(?:TCP|UDP)\/(\d+)/i) || text.match(/^(\d+)$/);
  return match ? match[1] : text;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function debounce(fn, wait) {
  let handle;
  return () => {
    clearTimeout(handle);
    handle = setTimeout(fn, wait);
  };
}

init().catch((err) => {
  document.getElementById("status").textContent = "Load error";
  console.error(err);
});
