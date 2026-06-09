const state = {
  data: null,
  source: "all",
  comboLayer: "all",
  networkEvidenceSignature: null,
  networkEvidenceSource: "all",
  networkEvidenceDirection: "all",
  networkEvidenceTimeGranularity: "day",
  networkEvidenceTime: null,
  networkEvidenceTimeRange: null,
  networkEvidenceIpPair: null,
  networkEvidencePortSelections: [],
  hostIdentityTimeRange: null,
  investigationContext: {
    ips: [],
    source: "Network Evidence",
    label: "",
  },
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
  const res = await fetch("../data/va_data.json?v=20260607-detail-all-days", { cache: "no-store" });
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
  document.querySelectorAll(".pivot-btn").forEach((button) => {
    button.addEventListener("click", () => switchView(button.dataset.targetView));
  });
  document.querySelectorAll(".combo-layer-btn").forEach((button) => {
    button.addEventListener("click", () => {
      state.comboLayer = button.dataset.comboLayer || "all";
      document.querySelectorAll(".combo-layer-btn").forEach((b) => b.classList.remove("active"));
      button.classList.add("active");
      renderCombinationDashboard();
    });
  });
  const newNetDirectionSelect = document.getElementById("newNetDirectionSelect");
  if (newNetDirectionSelect) {
    newNetDirectionSelect.addEventListener("change", (event) => {
      state.networkEvidenceDirection = event.target.value || "all";
      state.networkEvidenceSignature = null;
      renderNetworkEvidenceNewDashboard();
    });
  }
  const newNetEvidenceSourceSelect = document.getElementById("newNetEvidenceSourceSelect");
  if (newNetEvidenceSourceSelect) {
    newNetEvidenceSourceSelect.addEventListener("change", (event) => {
      state.networkEvidenceSource = event.target.value || "all";
      state.networkEvidenceSignature = null;
      if (state.networkEvidenceSource !== "firewall") state.networkEvidenceDirection = "all";
      renderNetworkEvidenceNewDashboard();
    });
  }
  const newNetTimeGranularitySelect = document.getElementById("newNetTimeGranularitySelect");
  if (newNetTimeGranularitySelect) {
    newNetTimeGranularitySelect.addEventListener("change", (event) => {
      state.networkEvidenceTimeGranularity = event.target.value || "hour";
      state.networkEvidenceTime = null;
      state.networkEvidenceTimeRange = null;
      state.networkEvidencePortSelections = [];
      renderNetworkEvidenceNewDashboard();
    });
  }
  ["newNetTimeCursorRange"].forEach((id) => {
    const slider = document.getElementById(id);
    slider?.addEventListener("input", applyNewNetworkTimeSlider);
    slider?.addEventListener("change", applyNewNetworkTimeSlider);
  });
  document.getElementById("newNetTimeStatus")?.addEventListener("click", () => {
    state.networkEvidenceTime = null;
    state.networkEvidenceTimeRange = null;
    state.networkEvidenceIpPair = null;
    setInvestigationContext([], "", "Network Evidence");
    renderNetworkEvidenceNewDashboard();
  });
  document.getElementById("newNetIpStatus")?.addEventListener("click", () => {
    state.networkEvidenceIpPair = null;
    setInvestigationContext([], "", "Network Evidence");
    renderNetworkEvidenceNewDashboard();
  });
  document.getElementById("newNetPortStatus")?.addEventListener("click", () => {
    state.networkEvidencePortSelections = [];
    renderNetworkEvidenceNewDashboard();
  });
  document.getElementById("newNetPortTooltip")?.addEventListener("click", (event) => {
    event.currentTarget.hidden = true;
  });
  document.getElementById("newNetDrawerClose")?.addEventListener("click", closeNewNetworkDetailDrawer);
  window.addEventListener("resize", debounce(renderAll, 150));
}

function switchView(viewName) {
  if (!viewName) return;
  const tab = document.querySelector(`.tab[data-view="${viewName}"]`);
  const view = document.getElementById(`${viewName}View`);
  if (!tab || !view) return;
  document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  tab.classList.add("active");
  view.classList.add("active");
  renderAll();
}

function syncNetworkEvidenceControls() {
  const sourceSelect = document.getElementById("newNetEvidenceSourceSelect");
  const directionSelect = document.getElementById("newNetDirectionSelect");
  const hint = document.getElementById("newNetFilterHint");
  const granularitySelect = document.getElementById("newNetTimeGranularitySelect");
  if (sourceSelect) sourceSelect.value = state.networkEvidenceSource || "all";
  if (granularitySelect) granularitySelect.value = state.networkEvidenceTimeGranularity || "hour";
  if (directionSelect) {
    directionSelect.value = state.networkEvidenceDirection || "all";
    directionSelect.disabled = (state.networkEvidenceSource || "all") !== "firewall";
  }
  if (hint) {
    const source = state.networkEvidenceSource || "all";
    hint.textContent = source === "firewall"
      ? "Direction filters Firewall evidence."
      : "Direction is active only when Evidence Source is Firewall.";
  }
}

function renderAll() {
  if (!state.data) return;
  [
    renderInvestigation,
    renderCombinationDashboard,
    renderNetworkEvidenceNewDashboard,
    renderFirewall,
    renderIdsDashboard,
    renderPcapDashboard,
    renderWindowsLogsDashboard,
    renderNessusDashboard,
    renderStory,
    renderNetwork,
    renderEvents,
    renderCatalog,
  ].forEach((renderFn) => safeRender(renderFn));
}

function safeRender(renderFn) {
  try {
    renderFn();
  } catch (error) {
    console.error(`Render failed in ${renderFn.name}`, error);
    const status = document.getElementById("status");
    if (status) status.textContent = `Render warning: ${renderFn.name}`;
  }
}

function renderCombinationDashboard() {
  const combo = buildCombinationModel();
  const series = [
    { key: "Firewall", color: colors.blue, layer: "firewall" },
    { key: "IDS", color: colors.red, layer: "ids" },
    { key: "PCAP", color: colors.teal, layer: "pcap" },
  ].filter((item) => state.comboLayer === "all" || item.layer === state.comboLayer);
  drawTimeline(document.getElementById("comboTimeline"), {
    rows: combo.timeline,
    series,
  });
  drawMatrixHeatmap(
    document.getElementById("comboIpHeatmap"),
    combo.ipPairs,
    { rowLimit: 12, colLimit: 10, color: "red" }
  );
  drawCombinationTimePortScatter(document.getElementById("comboTimePortScatter"), combo.timePorts);
  drawCombinationParallelCoordinates(document.getElementById("comboParallelCoordinates"), combo.parallelRows);
  renderCombinationLayerSummary(combo);
}

function renderNetworkEvidenceNewDashboard() {
  syncNetworkEvidenceControls();
  const sourceLayer = state.networkEvidenceSource || "all";
  const direction = sourceLayer === "firewall" ? state.networkEvidenceDirection : "all";
  const combo = buildCombinationModel(sourceLayer, { direction });
  const selectedSignature = state.networkEvidenceSignature;
  const selectedTime = state.networkEvidenceTime;
  const selectedTimeRange = state.networkEvidenceTimeRange;
  const timeGranularity = state.networkEvidenceTimeGranularity || "hour";
  const selectedIpPair = state.networkEvidenceIpPair;
  const selectedPortRows = state.networkEvidencePortSelections || [];
  const timelineRows = buildNetworkEvidenceTimelineRows(sourceLayer, direction, timeGranularity, selectedSignature);
  const timelineLimit = timeGranularity === "day" ? 30 : timeGranularity === "second" ? 220 : timeGranularity === "minute" ? 160 : timeGranularity === "ten" ? 140 : 90;
  let visibleTimePorts = selectedSignature ? buildIdsSignatureTimePorts(selectedSignature) : combo.timePorts;
  if (selectedTimeRange) visibleTimePorts = buildNetworkEvidenceRowsForTimeRange(sourceLayer, direction, selectedTimeRange, selectedSignature);
  else if (selectedTime) visibleTimePorts = buildNetworkEvidenceRowsForHour(sourceLayer, direction, selectedTime, selectedSignature);
  if (selectedIpPair) visibleTimePorts = filterRowsByIpPair(visibleTimePorts, selectedIpPair);
  let visibleIpPairs = selectedSignature ? buildIdsSignatureIpPairs(selectedSignature, selectedTime) : combo.ipPairs;
  if ((selectedTime || selectedTimeRange) && !selectedSignature) visibleIpPairs = buildIpPairsFromEvidenceRows(visibleTimePorts);
  if ((selectedTime || selectedTimeRange) && selectedSignature) visibleIpPairs = buildIpPairsFromEvidenceRows(visibleTimePorts);
  const visibleIpPairsForHeatmap = visibleIpPairs;
  const visibleParallelRows = selectedTime || selectedTimeRange ? buildParallelRowsFromEvidenceRows(visibleTimePorts) : combo.parallelRows;
  const portFilteredRows = selectedPortRows.length ? filterRowsByPortSelections(visibleTimePorts, selectedPortRows) : visibleTimePorts;
  const dependentParallelRows = selectedPortRows.length || selectedIpPair
    ? buildParallelRowsFromEvidenceRows(portFilteredRows)
    : visibleParallelRows;
  drawTimeline(document.getElementById("newNetTimeline"), {
    rows: timelineRows,
    limit: timelineLimit,
    series: [
      { key: "Firewall", color: colors.blue },
      { key: "IDS", color: colors.red },
      { key: "PCAP", color: colors.teal },
    ],
  });
  drawMatrixHeatmap(
    document.getElementById("newNetIpHeatmap"),
    visibleIpPairsForHeatmap,
    { rowLimit: 12, colLimit: 10, color: "red" }
  );
  drawCombinationTimePortScatter(document.getElementById("newNetTimePortScatter"), visibleTimePorts);
  drawCombinationParallelCoordinates(document.getElementById("newNetParallelCoordinates"), dependentParallelRows);
  renderIdsSignatureBars(portFilteredRows);
  renderEvidenceCompositionMiniView(portFilteredRows);
  renderNetworkEvidenceTimeStatus();
  renderNetworkEvidenceIpStatus();
  renderNetworkEvidencePortStatus();
  syncNewNetworkTimeSlider(timelineRows);
  const visibleCombo = { ...combo, timeline: timelineRows.slice(0, timelineLimit), ipPairs: visibleIpPairsForHeatmap, timePorts: visibleTimePorts, parallelRows: dependentParallelRows };
  bindNetworkEvidenceNewClicks(visibleCombo);
  renderNetworkEvidenceNewDetail(
    selectedSignature
      ? { type: "signature", signature: selectedSignature }
      : selectedPortRows.length
        ? { type: "port_selections", selections: selectedPortRows }
      : selectedIpPair
        ? { type: "ip_pair", source: selectedIpPair.source, target: selectedIpPair.target }
      : selectedTimeRange
        ? { type: "time_range", range: selectedTimeRange }
      : selectedTime
        ? { type: "time", time: selectedTime }
        : { type: "none" },
    visibleCombo
  );
}

function renderNessusDashboard() {
  const nessus = state.data.nessus;
  const ips = selectedInvestigationIps();
  const details = filterDetailsByInvestigationIps(nessus.details || [], ["host", "ip_address"]);
  renderLinkedContext("riskExposureContext", "Risk & Exposure");
  drawNessusSeverityTreemap(document.getElementById("nessusSeverityTreemap"), ips.length ? buildRiskCountsFromNessusDetails(details) : nessus.risk || []);
  drawMatrixHeatmap(
    document.getElementById("nessusHostServiceHeat"),
    buildNessusHostServiceCells(details),
    { rowLimit: 10, colLimit: 10, color: "blue" }
  );
  drawNessusHostPluginScatter(document.getElementById("nessusHostPluginScatter"), details, ips.length ? [] : nessus.top_cve_plugin || nessus.top_plugins || []);
  drawNessusParallelCoordinates(document.getElementById("nessusParallelCoordinates"), details);
}

function renderWindowsLogsDashboard() {
  const sec = state.data.security;
  const ips = selectedInvestigationIps();
  const timeScopedRows = getSecurityUserHostRowsForHostContext(sec);
  const userHostRows = filterDetailsByInvestigationIps(timeScopedRows, ["host"]);
  const scopedUserHostRows = userHostRows.length || ips.length ? userHostRows : timeScopedRows;
  const eventSeries = (sec.event_ids || []).slice(0, 6).map((item, index) => ({
    key: item.key,
    color: [colors.teal, colors.blue, colors.amber, colors.red, colors.violet, colors.gray][index],
  }));
  drawTimeline(document.getElementById("winEventTimeline"), {
    rows: sec.timeline || [],
    series: eventSeries,
  });
  bindHostIdentityTimelineSelection(document.getElementById("winEventTimeline"), sec.timeline || []);
  renderHostIdentityContext();
  renderBars("winAccountBars", buildSecurityAccountBars(scopedUserHostRows, sec.top_users || []), colors.violet);
  renderBars("winIpBars", buildSecurityIpBars(scopedUserHostRows, sec.top_ips || []), colors.blue);
  drawMatrixHeatmap(
    document.getElementById("winUserHostHeat"),
    scopedUserHostRows.map((d) => ({ row: d.user, col: d.host, value: d.value, detail: d.event_id })),
    { rowLimit: 12, colLimit: 10, color: "blue" }
  );
}

function renderPcapDashboard() {
  const pcap = state.data.pcap;
  drawTimeline(document.getElementById("pcapTimeline"), {
    rows: pcap.timeline || [],
    series: [
      { key: "TCP", color: colors.blue },
      { key: "UDP", color: colors.teal },
      { key: "ICMP", color: colors.amber },
      { key: "Other", color: colors.gray },
    ],
  });
  drawMatrixHeatmap(
    document.getElementById("pcapSourceDestHeat"),
    pcap.top_pairs.map((d) => ({ row: d.source, col: d.target, value: d.value })),
    { rowLimit: 10, colLimit: 8, color: "red" }
  );
  drawPcapTimePortScatter(document.getElementById("pcapTimePortScatter"), pcap.packet_details || [], pcap.source_port_matrix || []);
  drawPcapParallelCoordinates(document.getElementById("pcapParallelCoordinates"), pcap);
}

function renderIdsDashboard() {
  const ids = state.data.ids;
  drawLineChart(document.getElementById("idsTimelineBySignature"), ids.timeline || [], "alerts", colors.red);
  drawCategoricalScatter(
    document.getElementById("idsSrcDstScatter"),
    ids.top_pairs.map((d) => ({ x: stripEndpoint(d.source), y: stripEndpoint(d.target), value: d.value }))
  );
  drawMatrixHeatmap(
    document.getElementById("idsSrcDstHeat"),
    ids.top_pairs.map((d) => ({ row: stripEndpoint(d.source), col: stripEndpoint(d.target), value: d.value })),
    { rowLimit: 10, colLimit: 8, color: "red" }
  );
  drawIdsParallelCoordinates(document.getElementById("idsParallelCoordinates"), ids);
}

function renderFirewall() {
  const fw = state.data.firewall;
  const sourcePortMatrix = fw.source_port_matrix || [];
  const suspiciousConnections = fw.suspicious_connections || [];
  drawTimeline(document.getElementById("fwTimeline"), {
    rows: fw.timeline,
    series: [
      { key: "Built", color: colors.blue },
      { key: "Teardown", color: colors.teal },
      { key: "Deny", color: colors.red },
      { key: "(empty)", color: colors.gray },
    ],
  });
  drawMatrixHeatmap(
    document.getElementById("fwSourceDestHeat"),
    fw.top_flows.map((d) => ({ row: d.source, col: d.target, value: d.value })),
    { rowLimit: 10, colLimit: 8, color: "red" }
  );
  drawFirewallTimePortScatter(document.getElementById("fwTimePortScatter"), suspiciousConnections, sourcePortMatrix);
  drawParallelCoordinates(document.getElementById("fwParallelCoordinates"), suspiciousConnections);
}

function buildCombinationModel(layer = state.comboLayer || "all", options = {}) {
  const fw = state.data.firewall || {};
  const ids = state.data.ids || {};
  const pcap = state.data.pcap || {};
  const selectedLayer = layer;
  const selectedDirection = options.direction || "all";
  const directionFilteredFirewall = selectedDirection !== "all";
  const firewallDirectionRows = directionFilteredFirewall ? getFirewallRowsByDirection(selectedDirection) : [];
  const includeEvidence = (evidence) => selectedLayer === "all" || selectedLayer === evidence.toLowerCase();
  const timelineMap = new Map();
  const addTimeline = (rows, key, getter) => {
    if (!includeEvidence(key)) return;
    (rows || []).forEach((row) => {
      const time = String(row.time || "").slice(0, 13) + ":00";
      if (!time || time === ":00") return;
      const item = timelineMap.get(time) || { time, Firewall: 0, IDS: 0, PCAP: 0 };
      item[key] += Number(getter(row) || 0);
      timelineMap.set(time, item);
    });
  };
  if (directionFilteredFirewall) {
    addTimeline(buildFirewallDirectionTimeline(firewallDirectionRows), "Firewall", (row) => (row.Built || 0) + (row.Teardown || 0) + (row.Deny || 0) + (row["(empty)"] || 0));
  } else {
    addTimeline(fw.timeline, "Firewall", (row) => (row.Built || 0) + (row.Teardown || 0) + (row.Deny || 0));
  }
  addTimeline(ids.timeline, "IDS", (row) => row.alerts || 0);
  addTimeline(pcap.timeline, "PCAP", (row) => (row.TCP || 0) + (row.UDP || 0) + (row.ICMP || 0) + (row.Other || 0));

  const pairCounter = new Map();
  const addPair = (source, target, value, evidence) => {
    if (!includeEvidence(evidence)) return;
    source = stripEndpoint(source);
    target = stripEndpoint(target);
    if (!source || !target || source === "(empty)" || target === "(empty)") return;
    const key = `${source}|${target}`;
    const current = pairCounter.get(key) || { row: source, col: target, value: 0, evidence: new Set() };
    current.value += Number(value || 0);
    current.evidence.add(evidence);
    pairCounter.set(key, current);
  };
  if (directionFilteredFirewall) {
    buildFirewallDirectionPairs(firewallDirectionRows).forEach((d) => addPair(d.source, d.target, d.value, "Firewall"));
  } else {
    (fw.top_flows || []).forEach((d) => addPair(d.source, d.target, d.value, "Firewall"));
  }
  (ids.top_pairs || []).forEach((d) => addPair(d.source, d.target, d.value, "IDS"));
  (pcap.top_pairs || []).forEach((d) => addPair(d.source, d.target, d.value, "PCAP"));
  const ipPairs = [...pairCounter.values()]
    .map((d) => ({ row: d.row, col: d.col, value: d.value, detail: [...d.evidence].join("+") }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 120);

  const timePorts = [];
  if (includeEvidence("Firewall")) (directionFilteredFirewall ? firewallDirectionRows : (fw.suspicious_connections || [])).slice(0, 250).forEach((row) => {
    timePorts.push({
      time: normalizeEventSecondTime(row.time),
      port: String(row.destination_port || ""),
      source: row.source_ip,
      target: row.destination_ip,
      evidence: "Firewall",
      label: row.action || row.operation || "ASA",
      value: 1,
    });
  });
  if (includeEvidence("IDS")) (ids.source_port_matrix || []).slice(0, 120).forEach((row, index) => {
    const time = (ids.timeline || [])[index % Math.max((ids.timeline || []).length, 1)]?.time || "IDS";
    timePorts.push({
      time: normalizeEventSecondTime(time),
      port: String(row.port || ""),
      source: row.source,
      target: "multiple",
      evidence: "IDS",
      label: shortSignature(row.signature || "IDS"),
      value: row.value,
    });
  });
  if (includeEvidence("PCAP")) (pcap.packet_details || []).slice(0, 250).forEach((row) => {
    timePorts.push({
      time: normalizeEventSecondTime(row.time),
      port: String(row.destination_port || ""),
      source: row.source,
      target: row.destination,
      evidence: "PCAP",
      label: row.protocol || "PCAP",
      value: Math.max(1, Number(row.length || 1)),
    });
  });

  const parallelRows = [
    ...(includeEvidence("Firewall") ? (directionFilteredFirewall ? buildFirewallDirectionParallelRows(firewallDirectionRows) : (fw.source_port_matrix || [])).slice(0, 50).map((row) => ({
      evidence: "Firewall",
      source: row.source,
      destination: "multiple",
      port: String(row.port),
      protocol: row.protocol || "unknown",
      label: "ASA flow",
      count_bucket: bucketCount(row.value),
      value: row.value,
    })) : []),
    ...(includeEvidence("IDS") ? (ids.source_port_matrix || []).slice(0, 50).map((row) => ({
      evidence: "IDS",
      source: row.source,
      destination: "multiple",
      port: String(row.port),
      protocol: "alert",
      label: shortSignature(row.signature || "IDS"),
      count_bucket: bucketCount(row.value),
      value: row.value,
    })) : []),
    ...(includeEvidence("PCAP") ? (pcap.source_port_matrix || []).slice(0, 50).map((row) => ({
      evidence: "PCAP",
      source: row.source,
      destination: "multiple",
      port: String(row.port),
      protocol: row.protocol || "unknown",
      label: "packet flow",
      count_bucket: bucketCount(row.value),
      value: row.value,
    })) : []),
  ];

  return {
    layer: selectedLayer,
    direction: selectedDirection,
    timeline: [...timelineMap.values()].sort((a, b) => a.time.localeCompare(b.time)).slice(0, 140),
    ipPairs,
    timePorts,
    parallelRows,
  };
}

function buildNetworkEvidenceSupportingMetrics(combo) {
  const fw = state.data.firewall || {};
  const ids = state.data.ids || {};
  const pcap = state.data.pcap || {};
  const destinationPortCounter = new Map();
  const addDestinationPort = (destination, port, value) => {
    destination = stripEndpoint(destination || "");
    port = String(port || "(empty)");
    if (!destination || destination === "(empty)") return;
    const key = `${destination}|${port}`;
    const current = destinationPortCounter.get(key) || { row: destination, col: port, value: 0 };
    current.value += Number(value || 0);
    destinationPortCounter.set(key, current);
  };

  (fw.top_flows || []).forEach((row) => addDestinationPort(row.target, row.port, row.value));
  (pcap.source_port_matrix || []).slice(0, 80).forEach((row) => addDestinationPort("PCAP multiple", row.port, row.value));
  (ids.source_port_matrix || []).slice(0, 80).forEach((row) => addDestinationPort("IDS multiple", row.port, row.value));

  const topPorts = [...new Set((combo.timePorts || [])
    .map((row) => String(row.port || "unknown"))
    .filter((port) => port && port !== "unknown")
    .slice(0, 240))]
    .slice(0, 5);
  const portPalette = [colors.blue, colors.teal, colors.amber, colors.red, colors.violet];
  const portTimelineMap = new Map();
  (combo.timePorts || []).forEach((row) => {
    const time = String(row.time || "").slice(0, 13) + ":00";
    if (!time || time === ":00") return;
    const port = topPorts.includes(String(row.port)) ? String(row.port) : "other";
    const current = portTimelineMap.get(time) || { time };
    current[port] = Number(current[port] || 0) + Number(row.value || 1);
    portTimelineMap.set(time, current);
  });
  const portKeys = [...topPorts, "other"].filter((port, index, list) => list.indexOf(port) === index);

  const evidenceCounts = [
    { key: "Firewall events", value: Number(fw.rows_nonempty || 0) },
    { key: "IDS alerts", value: Number(ids.alerts || 0) },
    { key: "PCAP packets", value: Number(pcap.packets || 0) },
  ];

  const priorityActionCounts = [
    ...(fw.operations || []).slice(0, 4).map((item) => ({ key: `FW ${item.key}`, value: item.value })),
    ...(ids.priorities || []).slice(0, 4).map((item) => ({ key: `IDS priority ${item.key}`, value: item.value })),
  ].filter((item) => item.value);

  return {
    destinationPortCells: [...destinationPortCounter.values()].sort((a, b) => b.value - a.value).slice(0, 120),
    portTimelineRows: [...portTimelineMap.values()].sort((a, b) => a.time.localeCompare(b.time)).slice(0, 90),
    portTimelineSeries: portKeys.map((port, index) => ({ key: port, color: portPalette[index] || colors.gray })),
    evidenceCounts,
    priorityActionCounts,
  };
}

function renderNetworkEvidenceTimeStatus() {
  const el = document.getElementById("newNetTimeStatus");
  if (!el) return;
  const label = timeGranularityLabel(state.networkEvidenceTimeGranularity || "hour");
  if (state.networkEvidenceTimeRange) {
    el.textContent = `${label} range: ${state.networkEvidenceTimeRange.start} - ${state.networkEvidenceTimeRange.end} | click to clear`;
  } else if (state.networkEvidenceTime) {
    el.textContent = `${label}: ${state.networkEvidenceTime} | click to clear`;
  } else {
    el.textContent = `${label}: click or drag across spikes to filter all views`;
  }
  el.classList.toggle("active-filter", Boolean(state.networkEvidenceTime || state.networkEvidenceTimeRange));
}

function syncNewNetworkTimeSlider(timelineRows) {
  const cursorInput = document.getElementById("newNetTimeCursorRange");
  const panel = document.getElementById("newNetTimeSliderPanel");
  const label = document.getElementById("newNetTimeSliderLabel");
  const startLabel = document.getElementById("newNetTimeStartLabel");
  const endLabel = document.getElementById("newNetTimeEndLabel");
  if (!cursorInput || !label || !startLabel || !endLabel) return;
  let sliderGranularity = state.networkEvidenceTimeGranularity || "hour";
  let rows = timelineRows || [];
  if (rows.length < 2 && sliderGranularity === "day") {
    const sourceLayer = state.networkEvidenceSource || "all";
    const direction = sourceLayer === "firewall" ? state.networkEvidenceDirection : "all";
    sliderGranularity = "hour";
    rows = buildNetworkEvidenceTimelineRows(sourceLayer, direction, sliderGranularity, state.networkEvidenceSignature);
  }
  const maxIndex = Math.max(0, rows.length - 1);
  cursorInput.min = "0";
  cursorInput.max = String(maxIndex);
  cursorInput.disabled = rows.length < 2;
  cursorInput.dataset.sliderGranularity = sliderGranularity;

  let startIndex = 0;
  let endIndex = maxIndex;
  if (state.networkEvidenceTimeRange) {
    startIndex = findNearestTimeIndex(rows, state.networkEvidenceTimeRange.start);
    endIndex = findNearestTimeIndex(rows, state.networkEvidenceTimeRange.end);
  } else if (state.networkEvidenceTime) {
    startIndex = findNearestTimeIndex(rows, state.networkEvidenceTime);
    endIndex = startIndex;
  }
  if (startIndex > endIndex) [startIndex, endIndex] = [endIndex, startIndex];
  cursorInput.value = String(startIndex);

  const startTime = rows[startIndex]?.time || "start";
  const endTime = rows[endIndex]?.time || "end";
  label.textContent = rows.length
    ? `${timeGranularityLabel(sliderGranularity)}: ${state.networkEvidenceTimeRange ? `${startTime} - ${endTime}` : startTime}`
    : "no time buckets available";
  startLabel.textContent = startTime;
  endLabel.textContent = state.networkEvidenceTimeRange ? endTime : "move slider to change time";
  if (panel) panel.classList.toggle("active-filter", Boolean(state.networkEvidenceTime || state.networkEvidenceTimeRange));
}

function applyNewNetworkTimeSlider() {
  const cursorInput = document.getElementById("newNetTimeCursorRange");
  if (!cursorInput) return;
  const sourceLayer = state.networkEvidenceSource || "all";
  const direction = sourceLayer === "firewall" ? state.networkEvidenceDirection : "all";
  const granularity = cursorInput.dataset.sliderGranularity || state.networkEvidenceTimeGranularity || "hour";
  const rows = buildNetworkEvidenceTimelineRows(sourceLayer, direction, granularity, state.networkEvidenceSignature);
  if (!rows.length) return;
  const index = Math.max(0, Math.min(rows.length - 1, Number(cursorInput.value || 0)));
  const selected = rows[index]?.time;
  if (!selected) return;
  state.networkEvidenceTimeGranularity = granularity;
  state.networkEvidenceTime = selected;
  state.networkEvidenceTimeRange = null;
  state.networkEvidencePortSelections = [];
  renderNetworkEvidenceNewDashboard();
}

function findNearestTimeIndex(rows, value) {
  const time = String(value || "");
  if (!rows.length || !time) return 0;
  const exact = rows.findIndex((row) => row.time === time);
  if (exact >= 0) return exact;
  const bucket = timeBucketKey(time, state.networkEvidenceTimeGranularity || "hour");
  const bucketIndex = rows.findIndex((row) => timeBucketKey(row.time, state.networkEvidenceTimeGranularity || "hour") === bucket);
  return bucketIndex >= 0 ? bucketIndex : 0;
}

function renderNetworkEvidenceIpStatus() {
  const el = document.getElementById("newNetIpStatus");
  if (!el) return;
  const pair = state.networkEvidenceIpPair;
  el.textContent = pair
    ? `selected IP pair: ${pair.source} -> ${pair.target} | click to clear`
    : "click an IP-pair cell to filter dependent views";
  el.classList.toggle("active-filter", Boolean(pair));
}

function renderNetworkEvidencePortStatus() {
  const el = document.getElementById("newNetPortStatus");
  if (!el) return;
  const selections = state.networkEvidencePortSelections || [];
  if (!selections.length) {
    el.textContent = "click one or more points to filter signatures and parallel coordinates";
  } else {
    el.textContent = `${selections.length} selected time-port point(s) | click to clear`;
  }
  el.classList.toggle("active-filter", Boolean(selections.length));
}

function filterRowsByHour(rows, selectedTime) {
  const granularity = state.networkEvidenceTimeGranularity || "hour";
  const selectedBucket = timeBucketKey(selectedTime, granularity);
  return (rows || []).filter((row) => timeBucketKey(row.time, granularity) === selectedBucket);
}

function filterRowsByTimeRange(rows, range) {
  const granularity = state.networkEvidenceTimeGranularity || "hour";
  const start = timeBucketKey(range.start, granularity);
  const end = timeBucketKey(range.end, granularity);
  return (rows || []).filter((row) => {
    const bucket = timeBucketKey(row.time, granularity);
    return bucket >= start && bucket <= end;
  });
}

function filterRowsByIpPair(rows, pair) {
  if (!pair) return rows || [];
  return (rows || []).filter((row) => {
    const source = stripEndpoint(row.source);
    const target = stripEndpoint(row.target);
    return source === pair.source && target === pair.target;
  });
}

function filterRowsByPortSelections(rows, selections) {
  const keys = new Set((selections || []).map(portSelectionKey));
  return (rows || [])
    .map((row, index) => ({ ...row, _pointId: row._pointId || `point-${index}` }))
    .filter((row) => keys.has(portSelectionKey(row)));
}

function portSelectionKey(selection) {
  if (selection._pointId) return selection._pointId;
  const granularity = state.networkEvidenceTimeGranularity || "hour";
  return [
    timeBucketKey(selection.time, granularity),
    String(selection.port || ""),
    selection.evidence || "",
    stripEndpoint(selection.source || ""),
    stripEndpoint(selection.target || ""),
    selection.label || "",
  ].join("|");
}

function togglePortSelection(selection) {
  const key = portSelectionKey(selection);
  const current = state.networkEvidencePortSelections || [];
  const exists = current.some((item) => portSelectionKey(item) === key);
  state.networkEvidencePortSelections = exists
    ? current.filter((item) => portSelectionKey(item) !== key)
    : [...current, selection];
}

function buildNetworkEvidenceRowsForHour(sourceLayer, direction, selectedTime, signature = null) {
  return buildNetworkEvidenceRowsForTimeRange(sourceLayer, direction, { start: selectedTime, end: selectedTime }, signature);
}

function buildNetworkEvidenceRowsForTimeRange(sourceLayer, direction, range, signature = null) {
  const granularity = state.networkEvidenceTimeGranularity || "hour";
  const start = timeBucketKey(range.start, granularity);
  const end = timeBucketKey(range.end, granularity);
  return buildNetworkEvidenceEventRows(sourceLayer, direction, signature)
    .filter((row) => {
      const bucket = timeBucketKey(row.time, granularity);
      return bucket >= start && bucket <= end;
    });
}

function hourKey(value) {
  return timeBucketKey(value, "hour").slice(0, 13);
}

function buildNetworkEvidenceTimelineRows(sourceLayer, direction, granularity = "hour", signature = null) {
  const counter = new Map();
  buildNetworkEvidenceEventRows(sourceLayer, direction, signature).forEach((row) => {
    const time = timeBucketKey(row.time, granularity);
    if (!time) return;
    const current = counter.get(time) || { time, Firewall: 0, IDS: 0, PCAP: 0 };
    current[row.evidence] = Number(current[row.evidence] || 0) + 1;
    counter.set(time, current);
  });
  const limit = granularity === "day" ? 30 : granularity === "hour" ? 140 : granularity === "ten" ? 220 : granularity === "second" ? 500 : 360;
  return [...counter.values()].sort((a, b) => a.time.localeCompare(b.time)).slice(0, limit);
}

function buildNetworkEvidenceEventRows(sourceLayer = "all", direction = "all", signature = null) {
  const include = (layer) => sourceLayer === "all" || sourceLayer === layer;
  const rows = [];
  if (include("firewall")) {
    const firewallRows = direction !== "all" ? getFirewallRowsByDirection(direction) : (state.data.firewall?.suspicious_connections || []);
    firewallRows.forEach((row) => rows.push({
      time: normalizeEventSecondTime(row.time),
      port: String(row.destination_port || ""),
      source: row.source_ip,
      target: row.destination_ip,
      evidence: "Firewall",
      label: row.action || row.operation || "ASA",
      protocol: row.protocol || "",
      direction: row.direction || "",
      raw_ref: row.raw_ref || "",
      value: 1,
    }));
  }
  if (include("ids")) {
    (state.data.ids?.sample_alerts || [])
      .filter((alert) => !signature || alert.signature === signature)
      .forEach((alert) => rows.push({
        time: normalizeEventSecondTime(alert.time),
        port: "alert",
        source: alert.source,
        target: alert.destination,
        evidence: "IDS",
        label: shortSignature(alert.signature || "IDS"),
        fullSignature: alert.signature || "IDS",
        priority: alert.priority || "n/a",
        raw_ref: alert.raw_ref || "",
        value: 1,
      }));
  }
  if (include("pcap")) {
    (state.data.pcap?.packet_details || []).forEach((row) => rows.push({
      time: normalizeEventSecondTime(row.time),
      port: String(row.destination_port || ""),
      source: row.source,
      target: row.destination,
      evidence: "PCAP",
      label: row.protocol || "PCAP",
      protocol: row.protocol || "",
      raw_ref: row.file ? `${row.file}${row.no ? ` #${row.no}` : ""}` : "",
      value: Math.max(1, Number(row.length || 1)),
    }));
  }
  return rows.filter((row) => row.time);
}

function timeBucketKey(value, granularity = "hour") {
  const second = normalizeEventSecondTime(value);
  if (!second) return "";
  if (granularity === "day") return second.slice(0, 10);
  if (granularity === "second") return second;
  const minute = second.slice(0, 16);
  if (granularity === "minute") return minute;
  if (granularity === "ten") {
    const base = minute.slice(0, 14);
    const minuteValue = Number(minute.slice(14, 16));
    const bucketMinute = String(Math.floor(minuteValue / 10) * 10).padStart(2, "0");
    return `${base}${bucketMinute}`;
  }
  return `${minute.slice(0, 13)}:00`;
}

function timeGranularityLabel(granularity) {
  if (granularity === "day") return "Day overview";
  if (granularity === "second") return "1 sec detail";
  if (granularity === "minute") return "1 min detail";
  if (granularity === "ten") return "10 min zoom";
  return "1 hour overview";
}

function buildIpPairsFromEvidenceRows(rows) {
  const counter = new Map();
  (rows || []).forEach((row) => {
    const source = stripEndpoint(row.source);
    const target = stripEndpoint(row.target);
    if (!source || !target || target === "multiple" || target === "IDS multiple") return;
    const key = `${source}|${target}`;
    const current = counter.get(key) || { row: source, col: target, value: 0, detail: row.evidence || "evidence" };
    current.value += Number(row.value || 1);
    counter.set(key, current);
  });
  return [...counter.values()].sort((a, b) => b.value - a.value).slice(0, 120);
}

function buildParallelRowsFromEvidenceRows(rows) {
  return (rows || []).slice(0, 120).map((row) => ({
    evidence: row.evidence || "Network",
    source: stripEndpoint(row.source || ""),
    destination: stripEndpoint(row.target || "multiple"),
    port: String(row.port || "n/a"),
    protocol: row.label || "unknown",
    label: row.label || row.evidence || "evidence",
    count_bucket: bucketCount(row.value || 1),
    value: row.value || 1,
  }));
}

function getFirewallRowsByDirection(direction) {
  const wanted = normalizeDirectionFilter(direction);
  return (state.data.firewall?.suspicious_connections || []).filter((row) => normalizeDirectionFilter(row.direction) === wanted);
}

function normalizeDirectionFilter(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "empty" || normalized === "(empty)" || normalized === "" || normalized === "null" || normalized === "none") return "(empty)";
  return normalized;
}

function buildFirewallDirectionTimeline(rows) {
  const counter = new Map();
  rows.forEach((row) => {
    const time = normalizeFirewallTime(row.time);
    const action = row.action || row.operation || "(empty)";
    const current = counter.get(time) || { time, Built: 0, Teardown: 0, Deny: 0, "(empty)": 0 };
    current[action] = Number(current[action] || 0) + 1;
    counter.set(time, current);
  });
  return [...counter.values()].sort((a, b) => a.time.localeCompare(b.time));
}

function buildFirewallDirectionPairs(rows) {
  const counter = new Map();
  rows.forEach((row) => {
    const source = stripEndpoint(row.source_ip);
    const target = stripEndpoint(row.destination_ip);
    if (!source || !target) return;
    const key = `${source}|${target}`;
    const current = counter.get(key) || { source, target, value: 0 };
    current.value += 1;
    counter.set(key, current);
  });
  return [...counter.values()].sort((a, b) => b.value - a.value).slice(0, 120);
}

function buildFirewallDirectionParallelRows(rows) {
  const counter = new Map();
  rows.forEach((row) => {
    const source = stripEndpoint(row.source_ip);
    const port = String(row.destination_port || "(empty)");
    const protocol = row.protocol || "unknown";
    const key = `${source}|${port}|${protocol}`;
    const current = counter.get(key) || { source, port, protocol, value: 0 };
    current.value += 1;
    counter.set(key, current);
  });
  return [...counter.values()].sort((a, b) => b.value - a.value);
}

function normalizeFirewallTime(value) {
  const raw = String(value || "").trim();
  const match = raw.match(/^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}):/);
  if (match) return `${match[3]}-${match[2]}-${match[1]} ${match[4]}:00`;
  return raw.replace("T", " ").slice(0, 13) + ":00";
}

function normalizeFirewallMinuteTime(value) {
  const raw = String(value || "").trim();
  const match = raw.match(/^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}):(\d{2})/);
  if (match) return `${match[3]}-${match[2]}-${match[1]} ${match[4]}:${match[5]}`;
  return normalizeEventMinuteTime(raw);
}

function normalizeEventMinuteTime(value) {
  return normalizeEventSecondTime(value).slice(0, 16);
}

function normalizeEventSecondTime(value) {
  const raw = String(value || "").trim().replace("T", " ");
  if (!raw) return "";
  const months = {
    Jan: "01", Feb: "02", Mar: "03", Apr: "04", May: "05", Jun: "06",
    Jul: "07", Aug: "08", Sep: "09", Oct: "10", Nov: "11", Dec: "12",
  };
  const namedMonth = raw.match(/^(\d{2})\/([A-Za-z]{3})\/(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?/);
  if (namedMonth && months[namedMonth[2]]) return `${namedMonth[3]}-${months[namedMonth[2]]}-${namedMonth[1]} ${namedMonth[4]}:${namedMonth[5]}:${namedMonth[6] || "00"}`;
  const slash = raw.match(/^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?/);
  if (slash) return `${slash[3]}-${slash[2]}-${slash[1]} ${slash[4]}:${slash[5]}:${slash[6] || "00"}`;
  const iso = raw.match(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}):(\d{2})(?::(\d{2}(?:\.\d+)?))?/);
  if (iso) return `${iso[1]} ${iso[2]}:${iso[3]}:${String(iso[4] || "00").slice(0, 2)}`;
  return raw.slice(0, 19);
}

function renderEvidenceCompositionMiniView(contextRows = null) {
  const container = document.getElementById("newNetEvidenceComposition");
  if (!container) return;
  const fw = state.data.firewall || {};
  const ids = state.data.ids || {};
  const pcap = state.data.pcap || {};
  const hasContext = Boolean(state.networkEvidenceTime || state.networkEvidenceTimeRange || state.networkEvidenceIpPair || (state.networkEvidencePortSelections || []).length || state.networkEvidenceSignature);
  const source = state.networkEvidenceSource || "all";
  const rows = hasContext ? (contextRows || []) : null;
  const contextCounter = (evidence, getter, fallbackRows) => {
    if (!rows) return fallbackRows;
    const counter = new Map();
    rows
      .filter((row) => row.evidence === evidence)
      .forEach((row) => {
        const key = getter(row) || "unknown";
        counter.set(key, Number(counter.get(key) || 0) + Number(row.value || 1));
      });
    return [...counter.entries()].map(([key, value]) => ({ key, value })).sort((a, b) => b.value - a.value).slice(0, 4);
  };
  const groups = [
    {
      title: "Firewall actions",
      color: colors.blue,
      rows: source === "ids" || source === "pcap" ? [] : contextCounter("Firewall", (row) => row.label, (fw.operations || []).slice(0, 4)),
    },
    {
      title: "IDS priorities",
      color: colors.red,
      rows: source === "firewall" || source === "pcap"
        ? []
        : contextCounter("IDS", (row) => `Priority ${row.priority || "n/a"}`, (ids.priorities || []).slice(0, 4).map((item) => ({
          key: `Priority ${item.key}`,
          value: item.value,
        }))),
    },
    {
      title: "PCAP protocols",
      color: colors.teal,
      rows: source === "firewall" || source === "ids"
        ? []
        : contextCounter("PCAP", (row) => protocolName(row.label || row.protocol), (pcap.protocols || pcap.ip_protocols || []).slice(0, 4).map((item) => ({
          key: protocolName(item.key),
          value: item.value,
        }))),
    },
  ];

  container.innerHTML = groups.map((group) => {
    const rows = group.rows.filter((item) => Number(item.value || 0) > 0);
    const total = rows.reduce((sum, item) => sum + Number(item.value || 0), 0) || 1;
    return `
      <div class="composition-group">
        <div class="composition-title">
          <strong>${escapeHtml(group.title)}</strong>
          <span>${compact(total)}</span>
        </div>
        <div class="composition-stacked" aria-label="${escapeHtml(group.title)}">
          ${rows.map((item) => {
            const width = Math.max(2, (Number(item.value || 0) / total) * 100);
            return `<span style="width:${width}%;background:${group.color}" title="${escapeHtml(item.key)}: ${fmt.format(item.value)}"></span>`;
          }).join("")}
        </div>
        <div class="composition-bars">
          ${rows.map((item) => {
            const width = Math.max(2, (Number(item.value || 0) / total) * 100);
            return `
              <div class="composition-row" title="${escapeHtml(item.key)}: ${fmt.format(item.value)}">
                <span>${escapeHtml(item.key)}</span>
                <div><b style="width:${width}%;background:${group.color}"></b></div>
                <em>${compact(item.value)}</em>
              </div>
            `;
          }).join("")}
        </div>
      </div>
    `;
  }).join("");
}

function renderIdsSignatureBars(contextRows = null) {
  const container = document.getElementById("newNetIdsSignatures");
  if (!container) return;
  const scoped = hasNetworkEvidenceSelection();
  const groups = groupIdsSignaturesByPriority(buildIdsSignatureRows(contextRows));
  if (!groups.length) {
    container.innerHTML = `<div class="detail-empty">${
      scoped
        ? "No IDS signatures are present for the current selected evidence."
        : "IDS signatures are available when Evidence Source is All or IDS."
    }</div>`;
    return;
  }
  const values = [];
  groups.forEach((group) => group.rows.forEach((row) => values.push(row.value)));
  const max = Math.max(...values, 1);
  container.innerHTML = `
    <button type="button" class="signature-clear ${state.networkEvidenceSignature ? "" : "active"}" data-signature-clear>
      Show all signatures
    </button>
    ${groups.map((group) => `
      <div class="signature-priority-group">
        <div class="signature-group-title">
          <strong>${escapeHtml(group.title)}</strong>
          <span>${compact(group.total)} alerts</span>
        </div>
        ${group.rows.map((row) => {
          const width = Math.max(2, (row.value / max) * 100);
          const active = state.networkEvidenceSignature === row.key ? "active" : "";
          return `
            <button type="button" class="signature-row ${active}" data-signature="${escapeHtml(row.key)}" title="${escapeHtml(row.key)}: ${fmt.format(row.value)}">
              <span class="signature-label">${escapeHtml(shortSignature(row.key))}</span>
              <span class="signature-track"><b style="width:${width}%;background:${priorityColor(row.priority)}"></b></span>
              <span class="signature-priority">P${escapeHtml(row.priority || "n/a")}</span>
              <span class="signature-value">${compact(row.value)}</span>
            </button>
          `;
        }).join("")}
      </div>
    `).join("")}
  `;
  container.querySelector("[data-signature-clear]")?.addEventListener("click", () => {
    state.networkEvidenceSignature = null;
    renderNetworkEvidenceNewDashboard();
  });
  container.querySelectorAll("[data-signature]").forEach((button) => {
    button.addEventListener("click", () => {
      state.networkEvidenceSignature = button.dataset.signature;
      renderNetworkEvidenceNewDashboard();
    });
  });
}

function groupIdsSignaturesByPriority(rows) {
  const priorityOrder = ["1", "2", "3", "n/a"];
  const byPriority = new Map();
  rows.forEach((row) => {
    const priority = row.priority || "n/a";
    const list = byPriority.get(priority) || [];
    list.push(row);
    byPriority.set(priority, list);
  });
  return priorityOrder
    .filter((priority) => byPriority.has(priority))
    .map((priority) => {
      const groupRows = byPriority.get(priority).sort((a, b) => b.value - a.value);
      return {
        priority,
        title: priority === "n/a" ? "Priority unknown" : `Priority ${priority}`,
        total: groupRows.reduce((sum, row) => sum + row.value, 0),
        rows: groupRows,
      };
    });
}

function buildIdsSignatureRows(contextRows = null) {
  const ids = state.data.ids || {};
  if ((state.networkEvidenceSource || "all") === "firewall" || (state.networkEvidenceSource || "all") === "pcap") return [];
  if (contextRows && hasNetworkEvidenceSelection()) {
    const signatureCounts = new Map();
    contextRows
      .filter((row) => row.evidence === "IDS")
      .forEach((row) => {
        const key = row.fullSignature || row.label || "IDS";
        const current = signatureCounts.get(key) || { key, value: 0, priority: row.priority || "n/a" };
        current.value += Number(row.value || 1);
        signatureCounts.set(key, current);
      });
    return [...signatureCounts.values()].sort((a, b) => b.value - a.value).slice(0, 10);
  }
  const priorityBySignature = new Map();
  (ids.sample_alerts || []).forEach((alert) => {
    if (!priorityBySignature.has(alert.signature)) priorityBySignature.set(alert.signature, alert.priority || "n/a");
  });
  return (ids.types || []).slice(0, 10).map((row) => ({
    key: row.key,
    value: Number(row.value || 0),
    priority: priorityBySignature.get(row.key) || "n/a",
  }));
}

function hasNetworkEvidenceSelection() {
  return Boolean(
    state.networkEvidenceTime ||
    state.networkEvidenceTimeRange ||
    state.networkEvidenceIpPair ||
    (state.networkEvidencePortSelections || []).length ||
    state.networkEvidenceSignature
  );
}

function buildIdsSignatureIpPairs(signature, selectedTime = null) {
  const granularity = state.networkEvidenceTimeGranularity || "hour";
  const counter = new Map();
  (state.data.ids?.sample_alerts || [])
    .filter((alert) => alert.signature === signature)
    .filter((alert) => !selectedTime || timeBucketKey(alert.time, granularity) === timeBucketKey(selectedTime, granularity))
    .forEach((alert) => {
      const source = stripEndpoint(alert.source);
      const target = stripEndpoint(alert.destination);
      if (!source || !target) return;
      const key = `${source}|${target}`;
      const current = counter.get(key) || { row: source, col: target, value: 0, detail: signature };
      current.value += 1;
      counter.set(key, current);
    });
  return [...counter.values()].sort((a, b) => b.value - a.value).slice(0, 120);
}

function buildIdsSignatureTimePorts(signature) {
  const ids = state.data.ids || {};
  const timeRows = (ids.timeline_by_signature || []).filter((row) => Number(row[signature] || 0) > 0);
  const fallbackTime = timeRows[0]?.time || ids.first || "IDS";
  return (ids.source_port_matrix || [])
    .filter((row) => row.signature === signature)
    .slice(0, 180)
    .map((row, index) => {
      const time = timeRows[index % Math.max(timeRows.length, 1)]?.time || fallbackTime;
      return {
        time: normalizeEventSecondTime(time),
        port: String(row.port || ""),
        source: row.source,
        target: "IDS multiple",
        evidence: "IDS",
        label: shortSignature(signature),
        value: row.value,
      };
    });
}

function priorityColor(priority) {
  if (String(priority) === "1") return colors.red;
  if (String(priority) === "2") return colors.amber;
  if (String(priority) === "3") return colors.blue;
  return colors.gray;
}

function protocolName(value) {
  const names = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
  };
  return names[String(value)] || String(value || "unknown");
}

function bindNetworkEvidenceNewClicks(combo) {
  bindNewNetworkTimelineClick(document.getElementById("newNetTimeline"), combo);
  bindNewNetworkHeatmapClick(document.getElementById("newNetIpHeatmap"), combo);
  bindNewNetworkScatterClick(document.getElementById("newNetTimePortScatter"), combo);
}

function bindNewNetworkTimelineClick(svg, combo) {
  if (!svg) return;
  let dragStart = null;
  let brush = null;
  const widthHeight = () => svgSize(svg, 900, 250);
  const pad = { top: 18, right: 18, bottom: 38, left: 48 };
  const rows = () => combo.timeline || [];
  const timeAtX = (xValue) => {
    const { width } = widthHeight();
    const currentRows = rows();
    const innerW = width - pad.left - pad.right;
    const index = Math.min(currentRows.length - 1, Math.max(0, Math.floor(((xValue - pad.left) / innerW) * currentRows.length)));
    return currentRows[index]?.time;
  };

  svg.onmousedown = (event) => {
    const point = svgPoint(svg, event);
    const { width, height } = widthHeight();
    if (point.x < pad.left || point.x > width - pad.right || point.y < pad.top || point.y > height - pad.bottom) return;
    dragStart = point;
    brush = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    brush.setAttribute("y", pad.top);
    brush.setAttribute("height", height - pad.top - pad.bottom);
    brush.setAttribute("fill", "rgba(47,111,179,0.18)");
    brush.setAttribute("stroke", colors.blue);
    brush.setAttribute("stroke-width", "1");
    brush.setAttribute("pointer-events", "none");
    svg.appendChild(brush);
  };

  svg.onmousemove = (event) => {
    if (!dragStart || !brush) return;
    const point = svgPoint(svg, event);
    const { width } = widthHeight();
    const x1 = Math.max(pad.left, Math.min(dragStart.x, point.x));
    const x2 = Math.min(width - pad.right, Math.max(dragStart.x, point.x));
    brush.setAttribute("x", x1);
    brush.setAttribute("width", Math.max(1, x2 - x1));
  };

  svg.onmouseup = (event) => {
    if (!dragStart) return;
    const point = svgPoint(svg, event);
    const delta = Math.abs(point.x - dragStart.x);
    if (brush) brush.remove();
    brush = null;
    const startTime = timeAtX(Math.min(dragStart.x, point.x));
    const endTime = timeAtX(Math.max(dragStart.x, point.x));
    dragStart = null;
    if (!startTime || !endTime) return;
    if (delta > 10 && startTime !== endTime) {
      state.networkEvidenceTime = null;
      state.networkEvidenceTimeRange = startTime <= endTime
        ? { start: startTime, end: endTime }
        : { start: endTime, end: startTime };
    } else {
      state.networkEvidenceTime = startTime;
      state.networkEvidenceTimeRange = null;
    }
    state.networkEvidenceSignature = null;
    renderNetworkEvidenceNewDashboard();
  };

  svg.onmouseleave = () => {
    if (brush) brush.remove();
    brush = null;
    dragStart = null;
  };
}

function bindNewNetworkHeatmapClick(svg, combo) {
  if (!svg) return;
  svg.onclick = (event) => {
    const cells = combo.ipPairs || [];
    const point = svgPoint(svg, event);
    const { width, height } = svgSize(svg, 760, 360);
    const left = 118;
    const top = 36;
    const bottom = 24;
    const rowScores = new Map();
    const colScores = new Map();
    cells.forEach((cell) => {
      rowScores.set(cell.row, (rowScores.get(cell.row) || 0) + cell.value);
      colScores.set(cell.col, (colScores.get(cell.col) || 0) + cell.value);
    });
    const rows = [...rowScores.entries()].sort((a, b) => b[1] - a[1]).map(([k]) => k).slice(0, 12);
    const cols = [...colScores.entries()].sort((a, b) => b[1] - a[1]).map(([k]) => k).slice(0, 10);
    const cellW = (width - left - 12) / Math.max(cols.length, 1);
    const cellH = (height - top - bottom) / Math.max(rows.length, 1);
    const source = rows[Math.floor((point.y - top) / cellH)];
    const target = cols[Math.floor((point.x - left) / cellW)];
    if (!source || !target) return;
    const found = cells.find((cell) => cell.row === source && cell.col === target);
    if (found && found.value) {
      state.networkEvidenceIpPair = { source, target };
      state.networkEvidenceSignature = null;
      setInvestigationContext([source, target], `IP pair ${source} -> ${target}`, "Network Evidence IP heatmap");
      renderNetworkEvidenceNewDashboard();
    }
  };
}

function bindNewNetworkScatterClick(svg, combo) {
  if (!svg) return;
  let dragStart = null;
  let screenDragStart = null;
  let brush = null;
  svg._scatterDragging = false;
  svg._scatterSuppressNextClick = false;
  const handleMove = (event) => {
    if (!dragStart || !brush) return;
    const point = svgPoint(svg, event);
    const x1 = Math.min(dragStart.x, point.x);
    const x2 = Math.max(dragStart.x, point.x);
    const y1 = Math.min(dragStart.y, point.y);
    const y2 = Math.max(dragStart.y, point.y);
    brush.setAttribute("x", x1);
    brush.setAttribute("y", y1);
    brush.setAttribute("width", Math.max(1, x2 - x1));
    brush.setAttribute("height", Math.max(1, y2 - y1));
  };
  const handleUp = (event) => {
    if (!dragStart) return;
    const point = svgPoint(svg, event);
    const delta = Math.hypot(point.x - dragStart.x, point.y - dragStart.y);
    if (brush) brush.remove();
    brush = null;
    const start = dragStart;
    dragStart = null;
    svg._scatterDragging = false;
    document.removeEventListener("mousemove", handleMove);
    document.removeEventListener("mouseup", handleUp);
    if (delta > 10) {
      svg._scatterSuppressNextClick = true;
      selectScatterPointsInScreenBrush(svg, screenDragStart, { x: event.clientX, y: event.clientY });
    }
    screenDragStart = null;
  };
  const startBrush = (event) => {
    if (dragStart) return;
    screenDragStart = { x: event.clientX, y: event.clientY };
    const point = svgPoint(svg, event);
    const { width, height } = svgSize(svg, 620, 360);
    const pad = { top: 24, right: 30, bottom: 62, left: 78 };
    dragStart = {
      x: Math.max(pad.left, Math.min(width - pad.right, point.x)),
      y: Math.max(pad.top, Math.min(height - pad.bottom, point.y)),
    };
    svg._scatterDragging = true;
    brush = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    brush.setAttribute("fill", "rgba(47,111,179,0.16)");
    brush.setAttribute("stroke", colors.blue);
    brush.setAttribute("stroke-width", "1");
    brush.setAttribute("pointer-events", "none");
    svg.appendChild(brush);
    document.addEventListener("mousemove", handleMove);
    document.addEventListener("mouseup", handleUp);
  };
  if (svg._scatterMouseDown) svg.removeEventListener("mousedown", svg._scatterMouseDown, true);
  svg._scatterMouseDown = startBrush;
  svg.addEventListener("mousedown", startBrush, true);
  svg.onmousemove = handleMove;
  svg.onmouseup = handleUp;
  svg.onmouseleave = () => {
    if (dragStart) return;
    if (brush) brush.remove();
    brush = null;
    document.removeEventListener("mousemove", handleMove);
    document.removeEventListener("mouseup", handleUp);
  };
}

function selectScatterPointsInBrush(svg, combo, startPoint, endPoint) {
  const points = (combo.timePorts || [])
    .filter((row) => row.time && row.port && row.port !== "(empty)")
    .map((row, index) => ({ ...row, _pointId: row._pointId || `point-${index}` }))
    .slice(0, 360);
  if (!points.length) return;
  const { width, height } = svgSize(svg, 620, 360);
  const pad = { top: 24, right: 30, bottom: 62, left: 78 };
  const times = unique(points.map((p) => p.time)).slice(0, 24);
  const ports = unique(points.map((p) => p.port)).sort((a, b) => Number(a) - Number(b)).slice(0, 16);
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const xPos = (time) => pad.left + (times.indexOf(time) + 0.5) * (innerW / Math.max(times.length, 1));
  const yPos = (port) => pad.top + innerH - (ports.indexOf(port) + 0.5) * (innerH / Math.max(ports.length, 1));
  const x1 = Math.min(startPoint.x, endPoint.x);
  const x2 = Math.max(startPoint.x, endPoint.x);
  const y1 = Math.min(startPoint.y, endPoint.y);
  const y2 = Math.max(startPoint.y, endPoint.y);
  const tolerance = 8;
  const selected = points.filter((row) => {
    if (!times.includes(row.time) || !ports.includes(row.port)) return false;
    const x = xPos(row.time);
    const y = yPos(row.port);
    return x >= x1 - tolerance && x <= x2 + tolerance && y >= y1 - tolerance && y <= y2 + tolerance;
  });
  if (!selected.length) return;
  const existing = new Map((state.networkEvidencePortSelections || []).map((item) => [portSelectionKey(item), item]));
  selected.forEach((point) => {
    existing.set(portSelectionKey(point), {
      _pointId: point._pointId,
      time: point.time,
      port: point.port,
      evidence: point.evidence,
      source: point.source,
      target: point.target,
      label: point.label,
    });
  });
  state.networkEvidencePortSelections = [...existing.values()];
  setInvestigationContext(selected.flatMap((point) => [point.source, point.target]), `${selected.length} selected time-port points`, "Network Evidence scatter brush");
  renderNetworkEvidenceNewDashboard();
}

function selectScatterPointsInScreenBrush(svg, startPoint, endPoint) {
  if (!startPoint || !endPoint) return;
  const x1 = Math.min(startPoint.x, endPoint.x);
  const x2 = Math.max(startPoint.x, endPoint.x);
  const y1 = Math.min(startPoint.y, endPoint.y);
  const y2 = Math.max(startPoint.y, endPoint.y);
  const selected = Array.from(svg.querySelectorAll("[data-point-id]"))
    .filter((node) => {
      const box = node.getBoundingClientRect();
      const cx = box.left + box.width / 2;
      const cy = box.top + box.height / 2;
      return cx >= x1 - 8 && cx <= x2 + 8 && cy >= y1 - 8 && cy <= y2 + 8;
    })
    .map((node) => ({
      _pointId: node.dataset.pointId,
      time: node.dataset.time,
      port: node.dataset.port,
      evidence: node.dataset.evidence,
      source: node.dataset.source,
      target: node.dataset.target,
      label: node.dataset.label,
    }));
  if (!selected.length) return;
  const existing = new Map((state.networkEvidencePortSelections || []).map((item) => [portSelectionKey(item), item]));
  selected.forEach((point) => existing.set(portSelectionKey(point), point));
  state.networkEvidencePortSelections = [...existing.values()];
  setInvestigationContext(selected.flatMap((point) => [point.source, point.target]), `${selected.length} selected time-port points`, "Network Evidence scatter brush");
  renderNetworkEvidenceNewDashboard();
}

function renderNetworkEvidenceNewDetail(selection, combo) {
  const container = document.getElementById("newNetClickDetail");
  if (!container) return;
  if (!selection || selection.type === "none") {
    closeNewNetworkDetailDrawer();
    container.innerHTML = `
      <div class="status-empty">No evidence selected. Click a time bar, IP-pair cell, time-port point, or IDS signature.</div>
    `;
    return;
  }
  let title = "";
  let rows = [];
  if (selection.type === "time") {
    title = `Selected time: ${selection.time}`;
    rows = filterRowsByHour(combo.timePorts || [], selection.time);
  } else if (selection.type === "time_range") {
    title = `Selected time range: ${selection.range.start} - ${selection.range.end}`;
    rows = filterRowsByTimeRange(combo.timePorts || [], selection.range);
  } else if (selection.type === "ip_pair") {
    title = `Selected IP pair: ${selection.source} -> ${selection.target}`;
    rows = (combo.timePorts || []).filter((row) => stripEndpoint(row.source) === selection.source && stripEndpoint(row.target) === selection.target);
    if (!rows.length) {
      const aggregate = (combo.ipPairs || []).find((d) => d.row === selection.source && d.col === selection.target);
      rows = [{ evidence: aggregate?.detail || "Network", source: selection.source, target: selection.target, port: "multiple", label: "IP x IP aggregate", value: aggregate?.value || 0 }];
    }
  } else if (selection.type === "port_time") {
    title = `Selected time-port: ${selection.time}, port ${selection.port}`;
    rows = (combo.timePorts || []).filter((row) => row.port === selection.port && row.time === selection.time);
  } else if (selection.type === "port_selections") {
    title = `Selected time-port points: ${selection.selections.length}`;
    rows = filterRowsByPortSelections(combo.timePorts || [], selection.selections);
  } else if (selection.type === "signature") {
    title = `Selected IDS signature: ${shortSignature(selection.signature)}`;
    const alerts = (state.data.ids?.sample_alerts || [])
      .filter((alert) => alert.signature === selection.signature)
      .slice(0, 12)
      .map((alert) => ({
        evidence: "IDS",
        time: String(alert.time || "").replace("T", " ").slice(0, 16),
        source: alert.source,
        target: alert.destination,
        port: "n/a",
        label: `Priority ${alert.priority || "n/a"}`,
        value: 1,
      }));
    const ports = buildIdsSignatureTimePorts(selection.signature).slice(0, 12);
    rows = [...alerts, ...ports];
  }
  const evidenceCounts = countBy(rows, (row) => row.evidence || "unknown");
  const countLabel = `${fmt.format(rows.length)} evidence rows`;
  container.innerHTML = `
    <div class="status-main">
      <strong>${escapeHtml(title)}</strong>
      <span>${escapeHtml(countLabel)}</span>
    </div>
    <div class="detail-chips compact">
      ${Object.entries(evidenceCounts).map(([key, value]) => `<span>${escapeHtml(key)}: ${compact(value)}</span>`).join("")}
    </div>
    <button id="newNetOpenDrawerBtn" type="button">Open details</button>
  `;
  document.getElementById("newNetOpenDrawerBtn")?.addEventListener("click", () => {
    openNewNetworkDetailDrawer(title, countLabel, evidenceCounts, rows);
  });
  updateNewNetworkDetailDrawer(title, countLabel, evidenceCounts, rows);
}

function updateNewNetworkDetailDrawer(title, countLabel, evidenceCounts, rows) {
  const drawer = document.getElementById("newNetDetailDrawer");
  if (!drawer || drawer.getAttribute("aria-hidden") === "true") return;
  openNewNetworkDetailDrawer(title, countLabel, evidenceCounts, rows);
}

function openNewNetworkDetailDrawer(title, countLabel, evidenceCounts, rows) {
  const drawer = document.getElementById("newNetDetailDrawer");
  const drawerTitle = document.getElementById("newNetDrawerTitle");
  const drawerSubtitle = document.getElementById("newNetDrawerSubtitle");
  const body = document.getElementById("newNetDrawerBody");
  if (!drawer || !drawerTitle || !drawerSubtitle || !body) return;
  drawerTitle.textContent = title;
  drawerSubtitle.textContent = countLabel;
  body.innerHTML = `
    <div class="detail-chips">
      ${Object.entries(evidenceCounts).map(([key, value]) => `<span>${escapeHtml(key)}: ${compact(value)}</span>`).join("")}
    </div>
    <div class="drawer-note">Concrete selected evidence rows with prepared raw references.</div>
    <div class="drawer-event-list">
      ${(rows || []).slice(0, 80).map((row) => `
        <div class="drawer-event-row">
          <b>${escapeHtml(row.evidence || "unknown")}</b>
          <span>${escapeHtml(row.time || "aggregate")}</span>
          <span>${escapeHtml(stripEndpoint(row.source || ""))} -> ${escapeHtml(stripEndpoint(row.target || ""))}</span>
          <span>port ${escapeHtml(row.port || "n/a")}</span>
          <em>${escapeHtml(row.fullSignature || row.label || "")}${row.value ? ` (${compact(row.value)})` : ""}</em>
          <code>${escapeHtml(row.raw_ref || "prepared aggregate")}</code>
        </div>
      `).join("") || `<div class="detail-empty">No concrete rows are available for the current selection.</div>`}
    </div>
  `;
  drawer.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
}

function closeNewNetworkDetailDrawer() {
  const drawer = document.getElementById("newNetDetailDrawer");
  if (!drawer) return;
  drawer.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
}

function svgPoint(svg, event) {
  const rect = svg.getBoundingClientRect();
  const viewBox = svg.viewBox.baseVal;
  const width = viewBox && viewBox.width ? viewBox.width : rect.width;
  const height = viewBox && viewBox.height ? viewBox.height : rect.height;
  return {
    x: ((event.clientX - rect.left) / Math.max(rect.width, 1)) * width,
    y: ((event.clientY - rect.top) / Math.max(rect.height, 1)) * height,
  };
}

function svgSize(svg, fallbackWidth, fallbackHeight) {
  const viewBox = svg.viewBox.baseVal;
  return {
    width: viewBox && viewBox.width ? viewBox.width : (svg.clientWidth || fallbackWidth),
    height: viewBox && viewBox.height ? viewBox.height : (svg.clientHeight || fallbackHeight),
  };
}

function countBy(rows, getter) {
  return rows.reduce((acc, row) => {
    const key = getter(row);
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function selectedInvestigationIps() {
  return (state.investigationContext?.ips || []).map(stripEndpoint).filter(Boolean);
}

function setInvestigationContext(ips, label, source = "Network Evidence") {
  const uniqueIps = [...new Set((ips || []).map(stripEndpoint).filter(Boolean))];
  state.investigationContext = {
    ips: uniqueIps,
    source,
    label: label || uniqueIps.join(", "),
  };
}

function filterDetailsByInvestigationIps(rows, fields) {
  const ips = selectedInvestigationIps();
  if (!ips.length) return rows || [];
  const ipSet = new Set(ips);
  return (rows || []).filter((row) => fields.some((field) => ipSet.has(stripEndpoint(row[field] || ""))));
}

function renderLinkedContext(elementId, title) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const ips = selectedInvestigationIps();
  if (!ips.length) {
    el.classList.remove("active");
    el.innerHTML = `<span>${escapeHtml(title)} is not filtered. Select an IP or IP-pair in Network Evidence New to link this dashboard.</span>`;
    return;
  }
  el.classList.add("active");
  el.innerHTML = `
    <strong>Linked context:</strong>
    <span>${escapeHtml(state.investigationContext?.label || ips.join(", "))}</span>
    <span>from ${escapeHtml(state.investigationContext?.source || "Network Evidence")}</span>
  `;
}

function renderHostIdentityContext() {
  const el = document.getElementById("hostIdentityContext");
  if (!el) return;
  const ips = selectedInvestigationIps();
  const range = state.hostIdentityTimeRange;
  const hasContext = ips.length || range;
  el.classList.toggle("active", Boolean(hasContext));
  if (!hasContext) {
    el.textContent = "No linked IP or Windows time range selected.";
    return;
  }
  const ipText = ips.length ? `Linked IP: ${ips.join(", ")}` : "Linked IP: all";
  const timeText = range ? `Windows time: ${range.start} - ${range.end}` : "Windows time: full range";
  el.innerHTML = `
    <strong>Host context:</strong>
    <span>${escapeHtml(ipText)}</span>
    <span>${escapeHtml(timeText)}</span>
    ${range ? `<button type="button" id="clearHostTimeRange" class="context-clear">Clear time</button>` : ""}
  `;
  document.getElementById("clearHostTimeRange")?.addEventListener("click", () => {
    state.hostIdentityTimeRange = null;
    renderWindowsLogsDashboard();
  });
}

function getSecurityUserHostRowsForHostContext(sec) {
  const range = state.hostIdentityTimeRange;
  if (!range) return sec.user_host_matrix || [];
  return aggregateTimedRowsByKeys(
    filterSecurityRowsByTimeRange(sec.user_host_matrix_by_hour || [], range),
    ["user", "host", "event_id"],
    220
  );
}

function aggregateTimedRowsByKeys(rows, keys, limit = 200) {
  const counter = new Map();
  (rows || []).forEach((row) => {
    const key = keys.map((field) => row[field] || "").join("|");
    const current = counter.get(key) || { value: 0 };
    keys.forEach((field) => { current[field] = row[field] || ""; });
    current.value += Number(row.value || 0);
    counter.set(key, current);
  });
  return [...counter.values()].sort((a, b) => b.value - a.value).slice(0, limit);
}

function filterSecurityRowsByTimeRange(rows, range) {
  if (!range) return rows || [];
  return (rows || []).filter((row) => {
    const time = timeBucketKey(row.time, "hour");
    return time && time >= range.start && time <= range.end;
  });
}

function bindHostIdentityTimelineSelection(svg, rows) {
  if (!svg || !rows?.length) return;
  let dragStart = null;
  let brush = null;
  const pad = { top: 18, right: 18, bottom: 38, left: 48 };
  const visibleRows = rows.slice(0, 90);
  const timeAtX = (xValue) => {
    const { width } = svgSize(svg, 900, 250);
    const innerW = width - pad.left - pad.right;
    const index = Math.min(
      visibleRows.length - 1,
      Math.max(0, Math.floor(((xValue - pad.left) / Math.max(innerW, 1)) * visibleRows.length))
    );
    return visibleRows[index]?.time || "";
  };
  const clearBrush = () => {
    if (brush) brush.remove();
    brush = null;
  };
  svg.onmousedown = (event) => {
    const point = svgPoint(svg, event);
    const { width, height } = svgSize(svg, 900, 250);
    if (point.x < pad.left || point.x > width - pad.right || point.y < pad.top || point.y > height - pad.bottom) return;
    dragStart = point;
    clearBrush();
    brush = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    brush.setAttribute("y", pad.top);
    brush.setAttribute("height", height - pad.top - pad.bottom);
    brush.setAttribute("fill", "rgba(47,111,179,0.16)");
    brush.setAttribute("stroke", colors.blue);
    brush.setAttribute("stroke-width", "1");
    brush.setAttribute("pointer-events", "none");
    svg.appendChild(brush);
  };
  svg.onmousemove = (event) => {
    if (!dragStart || !brush) return;
    const point = svgPoint(svg, event);
    const x1 = Math.min(dragStart.x, point.x);
    const x2 = Math.max(dragStart.x, point.x);
    brush.setAttribute("x", x1);
    brush.setAttribute("width", Math.max(1, x2 - x1));
  };
  svg.onmouseup = (event) => {
    if (!dragStart) return;
    const point = svgPoint(svg, event);
    const delta = Math.abs(point.x - dragStart.x);
    const startTime = timeAtX(Math.min(dragStart.x, point.x));
    const endTime = timeAtX(Math.max(dragStart.x, point.x));
    clearBrush();
    dragStart = null;
    if (!startTime || !endTime) return;
    state.hostIdentityTimeRange = delta > 8
      ? { start: startTime <= endTime ? startTime : endTime, end: startTime <= endTime ? endTime : startTime }
      : { start: startTime, end: startTime };
    renderWindowsLogsDashboard();
  };
  svg.onmouseleave = () => {
    if (!dragStart) clearBrush();
  };
}

function buildRiskCountsFromNessusDetails(details) {
  const counter = new CounterShim();
  (details || []).forEach((row) => counter.add(row.severity || "unknown", 1));
  return counter.entries().map(([key, value]) => ({ key, value }));
}

function buildSecurityAccountBars(userHostRows, fallbackRows) {
  if (!selectedInvestigationIps().length && !state.hostIdentityTimeRange) return (fallbackRows || []).slice(0, 12);
  const counter = new Map();
  (userHostRows || []).forEach((row) => {
    const key = row.user || "unknown";
    counter.set(key, Number(counter.get(key) || 0) + Number(row.value || 0));
  });
  return [...counter.entries()]
    .map(([key, value]) => ({ key, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 12);
}

function buildSecurityIpBars(userHostRows, fallbackRows) {
  if (!selectedInvestigationIps().length && !state.hostIdentityTimeRange) return (fallbackRows || []).slice(0, 12);
  const counter = new Map();
  (userHostRows || []).forEach((row) => {
    const key = row.host || "unknown";
    counter.set(key, Number(counter.get(key) || 0) + Number(row.value || 0));
  });
  return [...counter.entries()]
    .map(([key, value]) => ({ key, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 12);
}

class CounterShim {
  constructor() {
    this.map = new Map();
  }
  add(key, value = 1) {
    this.map.set(key, Number(this.map.get(key) || 0) + Number(value || 0));
  }
  entries() {
    return [...this.map.entries()].sort((a, b) => b[1] - a[1]);
  }
}

function renderCombinationLayerSummary(combo) {
  const container = document.getElementById("comboLayerSummary");
  if (!container) return;
  const layer = combo.layer || "all";
  const fw = state.data.firewall || {};
  const ids = state.data.ids || {};
  const pcap = state.data.pcap || {};
  const summaries = {
    all: [
      ["Firewall events", fw.rows_nonempty || 0],
      ["IDS alerts", ids.alerts || 0],
      ["PCAP packets", pcap.packets || 0],
    ],
    firewall: [
      ["Rows", fw.rows_nonempty || 0],
      ["Built", (fw.operations || []).find((d) => d.key === "Built")?.value || 0],
      ["Deny", (fw.operations || []).find((d) => d.key === "Deny")?.value || 0],
    ],
    ids: [
      ["Alerts", ids.alerts || 0],
      ["Signatures", (ids.types || []).length],
      ["Top target", (ids.top_destinations || [])[0]?.key || "n/a"],
    ],
    pcap: [
      ["Packets", pcap.packets || 0],
      ["Sampled", pcap.sampled_packets || 0],
      ["Top target", (pcap.top_destinations || [])[0]?.key || "n/a"],
    ],
  };
  container.innerHTML = `
    <div class="layer-title">${escapeHtml(layer === "all" ? "All network evidence" : `${layer.toUpperCase()} evidence layer`)}</div>
    <div class="layer-metrics">
      ${(summaries[layer] || summaries.all).map(([label, value]) => `
        <div><span>${escapeHtml(label)}</span><strong>${typeof value === "number" ? fmt.format(value) : escapeHtml(value)}</strong></div>
      `).join("")}
    </div>
  `;
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
        `Raw files queried on demand: FOL/*/firewall/raw/*.txt`,
        `Filters: source=${payload.source || "any"}, dest=${payload.dest || "any"}, port=${payload.port || "any"}`,
        `Raw files available: ${fmt.format(payload.raw_files || 0)}, files scanned: ${fmt.format(payload.files_scanned || 0)}`,
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

function drawTreemap(svg, rows) {
  if (!svg) return;
  const width = svg.clientWidth || 520;
  const height = svg.clientHeight || 360;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";
  const data = rows.slice(0, 10);
  if (!data.length) {
    drawSvgEmptyState(svg, "No matching risk data", "The selected Network Evidence IP is not present in Nessus details.");
    return;
  }
  const total = data.reduce((sum, d) => sum + Number(d.value || 0), 0) || 1;
  const palette = [colors.red, colors.blue, colors.teal, colors.amber, colors.violet, colors.gray];
  let x = 0;
  let y = 0;
  let w = width;
  let h = height;
  data.forEach((item, index) => {
    const ratio = Number(item.value || 0) / total;
    const horizontal = w >= h;
    const size = Math.max(18, (horizontal ? w : h) * ratio);
    const cell = horizontal
      ? { x, y, w: Math.min(size, width - x), h }
      : { x, y, w, h: Math.min(size, height - y) };
    rect(svg, cell.x, cell.y, Math.max(1, cell.w - 2), Math.max(1, cell.h - 2), palette[index % palette.length]);
    if (cell.w > 95 && cell.h > 36) {
      text(svg, cell.x + 8, cell.y + 18, shortLabel(item.key), "treemap-label");
      text(svg, cell.x + 8, cell.y + 35, compact(item.value), "treemap-value");
    }
    if (horizontal) {
      x += cell.w;
      w = Math.max(0, width - x);
    } else {
      y += cell.h;
      h = Math.max(0, height - y);
    }
  });
}

function drawCategoricalScatter(svg, points) {
  if (!svg) return;
  const width = svg.clientWidth || 620;
  const height = svg.clientHeight || 360;
  const pad = { top: 22, right: 22, bottom: 70, left: 106 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";
  const xs = unique(points.map((p) => p.x)).slice(0, 12);
  const ys = unique(points.map((p) => p.y)).slice(0, 10);
  const max = Math.max(...points.map((p) => p.value), 1);
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const xPos = (x) => pad.left + (xs.indexOf(x) + 0.5) * (innerW / Math.max(xs.length, 1));
  const yPos = (y) => pad.top + (ys.indexOf(y) + 0.5) * (innerH / Math.max(ys.length, 1));

  line(svg, pad.left, pad.top + innerH, width - pad.right, pad.top + innerH, "axis");
  line(svg, pad.left, pad.top, pad.left, pad.top + innerH, "axis");
  xs.forEach((x, i) => {
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", xPos(x));
    label.setAttribute("y", height - 12);
    label.setAttribute("text-anchor", "end");
    label.setAttribute("transform", `rotate(-35 ${xPos(x)} ${height - 12})`);
    label.setAttribute("class", "tick-label");
    label.textContent = shortLabel(x);
    svg.appendChild(label);
  });
  ys.forEach((y) => text(svg, 8, yPos(y) + 4, shortLabel(y), "tick-label"));
  points.slice(0, 70).forEach((point) => {
    if (!xs.includes(point.x) || !ys.includes(point.y)) return;
    const radius = 4 + Math.sqrt(point.value / max) * 18;
    circle(svg, xPos(point.x), yPos(point.y), radius, "rgba(201, 74, 68, 0.68)");
  });
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
  const container = document.getElementById(id);
  if (!container) return;
  const rows = data || [];
  if (!rows.length) {
    container.innerHTML = `<div class="empty-state">No matching rows for the current linked context.</div>`;
    return;
  }
  const max = Math.max(...rows.map((d) => d.value), 1);
  container.innerHTML = rows.map((item) => {
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

function drawMatrixHeatmap(svg, cells, options = {}) {
  if (!svg) return;
  const width = svg.clientWidth || 760;
  const height = svg.clientHeight || 360;
  const rowLimit = options.rowLimit || 10;
  const colLimit = options.colLimit || 10;
  const palette = options.color === "blue" ? [47, 111, 179] : [176, 44, 44];
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";
  if (!cells || !cells.length) {
    drawSvgEmptyState(svg, "No IP-pair data for selection", "Try another time spike, source layer, or clear the current filter.");
    return;
  }

  const rowScores = new Map();
  const colScores = new Map();
  cells.forEach((cell) => {
    rowScores.set(cell.row, (rowScores.get(cell.row) || 0) + cell.value);
    colScores.set(cell.col, (colScores.get(cell.col) || 0) + cell.value);
  });
  const rows = [...rowScores.entries()].sort((a, b) => b[1] - a[1]).map(([k]) => k).slice(0, rowLimit);
  const cols = [...colScores.entries()].sort((a, b) => b[1] - a[1]).map(([k]) => k).slice(0, colLimit);
  const left = 118;
  const top = 36;
  const bottom = 24;
  const cellW = (width - left - 12) / Math.max(cols.length, 1);
  const cellH = (height - top - bottom) / Math.max(rows.length, 1);
  const max = Math.max(...cells.map((d) => d.value), 1);

  cols.forEach((col, i) => text(svg, left + i * cellW + 4, 22, shortLabel(col), "tick-label"));
  rows.forEach((row, i) => text(svg, 8, top + i * cellH + cellH / 2 + 4, shortLabel(row), "tick-label"));

  rows.forEach((row, y) => {
    cols.forEach((col, x) => {
      const found = cells.find((d) => d.row === row && d.col === col);
      const value = found ? found.value : 0;
      const alpha = value ? 0.12 + (value / max) * 0.88 : 0.035;
      rect(
        svg,
        left + x * cellW,
        top + y * cellH,
        Math.max(2, cellW - 2),
        Math.max(2, cellH - 2),
        `rgba(${palette[0]}, ${palette[1]}, ${palette[2]}, ${alpha})`
      );
      if (value && cellW > 45 && cellH > 22) {
        text(svg, left + x * cellW + 5, top + y * cellH + 15, compact(value), "heat-value");
      }
    });
  });
}

function renderFirewallDetailTable(rows) {
  const container = document.getElementById("fwDetailTable");
  if (!container) return;
  if (!rows.length) {
    container.innerHTML = `<div class="empty-state">No suspicious firewall detail rows are available. Refresh with Ctrl+F5 or rebuild va_data.json.</div>`;
    return;
  }
  const columns = [
    ["time", "Date/time"],
    ["source_ip", "Source IP"],
    ["destination_ip", "Destination IP"],
    ["source_port", "Source port"],
    ["destination_port", "Destination port"],
    ["protocol", "Protocol"],
    ["direction", "Direction"],
    ["action", "Action"],
    ["destination_service", "Destination service"],
    ["message_code", "Message code"],
  ];
  container.innerHTML = `
    <table>
      <thead>
        <tr>${columns.map(([, label]) => `<th>${label}</th>`).join("")}</tr>
      </thead>
      <tbody>
        ${rows.slice(0, 120).map((row) => `
          <tr>
            ${columns.map(([key]) => `<td>${escapeHtml(row[key] || "")}</td>`).join("")}
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function drawFirewallTimePortScatter(svg, rows, matrixRows) {
  if (!svg) return;
  const width = svg.clientWidth || 620;
  const height = svg.clientHeight || 360;
  const pad = { top: 24, right: 28, bottom: 58, left: 80 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";

  const grouped = new Map();
  rows.forEach((row) => {
    const time = String(row.time || "").slice(0, 16);
    const port = String(row.destination_port || "");
    if (!time || !port || port === "(empty)") return;
    const key = `${time}|${port}|${row.action || ""}`;
    const current = grouped.get(key) || { time, port, action: row.action || "", value: 0 };
    current.value += 1;
    grouped.set(key, current);
  });
  if (!grouped.size && matrixRows?.length) {
    matrixRows.slice(0, 80).forEach((row, index) => {
      const time = `rank ${Math.floor(index / 10) + 1}`;
      const key = `${time}|${row.port}|${row.protocol || ""}`;
      grouped.set(key, { time, port: String(row.port), action: row.protocol || "", value: row.value });
    });
  }
  const points = [...grouped.values()].slice(0, 120);
  if (!points.length) {
    drawSvgEmptyState(svg, "No firewall port scatter data", "No destination-port rows are available for this view.");
    return;
  }

  const times = unique(points.map((p) => p.time)).slice(0, 18);
  const ports = unique(points.map((p) => p.port))
    .sort((a, b) => Number(a) - Number(b))
    .slice(0, 14);
  const max = Math.max(...points.map((p) => p.value), 1);
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const xPos = (time) => pad.left + (times.indexOf(time) + 0.5) * (innerW / Math.max(times.length, 1));
  const yPos = (port) => pad.top + innerH - (ports.indexOf(port) + 0.5) * (innerH / Math.max(ports.length, 1));

  line(svg, pad.left, pad.top + innerH, width - pad.right, pad.top + innerH, "axis");
  line(svg, pad.left, pad.top, pad.left, pad.top + innerH, "axis");
  ports.forEach((port) => text(svg, 18, yPos(port) + 4, port, "tick-label"));
  times.filter((_, i) => i % Math.ceil(times.length / 6) === 0).forEach((time) => {
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", xPos(time));
    label.setAttribute("y", height - 14);
    label.setAttribute("text-anchor", "end");
    label.setAttribute("transform", `rotate(-35 ${xPos(time)} ${height - 14})`);
    label.setAttribute("class", "tick-label");
    label.textContent = time;
    svg.appendChild(label);
  });

  points.forEach((point) => {
    if (!times.includes(point.time) || !ports.includes(point.port)) return;
    const fill = point.action === "Deny" ? colors.red : point.action === "Teardown" ? colors.teal : colors.blue;
    const radius = 3 + Math.sqrt(point.value / max) * 16;
    circle(svg, xPos(point.time), yPos(point.port), radius, fill);
  });

  text(svg, pad.left, 14, "Bubble size = event count; red = Deny, blue = Built, teal = Teardown", "tick-label");
}

function drawParallelCoordinates(svg, rows) {
  if (!svg) return;
  const width = svg.clientWidth || 760;
  const height = svg.clientHeight || 360;
  const pad = { top: 42, right: 38, bottom: 34, left: 38 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";

  const sample = rows
    .filter((row) => row.time && row.source_ip && row.destination_ip && row.destination_port)
    .slice(0, 80);
  if (!sample.length) {
    drawSvgEmptyState(svg, "No multivariate firewall sample", "No rows with time, source, destination and port are available.");
    return;
  }

  const axes = [
    { key: "time", label: "Time", values: unique(sample.map((d) => String(d.time).slice(11, 16))).slice(0, 10), get: (d) => String(d.time).slice(11, 16) },
    { key: "source_ip", label: "Source IP", values: topValues(sample, "source_ip", 10), get: (d) => d.source_ip },
    { key: "destination_ip", label: "Destination IP", values: topValues(sample, "destination_ip", 10), get: (d) => d.destination_ip },
    { key: "destination_port", label: "Dst Port", values: topValues(sample, "destination_port", 10), get: (d) => d.destination_port },
    { key: "protocol", label: "Protocol", values: topValues(sample, "protocol", 6), get: (d) => d.protocol },
    { key: "action", label: "Action", values: topValues(sample, "action", 6), get: (d) => d.action },
  ];
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const x = (i) => pad.left + i * (innerW / Math.max(axes.length - 1, 1));
  const y = (axis, value) => {
    const values = axis.values.length ? axis.values : [value];
    const index = Math.max(0, values.indexOf(value));
    return pad.top + index * (innerH / Math.max(values.length - 1, 1));
  };

  axes.forEach((axis, i) => {
    line(svg, x(i), pad.top, x(i), pad.top + innerH, "axis");
    text(svg, x(i) - 22, 22, axis.label, "pc-axis-label");
    axis.values.slice(0, 8).forEach((value) => {
      const yy = y(axis, value);
      line(svg, x(i) - 4, yy, x(i) + 4, yy, "axis");
      text(svg, x(i) + 6, yy + 4, shortLabel(value), "pc-tick-label");
    });
  });

  sample.forEach((row) => {
    const points = axes.map((axis, i) => [x(i), y(axis, axis.get(row))]);
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", points.map(([px, py], i) => `${i ? "L" : "M"} ${px} ${py}`).join(" "));
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", row.action === "Deny" ? colors.red : row.action === "Teardown" ? colors.teal : colors.blue);
    path.setAttribute("stroke-opacity", row.action === "Deny" ? "0.42" : "0.22");
    path.setAttribute("stroke-width", row.action === "Deny" ? "1.8" : "1.1");
    svg.appendChild(path);
  });
}

function drawCombinationTimePortScatter(svg, rows) {
  if (!svg) return;
  const width = svg.clientWidth || 620;
  const height = svg.clientHeight || 360;
  const pad = { top: 24, right: 30, bottom: 62, left: 78 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";
  if (svg.id === "newNetTimePortScatter") {
    rect(svg, 0, 0, width, height, "rgba(0,0,0,0.001)");
  }

  const granularity = state.networkEvidenceTimeGranularity || "hour";
  const groupedPoints = new Map();
  (rows || [])
    .filter((row) => row.time && row.port && row.port !== "(empty)")
    .forEach((row, index) => {
      const bucketTime = timeBucketKey(row.time, granularity);
      const key = [
        bucketTime,
        row.port || "",
        row.evidence || "",
        stripEndpoint(row.source || ""),
        stripEndpoint(row.target || ""),
        row.label || "",
      ].join("|");
      const current = groupedPoints.get(key) || {
        ...row,
        time: bucketTime,
        value: 0,
        _pointId: key || row._pointId || `point-${index}`,
      };
      current.value += Number(row.value || 1);
      groupedPoints.set(key, current);
    });
  const points = [...groupedPoints.values()].slice(0, 360);
  if (!points.length) {
    drawSvgEmptyState(svg, "No combined time-port data", "No Firewall, IDS or PCAP port evidence is available.");
    return;
  }

  const times = unique(points.map((p) => p.time)).slice(0, 24);
  const ports = unique(points.map((p) => p.port))
    .sort((a, b) => Number(a) - Number(b))
    .slice(0, 16);
  const max = Math.max(...points.map((p) => Number(p.value || 1)), 1);
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const xPos = (time) => pad.left + (times.indexOf(time) + 0.5) * (innerW / Math.max(times.length, 1));
  const yPos = (port) => pad.top + innerH - (ports.indexOf(port) + 0.5) * (innerH / Math.max(ports.length, 1));

  line(svg, pad.left, pad.top + innerH, width - pad.right, pad.top + innerH, "axis");
  line(svg, pad.left, pad.top, pad.left, pad.top + innerH, "axis");
  ports.forEach((port) => text(svg, 18, yPos(port) + 4, port, "tick-label"));
  times.filter((_, i) => i % Math.ceil(times.length / 6) === 0).forEach((time) => {
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", xPos(time));
    label.setAttribute("y", height - 14);
    label.setAttribute("text-anchor", "end");
    label.setAttribute("transform", `rotate(-35 ${xPos(time)} ${height - 14})`);
    label.setAttribute("class", "tick-label");
    label.textContent = time;
    svg.appendChild(label);
  });

  points.forEach((point) => {
    if (!times.includes(point.time) || !ports.includes(point.port)) return;
    const fill = point.evidence === "IDS" ? colors.red : point.evidence === "PCAP" ? colors.teal : colors.blue;
    const radius = 3 + Math.sqrt(Number(point.value || 1) / max) * 16;
    const selected = (state.networkEvidencePortSelections || []).some((item) => portSelectionKey(item) === portSelectionKey(point));
    circle(svg, xPos(point.time), yPos(point.port), selected ? radius + 3 : radius, fill);
    if (selected) {
      const outline = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      outline.setAttribute("cx", xPos(point.time));
      outline.setAttribute("cy", yPos(point.port));
      outline.setAttribute("r", radius + 6);
      outline.setAttribute("fill", "none");
      outline.setAttribute("stroke", "#18212b");
      outline.setAttribute("stroke-width", "2");
      svg.appendChild(outline);
    }
    if (svg.id === "newNetTimePortScatter") {
      const hit = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      hit.setAttribute("cx", xPos(point.time));
      hit.setAttribute("cy", yPos(point.port));
      hit.setAttribute("r", Math.max(10, radius + 6));
      hit.setAttribute("fill", "rgba(0,0,0,0.001)");
      hit.setAttribute("style", "cursor:pointer;pointer-events:all");
      hit.setAttribute("data-point-id", point._pointId);
      hit.setAttribute("data-time", point.time || "");
      hit.setAttribute("data-port", point.port || "");
      hit.setAttribute("data-evidence", point.evidence || "");
      hit.setAttribute("data-source", point.source || "");
      hit.setAttribute("data-target", point.target || "");
      hit.setAttribute("data-label", point.label || "");
      hit.addEventListener("click", (event) => {
        if (svg._scatterSuppressNextClick) {
          svg._scatterSuppressNextClick = false;
          event.stopPropagation();
          return;
        }
        if (svg._scatterDragging) return;
        event.stopPropagation();
        togglePortSelection({
          _pointId: point._pointId,
          time: point.time,
          port: point.port,
          evidence: point.evidence,
          source: point.source,
          target: point.target,
          label: point.label,
        });
        setInvestigationContext([point.source, point.target], `Time-port ${point.time}, port ${point.port}`, "Network Evidence time-port scatterplot");
        showTimePortTooltip(point, event);
        renderNetworkEvidenceNewDashboard();
      });
      svg.appendChild(hit);
    }
  });
  drawLegend(svg, pad.left, 14, [
    ["Firewall", colors.blue],
    ["IDS", colors.red],
    ["PCAP", colors.teal],
  ]);
}

function showTimePortTooltip(point, event) {
  const tooltip = document.getElementById("newNetPortTooltip");
  if (!tooltip) return;
  const granularity = state.networkEvidenceTimeGranularity || "hour";
  const bucket = timeBucketKey(point.time, granularity);
  tooltip.hidden = false;
  tooltip.innerHTML = `
    <strong>Selected time-port</strong>
    <span>Time window: ${escapeHtml(bucket || point.time || "n/a")} (${escapeHtml(timeGranularityLabel(granularity))})</span>
    <span>Port: ${escapeHtml(point.port || "n/a")}</span>
    <span>Evidence: ${escapeHtml(point.evidence || "unknown")}</span>
    <span>Label: ${escapeHtml(point.label || "")}</span>
  `;
  const panel = tooltip.closest(".panel");
  const panelRect = panel ? panel.getBoundingClientRect() : { left: 0, top: 0 };
  tooltip.style.left = `${Math.max(12, event.clientX - panelRect.left + 10)}px`;
  tooltip.style.top = `${Math.max(44, event.clientY - panelRect.top + 10)}px`;
}

function drawCombinationParallelCoordinates(svg, rows) {
  if (!svg) return;
  const sample = (rows || []).slice(0, 130);
  if (!sample.length) {
    drawSvgEmptyState(svg, "No combined multivariate evidence", "No source-port aggregates are available.");
    return;
  }
  const width = svg.clientWidth || 760;
  const height = svg.clientHeight || 360;
  const pad = { top: 42, right: 38, bottom: 34, left: 38 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";

  const axes = [
    { key: "evidence", label: "Evidence", values: ["Firewall", "IDS", "PCAP"], get: (d) => d.evidence },
    { key: "source", label: "Source", values: topValues(sample, "source", 10), get: (d) => d.source },
    { key: "destination", label: "Destination", values: topValues(sample, "destination", 8), get: (d) => d.destination },
    { key: "port", label: "Port", values: topValues(sample, "port", 10), get: (d) => d.port },
    { key: "protocol", label: "Protocol", values: topValues(sample, "protocol", 8), get: (d) => d.protocol },
    { key: "count_bucket", label: "Count", values: ["low", "medium", "high", "very high"], get: (d) => d.count_bucket },
  ];
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const x = (i) => pad.left + i * (innerW / Math.max(axes.length - 1, 1));
  const y = (axis, value) => {
    const values = axis.values.length ? axis.values : [value];
    const index = Math.max(0, values.indexOf(value));
    return pad.top + index * (innerH / Math.max(values.length - 1, 1));
  };

  axes.forEach((axis, i) => {
    line(svg, x(i), pad.top, x(i), pad.top + innerH, "axis");
    text(svg, x(i) - 18, 22, axis.label, "pc-axis-label");
    axis.values.slice(0, 8).forEach((value) => {
      const yy = y(axis, value);
      line(svg, x(i) - 4, yy, x(i) + 4, yy, "axis");
      text(svg, x(i) + 6, yy + 4, shortLabel(value), "pc-tick-label");
    });
  });

  const max = Math.max(...sample.map((d) => Number(d.value || 1)), 1);
  sample.forEach((row) => {
    const points = axes.map((axis, i) => [x(i), y(axis, axis.get(row))]);
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", points.map(([px, py], i) => `${i ? "L" : "M"} ${px} ${py}`).join(" "));
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", row.evidence === "IDS" ? colors.red : row.evidence === "PCAP" ? colors.teal : colors.blue);
    path.setAttribute("stroke-opacity", String(0.15 + Math.min(0.35, Number(row.value || 1) / max)));
    path.setAttribute("stroke-width", Number(row.value || 0) > max * 0.5 ? "2" : "1.1");
    svg.appendChild(path);
  });
}

function drawIdsParallelCoordinates(svg, ids) {
  if (!svg) return;
  const pairRows = (ids.top_pairs || []).map((row) => ({
    source: stripEndpoint(row.source),
    destination: stripEndpoint(row.target),
    port: "any",
    signature: "source-target alert",
    count_bucket: bucketCount(row.value),
    value: row.value,
  }));
  const portRows = (ids.source_port_matrix || []).map((row) => ({
    source: row.source,
    destination: "multiple",
    port: String(row.port),
    signature: shortSignature(row.signature),
    count_bucket: bucketCount(row.value),
    value: row.value,
  }));
  const sample = [...pairRows, ...portRows].slice(0, 90);
  if (!sample.length) {
    drawSvgEmptyState(svg, "No IDS multivariate sample", "No source-target or source-port IDS aggregates are available.");
    return;
  }

  const width = svg.clientWidth || 760;
  const height = svg.clientHeight || 360;
  const pad = { top: 42, right: 38, bottom: 34, left: 38 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";

  const axes = [
    { key: "source", label: "SrcIP", values: topValues(sample, "source", 10), get: (d) => d.source },
    { key: "destination", label: "DstIP", values: topValues(sample, "destination", 10), get: (d) => d.destination },
    { key: "port", label: "DstPort", values: topValues(sample, "port", 10), get: (d) => d.port },
    { key: "signature", label: "Signature", values: topValues(sample, "signature", 8), get: (d) => d.signature },
    { key: "count_bucket", label: "Count", values: ["low", "medium", "high", "very high"], get: (d) => d.count_bucket },
  ];
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const x = (i) => pad.left + i * (innerW / Math.max(axes.length - 1, 1));
  const y = (axis, value) => {
    const values = axis.values.length ? axis.values : [value];
    const index = Math.max(0, values.indexOf(value));
    return pad.top + index * (innerH / Math.max(values.length - 1, 1));
  };

  axes.forEach((axis, i) => {
    line(svg, x(i), pad.top, x(i), pad.top + innerH, "axis");
    text(svg, x(i) - 18, 22, axis.label, "pc-axis-label");
    axis.values.slice(0, 8).forEach((value) => {
      const yy = y(axis, value);
      line(svg, x(i) - 4, yy, x(i) + 4, yy, "axis");
      text(svg, x(i) + 6, yy + 4, shortLabel(value), "pc-tick-label");
    });
  });

  const max = Math.max(...sample.map((d) => d.value), 1);
  sample.forEach((row) => {
    const points = axes.map((axis, i) => [x(i), y(axis, axis.get(row))]);
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", points.map(([px, py], i) => `${i ? "L" : "M"} ${px} ${py}`).join(" "));
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", row.port === "any" ? colors.red : colors.blue);
    path.setAttribute("stroke-opacity", String(0.16 + Math.min(0.32, row.value / max)));
    path.setAttribute("stroke-width", row.value > max * 0.5 ? "2" : "1.1");
    svg.appendChild(path);
  });
}

function shortSignature(value) {
  const text = String(value || "alert");
  if (text.includes("Portscan")) return "TCP Portscan";
  if (text.includes("Portsweep")) return "TCP Portsweep";
  if (text.includes("Window Scale")) return "TCP Window Scale";
  if (text.includes("Fragmentation")) return "Fragmentation";
  return shortLabel(text);
}

function bucketCount(value) {
  const n = Number(value || 0);
  if (n >= 500) return "very high";
  if (n >= 100) return "high";
  if (n >= 20) return "medium";
  return "low";
}

function topValues(rows, key, limit) {
  const counts = new Map();
  rows.forEach((row) => counts.set(row[key], (counts.get(row[key]) || 0) + 1));
  return [...counts.entries()]
    .filter(([value]) => value !== undefined && value !== null && value !== "")
    .sort((a, b) => b[1] - a[1])
    .map(([value]) => String(value))
    .slice(0, limit);
}

function renderPcapDetailTable(rows) {
  const container = document.getElementById("pcapDetailTable");
  if (!container) return;
  if (!rows.length) {
    container.innerHTML = `<div class="empty-state">No PCAP detail rows are available. Rebuild va_data.json.</div>`;
    return;
  }
  const columns = [
    ["no", "No."],
    ["time", "Date/time"],
    ["source", "Source"],
    ["destination", "Destination"],
    ["protocol", "Protocol"],
    ["length", "Length"],
    ["source_port", "Source_port"],
    ["destination_port", "Dest_port"],
  ];
  container.innerHTML = `
    <table>
      <thead>
        <tr>${columns.map(([, label]) => `<th>${label}</th>`).join("")}</tr>
      </thead>
      <tbody>
        ${rows.slice(0, 160).map((row) => `
          <tr>
            ${columns.map(([key]) => `<td>${escapeHtml(row[key] ?? "")}</td>`).join("")}
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function drawPcapTimePortScatter(svg, packetRows, matrixRows) {
  if (!svg) return;
  const width = svg.clientWidth || 620;
  const height = svg.clientHeight || 360;
  const pad = { top: 24, right: 28, bottom: 58, left: 80 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";

  const grouped = new Map();
  packetRows.forEach((row) => {
    const time = String(row.time || "").replace("T", " ").slice(0, 16);
    const port = String(row.destination_port || "");
    if (!time || !port) return;
    const key = `${time}|${port}|${row.protocol || ""}`;
    const current = grouped.get(key) || { time, port, protocol: row.protocol || "", value: 0, length: 0 };
    current.value += 1;
    current.length += Number(row.length || 0);
    grouped.set(key, current);
  });

  if (!grouped.size && matrixRows?.length) {
    matrixRows.slice(0, 100).forEach((row, index) => {
      const time = `rank ${Math.floor(index / 10) + 1}`;
      grouped.set(`${time}|${row.port}|${row.protocol}`, {
        time,
        port: String(row.port),
        protocol: row.protocol || "",
        value: row.value,
        length: row.value,
      });
    });
  }

  const points = [...grouped.values()].slice(0, 140);
  if (!points.length) {
    drawSvgEmptyState(svg, "No PCAP time-port scatter data", "No destination-port packet aggregates are available.");
    return;
  }

  const times = unique(points.map((p) => p.time)).slice(0, 18);
  const ports = unique(points.map((p) => p.port))
    .sort((a, b) => Number(a) - Number(b))
    .slice(0, 14);
  const max = Math.max(...points.map((p) => p.value), 1);
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const xPos = (time) => pad.left + (times.indexOf(time) + 0.5) * (innerW / Math.max(times.length, 1));
  const yPos = (port) => pad.top + innerH - (ports.indexOf(port) + 0.5) * (innerH / Math.max(ports.length, 1));

  line(svg, pad.left, pad.top + innerH, width - pad.right, pad.top + innerH, "axis");
  line(svg, pad.left, pad.top, pad.left, pad.top + innerH, "axis");
  ports.forEach((port) => text(svg, 18, yPos(port) + 4, port, "tick-label"));
  times.filter((_, i) => i % Math.ceil(times.length / 6) === 0).forEach((time) => {
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", xPos(time));
    label.setAttribute("y", height - 14);
    label.setAttribute("text-anchor", "end");
    label.setAttribute("transform", `rotate(-35 ${xPos(time)} ${height - 14})`);
    label.setAttribute("class", "tick-label");
    label.textContent = time;
    svg.appendChild(label);
  });

  points.forEach((point) => {
    if (!times.includes(point.time) || !ports.includes(point.port)) return;
    const fill = point.protocol === "UDP" ? colors.teal : point.protocol === "ICMP" ? colors.amber : colors.blue;
    const radius = 3 + Math.sqrt(point.value / max) * 17;
    circle(svg, xPos(point.time), yPos(point.port), radius, fill);
  });

  text(svg, pad.left, 14, "Bubble size = packet count; color = protocol", "tick-label");
}

function drawPcapParallelCoordinates(svg, pcap) {
  if (!svg) return;
  const detailRows = (pcap.packet_details || []).map((row) => ({
    source: row.source,
    destination: row.destination,
    source_port: String(row.source_port || "none"),
    destination_port: String(row.destination_port || "none"),
    protocol: row.protocol || "Other",
    length_bucket: bucketLength(row.length),
    weight: Number(row.length || 1),
  }));
  const matrixRows = (pcap.source_port_matrix || []).map((row) => ({
    source: row.source,
    destination: "multiple",
    source_port: "multiple",
    destination_port: String(row.port),
    protocol: row.protocol || "Other",
    length_bucket: bucketCount(row.value),
    weight: Number(row.value || 1),
  }));
  const sample = [...detailRows, ...matrixRows].slice(0, 100);
  if (!sample.length) {
    drawSvgEmptyState(svg, "No PCAP multivariate sample", "No packet detail or source-port aggregate rows are available.");
    return;
  }

  const width = svg.clientWidth || 760;
  const height = svg.clientHeight || 360;
  const pad = { top: 42, right: 38, bottom: 34, left: 38 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";

  const axes = [
    { key: "source", label: "Source", values: topValues(sample, "source", 10), get: (d) => d.source },
    { key: "destination", label: "Destination", values: topValues(sample, "destination", 10), get: (d) => d.destination },
    { key: "source_port", label: "SrcPort", values: topValues(sample, "source_port", 10), get: (d) => d.source_port },
    { key: "destination_port", label: "DstPort", values: topValues(sample, "destination_port", 10), get: (d) => d.destination_port },
    { key: "protocol", label: "Protocol", values: topValues(sample, "protocol", 6), get: (d) => d.protocol },
    { key: "length_bucket", label: "Length", values: ["small", "medium", "large", "very large", "low", "high", "very high"], get: (d) => d.length_bucket },
  ];
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const x = (i) => pad.left + i * (innerW / Math.max(axes.length - 1, 1));
  const y = (axis, value) => {
    const values = axis.values.length ? axis.values : [value];
    const index = Math.max(0, values.indexOf(value));
    return pad.top + index * (innerH / Math.max(values.length - 1, 1));
  };

  axes.forEach((axis, i) => {
    line(svg, x(i), pad.top, x(i), pad.top + innerH, "axis");
    text(svg, x(i) - 18, 22, axis.label, "pc-axis-label");
    axis.values.slice(0, 8).forEach((value) => {
      const yy = y(axis, value);
      line(svg, x(i) - 4, yy, x(i) + 4, yy, "axis");
      text(svg, x(i) + 6, yy + 4, shortLabel(value), "pc-tick-label");
    });
  });

  const max = Math.max(...sample.map((d) => d.weight), 1);
  sample.forEach((row) => {
    const points = axes.map((axis, i) => [x(i), y(axis, axis.get(row))]);
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", points.map(([px, py], i) => `${i ? "L" : "M"} ${px} ${py}`).join(" "));
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", row.protocol === "UDP" ? colors.teal : row.protocol === "ICMP" ? colors.amber : colors.blue);
    path.setAttribute("stroke-opacity", String(0.14 + Math.min(0.34, row.weight / max)));
    path.setAttribute("stroke-width", row.weight > max * 0.5 ? "2" : "1.1");
    svg.appendChild(path);
  });
}

function bucketLength(value) {
  const n = Number(value || 0);
  if (n >= 1200) return "very large";
  if (n >= 500) return "large";
  if (n >= 100) return "medium";
  return "small";
}

function drawProcessGraph(svg, edges) {
  if (!svg) return;
  if (!edges.length) {
    drawSvgEmptyState(
      svg,
      "No process creation data available",
      "This SecurityLog.xml does not contain ParentProcessName / ProcessName / CommandLine fields."
    );
    return;
  }
  drawGraph(svg, edges);
}

function renderProcessBars(rows) {
  const container = document.getElementById("winProcessBars");
  if (!container) return;
  if (!rows.length) {
    container.innerHTML = `<div class="empty-state">No ProcessName/Image fields found in this Windows log.</div>`;
    return;
  }
  renderBars("winProcessBars", rows, colors.violet);
}

function renderWindowsCommandTable(rows) {
  const container = document.getElementById("winCommandTable");
  if (!container) return;
  if (!rows.length) {
    container.innerHTML = `<div class="empty-state">No CommandLine/Image/Hash process detail rows are available in this Windows Security export.</div>`;
    return;
  }
  const columns = [
    ["time", "TimeCreated"],
    ["computer", "Computer"],
    ["user", "User"],
    ["process_name", "ProcessName"],
    ["parent_process_name", "ParentProcessName"],
    ["command_line", "CommandLine"],
    ["image", "Image"],
    ["hash", "Hash"],
    ["event_id", "EventID"],
  ];
  container.innerHTML = `
    <table>
      <thead>
        <tr>${columns.map(([, label]) => `<th>${label}</th>`).join("")}</tr>
      </thead>
      <tbody>
        ${rows.slice(0, 100).map((row) => `
          <tr>
            ${columns.map(([key]) => `<td>${escapeHtml(row[key] ?? "")}</td>`).join("")}
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function renderNessusDetailTable(rows) {
  const container = document.getElementById("nessusDetailTable");
  if (!container) return;
  if (!rows.length) {
    container.innerHTML = `<div class="empty-state">No Nessus vulnerability detail rows are available. Rebuild va_data.json.</div>`;
    return;
  }
  const columns = [
    ["host", "Host"],
    ["ip_address", "IP Address"],
    ["port", "Port"],
    ["service", "Service"],
    ["plugin_id", "Plugin ID"],
    ["plugin_name", "Plugin Name"],
    ["severity", "Severity"],
    ["cvss", "CVSS"],
    ["cve", "CVE"],
    ["exploit_available", "Exploit Available"],
    ["solution", "Solution"],
  ];
  container.innerHTML = `
    <table>
      <thead>
        <tr>${columns.map(([, label]) => `<th>${label}</th>`).join("")}</tr>
      </thead>
      <tbody>
        ${rows.slice(0, 200).map((row) => `
          <tr>
            ${columns.map(([key]) => `<td>${escapeHtml(row[key] ?? "")}</td>`).join("")}
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function drawNessusSeverityTreemap(svg, rows) {
  if (!svg) return;
  const severityOrder = {
    "Security Hole": 0,
    "Critical": 0,
    "High": 1,
    "Security Warning": 2,
    "Medium": 2,
    "Low": 3,
    "Security Note": 4,
    "Info": 4,
    "(empty)": 5,
  };
  const data = [...rows].sort((a, b) => (severityOrder[a.key] ?? 9) - (severityOrder[b.key] ?? 9));
  drawTreemap(svg, data);
}

function buildNessusHostServiceCells(details) {
  const counts = new Map();
  details.forEach((row) => {
    const host = row.host || row.ip_address;
    const service = row.service || row.port || "unknown";
    if (!host || !service) return;
    const key = `${host}|${service}`;
    const current = counts.get(key) || { row: host, col: service, value: 0 };
    current.value += severityWeight(row.severity);
    counts.set(key, current);
  });
  return [...counts.values()];
}

function drawNessusHostPluginScatter(svg, details, fallbackRows) {
  if (!svg) return;
  const counts = new Map();
  details.forEach((row) => {
    const host = row.host || row.ip_address;
    const finding = firstNonEmpty([firstCve(row.cve), row.plugin_id, row.plugin_name]);
    if (!host || !finding) return;
    const key = `${host}|${finding}`;
    const current = counts.get(key) || { x: host, y: finding, value: 0, severity: row.severity };
    current.value += 1;
    current.severity = strongerSeverity(current.severity, row.severity);
    counts.set(key, current);
  });
  const points = [...counts.values()];
  if (!points.length && fallbackRows?.length) {
    fallbackRows.slice(0, 30).forEach((row, index) => {
      points.push({ x: `asset ${index + 1}`, y: row.key, value: row.value, severity: "Security Warning" });
    });
  }
  drawSeverityScatter(svg, points);
}

function drawSeverityScatter(svg, points) {
  const width = svg.clientWidth || 620;
  const height = svg.clientHeight || 360;
  const pad = { top: 22, right: 22, bottom: 76, left: 126 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";
  if (!points.length) {
    drawSvgEmptyState(svg, "No Nessus scatter data", "No host-CVE/plugin combinations are available.");
    return;
  }
  const xs = unique(points.map((p) => p.x)).slice(0, 12);
  const ys = unique(points.map((p) => p.y)).slice(0, 10);
  const max = Math.max(...points.map((p) => p.value), 1);
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const xPos = (x) => pad.left + (xs.indexOf(x) + 0.5) * (innerW / Math.max(xs.length, 1));
  const yPos = (y) => pad.top + (ys.indexOf(y) + 0.5) * (innerH / Math.max(ys.length, 1));

  line(svg, pad.left, pad.top + innerH, width - pad.right, pad.top + innerH, "axis");
  line(svg, pad.left, pad.top, pad.left, pad.top + innerH, "axis");
  xs.forEach((x) => {
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", xPos(x));
    label.setAttribute("y", height - 14);
    label.setAttribute("text-anchor", "end");
    label.setAttribute("transform", `rotate(-35 ${xPos(x)} ${height - 14})`);
    label.setAttribute("class", "tick-label");
    label.textContent = shortLabel(x);
    svg.appendChild(label);
  });
  ys.forEach((y) => text(svg, 8, yPos(y) + 4, shortLabel(y), "tick-label"));
  points.slice(0, 80).forEach((point) => {
    if (!xs.includes(point.x) || !ys.includes(point.y)) return;
    const radius = 4 + Math.sqrt(point.value / max) * 18;
    circle(svg, xPos(point.x), yPos(point.y), radius, severityColor(point.severity));
  });
}

function drawNessusParallelCoordinates(svg, details) {
  if (!svg) return;
  const sample = details
    .filter((row) => row.host || row.ip_address)
    .slice(0, 100)
    .map((row) => ({
      host: row.host || row.ip_address,
      service: row.service || row.port || "unknown",
      severity: row.severity || "unknown",
      finding: firstNonEmpty([firstCve(row.cve), row.plugin_id, row.plugin_name, "unknown"]),
      exploit: row.exploit_available || "unknown",
      cvss: bucketCvss(row.cvss),
      weight: severityWeight(row.severity),
    }));
  if (!sample.length) {
    drawSvgEmptyState(svg, "No Nessus multivariate sample", "No vulnerability detail rows are available.");
    return;
  }

  const width = svg.clientWidth || 760;
  const height = svg.clientHeight || 360;
  const pad = { top: 42, right: 38, bottom: 34, left: 38 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";

  const axes = [
    { key: "host", label: "Host", values: topValues(sample, "host", 10), get: (d) => d.host },
    { key: "service", label: "Service", values: topValues(sample, "service", 10), get: (d) => d.service },
    { key: "severity", label: "Severity", values: topValues(sample, "severity", 6), get: (d) => d.severity },
    { key: "finding", label: "CVE/Plugin", values: topValues(sample, "finding", 8), get: (d) => d.finding },
    { key: "cvss", label: "CVSS", values: ["unknown", "low", "medium", "high", "critical"], get: (d) => d.cvss },
    { key: "exploit", label: "Exploit", values: topValues(sample, "exploit", 5), get: (d) => d.exploit },
  ];
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const x = (i) => pad.left + i * (innerW / Math.max(axes.length - 1, 1));
  const y = (axis, value) => {
    const values = axis.values.length ? axis.values : [value];
    const index = Math.max(0, values.indexOf(value));
    return pad.top + index * (innerH / Math.max(values.length - 1, 1));
  };

  axes.forEach((axis, i) => {
    line(svg, x(i), pad.top, x(i), pad.top + innerH, "axis");
    text(svg, x(i) - 18, 22, axis.label, "pc-axis-label");
    axis.values.slice(0, 8).forEach((value) => {
      const yy = y(axis, value);
      line(svg, x(i) - 4, yy, x(i) + 4, yy, "axis");
      text(svg, x(i) + 6, yy + 4, shortLabel(value), "pc-tick-label");
    });
  });

  sample.forEach((row) => {
    const points = axes.map((axis, i) => [x(i), y(axis, axis.get(row))]);
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", points.map(([px, py], i) => `${i ? "L" : "M"} ${px} ${py}`).join(" "));
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", severityColor(row.severity));
    path.setAttribute("stroke-opacity", String(0.16 + row.weight * 0.08));
    path.setAttribute("stroke-width", row.weight >= 4 ? "2" : "1.1");
    svg.appendChild(path);
  });
}

function severityWeight(severity) {
  const text = String(severity || "").toLowerCase();
  if (text.includes("hole") || text.includes("critical")) return 5;
  if (text.includes("high")) return 4;
  if (text.includes("warning") || text.includes("medium")) return 3;
  if (text.includes("low")) return 2;
  if (text.includes("note") || text.includes("info")) return 1;
  return 1;
}

function severityColor(severity) {
  const weight = severityWeight(severity);
  if (weight >= 5) return colors.red;
  if (weight >= 4) return "#d95f02";
  if (weight >= 3) return colors.amber;
  if (weight >= 2) return colors.teal;
  return colors.blue;
}

function strongerSeverity(a, b) {
  return severityWeight(b) > severityWeight(a) ? b : a;
}

function firstCve(value) {
  const text = String(value || "");
  return text.split(",").map((v) => v.trim()).find(Boolean) || "";
}

function firstNonEmpty(values) {
  return values.find((v) => String(v || "").trim()) || "";
}

function bucketCvss(value) {
  const n = Number(value || 0);
  if (!n) return "unknown";
  if (n >= 9) return "critical";
  if (n >= 7) return "high";
  if (n >= 4) return "medium";
  return "low";
}

function drawSvgEmptyState(svg, title, subtitle) {
  const width = svg.clientWidth || 520;
  const height = svg.clientHeight || 360;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";
  rect(svg, 0, 0, width, height, "#fbfcfd");
  text(svg, 24, 42, title, "empty-svg-title");
  text(svg, 24, 66, subtitle, "empty-svg-subtitle");
}

function drawTimeline(svg, config) {
  if (!svg) return;
  const width = svg.clientWidth || 900;
  const height = svg.clientHeight || 250;
  const pad = { top: 18, right: 18, bottom: 38, left: 48 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = "";
  const rows = config.rows.slice(0, config.limit || 90);
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

function drawLegend(svg, x, y, items) {
  let offset = 0;
  items.forEach(([label, fill]) => {
    rect(svg, x + offset, y - 9, 10, 10, fill);
    text(svg, x + offset + 15, y, label, "tick-label");
    offset += 86;
  });
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

function stripEndpoint(value) {
  const text = String(value || "");
  return text.includes(":") && text.split(":").length === 2 ? text.split(":")[0] : text;
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
