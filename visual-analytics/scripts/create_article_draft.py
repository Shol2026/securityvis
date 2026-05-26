from pathlib import Path

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "VA_Q1Q2_Article_Introduction_Literature_Review.docx"
OUT_FULL = ROOT / "VA_Q1Q2_Article_Draft_Intro_RelatedWork_Methods.docx"
OUT_RESULTS = ROOT / "VA_Q1Q2_Article_Draft_Intro_RelatedWork_Methods_Results.docx"
OUT_COMPLETE = ROOT / "VA_Q1Q2_Article_Draft_Complete.docx"


def set_font(run, size=11, bold=False, italic=False):
    run.font.name = "Times New Roman"
    run._element.rPr.rFonts.set(qn("w:eastAsia"), "Times New Roman")
    run.font.size = Pt(size)
    run.bold = bold
    run.italic = italic


def set_cell_shading(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def set_cell_text(cell, text, bold=False):
    cell.text = ""
    paragraph = cell.paragraphs[0]
    run = paragraph.add_run(text)
    set_font(run, size=10, bold=bold)
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP


def add_para(doc, text, italic=False, left_indent=None, right_indent=None):
    paragraph = doc.add_paragraph()
    if left_indent:
        paragraph.paragraph_format.left_indent = left_indent
    if right_indent:
        paragraph.paragraph_format.right_indent = right_indent
    paragraph.paragraph_format.space_after = Pt(6)
    paragraph.paragraph_format.line_spacing = 1.08
    run = paragraph.add_run(text)
    set_font(run, italic=italic)
    return paragraph


def add_reference(doc, text):
    paragraph = doc.add_paragraph(text)
    paragraph.paragraph_format.space_after = Pt(3)
    paragraph.paragraph_format.first_line_indent = Inches(-0.22)
    paragraph.paragraph_format.left_indent = Inches(0.22)
    for run in paragraph.runs:
        set_font(run, size=10)


INTRODUCTION = [
    "Modern cybersecurity investigations are increasingly shaped by the volume, heterogeneity, and temporal velocity of security evidence. A single incident may leave traces in firewall logs, intrusion detection system (IDS) alerts, packet captures, Windows security logs, vulnerability scanners, and raw system or network messages. Each source describes only a partial view of the same operational reality: firewall logs show whether communication was allowed or denied; IDS alerts encode signatures and priorities; PCAP data records packet-level behavior; Windows logs expose host, account, and authentication activity; and vulnerability scanners such as Nessus describe the exposure surface that may explain why a host was attractive to an attacker. In practice, analysts must combine these fragments into a coherent explanation of what happened, when it happened, which assets were involved, and which evidence supports the resulting hypothesis.",
    "The difficulty is not only computational but also cognitive. Security analysts rarely investigate a single homogeneous table. They move among different tools, schemas, time formats, identifiers, levels of abstraction, and evidential meanings. A suspicious IP address found in an IDS alert must often be checked against firewall deny, built, or teardown events, packet-level conversations, Windows logon activity, vulnerable services, and original raw messages. This cross-source navigation is central to incident response, yet many tools still present data in source-specific views that require analysts to mentally maintain relationships across time, entities, ports, protocols, signatures, accounts, and vulnerabilities. As a result, the burden of constructing an attack story is frequently shifted from the system to the analyst.",
    "Visual analytics offers a relevant methodological foundation for this problem because it emphasizes analytical reasoning supported by interactive visual interfaces rather than fully automated detection alone. In cybersecurity, visual analytics is especially important because automated alerts can be incomplete, noisy, or difficult to trust. Analysts need visual representations that help them identify temporal bursts, dense communication structures, scanning patterns, abnormal host behavior, vulnerable assets, and raw evidence confirming or refuting a hypothesis. Therefore, the central design problem is not simply to display more charts, but to support a reasoning process that moves from overview to detail, from anomaly to evidence, and from isolated observations to a coherent attack narrative.",
    "Over the last twenty-five years, the cybersecurity visualization literature has produced many influential systems. Early network security visualizations such as NVisionIP, PortVis, TNV, VisFlowConnect-IP, InetVis, Isis, RUMINT, Picviz, and NFlowVis demonstrated the value of timelines, port-based views, host-time matrices, flow links, scatterplots, and parallel coordinates for identifying scans, bursts, anomalous communications, and suspicious traffic structures. IDS-oriented systems such as IDS RainStorm, Avisa, AlertWheel, IDSRadar, IDSPlanet, and Hyperion addressed the problem of alert overload and showed how temporal, radial, heuristic, and interactive views can improve alert exploration. Firewall-oriented tools such as PolicyVis and VAFLE focused on policy inspection and firewall log event analysis. More recent systems, including MVSec, OCEANS, SemanticPrism, BANKSAFE, KAVAS, CyGraph, Situ, and Riverside, advanced the field toward heterogeneous data integration, collaboration, anomaly explanation, graph-based reasoning, and situation awareness.",
    "Despite this progress, a persistent gap remains. Many systems are optimized for a single evidence type, such as NetFlow, IDS alerts, firewall policies, malware traces, audit logs, or vulnerability data. Other systems integrate heterogeneous sources, but often emphasize general situation awareness, collaborative exploration, or alert management rather than an explicit reasoning workflow for reconstructing an attack story across firewall, IDS, PCAP, Windows log, vulnerability, and raw evidence. There is also a need for clearer mapping between cyber data types, visual encodings, and investigative reasoning patterns. For example, timeline views support temporal reasoning, heatmaps and matrices support relational reasoning, scatterplots support recognition of scanning and outlier patterns, parallel coordinates support multivariate correlation, and raw-message drill-down supports evidential validation. However, these visual encodings are often discussed separately rather than organized into a coordinated workflow for cross-source investigation.",
    "This study addresses that gap by proposing a reasoning-oriented visual analytics approach for multi-source cybersecurity evidence. The approach is based on a unified analytical layer that normalizes heterogeneous security data around shared investigative dimensions: time, source and destination IP addresses, host names, accounts, ports, protocols, event categories, severity, risk, and raw evidence references. On top of this layer, coordinated dashboards support source-specific analysis while enabling cross-source pivots by IP, host, account, port, protocol, and time interval. The intended workflow follows an analyst-centered progression: detect a temporal anomaly, identify involved entities, inspect communication and port patterns, correlate alerts with packet and host evidence, evaluate asset exposure through vulnerability findings, and validate normalized records against raw evidence.",
    "The main research question guiding the work is: how can coordinated visual analytics support the construction of a coherent attack story from heterogeneous cybersecurity data? A secondary question is: which visualization types are most appropriate for different cyber data sources and reasoning tasks? In response, the proposed system organizes visual encodings according to four complementary reasoning patterns: temporal reasoning, relational reasoning, visual attack-pattern recognition, and multivariate correlation. Timeline views reveal the development of events and attack phases; matrix-based heatmaps reveal source-target and host-service density; scatterplots expose scanning behavior, clusters, and outliers; and parallel coordinates help analysts trace multiple attributes within a single coordinated view. Together, these views are designed to reduce cognitive fragmentation and help analysts externalize the reasoning process.",
    "The expected contribution of the study is threefold. First, it provides a unified analytical model for heterogeneous cyber evidence rather than treating firewall, IDS, PCAP, Windows logs, Nessus findings, and raw messages as disconnected sources. Second, it proposes a reasoning-oriented navigation model that connects overview, pattern recognition, multivariate correlation, cross-source pivoting, and raw validation. Third, it presents a visualization map that explains why specific visual encodings are appropriate for specific cyber data types and investigative questions. This framing distinguishes the work from purely operational dashboards by positioning the system as a visual reasoning environment for attack story reconstruction.",
]


RELATED_WORK = [
    (
        "2.1. Foundational network security visualization and traffic analysis",
        [
            "Early work in network security visualization established the central importance of representing traffic in ways that allow analysts to preserve a global view while drilling down to suspicious entities. NVisionIP visualized large IP address spaces to help analysts inspect network state at different levels of granularity. PortVis introduced port-oriented visualization for detecting security events, making destination port distributions a primary analytical object. TNV contributed a host-time matrix and packet-level detail workflow that is especially relevant to the overview-to-detail principle. VisFlowConnect-IP and later NFlowVis emphasized flow-based relationships between internal and external hosts, while InetVis and related scatterplot approaches demonstrated how scanning activity can become visible as geometric patterns in a visual space.",
            "RUMINT and Conti's broader work on security data visualization showed how packet captures, logs, binary data, and protocol features can be represented through diverse visual encodings, including parallel coordinates and byte-level views. Picviz further emphasized parallel coordinates for log and network data, arguing that multivariate cyber events require displays where analysts can visually trace relationships among attributes. Isis introduced timelines and event plots for iterative investigation of intrusions using network flow data. Together, these systems show that traffic analysis benefits from a combination of temporal views, relational views, port-oriented views, scatterplots, and multivariate encodings. This is directly aligned with the proposed PCAP and Firewall dashboards, where timelines, heatmaps, scatterplots, and parallel coordinates are used to support different reasoning operations.",
        ],
    ),
    (
        "2.2. IDS alert visualization and alert overload",
        [
            "IDS alerts are a central source of cyber evidence, but they are also noisy, redundant, and difficult to interpret at scale. IDS RainStorm addressed this problem by visualizing large numbers of IDS alarms and supporting a progression from overview to zoomed detail. Avisa introduced heuristic host selection to help analysts focus on hosts with irregular alert behavior. AlertWheel used radial bipartite graph visualization to represent IDS alert relationships and supported filtering, annotation, and detail-on-demand. IDSRadar focused on real-time visualization of IDS alerts, while IDSPlanet used a radial metaphor with chrono rings and alert continents to encode temporal evolution, affected hosts, alert types, attackers, and targets.",
            "More recent IDPS-focused work, such as Hyperion, extends alert visualization toward rule management and rule revision. This is important because security analysts do not only ask which alerts occurred; they also need to understand how rules, signatures, network entities, and event frequencies interact. The IDS literature therefore supports the choice of timeline, heatmap, scatterplot, and parallel coordinates in the proposed IDS dashboard. The timeline helps identify when alert bursts occur; source-destination heatmaps reveal attacker-target density; scatterplots expose scanning or clustered alert behavior; and parallel coordinates help correlate signature, priority, protocol, source, destination, and port attributes.",
        ],
    ),
    (
        "2.3. Firewall visualization and policy/event interpretation",
        [
            "Firewall data has been studied from both policy and event-log perspectives. PolicyVis focused on firewall policy visualization and inspection, addressing the complexity of low-level firewall rules and rule interactions. This line of work is relevant because it shows that firewall data cannot be treated as ordinary logs; it encodes access-control decisions that must be interpreted in terms of rule behavior, allowed and denied spaces, and possible misconfiguration. VAFLE shifted attention toward firewall log events and used coordinated visualizations and clustering to help analysts detect anomalies and understand cyber situation awareness. Recent work on visual firewall log analysis further highlights the practical value of making firewall event patterns analytically visible.",
            "For the present study, firewall evidence is treated as the first layer of network access reasoning. Allow, deny, built, and teardown actions reveal how the perimeter reacted to connection attempts. A temporal burst of denied events may indicate scanning or blocked attack attempts, while a high number of allowed sessions to a sensitive service may require correlation with PCAP, IDS, and vulnerability data. Therefore, the proposed Firewall dashboard is designed around four reasoning functions: detecting temporal activity bursts, identifying source-target density, recognizing port-scanning patterns, and correlating action, protocol, port, and endpoint attributes through multivariate views.",
        ],
    ),
    (
        "2.4. Multi-source, heterogeneous, and coordinated visual analytics",
        [
            "A key limitation of many early systems is their focus on a single evidence type. Later work moved toward heterogeneous sources and coordinated views. VIAssist proposed visual analytics for cyber defense through coordinated views, collaborative workflows, and reporting support. SemanticPrism and BANKSAFE addressed large-scale, high-dimensional security data through multi-aspect visual analytics and situation awareness. MVSec is particularly relevant because it explicitly targets multi-perspective and deductive visual analytics on heterogeneous network security data. OCEANS similarly integrates NetFlow, IPS logs, and host-status logs in a collaborative visual analysis environment, supporting multi-level temporal, IP connection, and detailed connection views.",
            "Another important contribution is the concept of representational fluency, which links different visualizations of the same cybersecurity data to help analysts navigate across perspectives. This principle is directly applicable to cross-dashboard transitions in the proposed system. Instead of forcing analysts to re-enter a suspicious IP, host, account, port, or time interval in each tool, linked visual analytics should preserve context and allow the analyst to pivot among Firewall, IDS, PCAP, Windows Logs, Nessus, and raw evidence. Multi-source fusion research also demonstrates the value of combining heatmaps, treemaps, radial node-link diagrams, and time-series features to improve network situation awareness. However, the present study extends this logic by organizing heterogeneous evidence around explicit reasoning patterns and attack story construction.",
        ],
    ),
    (
        "2.5. Host, identity, audit-log, and malware behavior visualization",
        [
            "Network evidence alone is often insufficient to explain an intrusion. Host logs and identity events are required to understand whether suspicious communication corresponds to authentication activity, process execution, service installation, privilege use, or account compromise. Fink and colleagues' work on visual correlation of host processes and network traffic highlighted the host/network divide: administrators often detect suspicious communication first and then need to determine which host processes are responsible. This insight is central to the proposed cross-source workflow, where network anomalies discovered in Firewall, IDS, or PCAP should lead to Windows log and host/account investigation.",
            "LongLine addressed large-scale audit logs through interactive visual analysis, multi-scale temporal views, and comparative exploration of audit-log subsets. KAMAS focused on knowledge-assisted visual malware analysis and demonstrated that expert knowledge, workflow-specific interaction, and knowledge externalization are important for security analysis. These studies support the design of a WindowsLogs dashboard that emphasizes event timelines, user-host activity, process or event relationships, and suspicious command patterns when available. They also support the broader argument that visual analytics should not merely summarize events, but should help analysts externalize and refine hypotheses about attacker behavior.",
        ],
    ),
    (
        "2.6. Vulnerability, exposure, and attack-graph visualization",
        [
            "Vulnerability data differs from event data because it usually describes exposure rather than observed activity. Nevertheless, exposure is essential for attack reasoning: a service that receives suspicious traffic is more important if the target host is known to have a relevant high-risk vulnerability. NV Nessus and related vulnerability visualization systems showed the value of transforming scanner output into views that help analysts understand host exposure. VULNUS extended this direction by combining vulnerability analysis, treemaps, and attack-graph concepts to support patch prioritization and network risk reasoning. CyGraph and other graph-based cyber situational awareness systems integrate vulnerabilities, alerts, network topology, dependencies, and mission context into a graph representation for reasoning about attack paths and mission impact.",
            "For the proposed system, Nessus findings are not treated as a separate remediation list only. They provide explanatory context for why a target asset is exposed, which ports or services matter, and which vulnerabilities may dominate the risk landscape. A reasoning-oriented Nessus dashboard should therefore emphasize severity distribution, host-service exposure, repeated CVE/plugin patterns, and multivariate relationships among host, service, port, risk, CVSS, exploit availability, and solution information. When linked to Firewall, IDS, and PCAP views, vulnerability evidence helps analysts move from observed suspicious activity to plausible attack opportunity.",
        ],
    ),
    (
        "2.7. Human-centered design, explanation, and evaluation",
        [
            "The visual analytics literature repeatedly emphasizes that cybersecurity tools must be designed around analyst tasks and cognitive processes. The Real Work of Computer Network Defense Analysts used cognitive task analysis to describe how defenders actually perform investigation and sensemaking. Evaluation-focused work in VizSec, including Visualization Evaluation for Cyber Security and later evaluation frameworks for network security visualizations, argues that cyber visualization systems require careful assessment of tasks, data sources, interaction, usability, scalability, and operational relevance. EEVi and design-space analyses further reinforce the need to connect visual encodings, security tasks, input data, interaction, and evaluation.",
            "Recent systems such as Situ and Riverside are especially relevant to the reasoning orientation of the present study. Situ combines anomaly detection and visualization to help analysts identify suspicious behavior and understand why the system considers it anomalous. Riverside follows a user-centered design study for situation awareness and emphasizes dynamic network views connected to temporal navigation. These works support a shift from static dashboards to interactive reasoning environments. They also suggest that a Q1/Q2-level contribution should not be limited to interface construction; it should articulate the cognitive tasks, visual encodings, interaction model, and evaluation criteria that justify the system design.",
        ],
    ),
    (
        "2.8. Synthesis of gaps and positioning of the present study",
        [
            "The reviewed literature demonstrates that cybersecurity visual analytics has matured significantly, but several gaps remain relevant. First, many systems are evidence-specific: they focus on NetFlow, packet capture, IDS alerts, firewall policies, audit logs, malware behavior, or vulnerability scans separately. Second, heterogeneous systems often support situation awareness or collaborative exploration but do not always provide an explicit attack-story workflow that moves across firewall, IDS, PCAP, Windows logs, Nessus, and raw evidence. Third, many visualizations are presented as useful views but are not always mapped systematically to reasoning patterns such as temporal reasoning, relational reasoning, pattern recognition, multivariate correlation, and evidence validation. Fourth, raw evidence validation is often treated as an external step, even though forensic confidence depends on being able to compare normalized analytical records with original messages.",
            "The proposed study is positioned at the intersection of these gaps. It does not claim that timeline, heatmap, scatterplot, or parallel coordinates are novel in isolation. Instead, the novelty lies in organizing these encodings into a coordinated, reasoning-oriented workflow for multi-source cybersecurity investigation. The planned system links heterogeneous sources through common investigative dimensions and supports transitions among source-specific dashboards while preserving analytical context. This allows the analyst to construct a coherent attack story rather than inspect isolated charts. Such a framing is consistent with the direction of contemporary visual analytics research, where the central goal is not merely visualization of data, but support for human reasoning, hypothesis generation, evidence correlation, and decision-making under uncertainty.",
        ],
    ),
]


TABLE_ROWS = [
    (
        "Network traffic and flow visualization",
        "NVisionIP, PortVis, TNV, VisFlowConnect-IP, InetVis, Isis, RUMINT, Picviz, NFlowVis",
        "Timelines, host-time matrices, port views, scatterplots, flow links, parallel coordinates",
        "Supports PCAP/firewall/traffic reasoning, scan detection, port analysis, and overview-to-detail workflows.",
    ),
    (
        "IDS alert visualization",
        "IDS RainStorm, Avisa, AlertWheel, IDSRadar, IDSPlanet, Hyperion",
        "Alert overview, temporal rings, radial/bipartite views, heuristic host selection, alert-rule analysis",
        "Supports IDS tab design, alert overload reduction, signature-priority reasoning, and attacker-target correlation.",
    ),
    (
        "Firewall visualization",
        "PolicyVis, VAFLE, Visual Firewall Log Analysis",
        "Firewall policy visualization, rule inspection, event clustering, coordinated firewall log views",
        "Supports allow/deny reasoning, source-destination-port matrices, and firewall event interpretation.",
    ),
    (
        "Multi-source and collaborative VA",
        "VIAssist, SemanticPrism, BANKSAFE, MVSec, OCEANS, Fluency of Visualizations, multi-source fusion systems",
        "Linked views, heterogeneous data fusion, collaboration, semantic zoom, representation linking",
        "Provides foundation for cross-source pivots and attack story reconstruction.",
    ),
    (
        "Host, audit-log, and behavior analysis",
        "Portall/HoNe, LongLine, KAMAS",
        "Host-network correlation, audit-log timelines, behavior-based malware analysis, knowledge externalization",
        "Supports Windows log dashboard and correlation between account, process, host, and network evidence.",
    ),
    (
        "Vulnerability and attack graph visualization",
        "NV Nessus, VULNUS, CyGraph, attack-graph dashboards",
        "Vulnerability overview, asset exposure, graph-based dependencies, attack paths",
        "Supports Nessus dashboard and risk/exposure reasoning.",
    ),
    (
        "Human-centered cyber VA evaluation",
        "Real Work of CND Analysts, EEVi, Visualization Evaluation for Cyber Security, Situ, Riverside, design-space analyses",
        "Cognitive task analysis, expert studies, situation awareness, explanation, trust, evaluation taxonomies",
        "Supports Q1/Q2 framing: reasoning, user tasks, evaluation, and analyst-centered workflow.",
    ),
]


MATERIALS_ROWS = [
    (
        "Firewall",
        "firewall_log_1.csv",
        "Cisco ASA firewall/session events",
        "1,048,575 CSV rows; 306,786 non-empty rows; 741,789 blank rows",
        "2011-04-13 08:52 to 2011-04-13 11:41",
        "Date/time, source IP, destination IP, source port, destination port, protocol, direction, operation/action, service, message code",
    ),
    (
        "IDS",
        "IDS.txt",
        "Snort/Sourcefire intrusion detection alerts",
        "8,794 alerts",
        "2011-04-13 07:54:00.585009 to 2011-04-14 08:01:11.490642",
        "Timestamp, signature/classification, source endpoint, destination endpoint, source/destination ports derived from endpoints",
    ),
    (
        "Windows Logs",
        "SecurityLog.xml",
        "Windows Security event log from a domain controller",
        "79,688 events",
        "2011-04-13 14:57:43.578125+00:00 to 2011-04-14 15:03:12.562500+00:00",
        "SystemTime, EventID, Computer, TargetUserName, SubjectUserName, IpAddress, Status, authentication and Kerberos fields",
    ),
    (
        "PCAP",
        "pcap_1.pcap",
        "Packet capture, header-level packet evidence",
        "9,362,286 packets; 374,491,440 included bytes; snap length 40; Ethernet link type",
        "2011-04-13 20:12:03.418810 to 2011-04-13 20:15:06.838272",
        "Timestamp, Ethernet type, IP protocol, source IP, destination IP, TCP/UDP source port, TCP/UDP destination port, included length",
    ),
    (
        "Nessus",
        "Nessus.xls",
        "Vulnerability scan findings",
        "241 hosts; 1,534 result rows",
        "Scan evidence from 2011-04-11, represented as vulnerability findings",
        "Host, port, service, plugin ID/name, risk/severity, CVE, CVSS, exploit availability, synopsis, solution",
    ),
    (
        "Raw Evidence",
        "raw_firewall_log_1.txt",
        "Original raw firewall/syslog evidence",
        "Used as drill-down validation evidence; not loaded directly into overview dashboards",
        "Corresponds to the firewall evidence period",
        "Original message text queried on demand to validate normalized analytical records",
    ),
]


METHOD_VIS_ROWS = [
    (
        "Temporal reasoning",
        "When did suspicious activity emerge and how did it evolve?",
        "Timeline / stacked temporal view",
        "Firewall operations, IDS alerts, PCAP packet volume, Windows EventID activity",
    ),
    (
        "Relational reasoning",
        "Which sources, targets, hosts, services, or accounts are connected?",
        "Heatmap / matrix",
        "Source IP x Destination IP, Source IP x Destination Port, User x Host, Host x Service",
    ),
    (
        "Visual attack-pattern recognition",
        "Are there scan-like structures, clusters, or outliers?",
        "Scatterplot",
        "Time x Destination Port, Source IP x Destination IP, Host x Plugin/CVE, packet flow distributions",
    ),
    (
        "Multivariate correlation",
        "How do time, endpoint, port, protocol, action, signature, severity, and risk co-vary?",
        "Parallel coordinates",
        "Firewall, IDS, PCAP, and Nessus attributes represented as coordinated dimensions",
    ),
    (
        "Evidence validation",
        "Can the normalized record be checked against original evidence?",
        "Linked raw drill-down / original-message retrieval",
        "Raw firewall/syslog messages and source-specific detail references",
    ),
]


RESULT_SUMMARY_ROWS = [
    (
        "Firewall",
        "306,786 non-empty events",
        "Built: 144,640; Teardown: 126,331; Deny: 35,479",
        "Dominant HTTP traffic to 172.20.1.5 and visible access-control activity across TCP, UDP, and ICMP.",
    ),
    (
        "IDS",
        "8,794 alerts",
        "TCP window-scale anomaly: 6,144; TCP Portscan: 2,188; TCP Portsweep: 381",
        "Reconnaissance-oriented alerts concentrated around 192.168.2.x sources and 192.168.1.2 / 192.168.1.14 / 192.168.1.6 targets.",
    ),
    (
        "Windows Logs",
        "79,688 events",
        "EventID 4624: 35,045; 4634: 35,045; 4769: 4,751; 4672: 4,297",
        "Domain-controller evidence linking accounts, hosts, IP addresses, logons, Kerberos activity, and privileged logon events.",
    ),
    (
        "PCAP",
        "9,362,286 packets",
        "TCP: 8,272,015; UDP: 1,082,548; ICMP: 2,322",
        "Short high-volume packet slice showing HTTP to 172.20.1.5 and UDP/514 syslog-like traffic.",
    ),
    (
        "Nessus",
        "1,534 findings on 241 hosts",
        "Security Hole: 919; Security Note: 476; Security Warning: 125",
        "High exposure concentrated on 192.168.2.171-175, especially CIFS/SMB-related services.",
    ),
]


RESULT_STORY_ROWS = [
    (
        "1. Vulnerability surface",
        "2011-04-11 10:16-10:19",
        "Nessus.xls",
        "Workstations 192.168.2.171-175 contain many Security Hole findings, including SMB/CIFS and Microsoft Office/IE-related findings.",
        "Establishes exposed assets and plausible attack opportunity before later network activity.",
    ),
    (
        "2. Reconnaissance",
        "2011-04-13 07:54+",
        "IDS.txt",
        "IDS records TCP Portscan and TCP Portsweep patterns from 192.168.2.x hosts toward 192.168.1.2, 192.168.1.14, and 192.168.1.6.",
        "Supports the hypothesis of scanning or reconnaissance activity.",
    ),
    (
        "3. Connection attempts",
        "2011-04-13 08:52-11:41",
        "firewall_log_1.csv",
        "Firewall records Built, Teardown, and Deny events with prominent TCP, HTTP/80, SMB/RPC/Kerberos/LDAP-related ports.",
        "Shows how perimeter controls observed and reacted to network communication attempts.",
    ),
    (
        "4. Domain activity",
        "2011-04-13 14:57 to 2011-04-14 15:03 UTC",
        "SecurityLog.xml",
        "DC01 records successful logons, logoffs, Kerberos ticket events, and privileged logon events.",
        "Links network entities to account and domain activity, providing host/identity context.",
    ),
    (
        "5. Packet-level burst",
        "2011-04-13 20:12-20:15 UTC",
        "pcap_1.pcap",
        "PCAP records a short high-volume traffic slice including HTTP communication with 172.20.1.5 and UDP/514 traffic.",
        "Provides packet-level confirmation of observed communication patterns.",
    ),
]


RESULTS = [
    (
        "4.1. Overview of processed evidence",
        [
            "The proposed pipeline successfully transformed the heterogeneous evidence sources into a unified analytical layer while preserving the semantics of each source. Table 4 summarizes the main quantitative results obtained after preprocessing and aggregation. The resulting analytical layer contains source-specific summaries, timelines, top entities, relational matrices, vulnerability summaries, and a cross-source attack-story sequence. Importantly, the system does not collapse all records into a single flat table. Instead, it retains the distinct meaning of each source and exposes shared investigative dimensions for coordinated reasoning.",
            "The processed evidence shows substantial heterogeneity in both volume and time coverage. Firewall logs contain 306,786 non-empty events within a three-hour period. IDS alerts span approximately twenty-four hours and contain 8,794 alerts. Windows Security logs contain 79,688 domain-controller events across roughly one day. The PCAP file contains 9,362,286 packets within a short three-minute capture window. Nessus contains 1,534 vulnerability findings across 241 hosts. This heterogeneity confirms the need for a visual analytics layer that supports both source-specific exploration and cross-source pivots rather than applying a single uniform visualization to all data.",
        ],
    ),
    (
        "4.2. Firewall results",
        [
            "The firewall evidence shows a clear operational distribution: 144,640 Built events, 126,331 Teardown events, and 35,479 Deny events. TCP is the dominant protocol with 273,339 events, followed by UDP with 23,768 events and ICMP with 9,343 events. The highest-volume destination is 172.20.1.5 with 194,449 events, and the dominant destination port is TCP/80 with the same count. The top source-to-destination flows are from 10.200.150.201, 10.200.150.206, 10.200.150.207, 10.200.150.209, and 10.200.150.208 toward 172.20.1.5 on port 80.",
            "The firewall dashboard results demonstrate the value of complementary visual encodings. The timeline view reveals when firewall activity intensifies and whether Deny events rise together with Built and Teardown events. The Source IP x Destination IP heatmap identifies concentration around 172.20.1.5, while the Source IP x Destination Port matrix reveals prominent HTTP/80 traffic and additional service-oriented activity on ports such as 43032, 43025, 135, 445, 389, and 88. The scatterplot and parallel coordinates views support reasoning about whether the pattern reflects ordinary service access, concentrated automated activity, or blocked connection attempts requiring correlation with IDS and PCAP evidence.",
        ],
    ),
    (
        "4.3. IDS results",
        [
            "The IDS evidence is dominated by a small set of signatures. The most frequent alert is the TCP Window Scale Option anomaly with 6,144 occurrences. Reconnaissance-oriented detections are also prominent: TCP Portscan appears 2,188 times, and TCP Portsweep appears 381 times. The top IDS destinations are 192.168.1.2 with 1,421 alerts, 192.168.1.14 with 1,106 alerts, and 192.168.1.6 with 83 alerts. Several high-frequency source endpoints are associated with 192.168.2.171, 192.168.2.172, and 192.168.2.173 using different ephemeral source ports.",
            "These results support a reconnaissance hypothesis rather than a single isolated alert interpretation. In the IDS dashboard, the timeline shows when alert bursts occur, the heatmap reveals repeated relationships between 192.168.2.x sources and 192.168.1.x targets, and the scatterplot exposes repeated source-target and source-port patterns. Parallel coordinates make the relationship among source, destination, destination port, signature, and alert count visually traceable. This is important because portscan and portsweep activity is not defined by a single event; it becomes meaningful through repetition across targets, ports, and time.",
        ],
    ),
    (
        "4.4. PCAP results",
        [
            "The PCAP evidence contains a short but very dense traffic slice: 9,362,286 packets within approximately three minutes. TCP dominates the capture with 8,272,015 packets, followed by UDP with 1,082,548 packets and ICMP with 2,322 packets. The highest-volume destination is 172.20.1.5 with 4,822,779 packets. The top destination port is TCP/80 with 4,823,642 packets, which corresponds to the firewall evidence showing heavy HTTP traffic to 172.20.1.5. The second major pattern is UDP/514 with 1,076,993 packets, primarily from 192.168.1.1 to 192.168.1.50.",
            "The PCAP dashboard provides packet-level support for patterns observed in higher-level logs. The timeline reveals the intensity of the short capture window, while the Source IP x Destination IP heatmap and Source IP x Destination Port matrix show the dominant conversations and services. The agreement between firewall and PCAP evidence around 172.20.1.5 and port 80 is an example of cross-source corroboration. However, the PCAP evidence should be interpreted carefully because the capture window is much shorter than the firewall and IDS windows and the snap length is limited to 40 bytes. Therefore, the PCAP results are strongest as packet-level confirmation of traffic structure rather than complete payload-level forensic evidence.",
        ],
    ),
    (
        "4.5. Windows Security log results",
        [
            "The Windows Security log contains 79,688 events from DC01.AFC.com. The dominant Event IDs are 4634 logoff events and 4624 successful logon events, each with 35,045 occurrences. Kerberos service ticket events, represented by EventID 4769, occur 4,751 times. EventID 4672, indicating special privileges assigned to a new logon, appears 4,297 times. The top IP addresses include 192.168.1.14, 127.0.0.1, 192.168.1.2, ::1, 192.168.1.6, and 192.168.2.172.",
            "The WindowsLogs dashboard adds identity and domain context to the network evidence. The User x Host matrix links machine and account identities with IP addresses and authentication events. For example, 192.168.2.172 appears in the Windows log activity and also appears in IDS evidence and Nessus exposure results. This does not by itself prove compromise, but it provides an analytically valuable pivot point: an entity observed in vulnerability exposure, IDS alerts, and authentication evidence deserves deeper inspection. The results also show a dataset limitation: the available Windows Security log primarily contains authentication and Kerberos evidence, while process-chain evidence is limited. Therefore, process-tree conclusions should be treated as conditional on the presence of process creation fields.",
        ],
    ),
    (
        "4.6. Nessus vulnerability results",
        [
            "The Nessus evidence contains 1,534 findings across 241 hosts. The risk distribution is dominated by Security Hole findings, with 919 occurrences, followed by 476 Security Note findings and 125 Security Warning findings. The most exposed hosts are 192.168.2.175, 192.168.2.174, and 192.168.2.173 with 263 findings each, followed by 192.168.2.172 with 256 findings and 192.168.2.171 with 253 findings. CIFS on 445/tcp is the most frequent service category, with 939 findings, followed by general/tcp and SMB on 139/tcp.",
            "The Nessus dashboard results are important because they provide exposure context for network events. Several of the most vulnerable hosts, particularly 192.168.2.171, 192.168.2.172, and 192.168.2.173, also appear in IDS source patterns. This cross-source relationship suggests that vulnerability data can help prioritize which network entities deserve attention. In the reasoning workflow, Nessus does not prove that exploitation occurred; instead, it identifies assets and services where suspicious activity would have higher security relevance.",
        ],
    ),
    (
        "4.7. Cross-source attack story reconstruction",
        [
            "The most important result of the proposed system is not a single chart but the construction of a multi-source evidence chain. Table 5 summarizes the attack-story sequence generated from the available evidence. The sequence begins with exposure, where Nessus identifies vulnerable hosts in the 192.168.2.171-175 range. It then moves to reconnaissance, where IDS records portscan and portsweep patterns from 192.168.2.x hosts toward 192.168.1.x targets. Firewall evidence then shows connection attempts and access-control decisions across HTTP, SMB/RPC, Kerberos, LDAP, and related ports. Windows Security logs provide domain and authentication context, and PCAP supplies packet-level confirmation of short high-volume communication patterns.",
            "This sequence should be interpreted as an evidence-supported investigation narrative rather than an attribution claim. The system helps analysts formulate and test hypotheses by showing which facts are supported by which source. For example, the IDS source 192.168.2.172 is relevant because it also appears in Nessus exposure and Windows log activity. The target 172.20.1.5 is relevant because it dominates both firewall and PCAP HTTP traffic. The Windows targets 192.168.1.2, 192.168.1.14, and 192.168.1.6 are relevant because they appear in IDS destinations, firewall destinations, and Windows authentication evidence. Such cross-source intersections are precisely where a reasoning-oriented visual analytics system adds value.",
        ],
    ),
    (
        "4.8. Results of reasoning-oriented visualization design",
        [
            "The implemented visual analytics model supports four complementary reasoning patterns. Temporal reasoning is supported by timelines that reveal bursts and phase transitions. Relational reasoning is supported by heatmaps and matrices that expose dense communication, user-host, and host-service relationships. Visual attack-pattern recognition is supported by scatterplots that reveal repeated source-port, time-port, and entity-pattern structures. Multivariate reasoning is supported by parallel coordinates that allow analysts to trace how time, source, destination, port, protocol, action, signature, severity, and risk interact.",
            "The results also show why a multi-dashboard but coordinated design is preferable to a single monolithic visualization. Firewall, IDS, PCAP, Windows, and Nessus evidence have different semantics and should not be forced into one visual grammar. At the same time, analysts need transitions between dashboards by shared entities such as IP address, host, account, port, protocol, and time. Therefore, the system's main contribution is the combination of source-specific visual reasoning and cross-source pivoting. This design helps the analyst move from overview to detail without losing the evidential chain needed to reconstruct an attack story.",
        ],
    ),
]


DISCUSSION = [
    (
        "5.1. Interpretation of the findings",
        [
            "The results demonstrate that a reasoning-oriented visual analytics system can transform heterogeneous security evidence into a coherent investigative structure without eliminating the semantic differences among sources. Firewall logs, IDS alerts, PCAP packets, Windows Security events, Nessus findings, and raw messages each answer different questions. Firewall evidence explains access-control behavior; IDS evidence highlights suspicious signatures and reconnaissance patterns; PCAP evidence confirms packet-level communication; Windows logs provide host and identity context; Nessus findings reveal exposure; and raw messages provide evidential validation. The main finding is that these sources become analytically stronger when they are linked through shared investigative dimensions rather than examined as isolated dashboards.",
            "The case analysis shows several cross-source relationships that would be difficult to maintain mentally without coordinated visual support. The HTTP/80 concentration toward 172.20.1.5 appears in both firewall and PCAP evidence. The 192.168.2.x address range appears in IDS reconnaissance patterns, Nessus vulnerability findings, and Windows authentication evidence. The 192.168.1.x targets appear across IDS, firewall, and Windows log views. These intersections do not automatically prove a complete intrusion chain, but they provide a structured basis for hypothesis generation and validation. In this sense, the system supports analytical reasoning rather than automated attribution.",
        ],
    ),
    (
        "5.2. Contribution to visual analytics for cybersecurity",
        [
            "The contribution of the study is not the invention of a new visual encoding in isolation. Timelines, heatmaps, scatterplots, parallel coordinates, and linked details have all been used in prior cybersecurity visualization research. The contribution lies in organizing these encodings into a coordinated multi-source reasoning workflow for attack story reconstruction. This distinction is important for Q1/Q2-level positioning because the research value is not merely interface convenience, but the explicit connection between data type, reasoning pattern, visual representation, and investigative transition.",
            "Compared with systems focused on a single evidence type, the proposed approach emphasizes cross-source continuity. Compared with generic situation-awareness dashboards, it emphasizes attack-story construction and evidence validation. Compared with traditional SIEM-style views, it makes the reasoning process visible through complementary visual encodings. The system therefore contributes a design model in which source-specific dashboards remain semantically appropriate, while shared dimensions such as time, IP, host, account, port, protocol, risk, and raw reference enable pivots across evidence sources.",
        ],
    ),
    (
        "5.3. Reasoning support and overview-to-detail workflow",
        [
            "The proposed workflow operationalizes the classic overview-to-detail principle in a cybersecurity-specific form. The analyst first identifies a temporal burst, dense entity relationship, or risk concentration. The analyst then narrows the investigation to suspicious entities, ports, signatures, services, accounts, or vulnerabilities. Next, scatterplots and matrices help reveal whether the pattern resembles scanning, concentrated service access, repeated authentication, or exposure clustering. Finally, parallel coordinates and raw drill-down help correlate multiple attributes and validate normalized records against original evidence.",
            "This workflow supports four forms of reasoning. Temporal reasoning is used to locate phases of activity. Relational reasoning is used to identify source-target, user-host, and host-service structures. Pattern-recognition reasoning is used to detect scans, clusters, and outliers. Multivariate reasoning is used to connect action, protocol, port, signature, severity, and risk. The key point is that no single visualization is sufficient. A timeline can show when something happened but not fully explain who communicated with whom. A heatmap can show dense relationships but not temporal sequence. A scatterplot can reveal scan-like patterns but not all categorical context. Parallel coordinates can show multivariate relationships but require filtering and linked context. Their combination is what supports attack-story reasoning.",
        ],
    ),
    (
        "5.4. Implications for dashboard optimization",
        [
            "The findings suggest that a Q1/Q2-oriented visual analytics system does not necessarily require five completely separate dashboards if the goal is scientific reasoning rather than source-by-source reporting. A more optimized architecture may group evidence by investigative function. For example, Firewall, IDS, and PCAP can be combined into a Network Evidence dashboard because they jointly explain communication behavior. Windows logs can form a Host and Identity dashboard because they explain account, authentication, and endpoint context. Nessus can form a Risk and Exposure dashboard because it explains vulnerability opportunity and remediation priority. Raw evidence can be implemented as a validation layer rather than a full overview dashboard.",
            "However, source-specific views remain useful because each source has distinct semantics. Therefore, the optimal design is not simply fewer dashboards or more dashboards, but coordinated dashboards with shared pivots. An analyst should be able to click an IP address, host, account, port, or time interval in one view and inspect related evidence in another view. This linked-navigation model reduces cognitive fragmentation while preserving the evidential meaning of each source.",
        ],
    ),
    (
        "5.5. Practical implications",
        [
            "For security analysts, the proposed system can reduce the time spent moving manually among disconnected files and tools. It provides a structured path from anomaly detection to evidence validation: identify a suspicious pattern, examine involved entities, correlate across sources, inspect exposure, and validate against raw messages. This is particularly useful when data sources have different schemas and different levels of abstraction.",
            "For researchers, the study provides a reproducible design pattern for mapping cybersecurity data types to visual encodings and reasoning tasks. The same method can be extended to additional evidence sources such as DNS logs, proxy logs, endpoint detection and response telemetry, Active Directory audit logs, cloud audit logs, or threat intelligence indicators. The unified analytical layer can also be implemented with a database or graph backend for larger datasets while preserving the conceptual model.",
        ],
    ),
    (
        "5.6. Limitations",
        [
            "Several limitations must be acknowledged. First, the current evaluation is based on a bounded dataset and a prototype implementation. Broader validation would require multiple datasets, expert participants, and comparative user studies. Second, the time ranges of the sources are not identical. The method preserves source-specific time coverage and avoids unsupported temporal imputation, but this also means that some correlations are entity-based rather than strictly simultaneous. Third, the PCAP parser uses header-level evidence and a limited snap length, so it supports traffic-structure reasoning but not full payload analysis. Fourth, the Windows Security log primarily contains authentication and Kerberos events; process-tree reasoning is limited when process creation fields are absent. Fifth, the current system uses prepared aggregates; very large operational deployments would require indexing, streaming, and scalable storage.",
            "Another limitation concerns interpretation. Visual patterns indicate candidates for investigation, not definitive proof. Dense source-target relationships, portscan signatures, repeated logons, and vulnerability exposure must be interpreted in operational context. The system is therefore designed to support human reasoning and evidence validation, not to replace analyst judgment.",
        ],
    ),
    (
        "5.7. Future work",
        [
            "Future work should proceed in four directions. First, the system should be evaluated with cybersecurity professionals through controlled investigation tasks and expert review. Measures should include task completion, hypothesis accuracy, time to evidence, number of useful pivots, confidence, and perceived reasoning support. Second, the unified analytical layer should be extended into a graph-based model that explicitly represents entities, events, vulnerabilities, services, accounts, and raw evidence references. Third, the dashboard should support annotation and provenance, allowing analysts to mark hypotheses, evidence, uncertainty, and reasoning steps. Fourth, the method should be tested on additional datasets and mapped to ATT&CK-style tactics and techniques to strengthen the attack-story reconstruction framework.",
        ],
    ),
]


CONCLUSION = [
    "This paper presented a reasoning-oriented visual analytics approach for multi-source cybersecurity evidence. The study addressed the problem that security investigations often require analysts to connect firewall logs, IDS alerts, PCAP data, Windows Security logs, vulnerability findings, and raw messages manually. To reduce this cognitive burden, the proposed approach builds a unified analytical layer around shared investigative dimensions and uses coordinated visualizations to support attack story reconstruction.",
    "The results show that different visual encodings support different but complementary reasoning tasks. Timelines support temporal reasoning, heatmaps and matrices support relational reasoning, scatterplots support visual recognition of scan-like and outlier patterns, parallel coordinates support multivariate correlation, and raw drill-down supports evidence validation. Applied to the available dataset, the system revealed a multi-source evidence chain involving vulnerability exposure in the 192.168.2.171-175 range, IDS reconnaissance patterns from 192.168.2.x hosts toward 192.168.1.x targets, firewall connection and denial activity, Windows domain authentication events, and packet-level traffic bursts involving HTTP and syslog-like communication.",
    "The main conclusion is that cybersecurity visual analytics should not be designed merely as a collection of charts. For investigation tasks, the central design objective should be reasoning support: helping analysts move from overview to detail, from isolated events to linked evidence, and from suspicious patterns to a defensible attack narrative. The proposed system contributes to this objective by combining source-specific visual semantics with cross-source pivots through time, IP, host, account, port, protocol, risk, and raw evidence references.",
    "Future development should focus on expert evaluation, graph-based evidence modeling, annotation of reasoning steps, and integration of additional security sources. Such extensions would strengthen the system as both a practical investigative tool and a research contribution to visual analytics for cybersecurity.",
]


MATERIALS_METHODS = [
    (
        "3.1. Research design",
        [
            "This study follows a design-science and visual-analytics research design. The objective is not to build a conventional operational dashboard only, but to design and evaluate a reasoning-oriented visual analytics workflow for multi-source cybersecurity investigation. The artifact developed in the study is an interactive web-based visual analytics system that integrates heterogeneous security evidence and supports attack story reconstruction through coordinated visual views, entity-based pivots, and raw-evidence validation.",
            "The design was guided by three principles derived from the literature review. First, analysts require overview-to-detail navigation because high-volume cyber data cannot be interpreted record by record. Second, different cybersecurity data sources support different reasoning tasks and therefore require different visual encodings. Third, cross-source reasoning must preserve investigative context, because a suspicious IP address, host, account, port, or time interval often becomes meaningful only when it is examined across firewall, IDS, PCAP, Windows log, vulnerability, and raw evidence sources.",
        ],
    ),
    (
        "3.2. Materials: cybersecurity evidence sources",
        [
            "The empirical material consists of six heterogeneous cybersecurity evidence sources located in the VA dataset folder. These sources represent different layers of an investigation: perimeter access decisions, IDS detections, packet-level traffic, host and identity activity, vulnerability exposure, and original raw messages. Table 2 summarizes the data sources, their roles, volumes, time coverage, and key fields used by the proposed system.",
        ],
    ),
    (
        "3.3. Data preprocessing and normalization",
        [
            "Each source was parsed with a source-specific parser and then transformed into a prepared analytical layer. The purpose of preprocessing was not to replace the original evidence, but to create a normalized and queryable representation suitable for visualization. Firewall data were parsed from CSV and aggregated by operation, protocol, direction, source IP, destination IP, ports, services, source-target flows, source-port matrices, suspicious connections, and hourly timelines. IDS text alerts were parsed by extracting alert signatures and the following source-to-destination flow lines; endpoints were split into IP and port components when the syntax permitted it. Windows Security XML events were parsed with an XML event parser to extract EventID, Computer, TimeCreated/SystemTime, user-related fields, IP address, status, and authentication-related attributes. PCAP evidence was parsed at the packet-header level by reading the global header and packet records, extracting Ethernet type, IPv4 protocol, source and destination IP addresses, TCP/UDP ports, included length, and minute-level packet counts. Nessus findings were exported from the spreadsheet and parsed to extract host, port, service, plugin, risk, CVE, CVSS, exploit indicators, synopsis, and remediation-oriented solution text.",
            "The normalization process mapped heterogeneous field names and formats to common investigative dimensions: time, source IP, destination IP, host, account, source port, destination port, protocol, action, event type, signature, severity/risk, service, vulnerability identifier, and raw reference. The system intentionally does not use statistical imputation for cybersecurity fields marked as empty, null, N/A, dash, or equivalent missing values. In cyber investigations, predicting missing IP addresses, accounts, ports, signatures, or vulnerability identifiers could create false evidence. Therefore, missing values are preserved as unknown or excluded from entity-based joins when the field is required for a specific visual encoding.",
            "Temporal normalization converts parseable timestamps to ISO-like representations and aggregates them at time granularities suitable for visualization. Firewall events are aggregated by hour, IDS alerts by hour, PCAP packets by minute, and Windows Security events by hour. The system does not force all sources into a single artificial time window. Instead, it preserves the original time coverage of each source and supports temporal comparison where intervals overlap or where an investigation pivots from one source to another through a shared entity. This choice avoids creating misleading correlations when sources have different logging windows or time-zone assumptions.",
        ],
    ),
    (
        "3.4. Unified analytical layer",
        [
            "The prepared analytical layer is stored as a JSON structure that contains source-specific summaries, visualization-ready aggregates, cross-source story candidates, and a visualization catalog. The layer is not a row-wise concatenation of all raw files. Instead, it is a structured analytical representation that keeps each source's semantics while exposing shared dimensions for cross-source reasoning. This design allows the system to support both source-specific investigation and cross-source pivots without loading massive raw evidence directly into every dashboard.",
            "The analytical layer contains separate sections for firewall, IDS, Windows Security, PCAP, Nessus, and attack-story evidence. Each section includes counts, time ranges, top entities, source-target pairs, port matrices, timelines, and source-specific attributes. For example, firewall data include operation distributions and allow/deny-related flows; IDS data include alert signatures and source-target alert patterns; PCAP data include packet-volume timelines and source-destination-port matrices; Windows logs include EventID timelines and user-host matrices; and Nessus data include risk distributions, vulnerable hosts, plugin/CVE patterns, and remediation-oriented attributes. Raw firewall evidence is referenced for drill-down validation rather than used as an overview data source.",
        ],
    ),
    (
        "3.5. Visual analytics workflow",
        [
            "The proposed workflow is organized as a reasoning sequence rather than as a collection of independent charts. The analyst begins with an overview visualization that reveals temporal activity, risk concentration, or entity density. After identifying an anomaly or a suspicious region, the analyst moves to relational views to determine which sources, destinations, hosts, ports, accounts, or services are involved. The next step is pattern recognition through scatterplots and matrices, which can reveal scan-like structures, concentrated attacks, or outliers. Finally, multivariate views such as parallel coordinates allow the analyst to correlate action, protocol, port, signature, priority, severity, and risk within one coordinated view. When necessary, the analyst validates the finding through raw evidence retrieval.",
            "This workflow supports five investigation questions: (1) when did suspicious activity occur; (2) which entities were involved; (3) which ports, services, signatures, or event types characterize the activity; (4) whether the observed pattern is supported by multiple independent sources; and (5) whether the normalized analytical record can be checked against the original evidence. The workflow therefore operationalizes the attack-story concept as an evidence chain rather than a single alert.",
        ],
    ),
    (
        "3.6. Visual encoding selection",
        [
            "The choice of visual encodings was based on the type of cyber data and the reasoning operation required. Table 3 summarizes the mapping between reasoning patterns, investigative questions, visual encodings, and data sources. Timeline views were selected for temporal reasoning because they reveal bursts, phases, and changes over time. Heatmaps and matrices were selected for relational reasoning because they compactly show dense source-target, source-port, user-host, and host-service relationships. Scatterplots were selected for visual attack-pattern recognition because scan behavior and outliers often appear as repeated, linear, clustered, or sparse geometric patterns. Parallel coordinates were selected for multivariate reasoning because they allow analysts to trace relationships among several attributes without reducing the event to a single count. Linked raw drill-down was selected for evidence validation because high-confidence investigation requires the ability to verify normalized records against original messages.",
        ],
    ),
    (
        "3.7. System implementation",
        [
            "The prototype was implemented as a lightweight web-based visual analytics application. Data preparation was implemented in Python, using standard parsing libraries for CSV, XML, binary PCAP header parsing, regular expressions for IDS and Nessus text extraction, and JSON export for the analytical layer. The front-end dashboard was implemented with HTML, CSS, and vanilla JavaScript/SVG visualizations. The local server is a Python server that serves the application and provides an API endpoint for raw firewall evidence drill-down. This implementation was chosen to keep the system reproducible, transparent, and independent of proprietary dashboard platforms.",
            "The system uses prepared aggregates for overview dashboards and queries raw evidence only when the analyst requests validation. This separation is important for scalability and forensic clarity. Overview dashboards remain responsive because they operate on compact aggregate structures, while the original files remain available for evidence verification. The same principle can be extended to larger datasets by replacing local JSON files with a database or search backend while preserving the analytical schema and visual workflow.",
        ],
    ),
    (
        "3.8. Evaluation strategy",
        [
            "The evaluation is planned around both data validity and analytical usefulness. Data validity is assessed by checking whether parsed counts, time ranges, and extracted entities correspond to the original sources and by validating selected normalized records against raw messages. Analytical usefulness is assessed through task-based scenarios derived from the proposed attack-story workflow. Example tasks include identifying a burst of denied firewall activity, detecting IDS portscan patterns, tracing packet-level conversations for a selected IP address, linking Windows authentication activity to a suspicious host, and prioritizing vulnerable assets that are involved in network activity.",
            "For a Q1/Q2-oriented study, the evaluation should combine scenario-based expert review with measurable task outcomes. Suitable measures include task completion rate, time to first correct hypothesis, number of cross-source pivots used, correctness of identified entities, confidence in the final attack story, and subjective ratings of reasoning support. A comparative evaluation can be performed against a baseline condition in which the same evidence is inspected through separate source-specific tables or non-linked dashboards. The expected benefit of the proposed system is not merely faster chart reading, but improved ability to construct and justify a coherent multi-source explanation.",
        ],
    ),
    (
        "3.9. Reproducibility and limitations",
        [
            "The preprocessing pipeline is reproducible because the parsing and document-generation scripts are stored with the project. The analytical layer can be regenerated from the original files, and the dashboard can be launched locally through the provided Python server. Nevertheless, several limitations must be acknowledged. First, the dataset represents a bounded investigation scenario and should be complemented with additional datasets in future evaluation. Second, some source timestamps may have different time-zone assumptions; the current method preserves source time representations and avoids imposing unsupported offsets. Third, the Windows Security log contains authentication and Kerberos evidence but limited process-chain evidence, so process-tree visualizations depend on whether process creation fields are present. Fourth, the PCAP parser uses header-level information and the available snap length; it is designed for traffic reasoning rather than deep payload inspection.",
        ],
    ),
]


REFERENCES = [
    "[1] J. J. Thomas and K. A. Cook, Illuminating the Path: The Research and Development Agenda for Visual Analytics. IEEE Computer Society, 2005.",
    "[2] A. D'Amico and K. Whitley, The Real Work of Computer Network Defense Analysts, VizSec / Secure Decisions, 2007-2008. URL: https://securedecisions.com/the-real-work-of-computer-network-defense-analysts/",
    "[3] H. Shiravi, A. Shiravi, and A. A. Ghorbani, A Survey of Visualization Systems for Network Security, IEEE Transactions on Visualization and Computer Graphics, 18(8), 1313-1329, 2012. DOI: 10.1109/TVCG.2011.144. URL: https://pubmed.ncbi.nlm.nih.gov/21876227/",
    "[4] D. Staheli et al., Visualization Evaluation for Cyber Security: Trends and Future Directions, VizSec, 2014. URL: https://www.ll.mit.edu/sites/default/files/publication/doc/2018-04/2014-Staheli-Cyber-Visualization-Evaluation-VizSec.pdf",
    "[5] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, An Evaluation Framework for Network Security Visualizations, Computers & Security, 84, 70-92, 2019. DOI: 10.1016/j.cose.2019.03.005. URL: https://www.sciencedirect.com/science/article/pii/S0167404818308952",
    "[6] A. Komadina, Z. Mihajlovic, and S. Gros, Analysis of the Design Space for Cybersecurity Visualizations in VizSec, IEEE VizSec, 2022. DOI: 10.1109/VizSec56996.2022.9941422.",
    "[7] K. Lakkaraju, W. Yurcik, and A. J. Lee, NVisionIP: NetFlow Visualizations of System State for Security Situational Awareness, 2004/2005. URL: https://www.sei.cmu.edu/library/nvisionip-an-animated-state-analysis-tool-for-visualizing-netflows-white-paper/",
    "[8] J. McPherson et al., PortVis: A Tool for Port-Based Detection of Security Events, VizSec, 2004.",
    "[9] J. R. Goodall, W. G. Lutters, P. Rheingans, and A. Komlodi, Preserving the Big Picture: Visual Network Traffic Analysis with TNV, VizSec, 2005. URL: https://impact.ornl.gov/en/publications/preserving-the-big-picture-visual-network-traffic-analysis-with-t/",
    "[10] W. Yurcik, K. Lakkaraju, W. S. Mandia, and A. J. Lee, VisFlowConnect-IP: Visualizing NetFlows for Security Situational Awareness, 2005. URL: https://insights.sei.cmu.edu/library/visflowconnect-ip-an-animated-link-analysis-tool-for-visualizing-netflows-white-paper/",
    "[11] G. Conti, Security Data Visualization: Graphical Techniques for Network Analysis. No Starch Press, 2007. URL: https://books.google.com/books/about/Security_Data_Visualization.html?id=Cg2cEz10XpMC",
    "[12] S. Tricaud, Picviz: Finding a Needle in a Haystack, USENIX Workshop on the Analysis of System Logs, 2008. URL: https://www.usenix.org/legacy/event/wasl/tech/full_papers/tricaud/tricaud_html/",
    "[13] F. Fischer, NFlowVis: Large-Scale Network Monitoring for Visual Analysis of Attacks, VizSec, 2008. URL: https://ff.cx/nflowvis/",
    "[14] K. Abdullah, C. P. Lee, G. J. Conti, J. A. Copeland, and J. T. Stasko, IDS RainStorm: Visualizing IDS Alarms, VizSec, 2005. URL: https://faculty.cc.gatech.edu/~stasko/papers/vizsec05.pdf",
    "[15] H. Shiravi, A. Shiravi, and A. A. Ghorbani, IDS Alert Visualization and Monitoring Through Heuristic Host Selection, ICICS, 2010. DOI: 10.1007/978-3-642-17650-0_31.",
    "[16] M. Dumas, J.-M. Robert, and M. J. McGuffin, AlertWheel: Radial Bipartite Graph Visualization Applied to Intrusion Detection System Alerts, IEEE Network, 26(6), 12-18, 2012. DOI: 10.1109/MNET.2012.6375888. URL: https://espace2.etsmtl.ca/id/eprint/4834/",
    "[17] Y. Zhao, F. Zhou, X. Fan, X. Liang, and Y. Liu, IDSRadar: A Real-Time Visualization Framework for IDS Alerts, Science China Information Sciences, 56, 2013. DOI: 10.1007/s11432-013-4891-9.",
    "[18] Y. Shi, Y. Zhao, F. Zhou, R. Shi, and Y. Zhang, A Novel Radial Visualization of Intrusion Detection Alerts, IEEE Computer Graphics and Applications, 38(6), 83-95, 2018. DOI: 10.1109/MCG.2018.2879067. URL: https://pubmed.ncbi.nlm.nih.gov/30668457/",
    "[19] T. Tran, E. Al-Shaer, and R. Boutaba, PolicyVis: Firewall Security Policy Visualization and Inspection, LISA, 2007. URL: https://www.usenix.org/conference/lisa-07/policyvis-firewall-security-policy-visualization-and-inspection",
    "[20] M. Ghoniem, G. Shurkhovetskyy, A. Bahey, and B. Otjacques, VAFLE: Visual Analytics of Firewall Log Events, Visualization and Data Analysis, 2014. DOI: 10.1117/12.2037790. URL: https://www.list.lu/en/environment/scientific-publications/scientific-publications-detail/vafle-visual-analytics-of-firewall-log-events/",
    "[21] M. Schufrin, H. Lucke-Tieke, and J. Kohlhammer, Visual Firewall Log Analysis: At the Border Between Analytical and Appealing, IEEE VizSec, 2022.",
    "[22] J. R. Goodall and L. Sowul, VIAssist: Visual Analytics for Cyber Defense, 2009. URL: https://impact.ornl.gov/en/publications/viassist-visual-analytics-for-cyber-defense",
    "[23] S. Chen et al., Multi-Aspect Visual Analytics on Large-Scale High-Dimensional Cyber Security Data / SemanticPrism, Information Visualization, 2013. URL: https://experts.arizona.edu/en/publications/multi-aspect-visual-analytics-on-largescale-high-dimensional-cybe/",
    "[24] F. Fischer et al., BANKSAFE: A Visual Situational Awareness Tool for Large-Scale Computer Networks, IEEE VAST, 2012/2013. URL: https://journals.sagepub.com/doi/10.1177/1473871613488572",
    "[25] Z. C. Qian and Y. V. Chen, Fluency of Visualizations: Linking Spatiotemporal Visualizations to Improve Cybersecurity Visual Analytics, Security Informatics, 2014. URL: https://security-informatics.springeropen.com/articles/10.1186/s13388-014-0006-4",
    "[26] Y. Zhao et al., MVSec: Multi-Perspective and Deductive Visual Analytics on Heterogeneous Network Security Data, Journal of Visualization, 2014. DOI: 10.1007/s12650-014-0213-6.",
    "[27] S. Chen, C. Guo, X. Yuan, F. Merkle, H. Schaefer, and T. Ertl, OCEANS: Online Collaborative Explorative Analysis on Network Security, VizSec, 2014. DOI: 10.1145/2671491.2671493. URL: https://research-portal.uu.nl/en/publications/oceans-online-collaborative-explorative-analysis-on-network-secur/",
    "[28] S. Zhang, R. Shi, and J. Zhao, A Visualization System for Multiple Heterogeneous Network Security Data and Fusion Analysis, KSII Transactions on Internet and Information Systems, 10(6), 2801-2816, 2016. URL: https://kiss.kstudy.com/Detail/Ar?key=3532200",
    "[29] M. Wagner et al., A Knowledge-Assisted Visual Malware Analysis System: Design, Validation, and Reflection of KAMAS, Computers & Security, 67, 1-15, 2017. DOI: 10.1016/j.cose.2017.02.003. URL: https://www.sciencedirect.com/science/article/pii/S0167404817300263",
    "[30] G. A. Fink, P. Muessig, and C. North, Visual Correlation of Host Processes and Network Traffic, VizSec, 2005. URL: https://doczz.net/doc/4319328/visual-correlation-of-host-processes-and-network-traffic",
    "[31] Y. Zhao et al., LongLine: Visual Analytics System for Large-Scale Audit Logs, Visual Informatics, 2(1), 82-97, 2018. DOI: 10.1016/j.visinf.2018.04.009. URL: https://www.sciencedirect.com/science/article/pii/S2468502X18300159",
    "[32] K. Nance and B. Hay, NV: Nessus Vulnerability Visualization for the Web, 2006/2008. URL: https://impact.ornl.gov/en/publications/nv-nessus-vulnerability-visualization-for-the-web/",
    "[33] VULNUS: Visual Vulnerability Analysis and Patch Prioritization, 2018/2019. URL: https://iris.uniroma1.it/handle/11573/1180253",
    "[34] S. Noel et al., CyGraph: Graph-Based Visual Analytics for Cybersecurity and Mission Resilience, 2016/2018. URL: https://insights.sei.cmu.edu/library/cygraph-big-data-graph-analysis-for-cybersecurity-and-mission-resilience/",
    "[35] L. Franklin et al., Toward a Visualization-Supported Workflow for Cyber Alert Management Using Threat Models and Human-Centered Design, PNNL / VizSec, 2017. URL: https://www.pnnl.gov/publications/toward-visualization-supported-workflow-cyber-alert-management-using-threat-models-and",
    "[36] J. R. Goodall et al., Situ: Identifying and Explaining Suspicious Behavior in Networks, IEEE Transactions on Visualization and Computer Graphics, 25(1), 204-214, 2019. DOI: 10.1109/TVCG.2018.2865029. URL: https://www.ornl.gov/publication/situ-identifying-and-explaining-suspicious-behavior-networks",
    "[37] S. Yoo, J. Jo, B. Kim, and J. Seo, Hyperion: A Visual Analytics Tool for an Intrusion Detection and Prevention System, IEEE Access, 8, 133865-133881, 2020. DOI: 10.1109/ACCESS.2020.3010789. URL: https://snu.elsevierpure.com/en/publications/hyperion-a-visual-analytics-tool-for-an-intrusion-detection-and-p",
    "[38] K. DeValk and N. Elmqvist, Riverside: A Design Study on Visualization for Situation Awareness in Cybersecurity, Information Visualization, 23(1), 40-66, 2024. DOI: 10.1177/14738716231189220. URL: https://journals.sagepub.com/doi/abs/10.1177/14738716231189220",
]


def build_doc():
    doc = Document()
    section = doc.sections[0]
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.8)
    section.left_margin = Inches(0.9)
    section.right_margin = Inches(0.9)

    for style_name in ["Normal", "Title", "Heading 1", "Heading 2", "Heading 3"]:
        style = doc.styles[style_name]
        style.font.name = "Times New Roman"
        style._element.rPr.rFonts.set(qn("w:eastAsia"), "Times New Roman")
    doc.styles["Normal"].font.size = Pt(11)
    doc.styles["Title"].font.size = Pt(16)
    doc.styles["Heading 1"].font.size = Pt(14)
    doc.styles["Heading 2"].font.size = Pt(12)

    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run(
        "Reasoning-Oriented Visual Analytics for Multi-Source Cybersecurity Evidence:\n"
        "Toward Attack Story Reconstruction"
    )
    set_font(run, size=16, bold=True)

    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = subtitle.add_run(
        "Draft sections: Introduction, Related Work, Materials and Methods, Results, Discussion, and Conclusion"
    )
    set_font(run, size=11, italic=True)

    add_para(
        doc,
        "Note. This document is an initial Q1/Q2-oriented manuscript draft. It currently contains the Introduction, Related Work, Materials and Methods, Results, Discussion, and Conclusion sections. The abstract, keywords, figures, and final journal-specific formatting can be added in the next drafting stage.",
    )

    doc.add_heading("1. Introduction", level=1)
    for paragraph in INTRODUCTION:
        add_para(doc, paragraph)

    doc.add_heading("2. Related Work / Literature Review", level=1)
    add_para(
        doc,
        "The related work is organized around seven streams that are directly relevant to the proposed study: foundational network security visualization, IDS alert visualization, firewall visualization, multi-source visual analytics, host and audit-log analysis, vulnerability and attack-graph visualization, and human-centered evaluation for cyber visual analytics. This organization reflects the structure of the proposed system, where different evidence sources are linked through shared investigative dimensions and used to support reasoning from overview to detail.",
    )
    add_para(doc, "Table 1 summarizes representative research streams and their relevance to the present work.")

    table = doc.add_table(rows=1, cols=4)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"
    for cell, text in zip(
        table.rows[0].cells,
        ["Research stream", "Representative studies", "Main visual / analytical idea", "Relevance to this study"],
    ):
        set_cell_text(cell, text, bold=True)
        set_cell_shading(cell, "D9EAF7")
    for row in TABLE_ROWS:
        cells = table.add_row().cells
        for cell, text in zip(cells, row):
            set_cell_text(cell, text)

    for heading, paragraphs in RELATED_WORK:
        doc.add_heading(heading, level=2)
        for paragraph in paragraphs:
            add_para(doc, paragraph)

    doc.add_heading("Provisional research gap statement", level=2)
    add_para(doc, "Based on the reviewed literature, the following gap statement can be used later in the final manuscript:")
    add_para(
        doc,
        "Although previous studies have advanced network traffic visualization, IDS alert exploration, firewall log analysis, audit-log visualization, vulnerability analysis, and cyber situation awareness, fewer works explicitly organize firewall, IDS, PCAP, Windows security logs, Nessus findings, and raw messages into a unified reasoning workflow for attack story reconstruction. The present study addresses this gap by linking heterogeneous evidence through common investigative dimensions and by mapping visual encodings to complementary reasoning patterns: temporal reasoning, relational reasoning, visual attack-pattern recognition, multivariate correlation, and raw evidence validation.",
        italic=True,
        left_indent=Inches(0.25),
        right_indent=Inches(0.25),
    )

    doc.add_heading("3. Materials and Methods", level=1)
    for heading, paragraphs in MATERIALS_METHODS:
        doc.add_heading(heading, level=2)
        for paragraph in paragraphs:
            add_para(doc, paragraph)
        if heading.startswith("3.2."):
            table = doc.add_table(rows=1, cols=6)
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            table.style = "Table Grid"
            headers = [
                "Evidence source",
                "File",
                "Role",
                "Volume",
                "Time coverage",
                "Key fields",
            ]
            for cell, text in zip(table.rows[0].cells, headers):
                set_cell_text(cell, text, bold=True)
                set_cell_shading(cell, "D9EAF7")
            for row in MATERIALS_ROWS:
                cells = table.add_row().cells
                for cell, text in zip(cells, row):
                    set_cell_text(cell, text)
        if heading.startswith("3.6."):
            table = doc.add_table(rows=1, cols=4)
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            table.style = "Table Grid"
            headers = [
                "Reasoning pattern",
                "Investigation question",
                "Visual encoding",
                "Applied evidence",
            ]
            for cell, text in zip(table.rows[0].cells, headers):
                set_cell_text(cell, text, bold=True)
                set_cell_shading(cell, "D9EAF7")
            for row in METHOD_VIS_ROWS:
                cells = table.add_row().cells
                for cell, text in zip(cells, row):
                    set_cell_text(cell, text)

    doc.add_heading("4. Results", level=1)
    for heading, paragraphs in RESULTS:
        doc.add_heading(heading, level=2)
        for paragraph in paragraphs:
            add_para(doc, paragraph)
        if heading.startswith("4.1."):
            table = doc.add_table(rows=1, cols=4)
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            table.style = "Table Grid"
            headers = [
                "Evidence source",
                "Processed volume",
                "Dominant values",
                "Main analytical result",
            ]
            for cell, text in zip(table.rows[0].cells, headers):
                set_cell_text(cell, text, bold=True)
                set_cell_shading(cell, "D9EAF7")
            for row in RESULT_SUMMARY_ROWS:
                cells = table.add_row().cells
                for cell, text in zip(cells, row):
                    set_cell_text(cell, text)
        if heading.startswith("4.7."):
            table = doc.add_table(rows=1, cols=5)
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            table.style = "Table Grid"
            headers = [
                "Phase",
                "Time",
                "Source",
                "Evidence",
                "Reasoning value",
            ]
            for cell, text in zip(table.rows[0].cells, headers):
                set_cell_text(cell, text, bold=True)
                set_cell_shading(cell, "D9EAF7")
            for row in RESULT_STORY_ROWS:
                cells = table.add_row().cells
                for cell, text in zip(cells, row):
                    set_cell_text(cell, text)

    doc.add_heading("5. Discussion", level=1)
    for heading, paragraphs in DISCUSSION:
        doc.add_heading(heading, level=2)
        for paragraph in paragraphs:
            add_para(doc, paragraph)

    doc.add_heading("6. Conclusion", level=1)
    for paragraph in CONCLUSION:
        add_para(doc, paragraph)

    doc.add_heading("References", level=1)
    for reference in REFERENCES:
        add_reference(doc, reference)

    for path in [OUT_COMPLETE, OUT_RESULTS, OUT_FULL, OUT]:
        try:
            doc.save(path)
            print(f"Wrote {path}")
        except PermissionError:
            print(f"Skipped {path} because it is open or locked")


if __name__ == "__main__":
    build_doc()
