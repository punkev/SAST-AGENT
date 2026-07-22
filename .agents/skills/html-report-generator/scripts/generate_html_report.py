import os
import json
import glob
import html
import re
import sys
from datetime import datetime

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NEEDS-REVIEW": 0,
    "INFO": 0
}

def get_severity_score(sev):
    return SEVERITY_ORDER.get(str(sev).upper(), 0)

def extract_markdown_section(content, section_names):
    """Extracts section content under matching ## or ### headers."""
    for name in section_names:
        pattern = r"##?\s+" + re.escape(name) + r"\s*\n(.*?)(?=\n##?\s+|$)"
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""

def parse_markdown_finding(file_path):
    """Parses a Markdown finding file into a structured dictionary."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return None

    fid = os.path.splitext(os.path.basename(file_path))[0]
    finding = {
        "id": fid,
        "title": "Untitled Vulnerability Finding",
        "severity": "MEDIUM",
        "confidence": "High",
        "cwe": "N/A",
        "affected_file": "N/A",
        "endpoint": "N/A",
        "source": "N/A",
        "sink": "N/A",
        "description": "",
        "impact": "N/A",
        "why_issue": "",
        "payload": "",
        "burp_request": "",
        "burp_response": "",
        "data_flow": "",
        "vulnerable_code": "",
        "safe_code": "",
        "remediation": "",
        "status": "confirmed"
    }

    # Extract Title
    title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    if title_match:
        finding["title"] = title_match.group(1).strip()

    # Extract Key Metadata
    sev_match = re.search(r"\*\*Severity\*\*:\s*(\w+)", content, re.IGNORECASE)
    if sev_match:
        finding["severity"] = sev_match.group(1).strip()

    cwe_match = re.search(r"\*\*(?:CWE|OWASP)\*\*:\s*(.+)", content, re.IGNORECASE)
    if cwe_match:
        finding["cwe"] = cwe_match.group(1).strip()

    file_match = re.search(r"\*\*Affected File\*\*:\s*(.+)", content, re.IGNORECASE)
    if file_match:
        finding["affected_file"] = file_match.group(1).strip()

    endpoint_match = re.search(r"\*\*(?:Affected Endpoint|Endpoint)\*\*:\s*(.+)", content, re.IGNORECASE)
    if endpoint_match:
        finding["endpoint"] = endpoint_match.group(1).strip()

    source_match = re.search(r"\*\*Source\*\*:\s*(.+)", content, re.IGNORECASE)
    if source_match:
        finding["source"] = source_match.group(1).strip()

    sink_match = re.search(r"\*\*Sink\*\*:\s*(.+)", content, re.IGNORECASE)
    if sink_match:
        finding["sink"] = sink_match.group(1).strip()

    # Extract Sections
    finding["description"] = extract_markdown_section(content, ["Description", "Vulnerability Overview", "Overview"])
    finding["impact"] = extract_markdown_section(content, ["Impact", "Vulnerability Impact"]) or finding["description"]
    finding["why_issue"] = extract_markdown_section(content, ["False-Positive Checks & Rationale", "Evidence & Rationale", "Why Issue", "Evidence Rationale", "Control Bypass Rationale"])
    finding["payload"] = extract_markdown_section(content, ["Test PoC / Payload", "Attack Payload", "Test Payload", "Payload"])
    finding["burp_request"] = extract_markdown_section(content, ["Burp Suite HTTP PoC", "Burp Suite Request Template", "PoC or Steps to Reproduce (Burp Suite)", "Burp Suite Request"])
    finding["burp_response"] = extract_markdown_section(content, ["Burp Suite Expected Response", "Expected Response", "Burp Response", "Response Expected"])
    finding["data_flow"] = extract_markdown_section(content, ["Data Flow", "Control Flow Graph", "CFG Trace", "Data Flow Trace"])
    finding["vulnerable_code"] = extract_markdown_section(content, ["Vulnerable Code Snippet", "Bad Code", "Unsafe Implementation", "Vulnerable Code"])
    finding["safe_code"] = extract_markdown_section(content, ["Safe Implementation", "Good Code", "Secure Implementation", "Remediation Code"])
    finding["remediation"] = extract_markdown_section(content, ["Remediation Strategy", "Remediation Plan", "Defense Strategy", "Remediation"])

    return finding

def normalize_finding(raw):
    """Normalizes raw JSON or dictionary findings into a standardized structure."""
    if not isinstance(raw, dict):
        return None

    fid = str(raw.get("id", raw.get("finding_id", raw.get("issue_id", "FINDING-UNKNOWN"))))
    
    return {
        "id": fid,
        "title": str(raw.get("title", raw.get("issue_name", raw.get("name", "Untitled Vulnerability Finding")))),
        "severity": str(raw.get("severity", "MEDIUM")).upper(),
        "confidence": str(raw.get("confidence", "High")),
        "cwe": str(raw.get("cwe", raw.get("cwe_owasp", "N/A"))),
        "affected_file": str(raw.get("affected_file", raw.get("file", raw.get("location", "N/A")))),
        "endpoint": str(raw.get("endpoint", raw.get("affected_endpoint", "N/A"))),
        "source": str(raw.get("source", "N/A")),
        "sink": str(raw.get("sink", "N/A")),
        "description": str(raw.get("description", raw.get("overview", ""))),
        "impact": str(raw.get("impact", raw.get("description", "N/A"))),
        "why_issue": str(raw.get("why_issue", raw.get("why_vulnerable", raw.get("rationale", raw.get("evidence_rationale", raw.get("negative_verification", "")))))),
        "payload": str(raw.get("payload", raw.get("test_poc", raw.get("attack_payload", "")))),
        "burp_request": str(raw.get("burp_request", raw.get("burp_poc", raw.get("request_template", raw.get("poc", raw.get("steps_to_reproduce", "")))))),
        "burp_response": str(raw.get("burp_response", raw.get("expected_response", raw.get("response_expected", "")))),
        "data_flow": str(raw.get("data_flow", raw.get("dataflow", raw.get("cfg_trace", "")))),
        "vulnerable_code": str(raw.get("vulnerable_code", raw.get("vulnerable_code_snippet", raw.get("unsafe_code", raw.get("bad_code", ""))))),
        "safe_code": str(raw.get("safe_code", raw.get("safe_implementation", raw.get("remediation_code", raw.get("good_code", ""))))),
        "remediation": str(raw.get("remediation", raw.get("remediation_strategy", raw.get("remediation_plan", raw.get("recommendation", ""))))),
        "status": str(raw.get("status", "confirmed"))
    }

def merge_findings(existing, incoming):
    """Merges incoming finding data into existing finding to preserve all attributes."""
    for key, val in incoming.items():
        if val and val != "N/A" and val != "":
            if not existing.get(key) or existing.get(key) == "N/A" or existing.get(key) == "":
                existing[key] = val
            elif len(str(val)) > len(str(existing.get(key, ""))):
                existing[key] = val
    return existing

def parse_all_findings(findings_dir, jsonl_path):
    findings_map = {}

    # 1. Read JSONL file if present
    if os.path.exists(jsonl_path):
        try:
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                        norm = normalize_finding(raw)
                        if norm:
                            fid = norm["id"]
                            if fid in findings_map:
                                findings_map[fid] = merge_findings(findings_map[fid], norm)
                            else:
                                findings_map[fid] = norm
                    except Exception:
                        pass
        except Exception:
            pass

    # 2. Read subfolders for JSON and MD files
    for subfolder in ["confirmed", "needs-review", "duplicate", "false-positive"]:
        folder_path = os.path.join(findings_dir, subfolder)
        if os.path.exists(folder_path):
            for file_name in os.listdir(folder_path):
                full_p = os.path.join(folder_path, file_name)
                if file_name.endswith(".json"):
                    try:
                        with open(full_p, "r", encoding="utf-8") as f:
                            raw = json.load(f)
                            norm = normalize_finding(raw)
                            if norm:
                                norm["status"] = subfolder
                                fid = norm["id"]
                                if fid in findings_map:
                                    findings_map[fid] = merge_findings(findings_map[fid], norm)
                                else:
                                    findings_map[fid] = norm
                    except Exception:
                        pass
                elif file_name.endswith(".md"):
                    parsed = parse_markdown_finding(full_p)
                    if parsed:
                        parsed["status"] = subfolder
                        fid = parsed["id"]
                        if fid in findings_map:
                            findings_map[fid] = merge_findings(findings_map[fid], parsed)
                        else:
                            findings_map[fid] = parsed

    findings = list(findings_map.values())
    findings.sort(key=lambda x: get_severity_score(x.get("severity", "LOW")), reverse=True)
    return findings

def load_scan_state(state_path):
    if os.path.exists(state_path):
        try:
            with open(state_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def render_html_report(findings, scan_state, output_path):
    scan_id = scan_state.get("scan_id", "SAST-SCAN-LATEST")
    scan_date = scan_state.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    endpoints_scanned = scan_state.get("endpoints_scanned", 0)
    files_scanned = scan_state.get("files_scanned", 0)

    critical_count = sum(1 for f in findings if str(f.get("severity")).upper() == "CRITICAL")
    high_count = sum(1 for f in findings if str(f.get("severity")).upper() == "HIGH")
    medium_count = sum(1 for f in findings if str(f.get("severity")).upper() == "MEDIUM")
    low_count = sum(1 for f in findings if str(f.get("severity")).upper() == "LOW")
    total_count = len(findings)

    findings_html_cards = []
    for idx, f in enumerate(findings, 1):
        fid = html.escape(str(f.get("id", f"FINDING-{idx}")))
        title = html.escape(str(f.get("title", "Untitled Vulnerability Finding")))
        severity = str(f.get("severity", "MEDIUM")).upper()
        confidence = html.escape(str(f.get("confidence", "High")))
        cwe = html.escape(str(f.get("cwe", "N/A")))
        affected_file = html.escape(str(f.get("affected_file", "N/A")))
        endpoint = html.escape(str(f.get("endpoint", "N/A")))
        source = html.escape(str(f.get("source", "N/A")))
        sink = html.escape(str(f.get("sink", "N/A")))
        impact = html.escape(str(f.get("impact", "N/A")))
        why_issue = html.escape(str(f.get("why_issue", "")))
        payload = html.escape(str(f.get("payload", "")))
        burp_req = html.escape(str(f.get("burp_request", "")))
        burp_res = html.escape(str(f.get("burp_response", "")))
        data_flow = html.escape(str(f.get("data_flow", "")))
        vuln_code = html.escape(str(f.get("vulnerable_code", "")))
        safe_code = html.escape(str(f.get("safe_code", "")))
        remediation = html.escape(str(f.get("remediation", "")))
        status = html.escape(str(f.get("status", "confirmed")))

        badge_class = f"badge-{severity.lower()}"

        card = f"""
        <div class="finding-card" data-severity="{severity}" data-search="{fid} {title} {affected_file} {cwe}">
            <div class="card-header" onclick="toggleCard('{fid}')">
                <div class="header-left">
                    <span class="severity-badge {badge_class}">{severity}</span>
                    <span class="finding-id">#{fid}</span>
                    <span class="finding-title">{title}</span>
                </div>
                <div class="header-right">
                    <span class="cwe-tag">{cwe}</span>
                    <span class="expand-icon" id="icon-{fid}">▼</span>
                </div>
            </div>
            <div class="card-body" id="body-{fid}" style="display: none;">
                <div class="meta-grid">
                    <div><strong>Affected File:</strong> <code>{affected_file}</code></div>
                    <div><strong>Endpoint:</strong> <code>{endpoint}</code></div>
                    <div><strong>Confidence:</strong> {confidence}</div>
                    <div><strong>Status:</strong> <span class="status-tag">{status}</span></div>
                </div>

                <div class="section-block">
                    <h4>🔍 Vulnerability Description & Impact</h4>
                    <p>{impact}</p>
                </div>

                {"<div class='section-block'><h4>⚠️ Evidence & Control Bypass Rationale</h4><div class='info-box'>" + why_issue + "</div></div>" if why_issue else ""}

                {"<div class='section-block'><h4>🎯 Test PoC / Attack Payload</h4><pre class='code-block payload-block'>" + payload + "</pre></div>" if payload else ""}

                {"<div class='section-block'><h4>🧪 Burp Suite HTTP Request Template</h4><button class='copy-btn' onclick='copyText(this)'>Copy Request</button><pre class='code-block poc-block'>" + burp_req + "</pre></div>" if burp_req else ""}

                {"<div class='section-block'><h4>📥 Burp Suite Expected Response</h4><pre class='code-block response-block'>" + burp_res + "</pre></div>" if burp_res else ""}

                {"<div class='section-block'><h4>⛓️ Control Flow Graph (CFG) / Data Flow Trace</h4><div class='flow-meta'><span><strong>Source:</strong> <code>" + source + "</code></span><span><strong>Sink:</strong> <code>" + sink + "</code></span></div><pre class='code-block'>" + data_flow + "</pre></div>" if data_flow else ""}

                <div class="code-comparison">
                    {"<div class='code-box vuln-box'><h4>❌ Vulnerable / Unsafe Code</h4><pre class='code-block'>" + vuln_code + "</pre></div>" if vuln_code else ""}
                    {"<div class='code-box safe-box'><h4>✅ Secure / Safe Code</h4><pre class='code-block'>" + safe_code + "</pre></div>" if safe_code else ""}
                </div>

                {"<div class='section-block remediation-block'><h4>🛠️ Step-by-Step Remediation Plan</h4><div class='remediation-box'>" + remediation + "</div></div>" if remediation else ""}
            </div>
        </div>
        """
        findings_html_cards.append(card)

    cards_joined = "\n".join(findings_html_cards)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAST Security Audit Comprehensive Report</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --critical-color: #ef4444;
            --high-color: #f97316;
            --medium-color: #eab308;
            --low-color: #3b82f6;
            --code-bg: #090d16;
            --accent-blue: #38bdf8;
            --success-green: #22c55e;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 28px;
            color: var(--accent-blue);
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .metric-card .value {{
            font-size: 32px;
            font-weight: bold;
            margin-top: 8px;
        }}
        .controls {{
            display: flex;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }}
        .filter-buttons {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
        }}
        .filter-btn.active, .filter-btn:hover {{
            background: var(--accent-blue);
            color: #0f172a;
        }}
        .search-input {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 6px;
            width: 300px;
        }}
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
        }}
        .card-header {{
            padding: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            background: #1e293b;
            transition: background 0.2s;
        }}
        .card-header:hover {{
            background: #273549;
        }}
        .header-left {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .severity-badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
            color: #fff;
        }}
        .badge-critical {{ background: var(--critical-color); }}
        .badge-high {{ background: var(--high-color); }}
        .badge-medium {{ background: var(--medium-color); color: #000; }}
        .badge-low {{ background: var(--low-color); }}
        .finding-id {{ color: var(--text-muted); font-family: monospace; }}
        .finding-title {{ font-size: 16px; font-weight: 600; }}
        .cwe-tag {{ background: #334155; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .card-body {{
            padding: 20px;
            border-top: 1px solid var(--border-color);
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
            background: #0f172a;
            padding: 12px;
            border-radius: 6px;
        }}
        .section-block {{
            margin-bottom: 20px;
        }}
        .section-block h4 {{
            margin: 0 0 8px 0;
            color: var(--accent-blue);
            font-size: 15px;
        }}
        .info-box {{
            background: #0f172a;
            border-left: 4px solid var(--high-color);
            padding: 12px;
            border-radius: 4px;
            line-height: 1.5;
        }}
        .remediation-box {{
            background: #0f172a;
            border-left: 4px solid var(--success-green);
            padding: 12px;
            border-radius: 4px;
            line-height: 1.5;
        }}
        .flow-meta {{
            display: flex;
            gap: 24px;
            margin-bottom: 8px;
            background: #0f172a;
            padding: 8px 12px;
            border-radius: 4px;
        }}
        .code-block {{
            background: var(--code-bg);
            border: 1px solid var(--border-color);
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: monospace;
            font-size: 13px;
            color: #e2e8f0;
            white-space: pre-wrap;
            margin: 0;
        }}
        .code-comparison {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 20px;
        }}
        @media (max-width: 768px) {{
            .code-comparison {{
                grid-template-columns: 1fr;
            }}
        }}
        .vuln-box h4 {{ color: var(--critical-color); }}
        .safe-box h4 {{ color: var(--success-green); }}
        .copy-btn {{
            float: right;
            background: #334155;
            color: #fff;
            border: none;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }}
        .status-tag {{
            text-transform: uppercase;
            font-size: 11px;
            font-weight: bold;
            padding: 2px 6px;
            border-radius: 3px;
            background: #334155;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ SAST Security Audit Comprehensive Report</h1>
                <p style="color: var(--text-muted); margin: 4px 0 0 0;">Scan ID: {scan_id} | Generated: {scan_date}</p>
            </div>
            <div>
                <span style="color: var(--text-muted);">Endpoints Analyzed: <strong>{endpoints_scanned}</strong> | Files Inspected: <strong>{files_scanned}</strong></span>
            </div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card" style="border-top: 4px solid var(--critical-color);">
                <div>CRITICAL</div>
                <div class="value" style="color: var(--critical-color);">{critical_count}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--high-color);">
                <div>HIGH</div>
                <div class="value" style="color: var(--high-color);">{high_count}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--medium-color);">
                <div>MEDIUM</div>
                <div class="value" style="color: var(--medium-color);">{medium_count}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--low-color);">
                <div>LOW</div>
                <div class="value" style="color: var(--low-color);">{low_count}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--accent-blue);">
                <div>TOTAL ISSUES</div>
                <div class="value" style="color: var(--accent-blue);">{total_count}</div>
            </div>
        </div>

        <div class="controls">
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterSeverity('ALL')">All ({total_count})</button>
                <button class="filter-btn" onclick="filterSeverity('CRITICAL')">Critical ({critical_count})</button>
                <button class="filter-btn" onclick="filterSeverity('HIGH')">High ({high_count})</button>
                <button class="filter-btn" onclick="filterSeverity('MEDIUM')">Medium ({medium_count})</button>
                <button class="filter-btn" onclick="filterSeverity('LOW')">Low ({low_count})</button>
            </div>
            <input type="text" class="search-input" id="searchInput" onkeyup="searchFindings()" placeholder="Search findings, CWEs, files...">
        </div>

        <div id="findingsContainer">
            {cards_joined if cards_joined else "<p style='text-align:center; color: var(--text-muted); padding: 40px;'>No findings reported in scan.</p>"}
        </div>
    </div>

    <script>
        function toggleCard(id) {{
            const body = document.getElementById('body-' + id);
            const icon = document.getElementById('icon-' + id);
            if (body.style.display === 'none') {{
                body.style.display = 'block';
                icon.innerText = '▲';
            }} else {{
                body.style.display = 'none';
                icon.innerText = '▼';
            }}
        }}

        function filterSeverity(sev) {{
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                if (sev === 'ALL' || card.getAttribute('data-severity') === sev) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        function searchFindings() {{
            const q = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                const text = card.getAttribute('data-search').toLowerCase();
                if (text.includes(q)) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        function copyText(btn) {{
            const code = btn.nextElementSibling.innerText;
            navigator.clipboard.writeText(code);
            btn.innerText = 'Copied!';
            setTimeout(() => btn.innerText = 'Copy Request', 2000);
        }}
    </script>
</body>
</html>
"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] SAST HTML Report generated successfully: {output_path}")

def main():
    workspace_root = os.getcwd()
    sast_dir = os.path.join(workspace_root, ".sast-agent")
    findings_dir = os.path.join(sast_dir, "findings")
    jsonl_path = os.path.join(findings_dir, "findings.jsonl")
    state_path = os.path.join(sast_dir, "state", "scan-state.json")
    output_path = os.path.join(sast_dir, "reports", "index.html")

    findings = parse_all_findings(findings_dir, jsonl_path)
    scan_state = load_scan_state(state_path)
    render_html_report(findings, scan_state, output_path)

if __name__ == "__main__":
    main()
