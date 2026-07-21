import os
import json
import glob
import html
import re
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

def parse_markdown_finding(file_path):
    """Extracts structured finding data from markdown files."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return None

    finding = {
        "id": os.path.splitext(os.path.basename(file_path))[0],
        "title": "Untitled Finding",
        "severity": "MEDIUM",
        "confidence": "High",
        "cwe": "N/A",
        "affected_file": "N/A",
        "endpoint": "N/A",
        "source": "N/A",
        "sink": "N/A",
        "impact": "N/A",
        "why_issue": "",
        "data_flow": "",
        "poc": "",
        "vulnerable_code": "",
        "safe_code": "",
        "remediation": "",
        "status": "confirmed"
    }

    # Extract title
    title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    if title_match:
        finding["title"] = title_match.group(1).strip()

    # Extract Key-Value Metadata
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

    # Extract Sections
    def extract_section(section_name, next_sections):
        pattern = r"##?\s+" + re.escape(section_name) + r"\s*\n(.*?)(?=\n##?\s+|$)"
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ""

    finding["impact"] = extract_section("Impact", []) or finding["impact"]
    finding["data_flow"] = extract_section("Data Flow", []) or extract_section("Control Flow Graph", [])
    finding["why_issue"] = extract_section("False-Positive Checks & Rationale", []) or extract_section("Evidence & Rationale", [])
    finding["poc"] = extract_section("PoC or Steps to Reproduce (Burp Suite)", []) or extract_section("Burp Suite PoC", [])
    finding["vulnerable_code"] = extract_section("Vulnerable Code Snippet", []) or extract_section("Vulnerable Code", [])
    finding["safe_code"] = extract_section("Safe Implementation", []) or extract_section("Remediation Code", [])
    finding["remediation"] = extract_section("Remediation Strategy", []) or extract_section("Remediation", [])

    return finding

def parse_findings(findings_dir, jsonl_path):
    findings = []
    seen_ids = set()

    # 1. Try reading JSONL file if it exists
    if os.path.exists(jsonl_path):
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    fid = data.get("id", data.get("finding_id", ""))
                    if fid:
                        seen_ids.add(fid)
                    findings.append(data)
                except Exception:
                    pass

    # 2. Check subfolders for JSON and MD finding files
    for subfolder in ["confirmed", "needs-review", "duplicate", "false-positive"]:
        folder_path = os.path.join(findings_dir, subfolder)
        if os.path.exists(folder_path):
            for file_name in os.listdir(folder_path):
                full_p = os.path.join(folder_path, file_name)
                if file_name.endswith(".json"):
                    try:
                        with open(full_p, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            fid = data.get("id", file_name)
                            if fid not in seen_ids:
                                data["status"] = subfolder
                                seen_ids.add(fid)
                                findings.append(data)
                    except Exception:
                        pass
                elif file_name.endswith(".md"):
                    parsed = parse_markdown_finding(full_p)
                    if parsed:
                        fid = parsed["id"]
                        if fid not in seen_ids:
                            parsed["status"] = subfolder
                            seen_ids.add(fid)
                            findings.append(parsed)

    # Sort findings in decreasing order of severity (Critical -> High -> Medium -> Low)
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
    scan_id = scan_state.get("scan_id", "N/A")
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
        fid = html.escape(str(f.get("id", f.get("finding_id", f"FINDING-{idx}"))))
        title = html.escape(str(f.get("title", f.get("issue_name", "Untitled Vulnerability Finding"))))
        severity = str(f.get("severity", "Medium")).upper()
        confidence = html.escape(str(f.get("confidence", "High")))
        cwe = html.escape(str(f.get("cwe", f.get("cwe_owasp", "N/A"))))
        affected_file = html.escape(str(f.get("affected_file", f.get("file", f.get("location", "N/A")))))
        endpoint = html.escape(str(f.get("endpoint", f.get("affected_endpoint", "N/A"))))
        impact = html.escape(str(f.get("impact", "N/A")))
        source = html.escape(str(f.get("source", "N/A")))
        sink = html.escape(str(f.get("sink", "N/A")))
        data_flow = html.escape(str(f.get("data_flow", f.get("dataflow", f.get("cfg_trace", "N/A")))))
        poc = html.escape(str(f.get("poc", f.get("burp_poc", f.get("request_template", f.get("steps_to_reproduce", "N/A"))))))
        vuln_code = html.escape(str(f.get("vulnerable_code", f.get("vulnerable_code_snippet", f.get("unsafe_code", "")))))
        safe_code = html.escape(str(f.get("safe_code", f.get("safe_implementation", f.get("remediation_code", "")))))
        why_issue = html.escape(str(f.get("why_issue", f.get("why_vulnerable", f.get("rationale", f.get("evidence_rationale", f.get("negative_verification", "")))))))
        remediation = html.escape(str(f.get("remediation", f.get("remediation_strategy", f.get("recommendation", "")))))
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
                    <h4>🔍 Vulnerability Overview & Impact</h4>
                    <p>{impact}</p>
                </div>

                {"<div class='section-block'><h4>⚠️ Why This Is A Verified Issue (Evidence & Control Bypass Rationale)</h4><div class='info-box'>" + why_issue + "</div></div>" if why_issue else ""}

                <div class="section-block">
                    <h4>⛓️ Data Flow Trace (Source → Sink / CFG Propagation)</h4>
                    <div class="flow-meta">
                        <span><strong>Source:</strong> <code>{source}</code></span>
                        <span><strong>Sink:</strong> <code>{sink}</code></span>
                    </div>
                    <pre class="code-block">{data_flow}</pre>
                </div>

                {"<div class='section-block'><h4>🧪 Burp Suite HTTP Request Template & PoC</h4><button class='copy-btn' onclick='copyText(this)'>Copy PoC Request</button><pre class='code-block poc-block'>" + poc + "</pre></div>" if poc and poc != "N/A" else ""}

                <div class="code-comparison">
                    {"<div class='code-box vuln-box'><h4>❌ Vulnerable / Unsafe Implementation</h4><pre class='code-block'>" + vuln_code + "</pre></div>" if vuln_code else ""}
                    {"<div class='code-box safe-box'><h4>✅ Secure / Safe Implementation</h4><pre class='code-block'>" + safe_code + "</pre></div>" if safe_code else ""}
                </div>

                {"<div class='section-block remediation-block'><h4>🛠️ Step-by-Step Remediation Strategy</h4><div class='remediation-box'>" + remediation + "</div></div>" if remediation else ""}
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
    <title>SAST Comprehensive Security Audit Report</title>
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
                <h1>🛡️ SAST Comprehensive Security Audit Report</h1>
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
            setTimeout(() => btn.innerText = 'Copy PoC Request', 2000);
        }}
    </script>
</body>
</html>
"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] SAST Comprehensive HTML Report generated successfully: {output_path}")

def main():
    workspace_root = os.getcwd()
    sast_dir = os.path.join(workspace_root, ".sast-agent")
    findings_dir = os.path.join(sast_dir, "findings")
    jsonl_path = os.path.join(findings_dir, "findings.jsonl")
    state_path = os.path.join(sast_dir, "state", "scan-state.json")
    output_path = os.path.join(sast_dir, "reports", "index.html")

    findings = parse_findings(findings_dir, jsonl_path)
    scan_state = load_scan_state(state_path)
    render_html_report(findings, scan_state, output_path)

if __name__ == "__main__":
    main()
