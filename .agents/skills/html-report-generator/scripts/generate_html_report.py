import os
import json
import glob
import html
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

def parse_findings(findings_dir, jsonl_path):
    findings = []
    
    # 1. Try reading JSONL file if it exists
    if os.path.exists(jsonl_path):
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append(data)
                except Exception:
                    pass

    # 2. Also check confirmed / needs-review / duplicate / false-positive JSON/MD files if present
    for subfolder in ["confirmed", "needs-review", "duplicate", "false-positive"]:
        folder_path = os.path.join(findings_dir, subfolder)
        if os.path.exists(folder_path):
            for file_name in os.listdir(folder_path):
                if file_name.endswith(".json"):
                    full_p = os.path.join(folder_path, file_name)
                    try:
                        with open(full_p, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            if not any(f.get("id") == data.get("id") for f in findings):
                                data["status"] = subfolder
                                findings.append(data)
                    except Exception:
                        pass

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
        fid = html.escape(str(f.get("id", f"FINDING-{idx}")))
        title = html.escape(str(f.get("title", "Untitled Finding")))
        severity = str(f.get("severity", "Medium")).upper()
        confidence = html.escape(str(f.get("confidence", "High")))
        cwe = html.escape(str(f.get("cwe", "N/A")))
        affected_file = html.escape(str(f.get("affected_file", f.get("file", "N/A"))))
        endpoint = html.escape(str(f.get("endpoint", f.get("affected_endpoint", "N/A"))))
        impact = html.escape(str(f.get("impact", "N/A")))
        source = html.escape(str(f.get("source", "N/A")))
        sink = html.escape(str(f.get("sink", "N/A")))
        data_flow = html.escape(str(f.get("data_flow", f.get("dataflow", "N/A"))))
        poc = html.escape(str(f.get("poc", f.get("burp_poc", f.get("steps_to_reproduce", "N/A")))))
        vuln_code = html.escape(str(f.get("vulnerable_code", f.get("vulnerable_code_snippet", ""))))
        safe_code = html.escape(str(f.get("safe_code", f.get("safe_implementation", ""))))
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
                    <div><strong>Status:</strong> {status}</div>
                </div>

                <div class="section-block">
                    <h4>Impact</h4>
                    <p>{impact}</p>
                </div>

                <div class="section-block">
                    <h4>Data Flow (Source → Sink)</h4>
                    <p><strong>Source:</strong> <code>{source}</code></p>
                    <p><strong>Sink:</strong> <code>{sink}</code></p>
                    <pre class="code-block">{data_flow}</pre>
                </div>

                {"<div class='section-block'><h4>Burp Suite HTTP PoC</h4><button class='copy-btn' onclick='copyText(this)'>Copy PoC</button><pre class='code-block poc-block'>" + poc + "</pre></div>" if poc and poc != "N/A" else ""}

                <div class="code-comparison">
                    {"<div class='code-box vuln-box'><h4>Vulnerable Code</h4><pre class='code-block'>" + vuln_code + "</pre></div>" if vuln_code else ""}
                    {"<div class='code-box safe-box'><h4>Safe Implementation</h4><pre class='code-block'>" + safe_code + "</pre></div>" if safe_code else ""}
                </div>
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
    <title>SAST Security Audit Report</title>
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
            color: #38bdf8;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
            background: #38bdf8;
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
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
            background: #0f172a;
            padding: 12px;
            border-radius: 6px;
        }}
        .section-block {{
            margin-bottom: 16px;
        }}
        .section-block h4 {{
            margin: 0 0 8px 0;
            color: #38bdf8;
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
        }}
        .code-comparison {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }}
        .vuln-box h4 {{ color: var(--critical-color); }}
        .safe-box h4 {{ color: #4ade80; }}
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ SAST Security Audit Report</h1>
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
            <div class="metric-card" style="border-top: 4px solid #38bdf8;">
                <div>TOTAL ISSUES</div>
                <div class="value" style="color: #38bdf8;">{total_count}</div>
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
            setTimeout(() => btn.innerText = 'Copy PoC', 2000);
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

    findings = parse_findings(findings_dir, jsonl_path)
    scan_state = load_scan_state(state_path)
    render_html_report(findings, scan_state, output_path)

if __name__ == "__main__":
    main()
