const fs = require('fs');
const path = require('path');

const SEVERITY_ORDER = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'NEEDS-REVIEW': 0,
    'INFO': 0
};

function getSeverityScore(sev) {
    return SEVERITY_ORDER[String(sev).toUpperCase()] || 0;
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function parseFindings(findingsDir, jsonlPath) {
    const findings = [];

    // 1. Try reading JSONL file
    if (fs.existsSync(jsonlPath)) {
        const lines = fs.readFileSync(jsonlPath, 'utf-8').split('\n');
        for (let line of lines) {
            line = line.trim();
            if (!line) continue;
            try {
                findings.push(JSON.parse(line));
            } catch (e) {}
        }
    }

    // 2. Read subfolders
    const subfolders = ['confirmed', 'needs-review', 'duplicate', 'false-positive'];
    for (const sub of subfolders) {
        const folderPath = path.join(findingsDir, sub);
        if (fs.existsSync(folderPath)) {
            const files = fs.readdirSync(folderPath);
            for (const file of files) {
                if (file.endsWith('.json')) {
                    try {
                        const data = JSON.parse(fs.readFileSync(path.join(folderPath, file), 'utf-8'));
                        if (!findings.some(f => f.id === data.id)) {
                            data.status = sub;
                            findings.push(data);
                        }
                    } catch (e) {}
                }
            }
        }
    }

    // Sort decreasing severity
    findings.sort((a, b) => getSeverityScore(b.severity || 'LOW') - getSeverityScore(a.severity || 'LOW'));
    return findings;
}

function loadScanState(statePath) {
    if (fs.existsSync(statePath)) {
        try {
            return JSON.parse(fs.readFileSync(statePath, 'utf-8'));
        } catch (e) {}
    }
    return {};
}

function renderHtmlReport(findings, scanState, outputPath) {
    const scanId = scanState.scan_id || 'N/A';
    const scanDate = scanState.timestamp || new Date().toISOString().replace('T', ' ').substring(0, 19);
    const endpointsScanned = scanState.endpoints_scanned || 0;
    const filesScanned = scanState.files_scanned || 0;

    const criticalCount = findings.filter(f => String(f.severity).toUpperCase() === 'CRITICAL').length;
    const highCount = findings.filter(f => String(f.severity).toUpperCase() === 'HIGH').length;
    const mediumCount = findings.filter(f => String(f.severity).toUpperCase() === 'MEDIUM').length;
    const lowCount = findings.filter(f => String(f.severity).toUpperCase() === 'LOW').length;
    const totalCount = findings.length;

    const cardsHtml = findings.map((f, idx) => {
        const fid = escapeHtml(f.id || `FINDING-${idx + 1}`);
        const title = escapeHtml(f.title || 'Untitled Finding');
        const severity = String(f.severity || 'MEDIUM').toUpperCase();
        const confidence = escapeHtml(f.confidence || 'High');
        const cwe = escapeHtml(f.cwe || 'N/A');
        const affectedFile = escapeHtml(f.affected_file || f.file || 'N/A');
        const endpoint = escapeHtml(f.endpoint || f.affected_endpoint || 'N/A');
        const impact = escapeHtml(f.impact || 'N/A');
        const source = escapeHtml(f.source || 'N/A');
        const sink = escapeHtml(f.sink || 'N/A');
        const dataFlow = escapeHtml(f.data_flow || f.dataflow || 'N/A');
        const poc = escapeHtml(f.poc || f.burp_poc || f.steps_to_reproduce || 'N/A');
        const vulnCode = escapeHtml(f.vulnerable_code || f.vulnerable_code_snippet || '');
        const safeCode = escapeHtml(f.safe_code || f.safe_implementation || '');
        const status = escapeHtml(f.status || 'confirmed');
        const badgeClass = `badge-${severity.toLowerCase()}`;

        return `
        <div class="finding-card" data-severity="${severity}" data-search="${fid} ${title} ${affectedFile} ${cwe}">
            <div class="card-header" onclick="toggleCard('${fid}')">
                <div class="header-left">
                    <span class="severity-badge ${badgeClass}">${severity}</span>
                    <span class="finding-id">#${fid}</span>
                    <span class="finding-title">${title}</span>
                </div>
                <div class="header-right">
                    <span class="cwe-tag">${cwe}</span>
                    <span class="expand-icon" id="icon-${fid}">▼</span>
                </div>
            </div>
            <div class="card-body" id="body-${fid}" style="display: none;">
                <div class="meta-grid">
                    <div><strong>Affected File:</strong> <code>${affectedFile}</code></div>
                    <div><strong>Endpoint:</strong> <code>${endpoint}</code></div>
                    <div><strong>Confidence:</strong> ${confidence}</div>
                    <div><strong>Status:</strong> ${status}</div>
                </div>

                <div class="section-block">
                    <h4>Impact</h4>
                    <p>${impact}</p>
                </div>

                <div class="section-block">
                    <h4>Data Flow (Source → Sink)</h4>
                    <p><strong>Source:</strong> <code>${source}</code></p>
                    <p><strong>Sink:</strong> <code>${sink}</code></p>
                    <pre class="code-block">${dataFlow}</pre>
                </div>

                ${poc && poc !== 'N/A' ? `<div class="section-block"><h4>Burp Suite HTTP PoC</h4><button class="copy-btn" onclick="copyText(this)">Copy PoC</button><pre class="code-block poc-block">${poc}</pre></div>` : ''}

                <div class="code-comparison">
                    ${vulnCode ? `<div class="code-box vuln-box"><h4>Vulnerable Code</h4><pre class="code-block">${vulnCode}</pre></div>` : ''}
                    ${safeCode ? `<div class="code-box safe-box"><h4>Safe Implementation</h4><pre class="code-block">${safeCode}</pre></div>` : ''}
                </div>
            </div>
        </div>`;
    }).join('\n');

    const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAST Security Audit Report</title>
    <style>
        :root {
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
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
            color: #38bdf8;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .metric-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }
        .metric-card .value {
            font-size: 32px;
            font-weight: bold;
            margin-top: 8px;
        }
        .controls {
            display: flex;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }
        .filter-buttons {
            display: flex;
            gap: 8px;
        }
        .filter-btn {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
        }
        .filter-btn.active, .filter-btn:hover {
            background: #38bdf8;
            color: #0f172a;
        }
        .search-input {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 6px;
            width: 300px;
        }
        .finding-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
        }
        .card-header {
            padding: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            background: #1e293b;
        }
        .card-header:hover {
            background: #273549;
        }
        .header-left {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .severity-badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
            color: #fff;
        }
        .badge-critical { background: var(--critical-color); }
        .badge-high { background: var(--high-color); }
        .badge-medium { background: var(--medium-color); color: #000; }
        .badge-low { background: var(--low-color); }
        .finding-id { color: var(--text-muted); font-family: monospace; }
        .finding-title { font-size: 16px; font-weight: 600; }
        .cwe-tag { background: #334155; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .card-body {
            padding: 20px;
            border-top: 1px solid var(--border-color);
        }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
            background: #0f172a;
            padding: 12px;
            border-radius: 6px;
        }
        .section-block {
            margin-bottom: 16px;
        }
        .section-block h4 {
            margin: 0 0 8px 0;
            color: #38bdf8;
        }
        .code-block {
            background: var(--code-bg);
            border: 1px solid var(--border-color);
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: monospace;
            font-size: 13px;
            color: #e2e8f0;
            white-space: pre-wrap;
        }
        .code-comparison {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }
        .vuln-box h4 { color: var(--critical-color); }
        .safe-box h4 { color: #4ade80; }
        .copy-btn {
            float: right;
            background: #334155;
            color: #fff;
            border: none;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ SAST Security Audit Report</h1>
                <p style="color: var(--text-muted); margin: 4px 0 0 0;">Scan ID: ${scanId} | Generated: ${scanDate}</p>
            </div>
            <div>
                <span style="color: var(--text-muted);">Endpoints Analyzed: <strong>${endpointsScanned}</strong> | Files Inspected: <strong>${filesScanned}</strong></span>
            </div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card" style="border-top: 4px solid var(--critical-color);">
                <div>CRITICAL</div>
                <div class="value" style="color: var(--critical-color);">${criticalCount}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--high-color);">
                <div>HIGH</div>
                <div class="value" style="color: var(--high-color);">${highCount}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--medium-color);">
                <div>MEDIUM</div>
                <div class="value" style="color: var(--medium-color);">${mediumCount}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--low-color);">
                <div>LOW</div>
                <div class="value" style="color: var(--low-color);">${lowCount}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid #38bdf8;">
                <div>TOTAL ISSUES</div>
                <div class="value" style="color: #38bdf8;">${totalCount}</div>
            </div>
        </div>

        <div class="controls">
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterSeverity('ALL')">All (${totalCount})</button>
                <button class="filter-btn" onclick="filterSeverity('CRITICAL')">Critical (${criticalCount})</button>
                <button class="filter-btn" onclick="filterSeverity('HIGH')">High (${highCount})</button>
                <button class="filter-btn" onclick="filterSeverity('MEDIUM')">Medium (${mediumCount})</button>
                <button class="filter-btn" onclick="filterSeverity('LOW')">Low (${lowCount})</button>
            </div>
            <input type="text" class="search-input" id="searchInput" onkeyup="searchFindings()" placeholder="Search findings, CWEs, files...">
        </div>

        <div id="findingsContainer">
            ${cardsHtml ? cardsHtml : "<p style='text-align:center; color: var(--text-muted); padding: 40px;'>No findings reported in scan.</p>"}
        </div>
    </div>

    <script>
        function toggleCard(id) {
            const body = document.getElementById('body-' + id);
            const icon = document.getElementById('icon-' + id);
            if (body.style.display === 'none') {
                body.style.display = 'block';
                icon.innerText = '▲';
            } else {
                body.style.display = 'none';
                icon.innerText = '▼';
            }
        }

        function filterSeverity(sev) {
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {
                if (sev === 'ALL' || card.getAttribute('data-severity') === sev) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }

        function searchFindings() {
            const q = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {
                const text = card.getAttribute('data-search').toLowerCase();
                if (text.includes(q)) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }

        function copyText(btn) {
            const code = btn.nextElementSibling.innerText;
            navigator.clipboard.writeText(code);
            btn.innerText = 'Copied!';
            setTimeout(() => btn.innerText = 'Copy PoC', 2000);
        }
    </script>
</body>
</html>`;

    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, htmlContent, 'utf-8');
    console.log(`[+] SAST HTML Report generated successfully: ${outputPath}`);
}

function main() {
    const workspaceRoot = process.cwd();
    const sastDir = path.join(workspaceRoot, '.sast-agent');
    const findingsDir = path.join(sastDir, 'findings');
    const jsonlPath = path.join(findingsDir, 'findings.jsonl');
    const statePath = path.join(sastDir, 'state', 'scan-state.json');
    const outputPath = path.join(sastDir, 'reports', 'index.html');

    const findings = parseFindings(findingsDir, jsonlPath);
    const scanState = loadScanState(statePath);
    renderHtmlReport(findings, scanState, outputPath);
}

main();
