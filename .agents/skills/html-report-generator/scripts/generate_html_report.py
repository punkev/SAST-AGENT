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

# Mandatory fields that MUST contain real, specific evidence.
# If any of these are missing or contain placeholder text, the finding is flagged as incomplete.
MANDATORY_EVIDENCE_FIELDS = [
    "title", "severity", "cwe", "affected_file", "line_anchor",
    "function_anchor", "endpoint", "source", "sink", "data_flow",
    "impact", "why_issue", "payload", "poc", "expected_response",
    "evidence", "vulnerable_code", "safe_code", "remediation"
]

# Known placeholder/generic strings that indicate missing real evidence.
# If a field's value matches any of these (case-insensitive), it's flagged as a placeholder.
PLACEHOLDER_PATTERNS = [
    "n/a",
    "untitled vulnerability finding",
    "user http request parameter / input",
    "sensitive sink api execution",
    "handlermethod",
    "l1-l50",
    "' or '1'='1 --",
    "// vulnerable implementation",
    "// secure implementation",
    "string sanitized = sanitize(inputparam);",
    "exploitation allows attackers to bypass security controls",
    "control bypass verified: application inputs reach vulnerable sink",
    "get /api/v1/endpoint?input=",
    "http/1.1 200 ok\ncontent-type: application/json\n\n{\"status\":\"success\"",
    "1. enforce strict input validation",
    "verified unvalidated sink call",
    "input (user http request",
]

MISSING_MARKER = "⚠️ MISSING — Evidence not provided by scanner"


def get_severity_score(sev):
    return SEVERITY_ORDER.get(str(sev).upper(), 0)


def is_placeholder(value):
    """Check if a value matches known placeholder/generic patterns."""
    if not value or not value.strip():
        return True
    val_lower = value.strip().lower()
    if val_lower in ("", "n/a", "none", "null", "undefined", "unknown", "-", "—"):
        return True
    for pattern in PLACEHOLDER_PATTERNS:
        if pattern in val_lower:
            return True
    return False


def validate_finding(finding):
    """
    Validate a finding for mandatory field completeness.
    Returns (is_complete, missing_fields, placeholder_fields).
    """
    missing_fields = []
    placeholder_fields = []

    for field in MANDATORY_EVIDENCE_FIELDS:
        value = finding.get(field, "")
        if not value or not str(value).strip():
            missing_fields.append(field)
        elif is_placeholder(str(value)):
            placeholder_fields.append(field)

    is_complete = len(missing_fields) == 0 and len(placeholder_fields) == 0
    return is_complete, missing_fields, placeholder_fields


def parse_markdown_finding(file_path):
    """Extracts structured finding data from markdown files."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return None

    finding = {
        "id": os.path.splitext(os.path.basename(file_path))[0],
        "title": "",
        "severity": "MEDIUM",
        "confidence": "",
        "cwe": "",
        "affected_file": "",
        "line_anchor": "",
        "function_anchor": "",
        "endpoint": "",
        "source": "",
        "sink": "",
        "payload": "",
        "poc": "",
        "expected_response": "",
        "evidence": "",
        "data_flow": "",
        "vulnerable_code": "",
        "safe_code": "",
        "remediation": "",
        "impact": "",
        "why_issue": "",
        "status": "confirmed"
    }

    # Title
    title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    if title_match:
        finding["title"] = title_match.group(1).strip()

    # Key-Value Metadata
    sev_match = re.search(r"\*\*(?:Severity)\*\*:\s*(\w+)", content, re.IGNORECASE)
    if sev_match:
        finding["severity"] = sev_match.group(1).strip()

    cwe_match = re.search(r"\*\*(?:CWE|OWASP|CWE/OWASP)\*\*:\s*(.+)", content, re.IGNORECASE)
    if cwe_match:
        finding["cwe"] = cwe_match.group(1).strip()

    confidence_match = re.search(r"\*\*(?:Confidence)\*\*:\s*(\w+)", content, re.IGNORECASE)
    if confidence_match:
        finding["confidence"] = confidence_match.group(1).strip()

    file_match = re.search(r"\*\*(?:Affected File|File)\*\*:\s*(.+)", content, re.IGNORECASE)
    if file_match:
        finding["affected_file"] = file_match.group(1).strip()

    line_match = re.search(r"\*\*(?:Line/Function Anchor|Line Anchor|Line)\*\*:\s*(.+)", content, re.IGNORECASE)
    if line_match:
        finding["line_anchor"] = line_match.group(1).strip()

    func_match = re.search(r"\*\*(?:Function Anchor|Function)\*\*:\s*(.+)", content, re.IGNORECASE)
    if func_match:
        finding["function_anchor"] = func_match.group(1).strip()

    endpoint_match = re.search(r"\*\*(?:Affected Endpoint|Endpoint)\*\*:\s*(.+)", content, re.IGNORECASE)
    if endpoint_match:
        finding["endpoint"] = endpoint_match.group(1).strip()

    source_match = re.search(r"\*\*(?:Source)\*\*:\s*(.+)", content, re.IGNORECASE)
    if source_match:
        finding["source"] = source_match.group(1).strip()

    sink_match = re.search(r"\*\*(?:Sink)\*\*:\s*(.+)", content, re.IGNORECASE)
    if sink_match:
        finding["sink"] = sink_match.group(1).strip()

    status_match = re.search(r"\*\*(?:Status)\*\*:\s*(\S+)", content, re.IGNORECASE)
    if status_match:
        finding["status"] = status_match.group(1).strip()

    # Section extraction helper
    def extract_section(section_names):
        for name in section_names:
            pattern = r"##?\s+" + re.escape(name) + r"\s*\n(.*?)(?=\n##?\s+|$)"
            match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return ""

    finding["impact"] = extract_section(["Vulnerability Overview & Impact", "Impact", "Why This Is Exploitable"])
    finding["why_issue"] = extract_section(["False-Positive Checks & Rationale", "Evidence & Control Bypass Rationale", "Evidence Rationale", "Active Defense Check"])
    finding["payload"] = extract_section(["Payload to Exploit", "Exploit Payload", "Payload"])
    finding["poc"] = extract_section(["PoC or Steps to Reproduce (Burp Suite)", "Burp Suite PoC", "Test Burp Suite Request", "PoC Request", "Steps to Reproduce"])
    finding["expected_response"] = extract_section(["Expected Burp Suite Response", "Expected Response", "Burp Suite Response", "Test Response"])
    finding["evidence"] = extract_section(["Evidence & Line-Anchored Link", "Evidence", "Evidence Snippet"])
    finding["data_flow"] = extract_section(["Data Flow", "Control Flow Graph", "CFG Data Flow", "Data Flow Trace"])
    finding["vulnerable_code"] = extract_section(["Vulnerable Code Snippet", "Vulnerable Code", "Unsafe Line of Code", "Unsafe Implementation"])
    finding["safe_code"] = extract_section(["Safe Implementation", "Safe Line of Code", "Secure Implementation", "Remediation Code"])
    finding["remediation"] = extract_section(["Remediation Strategy", "Remediation Plan", "Remediation", "Whole Remediation Plan"])

    return finding


def normalize_finding_keys(data):
    """
    Normalize finding keys from various naming conventions used by the agent
    into the canonical field names expected by the report generator.
    """
    key_mappings = {
        # id variations
        "finding_id": "id",
        "findingId": "id",
        # title variations
        "issue_name": "title",
        "name": "title",
        "vulnerability_name": "title",
        "issueName": "title",
        # cwe variations
        "cwe_owasp": "cwe",
        "cweOwasp": "cwe",
        "owasp": "cwe",
        # affected_file variations
        "file": "affected_file",
        "location": "affected_file",
        "filePath": "affected_file",
        "file_path": "affected_file",
        # line_anchor variations
        "line": "line_anchor",
        "line_number": "line_anchor",
        "lineNumber": "line_anchor",
        "lines": "line_anchor",
        # function_anchor variations
        "function": "function_anchor",
        "functionName": "function_anchor",
        "function_name": "function_anchor",
        "method": "function_anchor",
        # endpoint variations
        "affected_endpoint": "endpoint",
        "route": "endpoint",
        "url": "endpoint",
        "path": "endpoint",
        # impact variations
        "vulnerability_overview": "impact",
        "description": "impact",
        # why_issue variations
        "why_vulnerable": "why_issue",
        "rationale": "why_issue",
        "evidence_rationale": "why_issue",
        "negative_verification": "why_issue",
        "false_positive_rationale": "why_issue",
        # payload variations
        "payload_to_exploit": "payload",
        "attack_payload": "payload",
        "exploit_payload": "payload",
        "exploit": "payload",
        # poc variations
        "burp_poc": "poc",
        "test_request": "poc",
        "request_template": "poc",
        "steps_to_reproduce": "poc",
        "burp_request": "poc",
        "burp_suite_request": "poc",
        # expected_response variations
        "burp_response": "expected_response",
        "expected_burp_response": "expected_response",
        "test_response": "expected_response",
        "burp_suite_response": "expected_response",
        # evidence variations
        "evidence_snippet": "evidence",
        "evidence_link": "evidence",
        "evidence_reference": "evidence",
        # data_flow variations
        "dataflow": "data_flow",
        "cfg_trace": "data_flow",
        "data_flow_trace": "data_flow",
        "control_flow": "data_flow",
        # vulnerable_code variations
        "vulnerable_code_snippet": "vulnerable_code",
        "unsafe_code": "vulnerable_code",
        "unsafe_line_of_code": "vulnerable_code",
        "vuln_code": "vulnerable_code",
        # safe_code variations
        "safe_implementation": "safe_code",
        "remediation_code": "safe_code",
        "safe_line_of_code": "safe_code",
        "secure_code": "safe_code",
        "fixed_code": "safe_code",
        # remediation variations
        "remediation_plan": "remediation",
        "remediation_strategy": "remediation",
        "recommendation": "remediation",
        "fix": "remediation",
    }

    normalized = {}
    for key, value in data.items():
        canonical = key_mappings.get(key, key)
        # Only set if the canonical key isn't already populated with a non-empty value
        if canonical not in normalized or not normalized[canonical]:
            normalized[canonical] = value
        # If canonical key exists but current key IS the canonical name, prefer it
        elif key == canonical:
            normalized[canonical] = value

    return normalized


def parse_findings(findings_dir, jsonl_path):
    findings = []
    seen_ids = set()

    # 1. Read JSONL file if present
    if os.path.exists(jsonl_path):
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    data = normalize_finding_keys(data)
                    fid = data.get("id", data.get("finding_id", ""))
                    if fid:
                        seen_ids.add(fid)
                    findings.append(data)
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
                            data = json.load(f)
                            data = normalize_finding_keys(data)
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

    # Sort strictly in decreasing order of severity (CRITICAL -> HIGH -> MEDIUM -> LOW)
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


def load_coverage_data(sast_dir):
    """Load scan-queue and visited-files to compute coverage metrics."""
    queue_path = os.path.join(sast_dir, "state", "scan-queue.jsonl")
    visited_path = os.path.join(sast_dir, "state", "visited-files.jsonl")

    queued_files = 0
    visited_files = 0

    if os.path.exists(queue_path):
        with open(queue_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    queued_files += 1

    if os.path.exists(visited_path):
        with open(visited_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    visited_files += 1

    return queued_files, visited_files


def get_field_value(finding, field_name):
    """
    Get a field value from a finding. Returns the actual value or empty string.
    NEVER returns a generic fallback — only real data or an explicit missing marker.
    """
    value = str(finding.get(field_name, "")).strip()
    if not value or is_placeholder(value):
        return ""
    return value


def render_html_report(findings, scan_state, output_path, sast_dir):
    scan_id = scan_state.get("scan_id", "SAST-SCAN-" + datetime.now().strftime("%Y%m%d"))
    scan_date = scan_state.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    endpoints_scanned = scan_state.get("endpoints_scanned", scan_state.get("endpoints_analyzed", 0))
    files_scanned = scan_state.get("files_scanned", scan_state.get("files_visited", 0))

    critical_count = sum(1 for f in findings if str(f.get("severity")).upper() == "CRITICAL")
    high_count = sum(1 for f in findings if str(f.get("severity")).upper() == "HIGH")
    medium_count = sum(1 for f in findings if str(f.get("severity")).upper() == "MEDIUM")
    low_count = sum(1 for f in findings if str(f.get("severity")).upper() == "LOW")
    total_count = len(findings)

    # Validate all findings and compute data quality metrics
    complete_count = 0
    incomplete_count = 0
    validation_results = []

    for f in findings:
        is_complete, missing, placeholders = validate_finding(f)
        all_issues = missing + placeholders
        validation_results.append((is_complete, all_issues))
        if is_complete:
            complete_count += 1
        else:
            incomplete_count += 1
            fid = f.get("id", f.get("finding_id", "UNKNOWN"))
            print(f"[!] WARNING: Finding '{fid}' is INCOMPLETE. Missing/placeholder fields: {', '.join(all_issues)}")

    if total_count > 0:
        completeness_pct = round((complete_count / total_count) * 100, 1)
    else:
        completeness_pct = 0

    # Load coverage data
    queued_files, visited_files = load_coverage_data(sast_dir)
    if queued_files > 0:
        coverage_pct = round((visited_files / queued_files) * 100, 1)
    else:
        coverage_pct = 0
        # Fallback to scan_state values if JSONL files don't exist
        queued_files = scan_state.get("files_queued", 0)
        visited_files = scan_state.get("files_visited", files_scanned)
        if queued_files > 0:
            coverage_pct = round((visited_files / queued_files) * 100, 1)

    print(f"[*] Data Quality: {complete_count}/{total_count} findings complete ({completeness_pct}%)")
    print(f"[*] File Coverage: {visited_files}/{queued_files} files visited ({coverage_pct}%)")

    findings_html_cards = []
    for idx, (f, (is_complete, issue_fields)) in enumerate(zip(findings, validation_results), 1):
        fid = str(f.get("id", f.get("finding_id", f"FINDING-{idx}")))
        title = get_field_value(f, "title") or f"Untitled Finding #{idx}"
        severity = str(f.get("severity", "MEDIUM")).upper()
        confidence = get_field_value(f, "confidence") or "Unknown"
        cwe = get_field_value(f, "cwe") or "Not specified"
        status = str(f.get("status", "confirmed"))

        # Where issue exists properties — NO fake fallbacks
        affected_file_raw = get_field_value(f, "affected_file")
        line_anchor_raw = get_field_value(f, "line_anchor")
        function_anchor = get_field_value(f, "function_anchor")
        endpoint_raw = get_field_value(f, "endpoint")

        source = get_field_value(f, "source")
        sink = get_field_value(f, "sink")

        # Section properties — NO fake fallbacks, only real data or missing markers
        impact = get_field_value(f, "impact")
        why_issue = get_field_value(f, "why_issue")
        payload = get_field_value(f, "payload")
        poc = get_field_value(f, "poc")
        expected_response = get_field_value(f, "expected_response")
        evidence = get_field_value(f, "evidence")
        data_flow = get_field_value(f, "data_flow")
        vuln_code = get_field_value(f, "vulnerable_code")
        safe_code = get_field_value(f, "safe_code")
        remediation = get_field_value(f, "remediation")

        # Helper to render a value or a styled missing marker
        def render_value(val, field_name):
            if val:
                return html.escape(val)
            return f'<span class="missing-marker">⚠️ MISSING — "{field_name}" not provided by scanner</span>'

        def render_code_value(val, field_name):
            if val:
                return html.escape(val)
            return f'⚠️ MISSING — "{field_name}" not provided by scanner'

        # Formatting hyperlinks
        if affected_file_raw and affected_file_raw.startswith("file://"):
            file_link = affected_file_raw
            display_file = affected_file_raw.replace("file:///", "").replace("file://", "")
        elif affected_file_raw:
            file_link = "file:///" + affected_file_raw.replace("\\", "/")
            display_file = affected_file_raw
        else:
            file_link = "#"
            display_file = ""

        badge_class = f"badge-{severity.lower()}"

        # Incomplete badge
        incomplete_badge = ""
        if not is_complete:
            incomplete_badge = f'<span class="incomplete-badge" title="Missing fields: {html.escape(", ".join(issue_fields))}">⚠️ INCOMPLETE ({len(issue_fields)} fields)</span>'

        card = f"""
        <div class="finding-card {'finding-incomplete' if not is_complete else ''}" data-severity="{severity}" data-search="{html.escape(fid)} {html.escape(title)} {html.escape(display_file)} {html.escape(cwe)}" data-complete="{'true' if is_complete else 'false'}">
            <div class="card-header" onclick="toggleCard('{html.escape(fid)}')">
                <div class="header-left">
                    <span class="severity-badge {badge_class}">{html.escape(severity)}</span>
                    <span class="finding-id">#{html.escape(fid)}</span>
                    <span class="finding-title">{html.escape(title)}</span>
                    {incomplete_badge}
                </div>
                <div class="header-right">
                    <span class="cwe-tag">{html.escape(cwe)}</span>
                    <span class="expand-icon" id="icon-{html.escape(fid)}">▼</span>
                </div>
            </div>
            <div class="card-body" id="body-{html.escape(fid)}" style="display: none;">
                
                <!-- SECTION 1: WHERE ISSUE EXISTS -->
                <div class="section-block">
                    <h4 class="section-title">📍 Where The Issue Exists</h4>
                    <div class="meta-grid">
                        <div><strong>Affected File:</strong> {f'<a href="{html.escape(file_link)}" target="_blank" class="file-link"><code>{html.escape(display_file)}</code></a>' if display_file else render_value("", "affected_file")}</div>
                        <div><strong>Line / Function Anchor:</strong> {f'<code>{html.escape(line_anchor_raw)} ({html.escape(function_anchor)})</code>' if line_anchor_raw or function_anchor else render_value("", "line_anchor / function_anchor")}</div>
                        <div><strong>Affected Endpoint:</strong> {f'<code>{html.escape(endpoint_raw)}</code>' if endpoint_raw else render_value("", "endpoint")}</div>
                        <div><strong>Status / Confidence:</strong> <span class="status-tag">{html.escape(status)}</span> | Confidence: {html.escape(confidence)}</div>
                    </div>
                </div>

                <!-- SECTION 2: VULNERABILITY OVERVIEW & IMPACT -->
                <div class="section-block">
                    <h4 class="section-title">🔍 Vulnerability Overview & Impact</h4>
                    <div class="info-box">
                        <p><strong>Impact:</strong> {render_value(impact, "impact")}</p>
                        <p style="margin-top: 8px;"><strong>Control Bypass & Rationale:</strong> {render_value(why_issue, "why_issue / false-positive rationale")}</p>
                    </div>
                </div>

                <!-- SECTION 3: PAYLOAD TO EXPLOIT -->
                <div class="section-block">
                    <h4 class="section-title">⚡ Payload to Exploit</h4>
                    <div class="payload-box">
                        {'<button class="copy-btn" onclick="copyText(this)">Copy Payload</button>' if payload else ''}
                        <pre class="code-block payload-text">{render_code_value(payload, "payload")}</pre>
                    </div>
                </div>

                <!-- SECTION 4: TEST BURPSUITE REQUEST -->
                <div class="section-block">
                    <h4 class="section-title">🧪 Test Burp Suite Request (Copy-Pasteable)</h4>
                    <div class="poc-container">
                        {'<button class="copy-btn" onclick="copyText(this)">Copy Burp Request</button>' if poc else ''}
                        <pre class="code-block poc-block">{render_code_value(poc, "poc / Burp Suite request")}</pre>
                    </div>
                </div>

                <!-- SECTION 5: EXPECTED BURPSUITE RESPONSE -->
                <div class="section-block">
                    <h4 class="section-title">📥 Expected Burp Suite Response</h4>
                    <div class="response-container">
                        {'<button class="copy-btn" onclick="copyText(this)">Copy Expected Response</button>' if expected_response else ''}
                        <pre class="code-block response-block">{render_code_value(expected_response, "expected_response")}</pre>
                    </div>
                </div>

                <!-- SECTION 6: EVIDENCE & LINK TO FILE / LINE NUMBER -->
                <div class="section-block">
                    <h4 class="section-title">📌 Evidence & Line-Anchored Link</h4>
                    <div class="evidence-box">
                        <p><strong>Evidence Reference Link:</strong> {f'<a href="{html.escape(file_link)}" target="_blank" class="file-link"><code>{html.escape(display_file)}#{html.escape(line_anchor_raw)}</code></a>' if display_file and line_anchor_raw else render_value("", "affected_file + line_anchor")}</p>
                        <div class="flow-meta" style="margin-top: 8px;">
                            <span><strong>Source:</strong> {f'<code>{html.escape(source)}</code>' if source else render_value("", "source")}</span>
                            <span><strong>Sink:</strong> {f'<code>{html.escape(sink)}</code>' if sink else render_value("", "sink")}</span>
                        </div>
                        <p style="margin-top: 8px;"><strong>Inter-Procedural CFG Trace:</strong></p>
                        <pre class="code-block" style="margin-top: 4px;">{render_code_value(data_flow, "data_flow / CFG trace")}</pre>
                        <p style="margin-top: 8px;"><strong>Raw Evidence Snippet:</strong></p>
                        <pre class="code-block">{render_code_value(evidence, "evidence snippet")}</pre>
                    </div>
                </div>

                <!-- SECTION 7: UNSAFE VS SAFE CODE COMPARISON -->
                <div class="section-block">
                    <h4 class="section-title">⚖️ Code Comparison: Unsafe vs Safe Line of Code</h4>
                    <div class="code-comparison">
                        <div class="code-box vuln-box">
                            <h4>❌ Unsafe / Vulnerable Code</h4>
                            <pre class="code-block">{render_code_value(vuln_code, "vulnerable_code")}</pre>
                        </div>
                        <div class="code-box safe-box">
                            <h4>✅ Safe / Remediated Implementation</h4>
                            <pre class="code-block">{render_code_value(safe_code, "safe_code")}</pre>
                        </div>
                    </div>
                </div>

                <!-- SECTION 8: WHOLE REMEDIATION PLAN -->
                <div class="section-block remediation-block">
                    <h4 class="section-title">🛠️ Whole Remediation Plan & Prevention Strategy</h4>
                    <div class="remediation-box">
                        <pre class="remediation-text">{render_code_value(remediation, "remediation plan")}</pre>
                    </div>
                </div>

            </div>
        </div>
        """
        findings_html_cards.append(card)

    cards_joined = "\n".join(findings_html_cards)

    # Data quality banner
    if total_count > 0 and incomplete_count > 0:
        quality_color = "#ef4444" if completeness_pct < 50 else ("#eab308" if completeness_pct < 80 else "#22c55e")
        quality_banner = f"""
        <div class="quality-banner" style="border-left-color: {quality_color};">
            <h3>⚠️ Data Quality Summary</h3>
            <div class="quality-grid">
                <div><strong>Complete Findings:</strong> <span style="color: #22c55e;">{complete_count}</span> / {total_count}</div>
                <div><strong>Incomplete Findings:</strong> <span style="color: #ef4444;">{incomplete_count}</span> / {total_count}</div>
                <div><strong>Evidence Completeness:</strong> <span style="color: {quality_color};">{completeness_pct}%</span></div>
                <div><strong>File Coverage:</strong> {visited_files} / {queued_files} ({coverage_pct}%)</div>
            </div>
            <p style="margin-top: 8px; color: #f87171; font-size: 13px;">⚠️ Findings marked INCOMPLETE have missing or placeholder evidence. These should be re-analyzed by the scanner before being treated as actionable results.</p>
        </div>
        """
    elif total_count > 0:
        quality_banner = f"""
        <div class="quality-banner" style="border-left-color: #22c55e;">
            <h3>✅ Data Quality Summary</h3>
            <div class="quality-grid">
                <div><strong>All Findings Complete:</strong> <span style="color: #22c55e;">{complete_count} / {total_count}</span></div>
                <div><strong>Evidence Completeness:</strong> <span style="color: #22c55e;">100%</span></div>
                <div><strong>File Coverage:</strong> {visited_files} / {queued_files} ({coverage_pct}%)</div>
            </div>
        </div>
        """
    else:
        quality_banner = ""

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
            --payload-purple: #a855f7;
            --warning-red: #ef4444;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1240px;
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
        .quality-banner {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-left: 4px solid;
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 24px;
        }}
        .quality-banner h3 {{
            margin: 0 0 12px 0;
            font-size: 16px;
        }}
        .quality-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
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
            width: 320px;
        }}
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .finding-card.finding-incomplete {{
            border-left: 4px solid var(--warning-red);
        }}
        .card-header {{
            padding: 16px 20px;
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
            flex-wrap: wrap;
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
        .incomplete-badge {{
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid var(--warning-red);
            color: #f87171;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }}
        .finding-id {{ color: var(--text-muted); font-family: monospace; }}
        .finding-title {{ font-size: 17px; font-weight: 600; }}
        .cwe-tag {{ background: #334155; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .card-body {{
            padding: 24px;
            border-top: 1px solid var(--border-color);
        }}
        .section-block {{
            margin-bottom: 24px;
        }}
        .section-title {{
            margin: 0 0 10px 0;
            color: var(--accent-blue);
            font-size: 16px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 4px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 12px;
            background: #0f172a;
            padding: 14px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }}
        .file-link {{
            color: var(--accent-blue);
            text-decoration: none;
        }}
        .file-link:hover {{
            text-decoration: underline;
        }}
        .info-box {{
            background: #0f172a;
            border-left: 4px solid var(--high-color);
            padding: 14px;
            border-radius: 4px;
            line-height: 1.6;
        }}
        .payload-box, .poc-container, .response-container {{
            position: relative;
        }}
        .payload-text {{
            color: var(--payload-purple);
            font-weight: bold;
        }}
        .evidence-box {{
            background: #0f172a;
            border-left: 4px solid var(--accent-blue);
            padding: 14px;
            border-radius: 4px;
        }}
        .remediation-box {{
            background: #0f172a;
            border-left: 4px solid var(--success-green);
            padding: 16px;
            border-radius: 4px;
            line-height: 1.6;
        }}
        .remediation-text {{
            font-family: inherit;
            white-space: pre-wrap;
            margin: 0;
            font-size: 14px;
            color: #e2e8f0;
        }}
        .flow-meta {{
            display: flex;
            gap: 24px;
            background: #1e293b;
            padding: 8px 12px;
            border-radius: 4px;
            flex-wrap: wrap;
        }}
        .code-block {{
            background: var(--code-bg);
            border: 1px solid var(--border-color);
            padding: 14px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: "Fira Code", Consolas, monospace;
            font-size: 13px;
            color: #e2e8f0;
            white-space: pre-wrap;
            margin: 4px 0 0 0;
        }}
        .code-comparison {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }}
        @media (max-width: 850px) {{
            .code-comparison {{
                grid-template-columns: 1fr;
            }}
        }}
        .vuln-box h4 {{ color: var(--critical-color); margin: 0 0 8px 0; }}
        .safe-box h4 {{ color: var(--success-green); margin: 0 0 8px 0; }}
        .copy-btn {{
            position: absolute;
            right: 10px;
            top: 10px;
            background: #334155;
            color: #fff;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            z-index: 10;
            transition: background 0.2s;
        }}
        .copy-btn:hover {{
            background: var(--accent-blue);
            color: #0f172a;
        }}
        .status-tag {{
            text-transform: uppercase;
            font-size: 11px;
            font-weight: bold;
            padding: 2px 6px;
            border-radius: 3px;
            background: #334155;
        }}
        .missing-marker {{
            color: #f87171;
            font-weight: bold;
            font-size: 13px;
            background: rgba(239, 68, 68, 0.1);
            padding: 2px 6px;
            border-radius: 3px;
            border: 1px dashed #ef4444;
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

        {quality_banner}

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
                {f'<button class="filter-btn" onclick="filterCompleteness(\'incomplete\')">⚠️ Incomplete ({incomplete_count})</button>' if incomplete_count > 0 else ''}
            </div>
            <input type="text" class="search-input" id="searchInput" onkeyup="searchFindings()" placeholder="Search findings, CWEs, files, payloads...">
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

        function filterCompleteness(filter) {{
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                const isComplete = card.getAttribute('data-complete');
                if (filter === 'incomplete' && isComplete === 'false') {{
                    card.style.display = 'block';
                }} else if (filter === 'complete' && isComplete === 'true') {{
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
            const orig = btn.innerText;
            btn.innerText = 'Copied!';
            setTimeout(() => btn.innerText = orig, 2000);
        }}
    </script>
</body>
</html>
"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] SAST Comprehensive HTML Report generated successfully: {output_path}")
    if incomplete_count > 0:
        print(f"[!] WARNING: {incomplete_count}/{total_count} findings are INCOMPLETE and shown with warning badges.")


def main():
    workspace_root = os.getcwd()
    sast_dir = os.path.join(workspace_root, ".sast-agent")
    findings_dir = os.path.join(sast_dir, "findings")
    jsonl_path = os.path.join(findings_dir, "findings.jsonl")
    state_path = os.path.join(sast_dir, "state", "scan-state.json")
    output_path = os.path.join(sast_dir, "reports", "index.html")

    findings = parse_findings(findings_dir, jsonl_path)
    scan_state = load_scan_state(state_path)
    render_html_report(findings, scan_state, output_path, sast_dir)


if __name__ == "__main__":
    main()
