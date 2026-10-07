param(
    [string]$TargetPath = "."
)

$ErrorActionPreference = "SilentlyContinue"
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Enterprise SAST Pre-Scan Indexing Engine (Fast-Mode)   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Resolve absolute path
$targetDir = (Resolve-Path $TargetPath).Path
Write-Host "[*] Auditing target workspace: $targetDir" -ForegroundColor Yellow

# Output directory setup
$outputDir = Join-Path $targetDir ".sast-agent\output"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}
$progressFile = Join-Path $outputDir "scan-progress.md"
$indexJsonFile = Join-Path $outputDir "pre-scan-index.json"

# Ignored directories pattern
$excludeDirs = @("node_modules", "target", "build", "dist", ".next", ".git", ".vscode", ".sast-agent", "bin", "obj", "coverage", "vendor")
$excludeDirRegex = "\\(" + ($excludeDirs -join "|") + ")\\"

# Gather source files (filtering out ignored directories)
Write-Host "[*] Discovering source files..." -ForegroundColor Gray
$allFiles = Get-ChildItem -Path $targetDir -Recurse -File | Where-Object {
    $_.FullName -notmatch $excludeDirRegex -and
    $_.Extension -match "\.(java|js|ts|tsx|jsx|py|go|cs|php|rb|sql|xml|yml|yaml|properties|json)$"
}

# 1. Detect Ecosystem
$isJava = ($allFiles | Where-Object { $_.Extension -eq ".java" }).Count -gt 0
$isNode = ($allFiles | Where-Object { $_.Extension -match "\.(js|ts|tsx|jsx)$" }).Count -gt 0
$ecosystem = if ($isJava -and $isNode) { "Polyglot (Java + Node.js/TypeScript)" } elseif ($isJava) { "Java / JVM (Spring Boot)" } elseif ($isNode) { "Node.js / TypeScript" } else { "Generic Web / Scripting" }
Write-Host "[+] Ecosystem detected: $ecosystem" -ForegroundColor Green

# 2. Fast Pattern Search for Entry Points
Write-Host "[*] Indexing entry points (REST, MVC, Queues, Schedulers)..." -ForegroundColor Gray
$entryPointPatterns = @(
    "@RestController", "@Controller", "@RequestMapping", "@GetMapping", "@PostMapping", "@PutMapping", "@DeleteMapping",
    "@KafkaListener", "@RabbitListener", "@JmsListener", "@Scheduled",
    "app\.get\(", "app\.post\(", "app\.put\(", "app\.delete\(", "router\.get\(", "router\.post\(",
    "@Controller\(", "@Get\(", "@Post\(", "@Put\(", "@Delete\("
)
$entryRegex = ($entryPointPatterns -join "|")

$entryMatches = @()
$candidateFiles = $allFiles | Where-Object { $_.FullName -notmatch "\\(test|tests|mocks|fixtures)\\" }
foreach ($file in $candidateFiles) {
    $matchesInFile = Select-String -Path $file.FullName -Pattern $entryRegex -SimpleMatch:$false
    foreach ($m in $matchesInFile) {
        $entryMatches += [PSCustomObject]@{
            File = $file.FullName.Replace($targetDir, "").TrimStart("\/")
            Line = $m.LineNumber
            Code = $m.Line.Trim()
        }
    }
}

# 3. Fast Pattern Search for Dangerous Sinks
Write-Host "[*] Locating dangerous sink signatures (SQL, OS Cmd, Eval, SSTI, Crypto)..." -ForegroundColor Gray
$sinkPatterns = @(
    "createNativeQuery", "createQuery", "Statement\.executeQuery", "JdbcTemplate", "FromSqlRaw", "\$queryRawUnsafe",
    "Runtime\.getRuntime\(\)\.exec", "ProcessBuilder", "child_process", "execSync", "spawn\(",
    "eval\(", "new Function\(", "ScriptEngine",
    "SecretKeySpec", "createCipheriv", "createHmac", "AES/ECB", "java\.util\.Random",
    "whsec_", "sk_live_", "AKIA[0-9A-Z]{16}", "AIza[0-9A-Za-z-_]{35}",
    "jwt\.sign", "jwt\.verify", "jwt\.decode", "parseExpression"
)
$sinkRegex = ($sinkPatterns -join "|")

$sinkMatches = @()
foreach ($file in $candidateFiles) {
    $matchesInFile = Select-String -Path $file.FullName -Pattern $sinkRegex -SimpleMatch:$false
    foreach ($m in $matchesInFile) {
        $sinkMatches += [PSCustomObject]@{
            File = $file.FullName.Replace($targetDir, "").TrimStart("\/")
            Line = $m.LineNumber
            Code = $m.Line.Trim()
        }
    }
}

# 4. Generate scan-progress.md
Write-Host "[*] Generating pre-scan inventory checklist in scan-progress.md..." -ForegroundColor Gray

$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# SAST Scan Progress & Attack Surface Inventory")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("**Target Workspace**: $targetDir")
[void]$sb.AppendLine("**Detected Ecosystem**: $ecosystem")
[void]$sb.AppendLine("**Discovered Entry Points**: $($entryMatches.Count)")
[void]$sb.AppendLine("**Candidate Sinks Flagged**: $($sinkMatches.Count)")
[void]$sb.AppendLine("**Pre-Scan Status**: Ready for LLM Deep Taint Verification")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("---")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## 1. Discovered HTTP Controllers & Entry Points ($($entryMatches.Count))")

if ($entryMatches.Count -eq 0) {
    [void]$sb.AppendLine("- [ ] No explicit entry point annotations found (Inspect main router manually)")
} else {
    foreach ($entry in ($entryMatches | Select-Object -First 50)) {
        $cleanRel = $entry.File.Replace('\', '/')
        $cleanAbs = $targetDir.Replace('\', '/') + "/" + $cleanRel
        $codeSnippet = $entry.Code.Replace('`', '')
        [void]$sb.AppendLine("- [ ] [`$($entry.File):$($entry.Line)`](file:///$cleanAbs#L$($entry.Line)) - ``$codeSnippet``")
    }
    if ($entryMatches.Count -gt 50) {
        [void]$sb.AppendLine("- [ ] ... and $($entryMatches.Count - 50) more entry points discovered in index")
    }
}

[void]$sb.AppendLine("")
[void]$sb.AppendLine("---")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## 2. Flagged Dangerous Sink Signatures ($($sinkMatches.Count))")

if ($sinkMatches.Count -eq 0) {
    [void]$sb.AppendLine("- [ ] No direct dangerous sink signatures identified via heuristic pass")
} else {
    foreach ($sink in ($sinkMatches | Select-Object -First 50)) {
        $cleanRel = $sink.File.Replace('\', '/')
        $cleanAbs = $targetDir.Replace('\', '/') + "/" + $cleanRel
        $codeSnippet = $sink.Code.Replace('`', '')
        [void]$sb.AppendLine("- [ ] [`$($sink.File):$($sink.Line)`](file:///$cleanAbs#L$($sink.Line)) - ``$codeSnippet``")
    }
    if ($sinkMatches.Count -gt 50) {
        [void]$sb.AppendLine("- [ ] ... and $($sinkMatches.Count - 50) more sinks discovered in index")
    }
}

[void]$sb.AppendLine("")
[void]$sb.AppendLine("---")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## 3. Specialized Scan Checkpoints")
[void]$sb.AppendLine("- [ ] Injection & Persistence Audit (`@sast-injection`)")
[void]$sb.AppendLine("- [ ] Authentication, Token & BOLA Audit (`@sast-auth`)")
[void]$sb.AppendLine("- [ ] Hardcoded Secrets & Keys Audit (`@sast-secrets`)")
[void]$sb.AppendLine("- [ ] Infrastructure as Code & Container Audit (`@sast-iac`)")
[void]$sb.AppendLine("- [ ] Deep Taint Propagation & False-Positive Elimination (`@sast-verifier`)")
[void]$sb.AppendLine("")

[System.IO.File]::WriteAllText($progressFile, $sb.ToString(), [System.Text.Encoding]::UTF8)

# 5. Output structured JSON for machine integration
$indexObject = @{
    targetDirectory = $targetDir
    ecosystem = $ecosystem
    scannedAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    entryPointsCount = $entryMatches.Count
    sinksCount = $sinkMatches.Count
    entryPoints = $entryMatches
    sinks = $sinkMatches
}
$jsonString = $indexObject | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($indexJsonFile, $jsonString, [System.Text.Encoding]::UTF8)

$stopwatch.Stop()
$elapsed = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "[+] Pre-scan index generated in $elapsed seconds!" -ForegroundColor Green
Write-Host "    - Checklist written to: .sast-agent/output/scan-progress.md" -ForegroundColor White
Write-Host "    - Structured index in:  .sast-agent/output/pre-scan-index.json" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "`nNEXT STEP: Open GitHub Copilot Chat and type /scan or @sast-orchestrator." -ForegroundColor Cyan
Write-Host "The agent will read the pre-computed index instantly without wasting tokens searching!`n" -ForegroundColor Cyan
