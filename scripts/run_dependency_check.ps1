$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

if (Get-Command mvn -ErrorAction SilentlyContinue) {
    $Maven = "mvn"
} elseif (Test-Path ".\mvnw.cmd") {
    $Maven = ".\mvnw.cmd"
} else {
    Write-Error "Maven not found. Install Maven 3.9+ or ensure mvnw.cmd is present."
}

Write-Host "==> Maven build + unit tests"
& $Maven -q clean test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> Dependency version lag probe (versions-maven-plugin)"
& $Maven -q versions:display-dependency-updates "-DoutputFile=target/dependency-updates.txt" "-DprocessDependencyManagement=false"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not $env:NVD_API_KEY) {
    Write-Warning "NVD_API_KEY not set. First scan may be slow or rate-limited. Get a free key at https://nvd.nist.gov/developers/request-an-api-key"
}

Write-Host "==> OWASP Dependency-Check SCA scan (first run may download NVD data; 10-30 min)"
& $Maven dependency-check:check "-Dformats=JSON,HTML"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> Export TESTABLE platform JSON"
python scripts/export_testable_dependency_check.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> Validate 100/100 metrics gate"
python scripts/validate_metrics_gate.py --require-100
exit $LASTEXITCODE
