$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

$PlatformFile = "dependency_check/0/dependency_check.json"
$S3Key = "dependency_check/0/dependency_check.json"

if (-not (Test-Path $PlatformFile)) {
    Write-Error "Platform file not found: $PlatformFile. Run export first."
}

$Bucket = $env:TESTABLE_METRICS_BUCKET
if (-not $Bucket) {
    Write-Error "Set TESTABLE_METRICS_BUCKET to the target S3 bucket name."
}

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Write-Error "AWS CLI not found. Install aws CLI to upload platform metrics."
}

$Destination = "s3://$Bucket/$S3Key"
Write-Host "==> Uploading $PlatformFile to $Destination"
aws s3 cp $PlatformFile $Destination --content-type "application/json"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> Verifying upload"
aws s3 ls $Destination
exit $LASTEXITCODE
