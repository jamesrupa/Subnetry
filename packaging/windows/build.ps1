# Build Subnetry.exe (PyInstaller) and the Windows installer (Inno Setup).
#
#   powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 [-Version 1.2.3]
#
# Needs: Python 3.10+ with the project's requirements and PyInstaller; Inno Setup 6 (installed with
# Chocolatey if missing). Output: dist\Subnetry\ and dist\Subnetry-Setup-windows-x64.exe
param([string]$Version = "")
$ErrorActionPreference = "Stop"
Set-Location (Resolve-Path "$PSScriptRoot\..\..")

if (-not $Version) {
    $Version = (Select-String -Path "subnetry\__init__.py" -Pattern '__version__ = "([^"]+)"').Matches[0].Groups[1].Value
}
Write-Host "==> Building Subnetry $Version"
python -m PyInstaller --noconfirm --clean packaging\subnetry.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

Write-Host "==> Smoke test"
$smokeData = Join-Path ([IO.Path]::GetTempPath()) ("subnetry-smoke-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $smokeData | Out-Null
$env:LOCALAPPDATA_BACKUP = $env:LOCALAPPDATA
$env:LOCALAPPDATA = $smokeData          # keep the smoke test's log/settings out of the build machine's profile
$env:SUBNETRY_REPORTS_DIR = Join-Path $smokeData "reports"
$proc = Start-Process -FilePath "dist\Subnetry\Subnetry.exe" -ArgumentList "--no-browser", "--port", "8799" -PassThru
$ok = $false
for ($i = 0; $i -lt 40 -and -not $ok; $i++) {
    Start-Sleep -Seconds 1
    try {
        $r = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:8799/api/subnet?q=10.0.0.5/22" -TimeoutSec 3
        $ok = $r.StatusCode -eq 200
    } catch { }
}
if ($ok) {
    $page = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:8799/" -TimeoutSec 5
    if ($page.Content -notmatch "<title>Subnetry</title>") { $ok = $false }
    Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:8799/api/dns/explainers" -TimeoutSec 5 | Out-Null
}
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
$env:LOCALAPPDATA = $env:LOCALAPPDATA_BACKUP
Remove-Item Env:\SUBNETRY_REPORTS_DIR
if (-not $ok) {
    Write-Host "Smoke test failed. Log:"
    Get-Content (Join-Path $smokeData "Subnetry\Subnetry.log") -ErrorAction SilentlyContinue
    throw "Smoke test failed"
}

Write-Host "==> Building the installer"
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    choco install innosetup -y --no-progress | Out-Host
    $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
& $iscc "/DAppVersion=$Version" "packaging\windows\subnetry.iss"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }
Write-Host "==> Done: dist\Subnetry-Setup-windows-x64.exe"
