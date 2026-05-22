param(
    [string]$BackendUrl = "http://localhost:8000",
    [string]$AssetId = $env:COMPUTERNAME,
    [string]$InstallDir = "C:\ProgramData\ComplianceAgent"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$Config = @{
    asset_id = $AssetId
    backend_url = $BackendUrl
    os_family = "windows"
    installed_at = (Get-Date).ToUniversalTime().ToString("o")
}

$Config | ConvertTo-Json -Depth 5 | Out-File -FilePath "$InstallDir\agent-config.json" -Encoding UTF8

$CollectorScript = @'
$ConfigPath = "C:\ProgramData\ComplianceAgent\agent-config.json"
$Config = Get-Content $ConfigPath | ConvertFrom-Json

function Test-ServicePresence {
    param([string[]]$Patterns)

    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $name = $_.Name
        $display = $_.DisplayName
        $Patterns | Where-Object { $name -match $_ -or $display -match $_ }
    }

    if ($services) {
        return @{
            present = $true
            services = $services | Select-Object Name, DisplayName, Status, StartType
        }
    }

    return @{
        present = $false
        services = @()
    }
}

$Results = [ordered]@{
    asset_id = $Config.asset_id
    os_family = "windows"
    collected_at = (Get-Date).ToUniversalTime().ToString("o")
    collectors = [ordered]@{}
}

$duo = Test-ServicePresence -Patterns @("Duo")
$automox = Test-ServicePresence -Patterns @("amagent", "Automox")
$trend = Test-ServicePresence -Patterns @("ds_agent", "Trend", "Deep Security")

$Results.collectors.duo_mfa_windows = @{
    status = if ($duo.present) { "present" } else { "missing" }
    validated = [bool]$duo.present
    raw = $duo
}

$Results.collectors.automox_windows_agent = @{
    status = if ($automox.present) { "present" } else { "missing" }
    validated = [bool]$automox.present
    raw = $automox
}

$Results.collectors.trend_micro_windows_agent = @{
    status = if ($trend.present) { "present" } else { "missing" }
    validated = [bool]$trend.present
    raw = $trend
}

$Results.collectors.open_ports_windows = @{
    status = "completed"
    validated = $true
    raw = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess
}

$OutFile = "C:\ProgramData\ComplianceAgent\latest-collection.json"
$Json = $Results | ConvertTo-Json -Depth 10
$Json | Out-File -FilePath $OutFile -Encoding UTF8

try {
    Invoke-RestMethod `
        -Uri "$($Config.backend_url)/api/windows-agent/ingest" `
        -Method Post `
        -ContentType "application/json" `
        -Body $Json `
        -TimeoutSec 30 | Out-File -FilePath "C:\ProgramData\ComplianceAgent\last-submit-response.json" -Encoding UTF8
} catch {
    $_ | Out-String | Out-File -FilePath "C:\ProgramData\ComplianceAgent\last-submit-error.log" -Encoding UTF8
}

Write-Output "Collection written to $OutFile"
'@

$CollectorScript | Out-File -FilePath "$InstallDir\collect.ps1" -Encoding UTF8

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\collect.ps1`""
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 15)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

Register-ScheduledTask `
    -TaskName "ComplianceAgentCollector" `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Force | Out-Null

Write-Output "Windows Compliance Agent installed."
Write-Output "InstallDir: $InstallDir"
Write-Output "Task: ComplianceAgentCollector"
