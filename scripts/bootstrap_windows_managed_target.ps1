param(
    [string]$BackendUrl = "http://localhost:8000",
    [string]$AssetId = $env:COMPUTERNAME,
    [string]$InstallDir = "C:\ProgramData\ComplianceAgent",
    [string]$AgentVersion = "2026.09.09.1",
    [Parameter(Mandatory = $true)]
    [string]$IngestToken,
    [Parameter(Mandatory = $true)]
    [string]$CredentialId
)

$ErrorActionPreference = "Stop"

New-Item `
    -ItemType Directory `
    -Force `
    -Path $InstallDir |
    Out-Null

$Config = [ordered]@{
    asset_id = $AssetId
    backend_url = $BackendUrl.TrimEnd("/")
    os_family = "windows"
    agent_version = $AgentVersion
    expected_agent_version = $AgentVersion
    collector_manifest_version = $AgentVersion
    ingest_token = $IngestToken
    credential_id = $CredentialId
    installed_at = (
        Get-Date
    ).ToUniversalTime().ToString("o")
}

$Config |
    ConvertTo-Json -Depth 10 |
    Out-File `
        -FilePath "$InstallDir\agent-config.json.new" `
        -Encoding UTF8

$CollectorScript = @'
$ErrorActionPreference = "Stop"

$InstallDir = "C:\ProgramData\ComplianceAgent"
$ConfigPath = Join-Path $InstallDir "agent-config.json"
$ManifestPath = Join-Path $InstallDir "collector-manifest.json"
$CollectorPath = Join-Path $InstallDir "collect.ps1"
$OutFile = Join-Path $InstallDir "latest-collection.json"
$ResponseFile = Join-Path $InstallDir "last-submit-response.json"
$ErrorFile = Join-Path $InstallDir "last-submit-error.log"

$Config = Get-Content `
    -LiteralPath $ConfigPath `
    -Raw |
    ConvertFrom-Json

function Test-ServicePresence {
    param(
        [Parameter(Mandatory)]
        [string[]]$Patterns
    )

    $Services = @(
        Get-Service -ErrorAction SilentlyContinue |
            Where-Object {
                $ServiceName = $_.Name
                $DisplayName = $_.DisplayName

                @(
                    $Patterns |
                        Where-Object {
                            $ServiceName -match $_ -or
                            $DisplayName -match $_
                        }
                ).Count -gt 0
            } |
            Select-Object `
                Name,
                DisplayName,
                Status,
                StartType
    )

    return [ordered]@{
        present = [bool]($Services.Count -gt 0)
        services = $Services
    }
}

function Get-SafeLocalGroupMembers {
    param(
        [Parameter(Mandatory)]
        [string]$GroupName
    )

    try {
        return @(
            Get-LocalGroupMember `
                -Group $GroupName `
                -ErrorAction Stop |
                Select-Object `
                    Name,
                    ObjectClass,
                    PrincipalSource,
                    SID
        )
    }
    catch {
        return @()
    }
}

function Get-LocalIdentityInventory {
    $LocalUsers = @(
        Get-LocalUser -ErrorAction SilentlyContinue
    )

    $LocalGroups = @(
        Get-LocalGroup -ErrorAction SilentlyContinue
    )

    $GroupMembership = @{}
    $GroupDetails = @()

    foreach ($Group in $LocalGroups) {
        $Members = @(
            Get-SafeLocalGroupMembers `
                -GroupName $Group.Name
        )

        $GroupDetails += [ordered]@{
            name = $Group.Name
            description = $Group.Description
            sid = [string]$Group.SID
            members = @(
                $Members |
                    ForEach-Object {
                        [ordered]@{
                            name = $_.Name
                            object_class = [string]$_.ObjectClass
                            principal_source = [string]$_.PrincipalSource
                            sid = [string]$_.SID
                        }
                    }
            )
        }

        foreach ($Member in $Members) {
            $MemberName = [string]$Member.Name
            $LeafName = (
                $MemberName -split "\\"
            )[-1]

            foreach ($IdentityName in @(
                $MemberName.ToLowerInvariant(),
                $LeafName.ToLowerInvariant()
            )) {
                if (
                    -not $GroupMembership.ContainsKey(
                        $IdentityName
                    )
                ) {
                    $GroupMembership[$IdentityName] = @()
                }

                if (
                    $GroupMembership[$IdentityName] `
                        -notcontains $Group.Name
                ) {
                    $GroupMembership[$IdentityName] += $Group.Name
                }
            }
        }
    }

    $RdpEnabled = $false

    try {
        $TerminalServerSettings = Get-ItemProperty `
            -LiteralPath (
                "HKLM:\SYSTEM\CurrentControlSet\" +
                "Control\Terminal Server"
            ) `
            -Name "fDenyTSConnections" `
            -ErrorAction Stop

        $RdpEnabled = (
            $TerminalServerSettings.fDenyTSConnections -eq 0
        )
    }
    catch {
        $RdpEnabled = $false
    }

    $RdpService = Get-Service `
        -Name "TermService" `
        -ErrorAction SilentlyContinue

    $RdpOperational = (
        $RdpEnabled -and
        $null -ne $RdpService -and
        $RdpService.Status -eq "Running"
    )

    $SshService = Get-Service `
        -Name "sshd" `
        -ErrorAction SilentlyContinue

    $SshOperational = (
        $null -ne $SshService -and
        $SshService.Status -eq "Running"
    )

    $WinRmService = Get-Service `
        -Name "WinRM" `
        -ErrorAction SilentlyContinue

    $WinRmOperational = (
        $null -ne $WinRmService -and
        $WinRmService.Status -eq "Running"
    )

    $Users = @()

    foreach ($User in $LocalUsers) {
        $Username = [string]$User.Name
        $LookupName = $Username.ToLowerInvariant()
        $Groups = @(
            $GroupMembership[$LookupName] |
                Sort-Object -Unique
        )

        $IsAdministrator = (
            $Groups -contains "Administrators"
        )

        $CanUseRdp = (
            $RdpOperational -and
            (
                $IsAdministrator -or
                $Groups -contains "Remote Desktop Users"
            )
        )

        $Access = @()

        if ($CanUseRdp) {
            $Access += "RDP"
        }

        if ($SshOperational -and $User.Enabled) {
            $Access += "SSH"
        }

        if ($WinRmOperational -and $IsAdministrator) {
            $Access += "WinRM"
        }

        $Users += [ordered]@{
            username = $Username
            uid = [string]$User.SID
            sid = [string]$User.SID
            enabled = [bool]$User.Enabled
            description = $User.Description
            last_logon = if ($User.LastLogon) {
                $User.LastLogon.ToUniversalTime().ToString("o")
            }
            else {
                $null
            }
            password_required = [bool]$User.PasswordRequired
            password_expires = if ($User.PasswordExpires) {
                $User.PasswordExpires.ToUniversalTime().ToString("o")
            }
            else {
                $null
            }
            password_last_set = if ($User.PasswordLastSet) {
                $User.PasswordLastSet.ToUniversalTime().ToString("o")
            }
            else {
                $null
            }
            groups = $Groups
            access = @(
                $Access |
                    Sort-Object -Unique
            )
            account_type = "local"
        }
    }

    return [ordered]@{
        hostname = $env:COMPUTERNAME
        collected_at = (
            Get-Date
        ).ToUniversalTime().ToString("o")
        users = $Users
        service_accounts = @()
        groups = $GroupDetails
        access_services = [ordered]@{
            rdp = [ordered]@{
                enabled = [bool]$RdpEnabled
                service_running = [bool](
                    $null -ne $RdpService -and
                    $RdpService.Status -eq "Running"
                )
                operational = [bool]$RdpOperational
            }
            ssh = [ordered]@{
                installed = [bool]($null -ne $SshService)
                service_running = [bool]$SshOperational
                operational = [bool]$SshOperational
            }
            winrm = [ordered]@{
                installed = [bool]($null -ne $WinRmService)
                service_running = [bool]$WinRmOperational
                operational = [bool]$WinRmOperational
            }
        }
    }
}

function Get-WindowsOsInventory {
    $OperatingSystem = Get-CimInstance `
        -ClassName Win32_OperatingSystem `
        -ErrorAction Stop

    return [ordered]@{
        hostname = $env:COMPUTERNAME
        os_name = [string]$OperatingSystem.Caption
        os_version = [string]$OperatingSystem.Version
        kernel_version = (
            "{0} (Build {1})" -f `
                $OperatingSystem.Version,
                $OperatingSystem.BuildNumber
        )
        build_number = [string]$OperatingSystem.BuildNumber
        architecture = [string]$OperatingSystem.OSArchitecture
        collected_at = (
            Get-Date
        ).ToUniversalTime().ToString("o")
    }
}

function Get-WindowsResourceInventory {
    $ComputerSystem = Get-CimInstance `
        -ClassName Win32_ComputerSystem `
        -ErrorAction Stop

    $SystemDrive = [string]$env:SystemDrive
    $LogicalDisk = Get-CimInstance `
        -ClassName Win32_LogicalDisk `
        -Filter "DeviceID='$SystemDrive'" `
        -ErrorAction Stop

    $MemoryTotalMb = [math]::Round(
        [double]$ComputerSystem.TotalPhysicalMemory / 1MB,
        0
    )
    $DiskTotalGb = [math]::Round(
        [double]$LogicalDisk.Size / 1GB,
        0
    )

    return [ordered]@{
        hostname = $env:COMPUTERNAME
        cpu_cores = [int]$ComputerSystem.NumberOfLogicalProcessors
        memory_total_mb = [int64]$MemoryTotalMb
        disk_total = "{0}G" -f [int64]$DiskTotalGb
        root_disk_allocated = "{0}G" -f [int64]$DiskTotalGb
        system_drive = $SystemDrive
        disk_total_bytes = [int64]$LogicalDisk.Size
        disk_free_bytes = [int64]$LogicalDisk.FreeSpace
        collected_at = (
            Get-Date
        ).ToUniversalTime().ToString("o")
    }
}

function Get-WindowsPackageInventory {
    $RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $Seen = @{}
    $Packages = @()

    foreach ($RegistryPath in $RegistryPaths) {
        $Entries = @(
            Get-ItemProperty `
                -Path $RegistryPath `
                -ErrorAction SilentlyContinue
        )

        foreach ($Entry in $Entries) {
            $Name = [string]$Entry.DisplayName
            $Version = [string]$Entry.DisplayVersion

            if ([string]::IsNullOrWhiteSpace($Name)) {
                continue
            }

            $Key = (
                "{0}|{1}" -f $Name, $Version
            ).ToLowerInvariant()

            if ($Seen.ContainsKey($Key)) {
                continue
            }

            $Seen[$Key] = $true
            $Packages += [ordered]@{
                name = $Name
                installed_version = $Version
                latest_candidate = $Version
                update_available = "no"
                held = "no"
                publisher = [string]$Entry.Publisher
                install_date = [string]$Entry.InstallDate
            }
        }
    }

    return [ordered]@{
        hostname = $env:COMPUTERNAME
        package_count = $Packages.Count
        packages = @(
            $Packages |
                Sort-Object `
                    name,
                    installed_version
        )
        collected_at = (
            Get-Date
        ).ToUniversalTime().ToString("o")
    }
}

function Get-WindowsAvailableUpdates {
    try {
        $UpdateSession = New-Object `
            -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $SearchResult = $UpdateSearcher.Search(
            "IsInstalled=0 and IsHidden=0"
        )

        $Updates = @()

        foreach ($Update in $SearchResult.Updates) {
            $Updates += [ordered]@{
                name = [string]$Update.Title
                title = [string]$Update.Title
                kb_article_ids = @($Update.KBArticleIDs)
                severity = [string]$Update.MsrcSeverity
                reboot_required = [bool]$Update.RebootRequired
            }
        }

        return [ordered]@{
            hostname = $env:COMPUTERNAME
            query_succeeded = $true
            available_count = $Updates.Count
            updates = $Updates
            collected_at = (
                Get-Date
            ).ToUniversalTime().ToString("o")
        }
    }
    catch {
        return [ordered]@{
            hostname = $env:COMPUTERNAME
            query_succeeded = $false
            available_count = 0
            updates = @()
            error = $_.Exception.Message
            collected_at = (
                Get-Date
            ).ToUniversalTime().ToString("o")
        }
    }
}

$Manifest = $null

if (Test-Path -LiteralPath $ManifestPath) {
    try {
        $Manifest = Get-Content `
            -LiteralPath $ManifestPath `
            -Raw |
            ConvertFrom-Json
    }
    catch {
        $Manifest = $null
    }
}

$CollectorHash = (
    Get-FileHash `
        -LiteralPath $CollectorPath `
        -Algorithm SHA256
).Hash.ToLowerInvariant()

$ManifestPresent = $null -ne $Manifest
$ExpectedHash = if ($ManifestPresent) {
    [string]$Manifest.collector_sha256
}
else {
    ""
}

$DriftDetected = (
    -not $ManifestPresent -or
    [string]::IsNullOrWhiteSpace($ExpectedHash) -or
    $CollectorHash -ne $ExpectedHash.ToLowerInvariant()
)

$Lifecycle = [ordered]@{
    hostname = $env:COMPUTERNAME
    collected_at = (
        Get-Date
    ).ToUniversalTime().ToString("o")
    agent_version = [string]$Config.agent_version
    expected_agent_version = [string](
        $Config.expected_agent_version
    )
    agent_current = (
        [string]$Config.agent_version -eq
        [string]$Config.expected_agent_version
    )
    collector_manifest_version = if ($ManifestPresent) {
        [string]$Manifest.manifest_version
    }
    else {
        $null
    }
    manifest_present = [bool]$ManifestPresent
    collector_sha256 = $CollectorHash
}

$CollectorHealth = [ordered]@{
    hostname = $env:COMPUTERNAME
    collected_at = (
        Get-Date
    ).ToUniversalTime().ToString("o")
    manifest_present = [bool]$ManifestPresent
    expected_collector_sha256 = $ExpectedHash
    actual_collector_sha256 = $CollectorHash
    drift_detected = [bool]$DriftDetected
}

$Duo = Test-ServicePresence `
    -Patterns @("Duo")

$Automox = Test-ServicePresence `
    -Patterns @("amagent", "Automox")

$Trend = Test-ServicePresence `
    -Patterns @(
        "ds_agent",
        "Trend",
        "Deep Security"
    )

$IdentityInventory = Get-LocalIdentityInventory
$OsInventory = Get-WindowsOsInventory
$ResourceInventory = Get-WindowsResourceInventory
$PackageInventory = Get-WindowsPackageInventory
$AvailableUpdates = Get-WindowsAvailableUpdates

$Results = [ordered]@{
    asset_id = [string]$Config.asset_id
    os_family = "windows"
    collected_at = (
        Get-Date
    ).ToUniversalTime().ToString("o")
    collectors = [ordered]@{
        agent_lifecycle = [ordered]@{
            status = "completed"
            validated = [bool](
                $Lifecycle.agent_current -and
                $Lifecycle.manifest_present
            )
            raw = $Lifecycle
        }
        collector_health = [ordered]@{
            status = if ($DriftDetected) {
                "drift_detected"
            }
            else {
                "completed"
            }
            validated = [bool](-not $DriftDetected)
            raw = $CollectorHealth
        }
        iam_users = [ordered]@{
            status = "completed"
            validated = $true
            raw = $IdentityInventory
        }
        os_inventory = [ordered]@{
            status = "completed"
            validated = $true
            raw = $OsInventory
        }
        disk_usage = [ordered]@{
            status = "completed"
            validated = $true
            raw = $ResourceInventory
        }
        package_inventory = [ordered]@{
            status = "completed"
            validated = $true
            raw = $PackageInventory
        }
        available_updates = [ordered]@{
            status = if ($AvailableUpdates.query_succeeded) {
                "completed"
            }
            else {
                "failed"
            }
            validated = [bool]$AvailableUpdates.query_succeeded
            raw = $AvailableUpdates
        }
        duo_mfa_windows = [ordered]@{
            status = if ($Duo.present) {
                "present"
            }
            else {
                "missing"
            }
            validated = [bool]$Duo.present
            raw = $Duo
        }
        automox_windows_agent = [ordered]@{
            status = if ($Automox.present) {
                "present"
            }
            else {
                "missing"
            }
            validated = [bool]$Automox.present
            raw = $Automox
        }
        trend_micro_windows_agent = [ordered]@{
            status = if ($Trend.present) {
                "present"
            }
            else {
                "missing"
            }
            validated = [bool]$Trend.present
            raw = $Trend
        }
        open_ports_windows = [ordered]@{
            status = "completed"
            validated = $true
            raw = @(
                Get-NetTCPConnection `
                    -State Listen `
                    -ErrorAction SilentlyContinue |
                    Select-Object `
                        LocalAddress,
                        LocalPort,
                        OwningProcess
            )
        }
    }
}

$Json = $Results |
    ConvertTo-Json -Depth 20

$Json |
    Out-File `
        -LiteralPath $OutFile `
        -Encoding UTF8

try {
    $Headers = @{
        "X-Windows-Agent-Token" = [string]$Config.ingest_token
    }

    if ($Config.credential_id) {
        $Headers["X-Windows-Agent-Credential-ID"] = `
            [string]$Config.credential_id
    }

    $Response = Invoke-RestMethod `
        -Uri (
            "$($Config.backend_url)" +
            "/api/windows-agent/ingest"
        ) `
        -Method Post `
        -ContentType "application/json" `
        -Headers $Headers `
        -Body $Json `
        -TimeoutSec 60

    $Response |
        ConvertTo-Json -Depth 10 |
        Out-File `
            -LiteralPath $ResponseFile `
            -Encoding UTF8

    Remove-Item `
        -LiteralPath $ErrorFile `
        -Force `
        -ErrorAction SilentlyContinue
}
catch {
    $_ |
        Out-String |
        Out-File `
            -LiteralPath $ErrorFile `
            -Encoding UTF8

    throw
}

Write-Output "Collection written to $OutFile"
'@

$CollectorPath = Join-Path $InstallDir "collect.ps1"

$CollectorScript |
    Out-File `
        -LiteralPath $CollectorPath `
        -Encoding UTF8

$CollectorHash = (
    Get-FileHash `
        -LiteralPath $CollectorPath `
        -Algorithm SHA256
).Hash.ToLowerInvariant()

$Manifest = [ordered]@{
    manifest_version = $AgentVersion
    agent_version = $AgentVersion
    collector_sha256 = $CollectorHash
    collectors = @(
        "agent_lifecycle",
        "collector_health",
        "iam_users",
        "os_inventory",
        "disk_usage",
        "package_inventory",
        "available_updates",
        "duo_mfa_windows",
        "automox_windows_agent",
        "trend_micro_windows_agent",
        "open_ports_windows"
    )
    generated_at = (
        Get-Date
    ).ToUniversalTime().ToString("o")
}

$Manifest |
    ConvertTo-Json -Depth 10 |
    Out-File `
        -LiteralPath (
            Join-Path $InstallDir "collector-manifest.json"
        ) `
        -Encoding UTF8

$PendingConfigPath = Join-Path $InstallDir "agent-config.json.new"
$ConfigPath = Join-Path $InstallDir "agent-config.json"
$PreflightHeaders = @{
    "X-Windows-Agent-Token" = $IngestToken
    "X-Windows-Agent-Credential-ID" = $CredentialId
}
$PreflightBody = @{
    asset_id = $AssetId
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri ($BackendUrl.TrimEnd("/") + "/api/windows-agent/auth-check") `
    -Method Post `
    -ContentType "application/json" `
    -Headers $PreflightHeaders `
    -Body $PreflightBody `
    -TimeoutSec 30 |
    Out-Null

Move-Item `
    -LiteralPath $PendingConfigPath `
    -Destination $ConfigPath `
    -Force

$Action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument (
        "-NoProfile -ExecutionPolicy Bypass " +
        "-File `"$CollectorPath`""
    )

$Trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(5) `
    -RepetitionInterval (
        New-TimeSpan -Minutes 15
    )

$Principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -RunLevel Highest

& icacls.exe `
    $InstallDir `
    /inheritance:r `
    /grant:r `
    '*S-1-5-18:(OI)(CI)F' `
    '*S-1-5-32-544:(OI)(CI)F' |
    Out-Null

Register-ScheduledTask `
    -TaskName "ComplianceAgentCollector" `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Force |
    Out-Null

& $CollectorPath

Write-Output "Windows Compliance Agent installed."
Write-Output "InstallDir: $InstallDir"
Write-Output "Task: ComplianceAgentCollector"
