# SecAudit Platform — Windows Server 2025 host audit
# Output: RULExxx= PASS|FAIL: actual=...; expected(OPERATOR)=...
$ErrorActionPreference = 'Continue'

$script:secaudit_reg_types = @{
    REG_SZ        = 1
    REG_EXPAND_SZ = 2
    REG_BINARY    = 3
    REG_DWORD     = 4
    REG_MULTI_SZ  = 7
}

$script:secaudit_wellknown_sids = @{
    'S-1-0-0' = 'Nobody'
    'S-1-1-0' = 'Everyone'
    'S-1-2-0' = 'Local'
    'S-1-2-1' = 'Console Logon'
    'S-1-3-0' = 'Creator Owner'
    'S-1-3-1' = 'Creator Group'
    'S-1-3-4' = 'Owner Rights'
    'S-1-5-1' = 'Dialup'
    'S-1-5-3' = 'Batch'
    'S-1-5-4' = 'Interactive'
    'S-1-5-6' = 'Service'
    'S-1-5-7' = 'Anonymous'
    'S-1-5-8' = 'Proxy'
    'S-1-5-9' = 'Enterprise Domain Controllers'
    'S-1-5-10' = 'Principal Self'
    'S-1-5-11' = 'Authenticated Users'
    'S-1-5-12' = 'Restricted Code'
    'S-1-5-13' = 'Terminal Server Users'
    'S-1-5-14' = 'Remote Interactive Logon'
    'S-1-5-15' = 'This Organization'
    'S-1-5-18' = 'Local System'
    'S-1-5-19' = 'Local Service'
    'S-1-5-20' = 'Network Service'
    'S-1-5-32-544' = 'Administrators'
    'S-1-5-32-545' = 'Users'
    'S-1-5-32-546' = 'Guests'
    'S-1-5-32-547' = 'Power Users'
    'S-1-5-32-548' = 'Account Operators'
    'S-1-5-32-549' = 'Server Operators'
    'S-1-5-32-550' = 'Print Operators'
    'S-1-5-32-551' = 'Backup Operators'
    'S-1-5-32-552' = 'Replicators'
    'S-1-5-32-555' = 'Remote Desktop Users'
    'S-1-5-32-556' = 'Network Configuration Operators'
    'S-1-5-32-557' = 'Incoming Forest Trust Builders'
    'S-1-5-32-558' = 'Performance Monitor Users'
    'S-1-5-32-559' = 'Performance Log Users'
    'S-1-5-32-560' = 'Windows Authorization Access Group'
    'S-1-5-32-561' = 'Terminal Server License Servers'
    'S-1-5-32-562' = 'Distributed COM Users'
    'S-1-5-32-569' = 'Cryptographic Operators'
    'S-1-5-32-573' = 'Event Log Readers'
    'S-1-5-32-574' = 'Certificate Service DCOM Access'
    'S-1-5-32-575' = 'RDS Remote Access Servers'
    'S-1-5-32-576' = 'RDS Endpoint Servers'
    'S-1-5-32-577' = 'RDS Management Servers'
    'S-1-5-32-578' = 'Hyper-V Administrators'
    'S-1-5-32-579' = 'Access Control Assistance Operators'
    'S-1-5-32-580' = 'Remote Management Users'
    'S-1-5-32-583' = 'Device Owners'
    'S-1-5-80-0' = 'All Services'
    'S-1-5-83-0' = 'Virtual Machines'
    'S-1-5-90-0' = 'Window Manager\Window Manager Group'
    'S-1-5-113' = 'Local Account'
    'S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420' = 'NT SERVICE\WdiServiceHost'
}

function secaudit_temp_path {
    param([Parameter(Mandatory)][string]$Prefix, [string]$Extension = '.tmp')
    $dir = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { Join-Path $env:windir 'Temp' } else { $env:TEMP }
    Join-Path $dir ('{0}_{1}{2}' -f $Prefix, (Get-Date).ToFileTime(), $Extension)
}

function secaudit_parse_ini {
    param([Parameter(Mandatory)][string]$Path)
    $ini = @{}; $section = 'NO_SECTION'; $ini[$section] = @{}
    foreach ($line in Get-Content -LiteralPath $Path -ErrorAction Stop) {
        switch -Regex ($line) {
            '^\s*\[(.+)\]' {
                $section = $Matches[1].Trim()
                if (-not $ini.ContainsKey($section)) { $ini[$section] = @{} }
                }
            '^\s*([^#;].+?)\s*=\s*(.*)$' {
                $ini[$section][$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
    }
    $ini
}

function secaudit_cim {
    param([Parameter(Mandatory)][string]$ClassName, [string]$Filter)
    try {
        @(Get-CimInstance -ClassName $ClassName -Filter $Filter -ErrorAction Stop)
    } catch {
        @(Get-WmiObject -Class $ClassName -Filter $Filter -ErrorAction Stop)
    }
}

function secaudit_export_secedit {
    $path = secaudit_temp_path -Prefix 'secedit' -Extension '.ini'
    try {
        $proc = Start-Process -FilePath "$env:windir\System32\secedit.exe" `
            -ArgumentList @('/export', '/cfg', $path) -Wait -PassThru -WindowStyle Hidden
        if ($proc.ExitCode -notin 0, $null) {
            throw "secedit export failed with exit code $($proc.ExitCode)"
        }
        if (-not (Test-Path -LiteralPath $path)) {
            throw "secedit output not found: $path"
        }
        secaudit_parse_ini -Path $path
    } finally {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function secaudit_collect_auditpol {
    $path = secaudit_temp_path -Prefix 'auditpol' -Extension '.txt'
    try {
        $proc = Start-Process -FilePath "$env:windir\System32\auditpol.exe" `
            -ArgumentList @('/get', '/category:*') `
            -RedirectStandardOutput $path -Wait -PassThru -WindowStyle Hidden
        if ($proc.ExitCode -notin 0, $null) {
            throw "auditpol failed with exit code $($proc.ExitCode)"
        }

        $markers = @(
            'Success and Failure', 'No Auditing', 'Success', 'Failure',
            'Успех и отказ', 'Успех и сбой', 'Нет аудита', 'Без аудита', 'Успех', 'Сбой', 'Отказ'
        )
        $entries = @()
        foreach ($line in Get-Content -LiteralPath $path -Encoding Oem -ErrorAction Stop) {
            $pos = -1
            foreach ($marker in $markers) {
                $idx = $line.IndexOf($marker)
                if ($idx -gt 0) { $pos = $idx; break }
                }
            if ($pos -gt 0) {
                $entries += @{
                    Policy  = $line.Substring(0, $pos).Trim()
                    Setting = $line.Substring($pos).Trim()
                }
            }
        }
        $entries
    } finally {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function secaudit_reg_provider {
    $reg = Get-WmiObject -List -Namespace 'root\default' | Where-Object { $_.Name -eq 'StdRegProv' }
    if (-not $reg) { throw 'StdRegProv is unavailable' }
    $reg
}

function secaudit_reg_type_name {
    param([int]$TypeId)
    foreach ($e in $script:secaudit_reg_types.GetEnumerator()) {
        if ($e.Value -eq $TypeId) { return [string]$e.Key }
    }
    [string]$TypeId
}

function secaudit_reg_read {
    param($Reg, $Hive, [string]$Key, [string]$Name, [int]$Type, [switch]$RawBinary)
    switch ($Type) {
        $script:secaudit_reg_types.REG_SZ {
            $Reg.GetStringValue($Hive, $Key, $Name).sValue
        }
        $script:secaudit_reg_types.REG_EXPAND_SZ {
            $Reg.GetExpandedStringValue($Hive, $Key, $Name).sValue
        }
        $script:secaudit_reg_types.REG_BINARY {
            $res = $Reg.GetBinaryValue($Hive, $Key, $Name)
            if ($RawBinary) { return $res.uValue }
            (@($res.uValue) | ForEach-Object { '{0:x2}' -f $_ }) -join ''
        }
        $script:secaudit_reg_types.REG_DWORD {
            $Reg.GetDwordValue($Hive, $Key, $Name).uValue
        }
        $script:secaudit_reg_types.REG_MULTI_SZ {
            $res = $Reg.GetMultiStringValue($Hive, $Key, $Name)
            if ($res.sValue -is [string[]]) { ($res.sValue -join ', ') } else { $res.sValue }
        }
        default { $null }
    }
}

function secaudit_reg_enum_values {
    param($Reg, $Hive, [string]$Key)
    $values = $Reg.EnumValues($Hive, $Key)
    if ($values.ReturnValue -ne 0 -or $null -eq $values.sNames) { return @() }
    $out = @()
    for ($i = 0; $i -lt @($values.sNames).Count; $i++) {
        $out += [pscustomobject]@{ Name = $values.sNames[$i]; Type = $values.Types[$i] }
    }
    $out
}

function secaudit_reg_enum_keys {
    param($Reg, $Hive, [string]$Key)
    if ($Key -and $Key.EndsWith('\')) { $Key = $Key.TrimEnd('\') }
    $keys = $Reg.EnumKey($Hive, $(if ($Key) { $Key } else { '' }))
    if ($keys.ReturnValue -ne 0 -or -not $keys.sNames) { return @() }
    foreach ($name in @($keys.sNames)) {
        if ($Key) { "$Key\$name" } else { $name }
    }
}

function secaudit_reg_tree {
    param($Reg, $Hive, [string]$Key, $Bucket, [switch]$Recursive)
    foreach ($v in @(secaudit_reg_enum_values -Reg $Reg -Hive $Hive -Key $Key)) {
        $val = secaudit_reg_read -Reg $Reg -Hive $Hive -Key $Key -Name $v.Name -Type $v.Type
        $vk = 'Val_' + $(if ([string]::IsNullOrEmpty($v.Name)) { 'Default' } else { $v.Name })
        $Bucket[$vk] = @{
            ValueType = (secaudit_reg_type_name -TypeId $v.Type)
            Value     = $val
        }
    }
    if (-not $Recursive) { return }
    foreach ($childPath in @(secaudit_reg_enum_keys -Reg $Reg -Hive $Hive -Key $Key)) {
        $child = ($childPath -split '\')[-1]
        if (-not $Bucket.ContainsKey($child)) { $Bucket[$child] = @{} }
        secaudit_reg_tree -Reg $Reg -Hive $Hive -Key $childPath -Bucket $Bucket[$child] -Recursive
    }
}

function secaudit_reg_mount {
    param($Root, [string]$LogicalPath, $Reg, $Hive, [string]$Key, [switch]$Recursive)
    if ($LogicalPath.Contains('\')) {
        $head = $LogicalPath.Substring(0, $LogicalPath.IndexOf('\'))
        $tail = $LogicalPath.Substring($LogicalPath.IndexOf('\') + 1)
        if (-not $Root.ContainsKey($head)) { $Root[$head] = @{} }
        secaudit_reg_mount -Root $Root[$head] -LogicalPath $tail -Reg $Reg -Hive $Hive -Key $Key -Recursive:$Recursive
        return
    }
    if (-not $Root.ContainsKey($LogicalPath)) { $Root[$LogicalPath] = @{} }
    secaudit_reg_tree -Reg $Reg -Hive $Hive -Key $Key -Bucket $Root[$LogicalPath] -Recursive:$Recursive
}

function secaudit_collect_secedit {
    $ErrorActionPreference = 'Stop'
    $ini = secaudit_export_secedit
    $secedit = @{}
    foreach ($sectionName in @($ini.Keys)) {
        $secedit[$sectionName] = @{}
        $section = $ini[$sectionName]
        if ($section -isnot [System.Collections.IDictionary]) { continue }
        foreach ($policy in @($section.Keys)) {
            $raw = [string]$section[$policy]
            if ($sectionName -like 'Privilege Rights') {
                $parts = @(
                    $raw.Replace('*', '') -split ',' |
                        ForEach-Object { $_.Trim() } |
                        Where-Object { $_ }
                )
                for ($i = 0; $i -lt $parts.Count; $i++) {
                    if ($script:secaudit_wellknown_sids.ContainsKey($parts[$i])) {
                        $parts[$i] = $script:secaudit_wellknown_sids[$parts[$i]]
                    }
                }
                $secedit[$sectionName][$policy] = ($parts -join ',')
            } else {
                $secedit[$sectionName][$policy] = $raw
            }
        }
    }
    @{
        Auditpol = secaudit_collect_auditpol
        Secedit  = $secedit
    }
}

function secaudit_collect_accounts {
    $ErrorActionPreference = 'Stop'
    $computer = [string]$env:COMPUTERNAME
    $select = @('PSComputerName','Name','Status','Disabled','AccountType','Lockout','PasswordRequired','PasswordChangeable','SID','Caption')
    $accounts = @()
    try {
        $accounts = @(secaudit_cim -ClassName Win32_UserAccount -Filter "LocalAccount='True' AND (SID LIKE 'S-1-5-21-%-500' OR SID LIKE 'S-1-5-21-%-501')")
    } catch { }
    if ($accounts.Count -eq 0) {
        $accounts = @(
        Get-WmiObject -Class Win32_UserAccount -ErrorAction Stop |
            Where-Object {
                    $_.Domain -eq $computer -and (
                        $_.SID -like 'S-1-5-21-*-500' -or $_.SID -like 'S-1-5-21-*-501'
                )
                }
    )
}
    $result = @{}
    foreach ($account in @($accounts | Select-Object $select)) {
        if ($account.SID -like 'S-1-5-21-*-501') {
            $result['LocalGuest'] = $account
        } else {
            $result['LocalAdministrator'] = $account
        }
    }
    $result
}

function secaudit_collect_registry {
    # Collector key in rules remains "registry10".
    $ErrorActionPreference = 'Stop'
    $hive = 2147483650 # HKLM
    $reg = secaudit_reg_provider
    $paths = @(
        @{ Path = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Recursive = $true },
        @{ Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"; Recursive = $true },
        @{ Path = "SOFTWARE\Microsoft\WcmSvc"; Recursive = $true },
        @{ Path = "SOFTWARE\Policies"; Recursive = $true },
        @{ Path = "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Control\Session Manager"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Control\Terminal Server"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Control\Lsa"; Recursive = $true },
        @{ Path = "SYSTEM\CurrentControlSet\Control\Print\Providers"; Recursive = $true },
        @{ Path = "SYSTEM\CurrentControlSet\Policies\EarlyLaunch"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Policies\Microsoft\FVE"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg"; Recursive = $true },
        @{ Path = "SYSTEM\CurrentControlSet\Services\browser"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\BthHFSrv"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\bthserv"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\Eventlog\Security"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\FTPSVC"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\HomeGroupListener"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\HomeGroupProvider"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\icssvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\IISADMIN"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\irmon"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\LanmanServer"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\LDAP"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\lfsvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\lltdsvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\LxssManager"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\MapsBroker"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\MSiSCSI"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\p2pimsvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\p2psvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\PNRPAutoReg"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\PNRPsvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\RasAuto"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\RasMan\Parameters"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\RemoteAccess"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\RemoteRegistry"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\RpcLocator"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\SessionEnv"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\SharedAccess"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\simptcp"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\SNMP"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\SSDPSRV"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\TermService"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\UmRdpService"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\upnphost"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\W3SVC"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\Wecsvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\wercplsupport"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\WerSvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\WinRM"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\WMSvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\XblAuthManager"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\XblGameSave"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\mrxsmb10"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\NTDS"; Recursive = $true },
        @{ Path = "SYSTEM\CurrentControlSet\Services\ehSched"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\ehRecvr"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\idsvc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\TlntSvr"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\Mcx2Svc"; Recursive = $false },
        @{ Path = "SYSTEM\CurrentControlSet\Services\XboxNetApiSvc"; Recursive = $false }
    )
    $deadline = (Get-Date).AddSeconds(120)
    $root = @{ ComputerName = 'localhost' }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        foreach ($item in $paths) {
            if ((Get-Date) -gt $deadline) {
                throw 'incomplete_scan: registry HKLM enumeration timed out after 120s'
            }
            secaudit_reg_mount -Root $root -LogicalPath ("HKLM\" + $item.Path) `
                -Reg $reg -Hive $hive -Key $item.Path -Recursive:([bool]$item.Recursive)
        }
    } finally {
        $ErrorActionPreference = $prev
    }
    $root
}

function secaudit_hku_eval {
    param([string]$Template, $Value)
    $expr = $Template.Replace('<val>', [string]$Value).Trim()
    if ($expr -match '^\[int\](.+?)\s+-eq\s+(-?\d+)$') { return ([int]$Matches[1] -eq [int]$Matches[2]) }
    if ($expr -match '^\[int\](.+?)\s+-ne\s+(-?\d+)$') { return ([int]$Matches[1] -ne [int]$Matches[2]) }
    if ($expr -match '^(.+?)\s+-eq\s+(.+)$') { return ([string]$Matches[1] -eq [string]$Matches[2]) }
    if ($expr -match '^(.+?)\s+-ne\s+(.+)$') { return ([string]$Matches[1] -ne [string]$Matches[2]) }
    if ($expr -match '^(.+?)\s+-ge\s+(-?\d+)$') { return ([double]$Matches[1] -ge [double]$Matches[2]) }
    if ($expr -match '^(.+?)\s+-le\s+(-?\d+)$') { return ([double]$Matches[1] -le [double]$Matches[2]) }
    $false
}

function secaudit_collect_hku {
    $ErrorActionPreference = 'Stop'
    $hive = 2147483651 # HKU
    $checks = @(
        @{
            Path = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
            Key  = "SaveZoneInformation"
            Rule = '<val> -eq 0'
            AcceptDefault = $true
        },
        @{
            Path = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
            Key  = "ScanWithAntiVirus"
            Rule = '<val> -eq 1'
            AcceptDefault = $false
        },
        @{
            Path = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            Key  = "NoInplaceSharing"
            Rule = '<val> -eq 1'
            AcceptDefault = $false
        },
        @{
            Path = "\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0"
            Key  = "NoImplicitFeedback"
            Rule = '<val> -eq 1'
            AcceptDefault = $false
        },
        @{
            Path = "\Software\Policies\Microsoft\Windows\CloudContent"
            Key  = "ConfigureWindowsSpotlight"
            Rule = '<val> -eq 0'
            AcceptDefault = $false
        },
        @{
            Path = "\Software\Policies\Microsoft\Windows\CloudContent"
            Key  = "DisableThirdPartySuggestions"
            Rule = '<val> -eq 1'
            AcceptDefault = $false
        },
        @{
            Path = "\Software\Policies\Microsoft\Windows\CloudContent"
            Key  = "DisableWindowsSpotlightFeatures"
            Rule = '<val> -eq 1'
            AcceptDefault = $false
        },
        @{
            Path = "\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
            Key  = "ScreenSaveActive"
            Rule = '<val> -eq 1'
            AcceptDefault = $false
        },
        @{
            Path = "\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
            Key  = "ScreenSaverIsSecure"
            Rule = '<val> -eq 1'
            AcceptDefault = $false
        },
        @{
            Path = "\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
            Key  = "ScreenSaveTimeOut"
            Rule = '(<val> -gt 0) -and (<val> -le 900)'
            AcceptDefault = $false
        },
        @{
            Path = "\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
            Key  = "SCRNSAVE.EXE"
            Rule = '"<val>" -like "*.scr"'
            AcceptDefault = $false
        },
        @{
            Path = "\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
            Key  = "NoToastApplicationNotificationOnLockScreen"
            Rule = '<val> -eq 1'
            AcceptDefault = $false
        },
        @{
            Path = "\SOFTWARE\Policies\Microsoft\Windows\Installer"
            Key  = "AlwaysInstallElevated"
            Rule = '<val> -eq 0'
            AcceptDefault = $true
        },
        @{
            Path = "\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer"
            Key  = "PreventCodecDownload"
            Rule = '<val> -eq 1'
            AcceptDefault = $false
        }
    )
    $reg = secaudit_reg_provider
    $users = @(
        @($reg.EnumKey($hive, '').sNames) |
            Where-Object { $_ -and $_.Length -gt 8 -and $_ -notlike '*_Classes' }
    )
    $deadline = (Get-Date).AddSeconds(90)
    $result = @{}
    foreach ($check in $checks) {
        if ((Get-Date) -gt $deadline) {
            throw 'incomplete_scan: HKU policy enumeration timed out after 90s'
        }
        $failed = New-Object System.Collections.Generic.List[string]
        foreach ($sid in $users) {
            $keyPath = $sid + $check.Path
            $values = $reg.EnumValues($hive, $keyPath)
            $fail = $false
            if ($values.sNames -and $values.sNames.Contains($check.Key)) {
                $idx = $values.sNames.IndexOf($check.Key)
                $type = $values.Types[$idx]
                $raw = ($type -eq $script:secaudit_reg_types.REG_BINARY)
                $val = secaudit_reg_read -Reg $reg -Hive $hive -Key $keyPath -Name $check.Key -Type $type -RawBinary:$raw
                if (-not (secaudit_hku_eval -Template $check.Rule -Value $val)) { $fail = $true }
            } elseif (-not $check.AcceptDefault) {
                $fail = $true
            }
            if ($fail) { [void]$failed.Add($sid) }
        }
        $result[$check.Key] = @{
            Path       = ('HKU:SID\' + $check.Path + '\' + $check.Key)
            Rule       = $check.Rule
            Result     = [int]$failed.Count
            FailedSids = @($failed)
        }
    }
    $result
}

function secaudit_jsonpath {
    param($Data, [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path.Trim()
    if ($p.StartsWith('$.')) { $p = $p.Substring(2) }
    elseif ($p.StartsWith('$')) { $p = $p.Substring(1).TrimStart('.') }

    if ($p.StartsWith('Auditpol.[?(') -or $p.StartsWith('Auditpol[?(')) {
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($m in [regex]::Matches($p, "Policy=='([^']+)'")) { [void]$names.Add($m.Groups[1].Value) }
        foreach ($m in [regex]::Matches($p, 'Policy=="([^"]+)"')) { [void]$names.Add($m.Groups[1].Value) }
        foreach ($item in @($Data.Auditpol)) {
            if ($null -eq $item) { continue }
            if ($names -contains [string]$item.Policy) { return $item.Setting }
        }
        return $null
    }

    $cur = $Data
    $rx = [regex]"(\['([^']+)'\])|(\[""([^""]+)""\])|([A-Za-z0-9_\-]+)"
    foreach ($m in $rx.Matches($p)) {
        if ($null -eq $cur) { return $null }
        $key = if ($m.Groups[2].Success) { $m.Groups[2].Value }
            elseif ($m.Groups[4].Success) { $m.Groups[4].Value }
            elseif ($m.Groups[5].Success) { $m.Groups[5].Value }
            else { $null }
        if (-not $key) { continue }

        if ($cur -is [System.Collections.IDictionary]) {
            $found = $false
            foreach ($k in @($cur.Keys)) {
                if ([string]$k -eq $key) { $cur = $cur[$k]; $found = $true; break }
                }
            if (-not $found) { return $null }
            continue
        }

        $prop = $cur.PSObject.Properties[$key]
        if (-not $prop) {
            $prop = $cur.PSObject.Properties | Where-Object { $_.Name -eq $key } | Select-Object -First 1
        }
        if (-not $prop) { return $null }
        $cur = $prop.Value
    }
    $cur
}

function secaudit_split_tokens {
    param([string]$Value)
    @($Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function secaudit_tokens_equal {
    param([string]$Actual, [string]$Target)
    $a = @(secaudit_split_tokens $Actual | Sort-Object -Unique)
    $t = @(secaudit_split_tokens $Target | Sort-Object -Unique)
    if ($a.Count -ne $t.Count) { return $false }
    for ($i = 0; $i -lt $a.Count; $i++) {
        if ($a[$i] -ne $t[$i]) { return $false }
    }
    $true
}

function secaudit_eval_rule {
    param($Actual, [string]$Operator, [string]$Target, [string]$Default, [string]$ValueType)
    if (($null -eq $Actual -or ([string]$Actual).Length -eq 0) -and $Default -ne '' -and $null -ne $Default) {
            $Actual = $Default
        }
    $a = [string]$Actual
    $op = $Operator.ToUpperInvariant()
    $isCollection = ($ValueType -and $ValueType.ToUpperInvariant() -eq 'COLLECTION')

    switch ($op) {
        'EQUAL' {
            if ($isCollection) { return (secaudit_tokens_equal $a $Target) }
            if ($Target -match '^(?i:true|false)$') {
                return ([bool]::Parse($a) -eq [bool]::Parse($Target))
            }
            $na = 0.0; $nt = 0.0
            if ([double]::TryParse($a, [ref]$na) -and [double]::TryParse($Target, [ref]$nt)) {
                return ($na -eq $nt)
            }
            return ($a -eq $Target)
        }
        'NOT_EQUAL' {
            -not (secaudit_eval_rule -Actual $Actual -Operator 'EQUAL' -Target $Target -Default $Default -ValueType $ValueType)
        }
        'CONTAINS' {
            if ($isCollection) {
                $have = @(secaudit_split_tokens $a)
                foreach ($token in @(secaudit_split_tokens $Target)) {
                    if (-not ($have -contains $token)) { return $false }
                }
                return $true
            }
            ($a -like ('*' + $Target + '*'))
        }
        'IN'     { (secaudit_split_tokens $Target) -contains $a }
        'NOT_IN' { -not ((secaudit_split_tokens $Target) -contains $a) }
        'GREATER_OR_EQUAL' { [double]$a -ge [double]$Target }
        'LESS_OR_EQUAL'    { [double]$a -le [double]$Target }
        'BETWEEN' {
            if ($Target -match '^(\d+(?:\.\d+)?)\.\.(\d+(?:\.\d+)?)$') {
                $v = [double]$a
                return ($v -ge [double]$Matches[1] -and $v -le [double]$Matches[2])
            }
            $false
        }
        default { $a -eq $Target }
    }
}

function secaudit_write_result {
    param([string]$Id, [bool]$Pass, [string]$Message)
    $status = if ($Pass) { 'PASS' } else { 'FAIL' }
    Write-Output ('{0}= {1}: {2}' -f $Id, $status, $Message)
}

function secaudit_merge {
    param($Target, $Source)
    if ($null -eq $Source) { return }
    if ($Source -is [System.Collections.IDictionary]) {
        foreach ($k in @($Source.Keys)) { $Target[$k] = $Source[$k] }
        return
    }
    foreach ($p in $Source.PSObject.Properties) { $Target[$p.Name] = $p.Value }
}

function secaudit_run_collector {
    param($Collected, $Errors, [string]$Key, [scriptblock]$Collector)
    try {
        secaudit_merge -Target $Collected -Source (& $Collector)
    } catch {
        $Errors[$Key] = $_.Exception.Message
    }
}

# --- main ---
$Collected = @{}
$CollectorErrors = @{}

secaudit_run_collector $Collected $CollectorErrors 'secedit'    { secaudit_collect_secedit }
secaudit_run_collector $Collected $CollectorErrors 'accounts'   { secaudit_collect_accounts }
secaudit_run_collector $Collected $CollectorErrors 'registry10' { secaudit_collect_registry }
secaudit_run_collector $Collected $CollectorErrors 'hku'        { secaudit_collect_hku }

function secaudit_load_rules {
    param([string]$RulesPath)
    if ([string]::IsNullOrWhiteSpace($RulesPath)) {
        $RulesPath = Join-Path $PSScriptRoot 'Win2025.rules.json'
    }
    if (-not (Test-Path -LiteralPath $RulesPath)) {
        throw "Rules file not found: $RulesPath"
    }
    Get-Content -LiteralPath $RulesPath -Raw -Encoding UTF8 | ConvertFrom-Json
}

$Rules = secaudit_load_rules

foreach ($rule in $Rules) {
    $key = [string]$rule.collector
    if ($CollectorErrors.ContainsKey($key)) {
        $err = [string]$CollectorErrors[$key]
        if ($err -like 'incomplete_scan:*') {
            secaudit_write_result -Id $rule.id -Pass:$false -Message $err
        } else {
            secaudit_write_result -Id $rule.id -Pass:$false -Message ("COLLECTOR_FAILED[$key]: " + $err)
        }
        continue
    }
    try {
        $actual = secaudit_jsonpath -Data $Collected -Path $rule.parser
        $ok = secaudit_eval_rule -Actual $actual -Operator $rule.operator -Target $rule.target `
            -Default $rule.default -ValueType $rule.value_type
        secaudit_write_result -Id $rule.id -Pass:([bool]$ok) `
            -Message ("actual=$actual; expected($($rule.operator))=$($rule.target)")
    } catch {
        secaudit_write_result -Id $rule.id -Pass:$false -Message ("ERROR: " + $_.Exception.Message)
    }
}

if ($CollectorErrors.Count -gt 0) {
    $parts = @($CollectorErrors.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value })
    Write-Output ('COLLECTOR_WARN=FAIL: ' + ($parts -join ' | '))
}
