# SecAudit Platform - Windows Server 2019 host audit
# Output: RULExxx= PASS|FAIL: actual=...; expected(OPERATOR)=...
# Every check below reads one piece of host state and compares it inline; no rule data file is used.
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

$script:CollectorErrors = @{}
$script:RegEnumCache = @{}
$script:RegProvider = $null
$script:Secedit = @{}
$script:Auditpol = @()
$script:Accounts = @{}
$script:Hku = @{}

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
            'Success and Failure', 'No Auditing', 'Success', 'Failure'
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
    if ($script:RegProvider) { return $script:RegProvider }
    $reg = Get-WmiObject -List -Namespace 'root\default' | Where-Object { $_.Name -eq 'StdRegProv' }
    if (-not $reg) { throw 'StdRegProv is unavailable' }
    $script:RegProvider = $reg
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

# Sentinel returned by a reader whose collector failed; check_rule renders it like the old engine did.
function sec_fail {
    param([string]$Group, [string]$Message)
    [pscustomobject]@{ __fail = $true; group = $Group; message = $Message }
}

function reg {
    param([string]$Key, [string]$Name)
    try {
        $hive = 2147483650 # HKLM
        if (-not $script:RegEnumCache.ContainsKey($Key)) {
            $script:RegEnumCache[$Key] = (secaudit_reg_provider).EnumValues($hive, $Key)
        }
        $values = $script:RegEnumCache[$Key]
        if ($null -eq $values -or $values.ReturnValue -ne 0 -or $null -eq $values.sNames) { return $null }
        $want = if ($Name -eq 'Default') { '' } else { $Name }
        $names = @($values.sNames)
        $types = @($values.Types)
        for ($i = 0; $i -lt $names.Count; $i++) {
            if ([string]$names[$i] -eq $want) {
                return secaudit_reg_read -Reg (secaudit_reg_provider) -Hive $hive -Key $Key -Name $names[$i] -Type $types[$i]
            }
        }
        $null
    } catch {
        sec_fail -Group 'registry10' -Message $_.Exception.Message
    }
}

function priv {
    param([string]$Name)
    if ($script:CollectorErrors.ContainsKey('secedit')) { return (sec_fail -Group 'secedit' -Message $script:CollectorErrors['secedit']) }
    if (-not $script:Secedit.ContainsKey('Privilege Rights')) { return $null }
    $section = $script:Secedit['Privilege Rights']
    foreach ($k in @($section.Keys)) { if ([string]$k -eq $Name) { return $section[$k] } }
    $null
}

function sysaccess {
    param([string]$Name)
    if ($script:CollectorErrors.ContainsKey('secedit')) { return (sec_fail -Group 'secedit' -Message $script:CollectorErrors['secedit']) }
    if (-not $script:Secedit.ContainsKey('System Access')) { return $null }
    $section = $script:Secedit['System Access']
    foreach ($k in @($section.Keys)) { if ([string]$k -eq $Name) { return $section[$k] } }
    $null
}

function auditpol {
    param([string]$Name, [string]$LocalizedName = '')
    if ($script:CollectorErrors.ContainsKey('secedit')) { return (sec_fail -Group 'secedit' -Message $script:CollectorErrors['secedit']) }
    foreach ($item in @($script:Auditpol)) {
        if ($null -eq $item) { continue }
        if ([string]$item.Policy -eq $Name) { return [string]$item.Setting }
        if ($LocalizedName -and [string]$item.Policy -eq $LocalizedName) { return [string]$item.Setting }
    }
    $null
}

function acct {
    param([string]$Which, [string]$Field)
    if ($script:CollectorErrors.ContainsKey('accounts')) { return (sec_fail -Group 'accounts' -Message $script:CollectorErrors['accounts']) }
    $entry = $script:Accounts[$Which]
    if ($null -eq $entry) { return $null }
    foreach ($p in $entry.PSObject.Properties) { if ($p.Name -eq $Field) { return $p.Value } }
    $null
}

function hku {
    param([string]$Key)
    if ($script:CollectorErrors.ContainsKey('hku')) { return (sec_fail -Group 'hku' -Message $script:CollectorErrors['hku']) }
    if (-not $script:Hku.ContainsKey($Key)) { return $null }
    $script:Hku[$Key].Result
}

function check_rule {
    param([string]$Id, $Actual, [string]$Operator, [string]$Target, [string]$Default, [string]$ValueType)
    if ($null -ne $Actual -and $Actual.PSObject.Properties['__fail']) {
        $message = [string]$Actual.message
        if ($message -like 'incomplete_scan:*') {
            secaudit_write_result -Id $Id -Pass:$false -Message $message
        } else {
            secaudit_write_result -Id $Id -Pass:$false -Message ("COLLECTOR_FAILED[" + $Actual.group + "]: " + $message)
        }
        return
    }
    try {
        $ok = secaudit_eval_rule -Actual $Actual -Operator $Operator -Target $Target -Default $Default -ValueType $ValueType
        secaudit_write_result -Id $Id -Pass:([bool]$ok) -Message ("actual=$Actual; expected($Operator)=$Target")
    } catch {
        secaudit_write_result -Id $Id -Pass:$false -Message ("ERROR: " + $_.Exception.Message)
    }
}

# --- collect host state once ---
try {
    $collected = secaudit_collect_secedit
    $script:Auditpol = @($collected.Auditpol)
    $script:Secedit = $collected.Secedit
} catch {
    $script:CollectorErrors['secedit'] = $_.Exception.Message
}

try { $script:Accounts = secaudit_collect_accounts } catch { $script:CollectorErrors['accounts'] = $_.Exception.Message }
try { $script:Hku = secaudit_collect_hku } catch { $script:CollectorErrors['hku'] = $_.Exception.Message }

# --- checks ---

# ================= Registry (HKLM) =================
check_rule RULE050 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'noconnecteduser') EQUAL '3' '' STRING
check_rule RULE052 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse') EQUAL '1' '0' INTEGER
check_rule RULE056 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'crashonauditfail') EQUAL '0' '0' INTEGER
check_rule RULE057 (reg 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'allocatedasd') EQUAL '0' '0' INTEGER
check_rule RULE058 (reg 'SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' 'AddPrinterDrivers') EQUAL '1' '1' INTEGER
check_rule RULE059 (reg 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireSignOrSeal') EQUAL '1' '1' INTEGER
check_rule RULE060 (reg 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SealSecureChannel') EQUAL '1' '1' INTEGER
check_rule RULE062 (reg 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'DisablePasswordChange') EQUAL '0' '0' INTEGER
check_rule RULE063 (reg 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'MaximumPasswordAge') BETWEEN '1..30' '30' INTEGER
check_rule RULE064 (reg 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireStrongKey') EQUAL '1' '1' INTEGER
check_rule RULE065 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'dontdisplaylastusername') EQUAL '1' '0' INTEGER
check_rule RULE066 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'disablecad') EQUAL '0' '1' INTEGER
check_rule RULE068 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'inactivitytimeoutsecs') BETWEEN '1..900' '0' INTEGER
check_rule RULE071 (reg 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount') LESS_OR_EQUAL '4' '#NULL' INTEGER
check_rule RULE072 (reg 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'PasswordExpiryWarning') BETWEEN '5..14' '5' INTEGER
check_rule RULE073 (reg 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'scremoveoption') GREATER_OR_EQUAL '1' '#NULL' INTEGER
check_rule RULE074 (reg 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature') EQUAL '1' '0' INTEGER
check_rule RULE075 (reg 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnableSecuritySignature') EQUAL '1' '1' INTEGER
check_rule RULE076 (reg 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnablePlainTextPassword') EQUAL '0' '0' INTEGER
check_rule RULE078 (reg 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'requiresecuritysignature') EQUAL '1' '0' INTEGER
check_rule RULE079 (reg 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'enablesecuritysignature') EQUAL '1' '1' INTEGER
check_rule RULE080 (reg 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'enableforcedlogoff') EQUAL '1' '1' INTEGER
check_rule RULE081 (reg 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'smbservernamehardeninglevel') GREATER_OR_EQUAL '1' '0' INTEGER
check_rule RULE083 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'restrictanonymoussam') EQUAL '1' '1' INTEGER
check_rule RULE084 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'restrictanonymous') EQUAL '1' '0' INTEGER
check_rule RULE086 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'everyoneincludesanonymous') EQUAL '0' '0' INTEGER
check_rule RULE087 (reg 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionPipes') EQUAL '' '' STRING
check_rule RULE090 (reg 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'restrictnullsessaccess') EQUAL '1' '1' INTEGER
check_rule RULE091 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'restrictremotesam') EQUAL 'O:BAG:BAD:(A;;RC;;;BA)' 'O:BAG:BAD:(A;;RC;;;BA)' STRING
check_rule RULE092 (reg 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'nullsessionshares') EQUAL '' '' STRING
check_rule RULE094 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'usemachineid') EQUAL '1' '0' STRING
check_rule RULE095 (reg 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'allownullsessionfallback') EQUAL '0' '0' INTEGER
check_rule RULE096 (reg 'SYSTEM\CurrentControlSet\Control\Lsa\pku2u' 'allowonlineid') EQUAL '0' '0' INTEGER
check_rule RULE097 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'supportedencryptiontypes') EQUAL '2147483640' '' STRING
check_rule RULE098 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'NoLmHash') EQUAL '1' '1' INTEGER
check_rule RULE099 (reg 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'enableforcedlogoff') EQUAL '1' '1' INTEGER
check_rule RULE100 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'lmcompatibilitylevel') EQUAL '5' '3' INTEGER
check_rule RULE101 (reg 'SYSTEM\CurrentControlSet\Services\LDAP' 'ldapclientintegrity') GREATER_OR_EQUAL '1' '1' INTEGER
check_rule RULE102 (reg 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NtlmMinClientSec') EQUAL '537395200' '' STRING
check_rule RULE106 (reg 'SYSTEM\CurrentControlSet\Control\Session Manager' 'ProtectionMode') EQUAL '1' '1' INTEGER
check_rule RULE107 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'FilterAdministratorToken') EQUAL '1' '0' INTEGER
check_rule RULE109 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin') EQUAL '2' '5' INTEGER
check_rule RULE110 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorUser') EQUAL '0' '1' INTEGER
check_rule RULE111 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableInstallerDetection') EQUAL '1' '1' INTEGER
check_rule RULE113 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') EQUAL '1' '1' INTEGER
check_rule RULE114 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop') EQUAL '1' '1' INTEGER
check_rule RULE115 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableVirtualization') EQUAL '1' '1' INTEGER
check_rule RULE158 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' 'EnableFirewall') EQUAL '1' '1' INTEGER
check_rule RULE160 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' 'DefaultOutboundAction') EQUAL '0' '0' INTEGER
check_rule RULE161 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' 'DisableNotifications') EQUAL '1' '0' INTEGER
check_rule RULE164 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' 'LogFilePath') EQUAL '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log' '%SystemRoot%\System32\logfiles\firewall\pfirewall.log' STRING
check_rule RULE165 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' 'LogFileSize') GREATER_OR_EQUAL '16384' '4096' INTEGER
check_rule RULE166 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' 'LogDroppedPackets') EQUAL '1' '0' INTEGER
check_rule RULE167 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' 'LogSuccessfulConnections') EQUAL '1' '0' INTEGER
check_rule RULE168 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'EnableFirewall') EQUAL '1' '1' INTEGER
check_rule RULE169 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'DefaultInboundAction') EQUAL '1' '1' INTEGER
check_rule RULE170 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'DefaultOutboundAction') EQUAL '0' '0' INTEGER
check_rule RULE171 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'DisableNotifications') EQUAL '1' '0' INTEGER
check_rule RULE174 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' 'LogFilePath') EQUAL '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log' '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log' STRING
check_rule RULE175 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' 'LogFileSize') GREATER_OR_EQUAL '16384' '4096' INTEGER
check_rule RULE176 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' 'LogDroppedPackets') EQUAL '1' '0' INTEGER
check_rule RULE177 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' 'LogSuccessfulConnections') EQUAL '1' '0' INTEGER
check_rule RULE178 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'EnableFirewall') EQUAL '1' '1' INTEGER
check_rule RULE179 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'DefaultInboundAction') EQUAL '1' '1' INTEGER
check_rule RULE180 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'DefaultOutboundAction') EQUAL '0' '0' INTEGER
check_rule RULE181 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'DisableNotifications') EQUAL '0' '1' INTEGER
check_rule RULE182 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'AllowLocalPolicyMerge') EQUAL '0' '1' INTEGER
check_rule RULE183 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'AllowLocalIPsecPolicyMerge') EQUAL '0' '1' INTEGER
check_rule RULE184 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' 'LogFilePath') EQUAL '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log' '%SystemRoot%\System32\logfiles\firewall\pfirewall.log' STRING
check_rule RULE185 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' 'LogFileSize') GREATER_OR_EQUAL '16384' '4096' INTEGER
check_rule RULE186 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' 'LogDroppedPackets') EQUAL '1' '0' INTEGER
check_rule RULE187 (reg 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' 'LogSuccessfulConnections') EQUAL '1' '0' INTEGER
check_rule RULE212 (reg 'SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenCamera') EQUAL '1' '0' INTEGER
check_rule RULE213 (reg 'SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenSlideshow') EQUAL '1' '0' INTEGER
check_rule RULE216 (reg 'SOFTWARE\Policies\Microsoft Services\AdmPwd' 'PwdExpirationProtectionEnabled') EQUAL '1' '0' INTEGER
check_rule RULE217 (reg 'SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled') EQUAL '1' '0' INTEGER
check_rule RULE218 (reg 'SOFTWARE\Policies\Microsoft Services\AdmPwd' 'PasswordComplexity') EQUAL '4' '4' INTEGER
check_rule RULE220 (reg 'SOFTWARE\Policies\Microsoft Services\AdmPwd' 'PasswordAgeDays') LESS_OR_EQUAL '30' '30' INTEGER
check_rule RULE221 (reg 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon') EQUAL '0' '0' INTEGER
check_rule RULE223 (reg 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DisableIPSourceRouting') EQUAL '2' '1' INTEGER
check_rule RULE225 (reg 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect') EQUAL '0' '1' INTEGER
check_rule RULE226 (reg 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'KeepAliveTime') EQUAL '300000' '7200000' INTEGER
check_rule RULE227 (reg 'SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NoNameReleaseOnDemand') EQUAL '1' '1' INTEGER
check_rule RULE228 (reg 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'PerformRouterDiscovery') EQUAL '0' '1' INTEGER
check_rule RULE229 (reg 'SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode') EQUAL '1' '1' INTEGER
check_rule RULE230 (reg 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ScreenSaverGracePeriod') EQUAL '5' '5' INTEGER
check_rule RULE232 (reg 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'TcpMaxDataRetransmissions') EQUAL '3' '5' INTEGER
check_rule RULE233 (reg 'SYSTEM\CurrentControlSet\Services\Eventlog\Security' 'WarningLevel') EQUAL '90' '0' INTEGER
check_rule RULE235 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') EQUAL '0' '1' INTEGER
check_rule RULE236 (reg 'SOFTWARE\Policies\Microsoft\Windows\System' 'EnableFontProviders') EQUAL '0' '1' INTEGER
check_rule RULE237 (reg 'SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth') EQUAL '0' '1' INTEGER
check_rule RULE238 (reg 'SOFTWARE\Policies\Microsoft\Windows\LLTD' 'AllowLLTDIOOnDomain') EQUAL '0' '0' INTEGER
check_rule RULE239 (reg 'SOFTWARE\Policies\Microsoft\Windows\LLTD' 'AllowRspndrOnDomain') EQUAL '0' '0' INTEGER
check_rule RULE240 (reg 'SOFTWARE\Policies\Microsoft\Peernet' 'Disabled') EQUAL '1' '0' INTEGER
check_rule RULE241 (reg 'SOFTWARE\Policies\Microsoft\Windows\Network Connections' 'NC_AllowNetBridge_NLA') EQUAL '0' '1' INTEGER
check_rule RULE242 (reg 'SOFTWARE\Policies\Microsoft\Windows\Network Connections' 'NC_ShowSharedAccessUI') EQUAL '0' '1' INTEGER
check_rule RULE243 (reg 'SOFTWARE\Policies\Microsoft\Windows\Network Connections' 'NC_StdDomainUserSetLocation') EQUAL '1' '0' INTEGER
check_rule RULE246 (reg 'SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' 'EnableRegistrars') EQUAL '0' '1' INTEGER
check_rule RULE248 (reg 'SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' 'fMinimizeConnections') EQUAL '3' '1' INTEGER
check_rule RULE249 (reg 'SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' 'fBlockNonDomain') EQUAL '1' '0' INTEGER
check_rule RULE251 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy') EQUAL '0' '0' INTEGER
check_rule RULE252 (reg 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') EQUAL '0' '0' INTEGER
check_rule RULE253 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') EQUAL '1' '0' INTEGER
check_rule RULE260 (reg 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch' 'DriverLoadPolicy') EQUAL '3' '' STRING
check_rule RULE261 (reg 'SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' 'NoBackgroundPolicy') EQUAL '0' '0' INTEGER
check_rule RULE262 (reg 'SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' 'NoGPOListChanges') EQUAL '0' '1' INTEGER
check_rule RULE263 (reg 'SOFTWARE\Policies\Microsoft\Windows\System' 'EnableCdp') EQUAL '0' '' STRING
check_rule RULE266 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'DisableWebPnPDownload') EQUAL '1' '0' INTEGER
check_rule RULE268 (reg 'SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' 'PreventHandwritingErrorReports') EQUAL '1' '0' INTEGER
check_rule RULE269 (reg 'SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard' 'ExitOnMSICW') EQUAL '1' '0' INTEGER
check_rule RULE272 (reg 'SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control' 'NoRegistration') EQUAL '1' '0' INTEGER
check_rule RULE273 (reg 'SOFTWARE\Policies\Microsoft\SearchCompanion' 'DisableContentFileUpdates') EQUAL '1' '0' INTEGER
check_rule RULE274 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoOnlinePrintsWizard') EQUAL '1' '0' INTEGER
check_rule RULE275 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoPublishingWizard') EQUAL '1' '0' INTEGER
check_rule RULE276 (reg 'SOFTWARE\Policies\Microsoft\Messenger\Client' 'CEIP') EQUAL '2' '' STRING
check_rule RULE277 (reg 'SOFTWARE\Policies\Microsoft\SQMClient\Windows' 'CEIPEnable') EQUAL '0' '' STRING
check_rule RULE278 (reg 'SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled') EQUAL '1' '0' INTEGER
check_rule RULE279 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'DevicePKInitBehavior') EQUAL '0' '0' INTEGER
check_rule RULE280 (reg 'SOFTWARE\Policies\Microsoft\Control Panel\International' 'BlockUserInputMethodsForSignIn') EQUAL '1' '0' INTEGER
check_rule RULE382 (reg 'SOFTWARE\Policies\Microsoft\Camera' 'AllowCamera') EQUAL '0' '1' INTEGER
check_rule RULE383 (reg 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures') EQUAL '1' '0' INTEGER
check_rule RULE384 (reg 'SOFTWARE\Policies\Microsoft\Windows\Connect' 'RequirePinForPairing') BETWEEN '1..2' '0' INTEGER
check_rule RULE387 (reg 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry') EQUAL '1' '' STRING
check_rule RULE389 (reg 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications') EQUAL '1' '0' INTEGER
check_rule RULE390 (reg 'SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' 'AllowBuildPreview') EQUAL '0' '1' INTEGER
check_rule RULE392 (reg 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' 'Retention') EQUAL '0' '0' INTEGER
check_rule RULE393 (reg 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' 'MaxSize') GREATER_OR_EQUAL '32768' '20480' INTEGER
check_rule RULE394 (reg 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' 'Retention') EQUAL '0' '0' INTEGER
check_rule RULE395 (reg 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' 'MaxSize') GREATER_OR_EQUAL '192608' '20480' INTEGER
check_rule RULE396 (reg 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup' 'Retention') EQUAL '0' '0' INTEGER
check_rule RULE397 (reg 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup' 'MaxSize') GREATER_OR_EQUAL '32768' '20480' INTEGER
check_rule RULE398 (reg 'SOFTWARE\Policies\Microsoft\Windows\EventLog\System' 'Retention') EQUAL '0' '0' INTEGER
check_rule RULE399 (reg 'SOFTWARE\Policies\Microsoft\Windows\EventLog\System' 'MaxSize') GREATER_OR_EQUAL '32768' '20480' INTEGER
check_rule RULE401 (reg 'SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoDataExecutionPrevention') EQUAL '0' '0' INTEGER
check_rule RULE402 (reg 'SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoHeapTerminationOnCorruption') EQUAL '0' '0' INTEGER
check_rule RULE403 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'PreXPSP2ShellProtocolBehavior') EQUAL '0' '0' INTEGER
check_rule RULE405 (reg 'SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableWindowsLocationProvider') EQUAL '1' '0' INTEGER
check_rule RULE417 (reg 'SOFTWARE\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC') EQUAL '1' '0' INTEGER
check_rule RULE418 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'DisablePasswordSaving') EQUAL '1' '0' INTEGER
check_rule RULE420 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableCcm') EQUAL '1' '0' INTEGER
check_rule RULE421 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableCdm') EQUAL '1' '0' INTEGER
check_rule RULE422 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableLPT') EQUAL '1' '0' INTEGER
check_rule RULE423 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDisablePNPRedir') EQUAL '1' '0' INTEGER
check_rule RULE424 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fPromptForPassword') EQUAL '1' '0' INTEGER
check_rule RULE425 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fEncryptRPCTraffic') EQUAL '1' '0' INTEGER
check_rule RULE426 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'MinEncryptionLevel') EQUAL '3' '3' INTEGER
check_rule RULE427 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'MaxIdleTime') BETWEEN '1..900000' '0' INTEGER
check_rule RULE428 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'MaxDisconnectionTime') EQUAL '60000' '0' INTEGER
check_rule RULE429 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'DeleteTempDirsOnExit') EQUAL '1' '1' INTEGER
check_rule RULE430 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'PerSessionTempDir') EQUAL '1' '1' INTEGER
check_rule RULE431 (reg 'SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' 'DisableEnclosureDownload') EQUAL '1' '0' INTEGER
check_rule RULE434 (reg 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowIndexingEncryptedStoresOrItems') EQUAL '0' '0' INTEGER
check_rule RULE436 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' 'NoGenTicket') EQUAL '1' '0' INTEGER
check_rule RULE441 (reg 'SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'LocalSettingOverrideSpynetReporting') EQUAL '0' '0' INTEGER
check_rule RULE442 (reg 'SOFTWARE\Policies\Microsoft\Windows Defender\Reporting' 'DisableGenericRePorts') EQUAL '1' '0' INTEGER
check_rule RULE444 (reg 'SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' 'AllowSuggestedAppsInWindowsInkWorkspace') EQUAL '0' '1' INTEGER
check_rule RULE446 (reg 'SOFTWARE\Policies\Microsoft\Windows\Installer' 'EnableUserControl') EQUAL '0' '0' INTEGER
check_rule RULE447 (reg 'SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated') EQUAL '0' '0' INTEGER
check_rule RULE448 (reg 'SOFTWARE\Policies\Microsoft\Windows\Installer' 'SafeForScripting') EQUAL '0' '0' INTEGER
check_rule RULE449 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableAutomaticRestartSignOn') EQUAL '1' '0' INTEGER
check_rule RULE450 (reg 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') EQUAL '1' '1' INTEGER
check_rule RULE451 (reg 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting') EQUAL '0' '0' INTEGER
check_rule RULE452 (reg 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowBasic') EQUAL '0' '0' INTEGER
check_rule RULE453 (reg 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowUnencryptedTraffic') EQUAL '0' '0' INTEGER
check_rule RULE454 (reg 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowDigest') EQUAL '0' '1' INTEGER
check_rule RULE455 (reg 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic') EQUAL '0' '0' INTEGER
check_rule RULE456 (reg 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowAutoConfig') EQUAL '0' '0' INTEGER
check_rule RULE457 (reg 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencryptedTraffic') EQUAL '0' '0' INTEGER
check_rule RULE458 (reg 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'DisableRunAs') EQUAL '1' '0' INTEGER
check_rule RULE459 (reg 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS' 'AllowRemoteShellAccess') EQUAL '0' '1' INTEGER
check_rule RULE461 (reg 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferQualityUpdates') EQUAL '1' '0' INTEGER
check_rule RULE462 (reg 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate') EQUAL '0' '0' INTEGER
check_rule RULE463 (reg 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'ScheduledInstallDay') EQUAL '0' '' STRING
check_rule RULE464 (reg 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoRebootWithLoggedOnUsers') EQUAL '0' '0' INTEGER
check_rule RULE479 (reg 'SOFTWARE\Policies\Microsoft\Windows\System' 'AllowCrossDeviceClipboard') EQUAL '0' '1' INTEGER
check_rule RULE480 (reg 'SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' 'DeviceEnumerationPolicy') EQUAL '0' '' STRING
check_rule RULE485 (reg 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'autodisconnect') GREATER_OR_EQUAL '15' '15' INTEGER
check_rule RULE486 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'disabledomaincreds') EQUAL '1' '1' STRING
check_rule RULE487 (reg 'SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths' 'Machine') EQUAL 'System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, Software\Microsoft\Windows NT\CurrentVersion' 'System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows ,NT\CurrentVersion' COLLECTION
check_rule RULE488 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'forceguest') EQUAL '0' '0' STRING
check_rule RULE489 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'shutdownwithoutlogon') EQUAL '0' '0' STRING
check_rule RULE490 (reg 'SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' 'obcaseinsensitive') EQUAL '1' '1' STRING
check_rule RULE491 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableSecureUIAPaths') EQUAL '1' '1' STRING
check_rule RULE497 (reg 'SOFTWARE\Policies\Microsoft\InputPersonalization' 'AllowInputPersonalization') EQUAL '0' '1' STRING
check_rule RULE498 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'AllowOnlineTips') EQUAL '0' '1' STRING
check_rule RULE499 (reg 'SOFTWARE\Policies\Microsoft Services\AdmPwd' 'PasswordLength') GREATER_OR_EQUAL '15' '14' INTEGER
check_rule RULE500 (reg 'SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start') EQUAL '0' '0' STRING
check_rule RULE501 (reg 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1') EQUAL '0' '0' STRING
check_rule RULE502 (reg 'SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' 'DisableExceptionChainValidation') EQUAL '1' '0' STRING
check_rule RULE503 (reg 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting') EQUAL '2' '2' STRING
check_rule RULE504 (reg 'SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' '\\*\NETLOGON') EQUAL 'RequireMutualAuthentication=1, RequireIntegrity=1' '' STRING
check_rule RULE505 (reg 'SOFTWARE\Policies\Microsoft\Windows\WCN\UI' 'DisableWcnUi') EQUAL '1' '0' STRING
check_rule RULE506 (reg 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' 'AllowProtectedCreds') EQUAL '1' '0' STRING
check_rule RULE507 (reg 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity') EQUAL '1' '0' STRING
check_rule RULE508 (reg 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'RequirePlatformSecurityFeatures') EQUAL '3' '3' COLLECTION
check_rule RULE509 (reg 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'HypervisorEnforcedCodeIntegrity') EQUAL '1' '3' STRING
check_rule RULE511 (reg 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'LsaCfgFlags') EQUAL '1' '3' STRING
check_rule RULE513 (reg 'SOFTWARE\Policies\Microsoft\Windows\TabletPC' 'PreventHandwritingDataSharing') EQUAL '1' '0' STRING
check_rule RULE514 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoWebServices') EQUAL '1' '0' STRING
check_rule RULE515 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'DisableHTTPPrinting') EQUAL '1' '0' STRING
check_rule RULE516 (reg 'SOFTWARE\Policies\Microsoft\Windows\System' 'BlockUserFromShowingAccountDetailsOnSignin') EQUAL '1' '0' STRING
check_rule RULE517 (reg 'SOFTWARE\Policies\Microsoft\Windows\System' 'DontEnumerateConnectedUsers') EQUAL '1' '0' STRING
check_rule RULE518 (reg 'SOFTWARE\Policies\Microsoft\Windows\System' 'BlockDomainPicturePassword') EQUAL '1' '0' STRING
check_rule RULE519 (reg 'SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9' 'DCSettingIndex') EQUAL '0' '1' STRING
check_rule RULE520 (reg 'SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9' 'ACSettingIndex') EQUAL '0' '1' STRING
check_rule RULE521 (reg 'SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' 'DisabledByGroupPolicy') EQUAL '1' '0' STRING
check_rule RULE522 (reg 'SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient' 'Enabled') EQUAL '1' '0' STRING
check_rule RULE523 (reg 'SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer' 'Enabled') EQUAL '0' '1' STRING
check_rule RULE525 (reg 'SOFTWARE\Policies\Microsoft\Windows\CredUI' 'DisablePasswordReveal') EQUAL '1' '0' STRING
check_rule RULE526 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' 'EnumerateAdministrators') EQUAL '0' '0' STRING
check_rule RULE527 (reg 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DisableEnterpriseAuthProxy') EQUAL '1' '0' STRING
check_rule RULE528 (reg 'SOFTWARE\Policies\Microsoft\Windows\Messaging' 'AllowMessageSync') EQUAL '0' '1' STRING
check_rule RULE529 (reg 'SOFTWARE\Policies\Microsoft\MicrosoftAccount' 'DisableUserAuth') EQUAL '1' '0' STRING
check_rule RULE530 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fSingleSessionPerUser') EQUAL '1' '1' STRING
check_rule RULE531 (reg 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCloudSearch') EQUAL '0' '1' STRING
check_rule RULE532 (reg 'SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'LocalSettingOverrideSpynetReporting') EQUAL '0' '0' STRING
check_rule RULE533 (reg 'SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableBehaviorMonitoring') EQUAL '1' '1' STRING
check_rule RULE534 (reg 'SOFTWARE\Policies\Microsoft\Windows Defender\Scan' 'DisableRemovableDriveScanning') EQUAL '0' '1' STRING
check_rule RULE535 (reg 'SOFTWARE\Policies\Microsoft\Windows Defender\Scan' 'DisableEmailScanning') EQUAL '1' '0' STRING
check_rule RULE536 (reg 'SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' 'EnableNetworkProtection') EQUAL '1' '1' STRING
check_rule RULE537 (reg 'SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware') EQUAL '0' '0' STRING
check_rule RULE538 (reg 'SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection' 'DisallowExploitProtectionOverride') EQUAL '1' '0' STRING
check_rule RULE540 (reg 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'ManagePreviewBuilds') EQUAL '1' '0' STRING
check_rule RULE543 (reg 'SOFTWARE\Policies\Microsoft\Windows\System' 'DontDisplayNetworkSelectionUI') EQUAL '1' '0' STRING
check_rule RULE544 (reg 'SOFTWARE\Policies\Microsoft\Windows\System' 'EnumerateLocalUsers') EQUAL '0' '0' STRING
check_rule RULE545 (reg 'SOFTWARE\Policies\Microsoft\Windows\System' 'DisableLockScreenAppNotifications') EQUAL '1' '0' STRING
check_rule RULE546 (reg 'SOFTWARE\Policies\Microsoft\Windows\System' 'AllowDomainPINLogon') EQUAL '0' '0' STRING
check_rule RULE548 (reg 'SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' 'DCSettingIndex') EQUAL '1' '1' STRING
check_rule RULE549 (reg 'SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' 'ACSettingIndex') EQUAL '1' '1' STRING
check_rule RULE550 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowUnsolicited') EQUAL '0' '0' STRING
check_rule RULE551 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp') EQUAL '0' '1' STRING
check_rule RULE552 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Rpc' 'EnableAuthEpResolution') EQUAL '0' '1' STRING
check_rule RULE553 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Rpc' 'RestrictRemoteClients') EQUAL '1' '1' STRING
check_rule RULE554 (reg 'SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy' 'DisableQueryRemoteServer') EQUAL '0' '1' STRING
check_rule RULE555 (reg 'SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}' 'ScenarioExecutionEnabled') EQUAL '0' '1' STRING
check_rule RULE556 (reg 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager' 'AllowSharedLocalAppData') EQUAL '0' '0' STRING
check_rule RULE557 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'MSAOptional') EQUAL '1' '0' STRING
check_rule RULE558 (reg 'SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume') EQUAL '1' '0' STRING
check_rule RULE559 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun') EQUAL '1' '0' STRING
check_rule RULE560 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun') EQUAL '255' '0' COLLECTION
check_rule RULE562 (reg 'SYSTEM\CurrentControlSet\Control\Lsa' 'submitcontrol') EQUAL '0' '0' STRING
check_rule RULE564 (reg 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'refusepasswordchange') EQUAL '0' '1' STRING
check_rule RULE565 (reg 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'legalnoticetext') NOT_EQUAL '' '' STRING
check_rule RULE566 (reg 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ForceUnlockLogon') EQUAL '1' '0' STRING
check_rule RULE567 (reg 'SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths' 'Machine') EQUAL 'System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog' 'System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print Software\Microsoft\Windows,NT\CurrentVersion\Windows System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog' COLLECTION
check_rule RULE569 (reg 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp') EQUAL '1' '1' STRING
check_rule RULE889 (reg 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'ManagePreviewBuildsPolicyValue') EQUAL '0' '0' COLLECTION
check_rule RULE890 (reg 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferFeatureUpdatesPeriodInDays') GREATER_OR_EQUAL '180' '1' INTEGER
check_rule RULE5041 (reg 'SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' '\\*\SYSVOL') EQUAL 'RequireMutualAuthentication=1, RequireIntegrity=1' '' STRING

# ================= Account policy (secedit) =================
check_rule RULE001 (sysaccess 'PasswordHistorySize') GREATER_OR_EQUAL '24' '0' INTEGER
check_rule RULE002 (sysaccess 'MaximumPasswordAge') BETWEEN '1..60' '42' INTEGER
check_rule RULE003 (sysaccess 'MinimumPasswordAge') GREATER_OR_EQUAL '1' '0' INTEGER
check_rule RULE004 (sysaccess 'MinimumPasswordLength') GREATER_OR_EQUAL '14' '0' INTEGER
check_rule RULE005 (sysaccess 'PasswordComplexity') EQUAL '1' '0' INTEGER
check_rule RULE007 (sysaccess 'LockoutDuration') GREATER_OR_EQUAL '15' '#NULL' INTEGER
check_rule RULE008 (sysaccess 'LockoutBadCount') BETWEEN '1..10' '0' INTEGER
check_rule RULE009 (sysaccess 'ResetLockoutCount') GREATER_OR_EQUAL '15' '#NULL' INTEGER

# ================= User rights (secedit) =================
check_rule RULE010 (priv 'SeTrustedCredManAccessPrivilege') EQUAL '' '' COLLECTION
check_rule RULE011 (priv 'SeNetworkLogonRight') EQUAL 'Administrators,Authenticated Users' 'Administrators, Backup Operators, Users, Everyone' COLLECTION
check_rule RULE012 (priv 'SeTcbPrivilege') EQUAL '' '' COLLECTION
check_rule RULE013 (priv 'SeIncreaseQuotaPrivilege') EQUAL 'Administrators,LOCAL SERVICE,NETWORK SERVICE' 'Administrators, LOCAL SERVICE, NETWORK SERVICE' COLLECTION
check_rule RULE014 (priv 'SeInteractiveLogonRight') EQUAL 'Administrators' 'Administrators, Backup Operators' COLLECTION
check_rule RULE015 (priv 'SeRemoteInteractiveLogonRight') EQUAL 'Administrators,Remote Desktop Users' 'Administrators,Remote Desktop Users' COLLECTION
check_rule RULE016 (priv 'SeBackupPrivilege') EQUAL 'Administrators' 'Administrators, Backup Operators' COLLECTION
check_rule RULE017 (priv 'SeSystemtimePrivilege') IN 'Administrators, LOCAL SERVICE' 'Administrators, LOCAL SERVICE' COLLECTION
check_rule RULE018 (priv 'SeTimeZonePrivilege') EQUAL 'Administrators, LOCAL SERVICE' 'Administrators, LOCAL SERVICE' COLLECTION
check_rule RULE019 (priv 'SeCreatePagefilePrivilege') EQUAL 'Administrators' 'Administrators' COLLECTION
check_rule RULE020 (priv 'SeCreateTokenPrivilege') EQUAL '' '' COLLECTION
check_rule RULE021 (priv 'SeCreateGlobalPrivilege') EQUAL 'Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE' 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' COLLECTION
check_rule RULE022 (priv 'SeCreatePermanentPrivilege') EQUAL '' '' COLLECTION
check_rule RULE023 (priv 'SeCreateSymbolicLinkPrivilege') EQUAL 'Administrators' 'Administrators' COLLECTION
check_rule RULE024 (priv 'SeDebugPrivilege') EQUAL 'Administrators' 'Administrators' COLLECTION
check_rule RULE025 (priv 'SeDenyNetworkLogonRight') EQUAL 'Guests,Local account' '' COLLECTION
check_rule RULE026 (priv 'SeDenyBatchLogonRight') EQUAL 'Guests' '' COLLECTION
check_rule RULE027 (priv 'SeDenyServiceLogonRight') EQUAL 'Guests' '' COLLECTION
check_rule RULE028 (priv 'SeDenyInteractiveLogonRight') EQUAL 'Guests' '' COLLECTION
check_rule RULE030 (priv 'SeEnableDelegationPrivilege') EQUAL '' '' COLLECTION
check_rule RULE031 (priv 'SeRemoteShutdownPrivilege') EQUAL 'Administrators' 'Administrators' COLLECTION
check_rule RULE032 (priv 'SeAuditPrivilege') EQUAL 'LOCAL SERVICE,NETWORK SERVICE' 'LOCAL SERVICE, NETWORK SERVICE' COLLECTION
check_rule RULE033 (priv 'SeImpersonatePrivilege') EQUAL 'Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE' 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' COLLECTION
check_rule RULE034 (priv 'SeIncreaseBasePriorityPrivilege') EQUAL 'Administrators, Window Manager\Window Manager Group' 'Administrators, Window Manager\Window Manager Group' COLLECTION
check_rule RULE035 (priv 'SeLoadDriverPrivilege') EQUAL 'Administrators' '' COLLECTION
check_rule RULE036 (priv 'SeLockMemoryPrivilege') EQUAL '' '' COLLECTION
check_rule RULE037 (priv 'SeBatchLogonRight') EQUAL 'Administrators' 'Administrators' COLLECTION
check_rule RULE039 (priv 'SeSecurityPrivilege') EQUAL 'Administrators' 'Administrators' COLLECTION
check_rule RULE040 (priv 'SeRelabelPrivilege') EQUAL '' '' COLLECTION
check_rule RULE041 (priv 'SeSystemEnvironmentPrivilege') EQUAL 'Administrators' 'Administrators' COLLECTION
check_rule RULE042 (priv 'SeManageVolumePrivilege') EQUAL 'Administrators' 'Administrators' COLLECTION
check_rule RULE043 (priv 'SeProfileSingleProcessPrivilege') EQUAL 'Administrators' 'Administrators' COLLECTION
check_rule RULE045 (priv 'SeAssignPrimaryTokenPrivilege') EQUAL 'LOCAL SERVICE,NETWORK SERVICE' 'LOCAL SERVICE, NETWORK SERVICE' COLLECTION
check_rule RULE046 (priv 'SeRestorePrivilege') EQUAL 'Administrators' 'Administrators, Backup Operators' COLLECTION
check_rule RULE047 (priv 'SeShutdownPrivilege') IN 'Administrators' 'Administrators, Backup Operators,Server Operators, Print Operators' COLLECTION
check_rule RULE048 (priv 'SeTakeOwnershipPrivilege') EQUAL 'Administrators' 'Administrators' COLLECTION

# ================= Audit policy (auditpol) =================
check_rule RULE188 (auditpol 'Credential Validation') IN 'Success and Failure' 'Success' COLLECTION
check_rule RULE189 (auditpol 'Application Group Management') IN 'Success and Failure' 'No Auditing' COLLECTION
check_rule RULE192 (auditpol 'Security Group Management') IN 'Success and Failure, Failure, Failure, Success and Failure' 'Success' COLLECTION
check_rule RULE193 (auditpol 'User Account Management') IN 'Success and Failure' 'Success' COLLECTION
check_rule RULE195 (auditpol 'Process Creation') IN 'Success and Failure, Failure, Failure, Success and Failure' 'No Auditing' COLLECTION
check_rule RULE196 (auditpol 'Account Lockout') IN 'Success and Failure, Failure, Failure, Success and Failure' 'Success' COLLECTION
check_rule RULE197 (auditpol 'Group Membership') IN 'Success and Failure, Failure, Failure, Success and Failure' 'No Auditing' COLLECTION
check_rule RULE198 (auditpol 'Logoff') IN 'Success and Failure, Failure, Failure, Success and Failure' 'Success' COLLECTION
check_rule RULE199 (auditpol 'Logon') IN 'Success and Failure' 'Success and Failure' COLLECTION
check_rule RULE200 (auditpol 'Other Logon/Logoff Events') IN 'Success and Failure' 'No Auditing' COLLECTION
check_rule RULE201 (auditpol 'Special Logon') IN 'Success and Failure, Failure, Failure, Success and Failure' 'Success' COLLECTION
check_rule RULE202 (auditpol 'Removable Storage') IN 'Success and Failure' 'No Auditing' COLLECTION
check_rule RULE203 (auditpol 'Audit Policy Change') IN 'Success and Failure, Failure, Failure, Success and Failure' 'Success' COLLECTION
check_rule RULE204 (auditpol 'Authentication Policy Change') IN 'Success and Failure, Failure, Failure, Success and Failure' 'Success' COLLECTION
check_rule RULE205 (auditpol 'Authorization Policy Change') IN 'Success and Failure, Failure, Failure, Success and Failure' 'Success' COLLECTION
check_rule RULE206 (auditpol 'Sensitive Privilege Use') IN 'Success and Failure' 'No Auditing' COLLECTION
check_rule RULE207 (auditpol 'IPsec Driver') IN 'Success and Failure' 'No Auditing' COLLECTION
check_rule RULE208 (auditpol 'Other System Events') IN 'Success and Failure' 'Success and Failure' COLLECTION
check_rule RULE209 (auditpol 'Security State Change') IN 'Success and Failure, Failure, Failure, Success and Failure' 'Success' COLLECTION
check_rule RULE210 (auditpol 'Security System Extension') IN 'Success and Failure, Failure, Failure, Success and Failure' 'No Auditing' COLLECTION
check_rule RULE211 (auditpol 'System Integrity') IN 'Success and Failure' 'Success and Failure' COLLECTION

# ================= Built-in accounts =================
check_rule RULE049 (acct 'LocalAdministrator' 'Disabled') EQUAL 'True' 'False' BOOLEAN
check_rule RULE051 (acct 'LocalGuest' 'Disabled') EQUAL 'True' 'False' BOOLEAN
check_rule RULE053 (acct 'LocalAdministrator' 'Name') NOT_IN 'Administrator' 'Administrator' COLLECTION
check_rule RULE054 (acct 'LocalGuest' 'Name') NOT_IN 'Guest' 'Guest' COLLECTION

# ================= Per-user policy (HKU) =================
check_rule RULE465 (hku 'ScreenSaveActive') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE466 (hku 'SCRNSAVE.EXE') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE467 (hku 'ScreenSaverIsSecure') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE468 (hku 'ScreenSaveTimeOut') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE469 (hku 'NoToastApplicationNotificationOnLockScreen') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE470 (hku 'NoImplicitFeedback') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE471 (hku 'SaveZoneInformation') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE472 (hku 'ScanWithAntiVirus') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE473 (hku 'ConfigureWindowsSpotlight') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE474 (hku 'DisableThirdPartySuggestions') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE475 (hku 'DisableWindowsSpotlightFeatures') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE476 (hku 'NoInplaceSharing') EQUAL '0' '...Count Of all SIDs[0]' INTEGER
check_rule RULE478 (hku 'PreventCodecDownload') EQUAL '0' '...Count Of all SIDs[0]' INTEGER

if ($script:CollectorErrors.Count -gt 0) {
    $parts = @($script:CollectorErrors.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value })
    Write-Output ('COLLECTOR_WARN=FAIL: ' + ($parts -join ' | '))
}
