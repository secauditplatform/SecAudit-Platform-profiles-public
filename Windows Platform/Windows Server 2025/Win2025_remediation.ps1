# SecAudit Platform — Windows Server 2025 remediation
# Generated from audit check_rule expectations.
# Output: REMEDIATE RULExxx= applied|SKIP: ...
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File .\Win2025_remediation.ps1 [-DryRun]
param(
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
if ($env:SECAUDIT_REMEDIATE_DRYRUN -eq '1') { $DryRun = $true }

function Write-RemDone {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Message)
    Write-Output ("REMEDIATE {0}= applied: {1}" -f $Id, $Message)
}

function Write-RemSkip {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Message)
    Write-Output ("REMEDIATE {0}= SKIP: manual step required - {1}" -f $Id, $Message)
}

function Set-SecAuditReg {
    param(
        [Parameter(Mandatory)][string]$RelativeKey,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('INTEGER','STRING','BOOLEAN')][string]$ValueType = 'INTEGER'
    )
    $path = Join-Path 'HKLM:\' $RelativeKey
    if ($DryRun) {
        Write-Verbose ("DRYRUN registry {0}\{1}={2} ({3})" -f $path, $Name, $Value, $ValueType)
        return $true
    }
    try {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        $propName = if ($Name -eq 'Default') { '(default)' } else { $Name }
        switch ($ValueType) {
            'INTEGER' {
                $n = [int64]$Value
                New-ItemProperty -LiteralPath $path -Name $propName -PropertyType DWord -Value ([int]$n) -Force | Out-Null
            }
            'BOOLEAN' {
                $b = if ("$Value" -match '^(1|true|yes)$') { 1 } else { 0 }
                New-ItemProperty -LiteralPath $path -Name $propName -PropertyType DWord -Value $b -Force | Out-Null
            }
            default {
                New-ItemProperty -LiteralPath $path -Name $propName -PropertyType String -Value ([string]$Value) -Force | Out-Null
            }
        }
        return $true
    } catch {
        Write-Warning ("registry set failed {0}\{1}: {2}" -f $RelativeKey, $Name, $_.Exception.Message)
        return $false
    }
}

function Set-SecAuditAuditpol {
    param([Parameter(Mandatory)][string]$Subcategory, [Parameter(Mandatory)][string]$Setting)
    if ($DryRun) {
        Write-Verbose ("DRYRUN auditpol /set /subcategory:{0} => {1}" -f $Subcategory, $Setting)
        return $true
    }
    try {
        $success = 'disable'
        $failure = 'disable'
        switch -Regex ($Setting) {
            'Success and Failure' { $success = 'enable'; $failure = 'enable' }
            '^Success$' { $success = 'enable'; $failure = 'disable' }
            '^Failure$' { $success = 'disable'; $failure = 'enable' }
            default { $success = 'enable'; $failure = 'enable' }
        }
        $args = @('/set', "/subcategory:$Subcategory", "/success:$success", "/failure:$failure")
        $p = Start-Process -FilePath "$env:windir\System32\auditpol.exe" -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
        return ($p.ExitCode -in 0, $null)
    } catch {
        Write-Warning ("auditpol failed {0}: {1}" -f $Subcategory, $_.Exception.Message)
        return $false
    }
}

$script:SystemAccessLines = New-Object System.Collections.Generic.List[string]
$script:PrivilegeLines = New-Object System.Collections.Generic.List[string]

function Queue-SecAuditSysAccess {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value)
    $script:SystemAccessLines.Add(('{0} = {1}' -f $Name, $Value))
}

function Queue-SecAuditPrivilege {
    param([Parameter(Mandatory)][string]$Name, [string]$Value)
    $map = @{
        'Administrators' = '*S-1-5-32-544'
        'Users' = '*S-1-5-32-545'
        'Guests' = '*S-1-5-32-546'
        'Backup Operators' = '*S-1-5-32-551'
        'Remote Desktop Users' = '*S-1-5-32-555'
        'LOCAL SERVICE' = '*S-1-5-19'
        'NETWORK SERVICE' = '*S-1-5-20'
        'SERVICE' = '*S-1-5-6'
        'Everyone' = '*S-1-1-0'
        'Local account' = '*S-1-5-113'
        'Window Manager\Window Manager Group' = '*S-1-5-90-0'
        'ALL SERVICES' = '*S-1-5-80-0'
        'Enterprise Domain Controllers' = '*S-1-5-9'
        'Enterprise Admins' = '*S-1-5-21-*-519'
        'Domain Admins' = '*S-1-5-21-*-512'
    }
    $tokens = @()
    foreach ($t in @(($Value -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        if ($map.ContainsKey($t)) { $tokens += $map[$t] }
        elseif ($t -like 'S-1-*') { $tokens += ('*{0}' -f $t) }
        else { $tokens += $t }
    }
    $rhs = ($tokens -join ',')
    $script:PrivilegeLines.Add(('{0} = {1}' -f $Name, $rhs))
}

function Apply-SecAuditSecedit {
    if ($DryRun) {
        Write-Verbose 'DRYRUN secedit /configure skipped'
        return $true
    }
    if ($script:SystemAccessLines.Count -eq 0 -and $script:PrivilegeLines.Count -eq 0) { return $true }
    $inf = Join-Path $env:TEMP ('secaudit_win2025_rem_{0}.inf' -f (Get-Date).ToFileTime())
    $db = Join-Path $env:TEMP ('secaudit_win2025_rem_{0}.sdb' -f (Get-Date).ToFileTime())
    try {
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add('[Unicode]')
        $lines.Add('Unicode=yes')
        if ($script:SystemAccessLines.Count -gt 0) {
            $lines.Add('[System Access]')
            foreach ($l in $script:SystemAccessLines) { $lines.Add($l) }
        }
        if ($script:PrivilegeLines.Count -gt 0) {
            $lines.Add('[Privilege Rights]')
            foreach ($l in $script:PrivilegeLines) { $lines.Add($l) }
        }
        $lines.Add('[Version]')
        $lines.Add('signature="$CHICAGO$"')
        $lines.Add('Revision=1')
        Set-Content -LiteralPath $inf -Value $lines -Encoding Unicode
        $areas = @()
        if ($script:SystemAccessLines.Count -gt 0) { $areas += 'SECURITYPOLICY' }
        if ($script:PrivilegeLines.Count -gt 0) { $areas += 'USER_RIGHTS' }
        $p = Start-Process -FilePath "$env:windir\System32\secedit.exe" `
            -ArgumentList @('/configure', '/db', $db, '/cfg', $inf, '/areas', ($areas -join ',')) `
            -Wait -PassThru -WindowStyle Hidden
        return ($p.ExitCode -in 0, $null)
    } catch {
        Write-Warning ("secedit configure failed: {0}" -f $_.Exception.Message)
        return $false
    } finally {
        Remove-Item -LiteralPath $inf, $db -Force -ErrorAction SilentlyContinue
    }
}

function Set-SecAuditAccountDisabled {
    param([Parameter(Mandatory)][ValidateSet('LocalAdministrator','LocalGuest')][string]$Which, [bool]$Disabled = $true)
    if ($DryRun) {
        Write-Verbose ("DRYRUN disable account {0}={1}" -f $Which, $Disabled)
        return $true
    }
    try {
        if ($Which -eq 'LocalAdministrator') {
            $u = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
        } else {
            $u = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
        }
        if (-not $u) { return $false }
        if ($Disabled) { Disable-LocalUser -Name $u.Name -ErrorAction Stop }
        else { Enable-LocalUser -Name $u.Name -ErrorAction Stop }
        return $true
    } catch {
        Write-Warning ("account disable failed {0}: {1}" -f $Which, $_.Exception.Message)
        return $false
    }
}

function Rename-SecAuditBuiltIn {
    param([Parameter(Mandatory)][ValidateSet('LocalAdministrator','LocalGuest')][string]$Which, [Parameter(Mandatory)][string]$NewName)
    if ($DryRun) {
        Write-Verbose ("DRYRUN rename {0} => {1}" -f $Which, $NewName)
        return $true
    }
    try {
        if ($Which -eq 'LocalAdministrator') {
            $u = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
        } else {
            $u = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
        }
        if (-not $u) { return $false }
        if ($u.Name -eq $NewName) { return $true }
        Rename-LocalUser -Name $u.Name -NewName $NewName -ErrorAction Stop
        return $true
    } catch {
        Write-Warning ("account rename failed {0}: {1}" -f $Which, $_.Exception.Message)
        return $false
    }
}

Write-Output ("[remediation] starting Windows Server 2025 remediation" + $(if ($DryRun) { " (DryRun)" } else { "" }))

# RULE050
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "noconnecteduser" -Value "3" -ValueType STRING) { Write-RemDone -Id RULE050 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\noconnecteduser=3" } else { Write-RemSkip -Id RULE050 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\noconnecteduser" }

# RULE052
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE052 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=1" } else { Write-RemSkip -Id RULE052 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" }

# RULE056
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "crashonauditfail" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE056 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\crashonauditfail=0" } else { Write-RemSkip -Id RULE056 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\crashonauditfail" }

# RULE057
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "allocatedasd" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE057 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\allocatedasd=0" } else { Write-RemSkip -Id RULE057 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\allocatedasd" }

# RULE058
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE058 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=1" } else { Write-RemSkip -Id RULE058 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers" }

# RULE059
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE059 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=1" } else { Write-RemSkip -Id RULE059 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal" }

# RULE060
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE060 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=1" } else { Write-RemSkip -Id RULE060 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel" }

# RULE062
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE062 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=0" } else { Write-RemSkip -Id RULE062 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange" }

# RULE063
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -Value "30" -ValueType INTEGER) { Write-RemDone -Id RULE063 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=30" } else { Write-RemSkip -Id RULE063 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge" }

# RULE064
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE064 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=1" } else { Write-RemSkip -Id RULE064 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey" }

# RULE065
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "dontdisplaylastusername" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE065 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\dontdisplaylastusername=1" } else { Write-RemSkip -Id RULE065 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\dontdisplaylastusername" }

# RULE066
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "disablecad" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE066 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\disablecad=0" } else { Write-RemSkip -Id RULE066 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\disablecad" }

# RULE068
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "inactivitytimeoutsecs" -Value "900" -ValueType INTEGER) { Write-RemDone -Id RULE068 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\inactivitytimeoutsecs=900" } else { Write-RemSkip -Id RULE068 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\inactivitytimeoutsecs" }

# RULE071
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE071 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=4" } else { Write-RemSkip -Id RULE071 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount" }

# RULE072
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "PasswordExpiryWarning" -Value "14" -ValueType INTEGER) { Write-RemDone -Id RULE072 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=14" } else { Write-RemSkip -Id RULE072 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning" }

# RULE073
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "scremoveoption" -Value "1..2" -ValueType INTEGER) { Write-RemDone -Id RULE073 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\scremoveoption=1..2" } else { Write-RemSkip -Id RULE073 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\scremoveoption" }

# RULE074
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE074 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=1" } else { Write-RemSkip -Id RULE074 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature" }

# RULE075
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE075 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=1" } else { Write-RemSkip -Id RULE075 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature" }

# RULE076
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE076 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=0" } else { Write-RemSkip -Id RULE076 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword" }

# RULE078
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "requiresecuritysignature" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE078 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\requiresecuritysignature=1" } else { Write-RemSkip -Id RULE078 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\requiresecuritysignature" }

# RULE079
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "enablesecuritysignature" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE079 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enablesecuritysignature=1" } else { Write-RemSkip -Id RULE079 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enablesecuritysignature" }

# RULE080
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "enableforcedlogoff" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE080 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enableforcedlogoff=1" } else { Write-RemSkip -Id RULE080 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enableforcedlogoff" }

# RULE081
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "smbservernamehardeninglevel" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE081 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\smbservernamehardeninglevel=1" } else { Write-RemSkip -Id RULE081 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\smbservernamehardeninglevel" }

# RULE083
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymoussam" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE083 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymoussam=1" } else { Write-RemSkip -Id RULE083 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymoussam" }

# RULE084
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE084 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymous=1" } else { Write-RemSkip -Id RULE084 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymous" }

# RULE086
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "everyoneincludesanonymous" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE086 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\everyoneincludesanonymous=0" } else { Write-RemSkip -Id RULE086 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\everyoneincludesanonymous" }

# RULE087
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes" -Value "" -ValueType STRING) { Write-RemDone -Id RULE087 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes=" } else { Write-RemSkip -Id RULE087 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes" }

# RULE090
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "restrictnullsessaccess" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE090 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\restrictnullsessaccess=1" } else { Write-RemSkip -Id RULE090 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\restrictnullsessaccess" }

# RULE091
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictremotesam" -Value "O:BAG:BAD:(A;;RC;;;BA)" -ValueType STRING) { Write-RemDone -Id RULE091 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictremotesam=O:BAG:BAD:(A;;RC;;;BA)" } else { Write-RemSkip -Id RULE091 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictremotesam" }

# RULE092
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "nullsessionshares" -Value "" -ValueType STRING) { Write-RemDone -Id RULE092 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\nullsessionshares=" } else { Write-RemSkip -Id RULE092 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\nullsessionshares" }

# RULE094
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "usemachineid" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE094 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\usemachineid=1" } else { Write-RemSkip -Id RULE094 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\usemachineid" }

# RULE095
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "allownullsessionfallback" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE095 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback=0" } else { Write-RemSkip -Id RULE095 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback" }

# RULE096
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa\pku2u" -Name "allowonlineid" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE096 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u\allowonlineid=0" } else { Write-RemSkip -Id RULE096 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u\allowonlineid" }

# RULE097
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "supportedencryptiontypes" -Value "2147483640" -ValueType STRING) { Write-RemDone -Id RULE097 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\supportedencryptiontypes=2147483640" } else { Write-RemSkip -Id RULE097 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\supportedencryptiontypes" }

# RULE098
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLmHash" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE098 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLmHash=1" } else { Write-RemSkip -Id RULE098 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLmHash" }

# RULE099
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "enableforcedlogoff" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE099 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enableforcedlogoff=1" } else { Write-RemSkip -Id RULE099 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enableforcedlogoff" }

# RULE100
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "lmcompatibilitylevel" -Value "5" -ValueType INTEGER) { Write-RemDone -Id RULE100 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\lmcompatibilitylevel=5" } else { Write-RemSkip -Id RULE100 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\lmcompatibilitylevel" }

# RULE101
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LDAP" -Name "ldapclientintegrity" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE101 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LDAP\ldapclientintegrity=1" } else { Write-RemSkip -Id RULE101 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LDAP\ldapclientintegrity" }

# RULE102
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinClientSec" -Value "537395200" -ValueType STRING) { Write-RemDone -Id RULE102 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinClientSec=537395200" } else { Write-RemSkip -Id RULE102 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinClientSec" }

# RULE106
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE106 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\ProtectionMode=1" } else { Write-RemSkip -Id RULE106 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\ProtectionMode" }

# RULE107
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE107 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=1" } else { Write-RemSkip -Id RULE107 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken" }

# RULE109
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "2" -ValueType INTEGER) { Write-RemDone -Id RULE109 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=2" } else { Write-RemSkip -Id RULE109 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin" }

# RULE110
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE110 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=0" } else { Write-RemSkip -Id RULE110 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser" }

# RULE111
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE111 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=1" } else { Write-RemSkip -Id RULE111 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection" }

# RULE113
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE113 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=1" } else { Write-RemSkip -Id RULE113 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" }

# RULE114
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE114 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=1" } else { Write-RemSkip -Id RULE114 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop" }

# RULE115
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE115 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=1" } else { Write-RemSkip -Id RULE115 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization" }

# RULE158
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE158 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall=1" } else { Write-RemSkip -Id RULE158 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall" }

# RULE160
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultOutboundAction" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE160 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction=0" } else { Write-RemSkip -Id RULE160 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction" }

# RULE161
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DisableNotifications" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE161 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications=1" } else { Write-RemSkip -Id RULE161 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications" }

# RULE164
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogFilePath" -Value "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log" -ValueType STRING) { Write-RemDone -Id RULE164 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath=%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log" } else { Write-RemSkip -Id RULE164 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath" }

# RULE165
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogFileSize" -Value "16384" -ValueType INTEGER) { Write-RemDone -Id RULE165 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize=16384" } else { Write-RemSkip -Id RULE165 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize" }

# RULE166
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogDroppedPackets" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE166 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets=1" } else { Write-RemSkip -Id RULE166 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets" }

# RULE167
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogSuccessfulConnections" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE167 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections=1" } else { Write-RemSkip -Id RULE167 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections" }

# RULE168
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "EnableFirewall" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE168 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall=1" } else { Write-RemSkip -Id RULE168 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall" }

# RULE169
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultInboundAction" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE169 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction=1" } else { Write-RemSkip -Id RULE169 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction" }

# RULE170
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultOutboundAction" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE170 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction=0" } else { Write-RemSkip -Id RULE170 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction" }

# RULE171
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DisableNotifications" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE171 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications=1" } else { Write-RemSkip -Id RULE171 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications" }

# RULE174
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFilePath" -Value "%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log" -ValueType STRING) { Write-RemDone -Id RULE174 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFilePath=%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log" } else { Write-RemSkip -Id RULE174 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFilePath" }

# RULE175
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFileSize" -Value "16384" -ValueType INTEGER) { Write-RemDone -Id RULE175 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize=16384" } else { Write-RemSkip -Id RULE175 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize" }

# RULE176
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogDroppedPackets" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE176 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets=1" } else { Write-RemSkip -Id RULE176 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets" }

# RULE177
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogSuccessfulConnections" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE177 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections=1" } else { Write-RemSkip -Id RULE177 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections" }

# RULE178
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "EnableFirewall" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE178 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall=1" } else { Write-RemSkip -Id RULE178 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall" }

# RULE179
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DefaultInboundAction" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE179 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction=1" } else { Write-RemSkip -Id RULE179 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction" }

# RULE180
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DefaultOutboundAction" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE180 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction=0" } else { Write-RemSkip -Id RULE180 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction" }

# RULE181
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DisableNotifications" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE181 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications=0" } else { Write-RemSkip -Id RULE181 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications" }

# RULE182
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalPolicyMerge" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE182 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge=0" } else { Write-RemSkip -Id RULE182 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge" }

# RULE183
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalIPsecPolicyMerge" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE183 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge=0" } else { Write-RemSkip -Id RULE183 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge" }

# RULE184
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFilePath" -Value "%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log" -ValueType STRING) { Write-RemDone -Id RULE184 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFilePath=%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log" } else { Write-RemSkip -Id RULE184 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFilePath" }

# RULE185
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFileSize" -Value "16384" -ValueType INTEGER) { Write-RemDone -Id RULE185 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize=16384" } else { Write-RemSkip -Id RULE185 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize" }

# RULE186
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogDroppedPackets" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE186 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets=1" } else { Write-RemSkip -Id RULE186 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets" }

# RULE187
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogSuccessfulConnections" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE187 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections=1" } else { Write-RemSkip -Id RULE187 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections" }

# RULE212
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE212 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera=1" } else { Write-RemSkip -Id RULE212 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera" }

# RULE213
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE213 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow=1" } else { Write-RemSkip -Id RULE213 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow" }

# RULE216
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PwdExpirationProtectionEnabled" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE216 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PwdExpirationProtectionEnabled=1" } else { Write-RemSkip -Id RULE216 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PwdExpirationProtectionEnabled" }

# RULE217
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "AdmPwdEnabled" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE217 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled=1" } else { Write-RemSkip -Id RULE217 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled" }

# RULE218
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordComplexity" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE218 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordComplexity=4" } else { Write-RemSkip -Id RULE218 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordComplexity" }

# RULE220
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordAgeDays" -Value "30" -ValueType INTEGER) { Write-RemDone -Id RULE220 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays=30" } else { Write-RemSkip -Id RULE220 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays" }

# RULE221
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE221 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon=0" } else { Write-RemSkip -Id RULE221 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon" }

# RULE223
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value "2" -ValueType INTEGER) { Write-RemDone -Id RULE223 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting=2" } else { Write-RemSkip -Id RULE223 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting" }

# RULE225
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE225 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect=0" } else { Write-RemSkip -Id RULE225 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect" }

# RULE226
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value "300000" -ValueType INTEGER) { Write-RemDone -Id RULE226 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime=300000" } else { Write-RemSkip -Id RULE226 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime" }

# RULE227
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE227 -Message "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NoNameReleaseOnDemand=1" } else { Write-RemSkip -Id RULE227 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NoNameReleaseOnDemand" }

# RULE228
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "PerformRouterDiscovery" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE228 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery=0" } else { Write-RemSkip -Id RULE228 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery" }

# RULE229
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE229 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode=1" } else { Write-RemSkip -Id RULE229 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode" }

# RULE230
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -Value "5" -ValueType INTEGER) { Write-RemDone -Id RULE230 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod=5" } else { Write-RemSkip -Id RULE230 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod" }

# RULE232
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value "3" -ValueType INTEGER) { Write-RemDone -Id RULE232 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions=3" } else { Write-RemSkip -Id RULE232 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions" }

# RULE233
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "WarningLevel" -Value "90" -ValueType INTEGER) { Write-RemDone -Id RULE233 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel=90" } else { Write-RemSkip -Id RULE233 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel" }

# RULE235
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE235 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast=0" } else { Write-RemSkip -Id RULE235 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast" }

# RULE236
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableFontProviders" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE236 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableFontProviders=0" } else { Write-RemSkip -Id RULE236 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableFontProviders" }

# RULE237
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE237 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth=0" } else { Write-RemSkip -Id RULE237 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth" }

# RULE238
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowLLTDIOOnDomain" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE238 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain=0" } else { Write-RemSkip -Id RULE238 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain" }

# RULE239
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowRspndrOnDomain" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE239 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain=0" } else { Write-RemSkip -Id RULE239 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain" }

# RULE240
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE240 -Message "HKLM\SOFTWARE\Policies\Microsoft\Peernet\Disabled=1" } else { Write-RemSkip -Id RULE240 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Peernet\Disabled" }

# RULE241
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE241 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA=0" } else { Write-RemSkip -Id RULE241 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA" }

# RULE242
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE242 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI=0" } else { Write-RemSkip -Id RULE242 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI" }

# RULE243
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE243 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation=1" } else { Write-RemSkip -Id RULE243 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation" }

# RULE246
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE246 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars=0" } else { Write-RemSkip -Id RULE246 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars" }

# RULE248
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value "3" -ValueType INTEGER) { Write-RemDone -Id RULE248 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections=3" } else { Write-RemSkip -Id RULE248 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections" }

# RULE249
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE249 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain=1" } else { Write-RemSkip -Id RULE249 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain" }

# RULE251
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE251 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy=0" } else { Write-RemSkip -Id RULE251 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy" }

# RULE252
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE252 -Message "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=0" } else { Write-RemSkip -Id RULE252 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential" }

# RULE253
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE253 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled=1" } else { Write-RemSkip -Id RULE253 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled" }

# RULE260
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value "3" -ValueType STRING) { Write-RemDone -Id RULE260 -Message "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy=3" } else { Write-RemSkip -Id RULE260 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy" }

# RULE261
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE261 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy=0" } else { Write-RemSkip -Id RULE261 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy" }

# RULE262
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE262 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges=0" } else { Write-RemSkip -Id RULE262 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges" }

# RULE263
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE263 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp=0" } else { Write-RemSkip -Id RULE263 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp" }

# RULE266
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE266 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload=1" } else { Write-RemSkip -Id RULE266 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload" }

# RULE268
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE268 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports=1" } else { Write-RemSkip -Id RULE268 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports" }

# RULE269
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE269 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard\ExitOnMSICW=1" } else { Write-RemSkip -Id RULE269 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard\ExitOnMSICW" }

# RULE272
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Name "NoRegistration" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE272 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control\NoRegistration=1" } else { Write-RemSkip -Id RULE272 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control\NoRegistration" }

# RULE273
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE273 -Message "HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion\DisableContentFileUpdates=1" } else { Write-RemSkip -Id RULE273 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion\DisableContentFileUpdates" }

# RULE274
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoOnlinePrintsWizard" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE274 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoOnlinePrintsWizard=1" } else { Write-RemSkip -Id RULE274 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoOnlinePrintsWizard" }

# RULE275
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPublishingWizard" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE275 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPublishingWizard=1" } else { Write-RemSkip -Id RULE275 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPublishingWizard" }

# RULE276
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Value "2" -ValueType STRING) { Write-RemDone -Id RULE276 -Message "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client\CEIP=2" } else { Write-RemSkip -Id RULE276 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client\CEIP" }

# RULE277
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE277 -Message "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows\CEIPEnable=0" } else { Write-RemSkip -Id RULE277 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows\CEIPEnable" }

# RULE278
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE278 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled=1" } else { Write-RemSkip -Id RULE278 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled" }

# RULE279
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "DevicePKInitBehavior" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE279 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitBehavior=0" } else { Write-RemSkip -Id RULE279 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitBehavior" }

# RULE280
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Control Panel\International" -Name "BlockUserInputMethodsForSignIn" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE280 -Message "HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn=1" } else { Write-RemSkip -Id RULE280 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn" }

# RULE382
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Camera" -Name "AllowCamera" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE382 -Message "HKLM\SOFTWARE\Policies\Microsoft\Camera\AllowCamera=0" } else { Write-RemSkip -Id RULE382 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Camera\AllowCamera" }

# RULE383
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE383 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures=1" } else { Write-RemSkip -Id RULE383 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures" }

# RULE384
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value "2" -ValueType INTEGER) { Write-RemDone -Id RULE384 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing=2" } else { Write-RemSkip -Id RULE384 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing" }

# RULE387
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE387 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry=1" } else { Write-RemSkip -Id RULE387 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry" }

# RULE389
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE389 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications=1" } else { Write-RemSkip -Id RULE389 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications" }

# RULE390
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE390 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview=0" } else { Write-RemSkip -Id RULE390 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview" }

# RULE392
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "Retention" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE392 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention=0" } else { Write-RemSkip -Id RULE392 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention" }

# RULE393
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -Value "32768" -ValueType INTEGER) { Write-RemDone -Id RULE393 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize=32768" } else { Write-RemSkip -Id RULE393 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize" }

# RULE394
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE394 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention=0" } else { Write-RemSkip -Id RULE394 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention" }

# RULE395
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Value "192608" -ValueType INTEGER) { Write-RemDone -Id RULE395 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize=192608" } else { Write-RemSkip -Id RULE395 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize" }

# RULE396
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "Retention" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE396 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\Retention=0" } else { Write-RemSkip -Id RULE396 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\Retention" }

# RULE397
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -Value "32768" -ValueType INTEGER) { Write-RemDone -Id RULE397 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\MaxSize=32768" } else { Write-RemSkip -Id RULE397 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\MaxSize" }

# RULE398
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "Retention" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE398 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\Retention=0" } else { Write-RemSkip -Id RULE398 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\Retention" }

# RULE399
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -Value "32768" -ValueType INTEGER) { Write-RemDone -Id RULE399 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize=32768" } else { Write-RemSkip -Id RULE399 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize" }

# RULE401
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE401 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention=0" } else { Write-RemSkip -Id RULE401 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention" }

# RULE402
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE402 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption=0" } else { Write-RemSkip -Id RULE402 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption" }

# RULE403
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "PreXPSP2ShellProtocolBehavior" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE403 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior=0" } else { Write-RemSkip -Id RULE403 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior" }

# RULE405
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE405 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\DisableWindowsLocationProvider=1" } else { Write-RemSkip -Id RULE405 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\DisableWindowsLocationProvider" }

# RULE417
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE417 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC=1" } else { Write-RemSkip -Id RULE417 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC" }

# RULE418
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE418 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving=1" } else { Write-RemSkip -Id RULE418 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving" }

# RULE420
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE420 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCcm=1" } else { Write-RemSkip -Id RULE420 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCcm" }

# RULE421
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE421 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm=1" } else { Write-RemSkip -Id RULE421 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm" }

# RULE422
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLPT" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE422 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableLPT=1" } else { Write-RemSkip -Id RULE422 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableLPT" }

# RULE423
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisablePNPRedir" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE423 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir=1" } else { Write-RemSkip -Id RULE423 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir" }

# RULE424
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE424 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword=1" } else { Write-RemSkip -Id RULE424 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword" }

# RULE425
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE425 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic=1" } else { Write-RemSkip -Id RULE425 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic" }

# RULE426
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value "3" -ValueType INTEGER) { Write-RemDone -Id RULE426 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel=3" } else { Write-RemSkip -Id RULE426 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel" }

# RULE427
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value "900000" -ValueType INTEGER) { Write-RemDone -Id RULE427 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime=900000" } else { Write-RemSkip -Id RULE427 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime" }

# RULE428
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value "60000" -ValueType INTEGER) { Write-RemDone -Id RULE428 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxDisconnectionTime=60000" } else { Write-RemSkip -Id RULE428 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxDisconnectionTime" }

# RULE429
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DeleteTempDirsOnExit" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE429 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit=1" } else { Write-RemSkip -Id RULE429 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit" }

# RULE430
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "PerSessionTempDir" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE430 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir=1" } else { Write-RemSkip -Id RULE430 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir" }

# RULE431
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE431 -Message "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload=1" } else { Write-RemSkip -Id RULE431 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload" }

# RULE434
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE434 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems=0" } else { Write-RemSkip -Id RULE434 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems" }

# RULE436
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE436 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\NoGenTicket=1" } else { Write-RemSkip -Id RULE436 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\NoGenTicket" }

# RULE441
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE441 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting=0" } else { Write-RemSkip -Id RULE441 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting" }

# RULE442
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE442 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts=1" } else { Write-RemSkip -Id RULE442 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts" }

# RULE444
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE444 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowSuggestedAppsInWindowsInkWorkspace=0" } else { Write-RemSkip -Id RULE444 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowSuggestedAppsInWindowsInkWorkspace" }

# RULE446
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "EnableUserControl" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE446 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\EnableUserControl=0" } else { Write-RemSkip -Id RULE446 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\EnableUserControl" }

# RULE447
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE447 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated=0" } else { Write-RemSkip -Id RULE447 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated" }

# RULE448
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "SafeForScripting" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE448 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\SafeForScripting=0" } else { Write-RemSkip -Id RULE448 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\SafeForScripting" }

# RULE449
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE449 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn=1" } else { Write-RemSkip -Id RULE449 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn" }

# RULE450
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE450 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging=1" } else { Write-RemSkip -Id RULE450 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging" }

# RULE451
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE451 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting=0" } else { Write-RemSkip -Id RULE451 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting" }

# RULE452
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE452 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic=0" } else { Write-RemSkip -Id RULE452 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic" }

# RULE453
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE453 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic=0" } else { Write-RemSkip -Id RULE453 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic" }

# RULE454
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE454 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest=0" } else { Write-RemSkip -Id RULE454 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest" }

# RULE455
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE455 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic=0" } else { Write-RemSkip -Id RULE455 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic" }

# RULE456
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowAutoConfig" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE456 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowAutoConfig=0" } else { Write-RemSkip -Id RULE456 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowAutoConfig" }

# RULE457
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE457 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic=0" } else { Write-RemSkip -Id RULE457 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic" }

# RULE458
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE458 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs=1" } else { Write-RemSkip -Id RULE458 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs" }

# RULE459
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE459 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS\AllowRemoteShellAccess=0" } else { Write-RemSkip -Id RULE459 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS\AllowRemoteShellAccess" }

# RULE461
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE461 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates=1" } else { Write-RemSkip -Id RULE461 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates" }

# RULE462
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE462 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate=0" } else { Write-RemSkip -Id RULE462 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate" }

# RULE463
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE463 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay=0" } else { Write-RemSkip -Id RULE463 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay" }

# RULE464
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE464 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers=0" } else { Write-RemSkip -Id RULE464 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers" }

# RULE479
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE479 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowCrossDeviceClipboard=0" } else { Write-RemSkip -Id RULE479 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowCrossDeviceClipboard" }

# RULE480
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE480 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy=0" } else { Write-RemSkip -Id RULE480 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy" }

# RULE485
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "autodisconnect" -Value "15" -ValueType INTEGER) { Write-RemDone -Id RULE485 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\autodisconnect=15" } else { Write-RemSkip -Id RULE485 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\autodisconnect" }

# RULE486
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "disabledomaincreds" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE486 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\disabledomaincreds=1" } else { Write-RemSkip -Id RULE486 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\disabledomaincreds" }

# RULE487
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" -Name "Machine" -Value "System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, Software\Microsoft\Windows NT\CurrentVersion" -ValueType STRING) { Write-RemDone -Id RULE487 -Message "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, Software\Microsoft\Windows NT\CurrentVersion" } else { Write-RemSkip -Id RULE487 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine" }

# RULE488
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "forceguest" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE488 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\forceguest=0" } else { Write-RemSkip -Id RULE488 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\forceguest" }

# RULE489
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "shutdownwithoutlogon" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE489 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\shutdownwithoutlogon=0" } else { Write-RemSkip -Id RULE489 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\shutdownwithoutlogon" }

# RULE490
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "obcaseinsensitive" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE490 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\obcaseinsensitive=1" } else { Write-RemSkip -Id RULE490 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\obcaseinsensitive" }

# RULE491
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE491 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=1" } else { Write-RemSkip -Id RULE491 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths" }

# RULE497
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE497 -Message "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization=0" } else { Write-RemSkip -Id RULE497 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization" }

# RULE498
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE498 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\AllowOnlineTips=0" } else { Write-RemSkip -Id RULE498 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\AllowOnlineTips" }

# RULE499
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordLength" -Value "15" -ValueType INTEGER) { Write-RemDone -Id RULE499 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordLength=15" } else { Write-RemSkip -Id RULE499 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordLength" }

# RULE500
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE500 -Message "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start=0" } else { Write-RemSkip -Id RULE500 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start" }

# RULE501
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE501 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1=0" } else { Write-RemSkip -Id RULE501 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1" }

# RULE502
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "DisableExceptionChainValidation" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE502 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\DisableExceptionChainValidation=1" } else { Write-RemSkip -Id RULE502 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\DisableExceptionChainValidation" }

# RULE503
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value "2" -ValueType STRING) { Write-RemDone -Id RULE503 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting=2" } else { Write-RemSkip -Id RULE503 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting" }

# RULE504
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -ValueType STRING) { Write-RemDone -Id RULE504 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\NETLOGON=RequireMutualAuthentication=1, RequireIntegrity=1" } else { Write-RemSkip -Id RULE504 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\NETLOGON" }

# RULE505
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE505 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI\DisableWcnUi=1" } else { Write-RemSkip -Id RULE505 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI\DisableWcnUi" }

# RULE506
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE506 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds=1" } else { Write-RemSkip -Id RULE506 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds" }

# RULE507
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE507 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity=1" } else { Write-RemSkip -Id RULE507 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity" }

# RULE508
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value "3" -ValueType STRING) { Write-RemDone -Id RULE508 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures=3" } else { Write-RemSkip -Id RULE508 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures" }

# RULE509
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HypervisorEnforcedCodeIntegrity" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE509 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity=1" } else { Write-RemSkip -Id RULE509 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity" }

# RULE511
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE511 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags=1" } else { Write-RemSkip -Id RULE511 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags" }

# RULE513
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE513 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing=1" } else { Write-RemSkip -Id RULE513 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing" }

# RULE514
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE514 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices=1" } else { Write-RemSkip -Id RULE514 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices" }

# RULE515
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE515 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting=1" } else { Write-RemSkip -Id RULE515 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting" }

# RULE516
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE516 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin=1" } else { Write-RemSkip -Id RULE516 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin" }

# RULE517
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE517 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers=1" } else { Write-RemSkip -Id RULE517 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers" }

# RULE518
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE518 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockDomainPicturePassword=1" } else { Write-RemSkip -Id RULE518 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockDomainPicturePassword" }

# RULE519
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE519 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex=0" } else { Write-RemSkip -Id RULE519 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex" }

# RULE520
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE520 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex=0" } else { Write-RemSkip -Id RULE520 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex" }

# RULE521
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE521 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo\DisabledByGroupPolicy=1" } else { Write-RemSkip -Id RULE521 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo\DisabledByGroupPolicy" }

# RULE522
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -Name "Enabled" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE522 -Message "HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient\Enabled=1" } else { Write-RemSkip -Id RULE522 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient\Enabled" }

# RULE523
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer" -Name "Enabled" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE523 -Message "HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled=0" } else { Write-RemSkip -Id RULE523 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled" }

# RULE525
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE525 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal=1" } else { Write-RemSkip -Id RULE525 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal" }

# RULE526
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE526 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators=0" } else { Write-RemSkip -Id RULE526 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators" }

# RULE527
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableEnterpriseAuthProxy" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE527 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DisableEnterpriseAuthProxy=1" } else { Write-RemSkip -Id RULE527 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DisableEnterpriseAuthProxy" }

# RULE528
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE528 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging\AllowMessageSync=0" } else { Write-RemSkip -Id RULE528 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging\AllowMessageSync" }

# RULE529
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE529 -Message "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount\DisableUserAuth=1" } else { Write-RemSkip -Id RULE529 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount\DisableUserAuth" }

# RULE530
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fSingleSessionPerUser" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE530 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fSingleSessionPerUser=1" } else { Write-RemSkip -Id RULE530 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fSingleSessionPerUser" }

# RULE531
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE531 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCloudSearch=0" } else { Write-RemSkip -Id RULE531 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCloudSearch" }

# RULE532
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE532 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting=0" } else { Write-RemSkip -Id RULE532 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting" }

# RULE533
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE533 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring=1" } else { Write-RemSkip -Id RULE533 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring" }

# RULE534
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE534 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning=0" } else { Write-RemSkip -Id RULE534 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning" }

# RULE535
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE535 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning=1" } else { Write-RemSkip -Id RULE535 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning" }

# RULE536
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE536 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection=1" } else { Write-RemSkip -Id RULE536 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection" }

# RULE537
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE537 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware=0" } else { Write-RemSkip -Id RULE537 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware" }

# RULE538
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "DisallowExploitProtectionOverride" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE538 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\DisallowExploitProtectionOverride=1" } else { Write-RemSkip -Id RULE538 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\DisallowExploitProtectionOverride" }

# RULE540
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE540 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuilds=1" } else { Write-RemSkip -Id RULE540 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuilds" }

# RULE543
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE543 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI=1" } else { Write-RemSkip -Id RULE543 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI" }

# RULE544
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnumerateLocalUsers" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE544 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers=0" } else { Write-RemSkip -Id RULE544 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers" }

# RULE545
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE545 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications=1" } else { Write-RemSkip -Id RULE545 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications" }

# RULE546
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE546 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon=0" } else { Write-RemSkip -Id RULE546 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon" }

# RULE548
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "DCSettingIndex" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE548 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex=1" } else { Write-RemSkip -Id RULE548 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex" }

# RULE549
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "ACSettingIndex" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE549 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex=1" } else { Write-RemSkip -Id RULE549 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex" }

# RULE550
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE550 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited=0" } else { Write-RemSkip -Id RULE550 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited" }

# RULE551
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE551 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp=0" } else { Write-RemSkip -Id RULE551 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp" }

# RULE552
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE552 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution=0" } else { Write-RemSkip -Id RULE552 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution" }

# RULE553
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE553 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients=1" } else { Write-RemSkip -Id RULE553 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients" }

# RULE554
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE554 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer=0" } else { Write-RemSkip -Id RULE554 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer" }

# RULE555
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name "ScenarioExecutionEnabled" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE555 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled=0" } else { Write-RemSkip -Id RULE555 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled" }

# RULE556
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" -Name "AllowSharedLocalAppData" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE556 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\AllowSharedLocalAppData=0" } else { Write-RemSkip -Id RULE556 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\AllowSharedLocalAppData" }

# RULE557
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE557 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional=1" } else { Write-RemSkip -Id RULE557 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional" }

# RULE558
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE558 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume=1" } else { Write-RemSkip -Id RULE558 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume" }

# RULE559
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE559 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun=1" } else { Write-RemSkip -Id RULE559 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun" }

# RULE560
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value "255" -ValueType STRING) { Write-RemDone -Id RULE560 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun=255" } else { Write-RemSkip -Id RULE560 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun" }

# RULE562
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "submitcontrol" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE562 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\submitcontrol=0" } else { Write-RemSkip -Id RULE562 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\submitcontrol" }

# RULE564
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "refusepasswordchange" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE564 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\refusepasswordchange=0" } else { Write-RemSkip -Id RULE564 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\refusepasswordchange" }

# RULE565
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE565 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\legalnoticetext=0" } else { Write-RemSkip -Id RULE565 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\legalnoticetext" }

# RULE566
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceUnlockLogon" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE566 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=1" } else { Write-RemSkip -Id RULE566 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon" }

# RULE567
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" -Name "Machine" -Value "System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog" -ValueType STRING) { Write-RemDone -Id RULE567 -Message "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog" } else { Write-RemSkip -Id RULE567 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine" }

# RULE569
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE569 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp=1" } else { Write-RemSkip -Id RULE569 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp" }

# RULE889
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE889 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuildsPolicyValue=0" } else { Write-RemSkip -Id RULE889 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuildsPolicyValue" }

# RULE890
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value "180" -ValueType INTEGER) { Write-RemDone -Id RULE890 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays=180" } else { Write-RemSkip -Id RULE890 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays" }

# RULE5041
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -ValueType STRING) { Write-RemDone -Id RULE5041 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\SYSVOL=RequireMutualAuthentication=1, RequireIntegrity=1" } else { Write-RemSkip -Id RULE5041 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\SYSVOL" }

# RULE891
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "RedirectionguardPolicy" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE891 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RedirectionguardPolicy=1" } else { Write-RemSkip -Id RULE891 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RedirectionguardPolicy" }

# RULE892
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE892 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators=1" } else { Write-RemSkip -Id RULE892 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators" }

# RULE893
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCustomSSPsAPs" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE893 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowCustomSSPsAPs=0" } else { Write-RemSkip -Id RULE893 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowCustomSSPsAPs" }

# RULE999
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE999 -Message "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity=1" } else { Write-RemSkip -Id RULE999 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity" }

# RULE998
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE998 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen=1" } else { Write-RemSkip -Id RULE998 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen" }

# RULE997
if (Set-SecAuditReg -RelativeKey "Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE997 -Message "HKLM\Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck=1" } else { Write-RemSkip -Id RULE997 -Message "failed to set HKLM\Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck" }

# RULE996
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "ExpectedDialupDelay" -Value "2000" -ValueType INTEGER) { Write-RemDone -Id RULE996 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ExpectedDialupDelay=2000" } else { Write-RemSkip -Id RULE996 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ExpectedDialupDelay" }

# RULE991
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Bowser" -Name "EnableMailslots" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE991 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Bowser\EnableMailslots=0" } else { Write-RemSkip -Id RULE991 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Bowser\EnableMailslots" }

# RULE990
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LanmanServer" -Name "AuditClientDoesNotSupportEncryption" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE990 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\AuditClientDoesNotSupportEncryption=1" } else { Write-RemSkip -Id RULE990 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\AuditClientDoesNotSupportEncryption" }

# RULE989
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Netlogon\Parameters" -Name "BlockNetbiosDiscovery" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE989 -Message "HKLM\SOFTWARE\Policies\Microsoft\Netlogon\Parameters\BlockNetbiosDiscovery=1" } else { Write-RemSkip -Id RULE989 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Netlogon\Parameters\BlockNetbiosDiscovery" }

# RULE985
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "DevicePKInitEnabled" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE985 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled=1" } else { Write-RemSkip -Id RULE985 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled" }

# RULE984
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableBkGndGroupPolicy" -Value "" -ValueType STRING) { Write-RemDone -Id RULE984 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy=" } else { Write-RemSkip -Id RULE984 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy" }

# RULE981
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE981 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled=1" } else { Write-RemSkip -Id RULE981 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled" }

# RULE980
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -Value "255" -ValueType STRING) { Write-RemDone -Id RULE980 -Message "HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\DisabledComponents=255" } else { Write-RemSkip -Id RULE980 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\DisabledComponents" }

# RULE979
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "RunAsPPL " -Value "1" -ValueType STRING) { Write-RemDone -Id RULE979 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\RunAsPPL =1" } else { Write-RemSkip -Id RULE979 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\RunAsPPL " }

# RULE978
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block" -ValueType STRING) { Write-RemDone -Id RULE978 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ShellSmartScreenLevel=Block" } else { Write-RemSkip -Id RULE978 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ShellSmartScreenLevel" }

# RULE977
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LanmanServer" -Name "InvalidAuthenticationDelayTimeInMs" -Value "2000" -ValueType INTEGER) { Write-RemDone -Id RULE977 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\InvalidAuthenticationDelayTimeInMs=2000" } else { Write-RemSkip -Id RULE977 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\InvalidAuthenticationDelayTimeInMs" }

# RULE975
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" -Name "RpcUseNamedPipeProtocol" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE975 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC\RpcUseNamedPipeProtocol=0" } else { Write-RemSkip -Id RULE975 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC\RpcUseNamedPipeProtocol" }

# RULE974
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE974 -Message "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DoReport=0" } else { Write-RemSkip -Id RULE974 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DoReport" }

# RULE001
Queue-SecAuditSysAccess -Name "PasswordHistorySize" -Value "24"
Write-RemDone -Id RULE001 -Message "queued System Access PasswordHistorySize=24"

# RULE002
Queue-SecAuditSysAccess -Name "MaximumPasswordAge" -Value "60"
Write-RemDone -Id RULE002 -Message "queued System Access MaximumPasswordAge=60"

# RULE003
Queue-SecAuditSysAccess -Name "MinimumPasswordAge" -Value "1"
Write-RemDone -Id RULE003 -Message "queued System Access MinimumPasswordAge=1"

# RULE004
Queue-SecAuditSysAccess -Name "MinimumPasswordLength" -Value "14"
Write-RemDone -Id RULE004 -Message "queued System Access MinimumPasswordLength=14"

# RULE005
Queue-SecAuditSysAccess -Name "PasswordComplexity" -Value "1"
Write-RemDone -Id RULE005 -Message "queued System Access PasswordComplexity=1"

# RULE007
Queue-SecAuditSysAccess -Name "LockoutDuration" -Value "15"
Write-RemDone -Id RULE007 -Message "queued System Access LockoutDuration=15"

# RULE008
Queue-SecAuditSysAccess -Name "LockoutBadCount" -Value "10"
Write-RemDone -Id RULE008 -Message "queued System Access LockoutBadCount=10"

# RULE009
Queue-SecAuditSysAccess -Name "ResetLockoutCount" -Value "15"
Write-RemDone -Id RULE009 -Message "queued System Access ResetLockoutCount=15"

# RULE010
Queue-SecAuditPrivilege -Name "SeTrustedCredManAccessPrivilege" -Value ""
Write-RemDone -Id RULE010 -Message "queued privilege SeTrustedCredManAccessPrivilege"

# RULE011
Queue-SecAuditPrivilege -Name "SeNetworkLogonRight" -Value "Administrators,Authenticated Users"
Write-RemDone -Id RULE011 -Message "queued privilege SeNetworkLogonRight"

# RULE012
Queue-SecAuditPrivilege -Name "SeTcbPrivilege" -Value ""
Write-RemDone -Id RULE012 -Message "queued privilege SeTcbPrivilege"

# RULE013
Queue-SecAuditPrivilege -Name "SeIncreaseQuotaPrivilege" -Value "Administrators"
Write-RemDone -Id RULE013 -Message "queued privilege SeIncreaseQuotaPrivilege"

# RULE014
Queue-SecAuditPrivilege -Name "SeInteractiveLogonRight" -Value "Administrators"
Write-RemDone -Id RULE014 -Message "queued privilege SeInteractiveLogonRight"

# RULE015
Queue-SecAuditPrivilege -Name "SeRemoteInteractiveLogonRight" -Value "Administrators,Remote Desktop Users"
Write-RemDone -Id RULE015 -Message "queued privilege SeRemoteInteractiveLogonRight"

# RULE016
Queue-SecAuditPrivilege -Name "SeBackupPrivilege" -Value "Administrators"
Write-RemDone -Id RULE016 -Message "queued privilege SeBackupPrivilege"

# RULE017
Queue-SecAuditPrivilege -Name "SeSystemtimePrivilege" -Value "Administrators, LOCAL SERVICE"
Write-RemDone -Id RULE017 -Message "queued privilege SeSystemtimePrivilege"

# RULE018
Queue-SecAuditPrivilege -Name "SeTimeZonePrivilege" -Value "Administrators, LOCAL SERVICE"
Write-RemDone -Id RULE018 -Message "queued privilege SeTimeZonePrivilege"

# RULE019
Queue-SecAuditPrivilege -Name "SeCreatePagefilePrivilege" -Value "Administrators"
Write-RemDone -Id RULE019 -Message "queued privilege SeCreatePagefilePrivilege"

# RULE020
Queue-SecAuditPrivilege -Name "SeCreateTokenPrivilege" -Value ""
Write-RemDone -Id RULE020 -Message "queued privilege SeCreateTokenPrivilege"

# RULE021
Queue-SecAuditPrivilege -Name "SeCreateGlobalPrivilege" -Value "Administrators,LOCAL SERVICE,NETWORK SERVICE"
Write-RemDone -Id RULE021 -Message "queued privilege SeCreateGlobalPrivilege"

# RULE022
Queue-SecAuditPrivilege -Name "SeCreatePermanentPrivilege" -Value ""
Write-RemDone -Id RULE022 -Message "queued privilege SeCreatePermanentPrivilege"

# RULE023
Queue-SecAuditPrivilege -Name "SeCreateSymbolicLinkPrivilege" -Value "Administrators"
Write-RemDone -Id RULE023 -Message "queued privilege SeCreateSymbolicLinkPrivilege"

# RULE024
Queue-SecAuditPrivilege -Name "SeDebugPrivilege" -Value "Administrators"
Write-RemDone -Id RULE024 -Message "queued privilege SeDebugPrivilege"

# RULE025
Queue-SecAuditPrivilege -Name "SeDenyNetworkLogonRight" -Value "Guests,Local account"
Write-RemDone -Id RULE025 -Message "queued privilege SeDenyNetworkLogonRight"

# RULE026
Queue-SecAuditPrivilege -Name "SeDenyBatchLogonRight" -Value "Guests"
Write-RemDone -Id RULE026 -Message "queued privilege SeDenyBatchLogonRight"

# RULE027
Queue-SecAuditPrivilege -Name "SeDenyServiceLogonRight" -Value "Guests"
Write-RemDone -Id RULE027 -Message "queued privilege SeDenyServiceLogonRight"

# RULE028
Queue-SecAuditPrivilege -Name "SeDenyInteractiveLogonRight" -Value "Guests"
Write-RemDone -Id RULE028 -Message "queued privilege SeDenyInteractiveLogonRight"

# RULE030
Queue-SecAuditPrivilege -Name "SeEnableDelegationPrivilege" -Value ""
Write-RemDone -Id RULE030 -Message "queued privilege SeEnableDelegationPrivilege"

# RULE031
Queue-SecAuditPrivilege -Name "SeRemoteShutdownPrivilege" -Value "Administrators"
Write-RemDone -Id RULE031 -Message "queued privilege SeRemoteShutdownPrivilege"

# RULE032
Queue-SecAuditPrivilege -Name "SeAuditPrivilege" -Value "LOCAL SERVICE,NETWORK SERVICE"
Write-RemDone -Id RULE032 -Message "queued privilege SeAuditPrivilege"

# RULE033
Queue-SecAuditPrivilege -Name "SeImpersonatePrivilege" -Value "Administrators,LOCAL SERVICE,NETWORK SERVICE"
Write-RemDone -Id RULE033 -Message "queued privilege SeImpersonatePrivilege"

# RULE034
Queue-SecAuditPrivilege -Name "SeIncreaseBasePriorityPrivilege" -Value "Administrators"
Write-RemDone -Id RULE034 -Message "queued privilege SeIncreaseBasePriorityPrivilege"

# RULE035
Queue-SecAuditPrivilege -Name "SeLoadDriverPrivilege" -Value "Administrators"
Write-RemDone -Id RULE035 -Message "queued privilege SeLoadDriverPrivilege"

# RULE036
Queue-SecAuditPrivilege -Name "SeLockMemoryPrivilege" -Value ""
Write-RemDone -Id RULE036 -Message "queued privilege SeLockMemoryPrivilege"

# RULE037
Queue-SecAuditPrivilege -Name "SeBatchLogonRight" -Value "Administrators"
Write-RemDone -Id RULE037 -Message "queued privilege SeBatchLogonRight"

# RULE039
Queue-SecAuditPrivilege -Name "SeSecurityPrivilege" -Value "Administrators"
Write-RemDone -Id RULE039 -Message "queued privilege SeSecurityPrivilege"

# RULE040
Queue-SecAuditPrivilege -Name "SeRelabelPrivilege" -Value ""
Write-RemDone -Id RULE040 -Message "queued privilege SeRelabelPrivilege"

# RULE041
Queue-SecAuditPrivilege -Name "SeSystemEnvironmentPrivilege" -Value "Administrators"
Write-RemDone -Id RULE041 -Message "queued privilege SeSystemEnvironmentPrivilege"

# RULE042
Queue-SecAuditPrivilege -Name "SeManageVolumePrivilege" -Value "Administrators"
Write-RemDone -Id RULE042 -Message "queued privilege SeManageVolumePrivilege"

# RULE043
Queue-SecAuditPrivilege -Name "SeProfileSingleProcessPrivilege" -Value "Administrators"
Write-RemDone -Id RULE043 -Message "queued privilege SeProfileSingleProcessPrivilege"

# RULE045
Queue-SecAuditPrivilege -Name "SeAssignPrimaryTokenPrivilege" -Value "LOCAL SERVICE,NETWORK SERVICE"
Write-RemDone -Id RULE045 -Message "queued privilege SeAssignPrimaryTokenPrivilege"

# RULE046
Queue-SecAuditPrivilege -Name "SeRestorePrivilege" -Value "Administrators"
Write-RemDone -Id RULE046 -Message "queued privilege SeRestorePrivilege"

# RULE047
Queue-SecAuditPrivilege -Name "SeShutdownPrivilege" -Value "Administrators"
Write-RemDone -Id RULE047 -Message "queued privilege SeShutdownPrivilege"

# RULE048
Queue-SecAuditPrivilege -Name "SeTakeOwnershipPrivilege" -Value "Administrators"
Write-RemDone -Id RULE048 -Message "queued privilege SeTakeOwnershipPrivilege"

# RULE188
if (Set-SecAuditAuditpol -Subcategory "Credential Validation" -Setting "Success and Failure") { Write-RemDone -Id RULE188 -Message "auditpol Credential Validation => Success and Failure" } else { Write-RemSkip -Id RULE188 -Message "auditpol set failed for Credential Validation" }

# RULE189
if (Set-SecAuditAuditpol -Subcategory "Application Group Management" -Setting "Success and Failure") { Write-RemDone -Id RULE189 -Message "auditpol Application Group Management => Success and Failure" } else { Write-RemSkip -Id RULE189 -Message "auditpol set failed for Application Group Management" }

# RULE192
if (Set-SecAuditAuditpol -Subcategory "Security Group Management" -Setting "Success and Failure") { Write-RemDone -Id RULE192 -Message "auditpol Security Group Management => Success and Failure" } else { Write-RemSkip -Id RULE192 -Message "auditpol set failed for Security Group Management" }

# RULE193
if (Set-SecAuditAuditpol -Subcategory "User Account Management" -Setting "Success and Failure") { Write-RemDone -Id RULE193 -Message "auditpol User Account Management => Success and Failure" } else { Write-RemSkip -Id RULE193 -Message "auditpol set failed for User Account Management" }

# RULE195
if (Set-SecAuditAuditpol -Subcategory "Process Creation" -Setting "Success and Failure") { Write-RemDone -Id RULE195 -Message "auditpol Process Creation => Success and Failure" } else { Write-RemSkip -Id RULE195 -Message "auditpol set failed for Process Creation" }

# RULE196
if (Set-SecAuditAuditpol -Subcategory "Account Lockout" -Setting "Success and Failure") { Write-RemDone -Id RULE196 -Message "auditpol Account Lockout => Success and Failure" } else { Write-RemSkip -Id RULE196 -Message "auditpol set failed for Account Lockout" }

# RULE197
if (Set-SecAuditAuditpol -Subcategory "Group Membership" -Setting "Success and Failure") { Write-RemDone -Id RULE197 -Message "auditpol Group Membership => Success and Failure" } else { Write-RemSkip -Id RULE197 -Message "auditpol set failed for Group Membership" }

# RULE198
if (Set-SecAuditAuditpol -Subcategory "Logoff" -Setting "Success and Failure") { Write-RemDone -Id RULE198 -Message "auditpol Logoff => Success and Failure" } else { Write-RemSkip -Id RULE198 -Message "auditpol set failed for Logoff" }

# RULE199
if (Set-SecAuditAuditpol -Subcategory "Logon" -Setting "Success and Failure") { Write-RemDone -Id RULE199 -Message "auditpol Logon => Success and Failure" } else { Write-RemSkip -Id RULE199 -Message "auditpol set failed for Logon" }

# RULE200
if (Set-SecAuditAuditpol -Subcategory "Other Logon/Logoff Events" -Setting "Success and Failure") { Write-RemDone -Id RULE200 -Message "auditpol Other Logon/Logoff Events => Success and Failure" } else { Write-RemSkip -Id RULE200 -Message "auditpol set failed for Other Logon/Logoff Events" }

# RULE201
if (Set-SecAuditAuditpol -Subcategory "Special Logon" -Setting "Success and Failure") { Write-RemDone -Id RULE201 -Message "auditpol Special Logon => Success and Failure" } else { Write-RemSkip -Id RULE201 -Message "auditpol set failed for Special Logon" }

# RULE202
if (Set-SecAuditAuditpol -Subcategory "Removable Storage" -Setting "Success and Failure") { Write-RemDone -Id RULE202 -Message "auditpol Removable Storage => Success and Failure" } else { Write-RemSkip -Id RULE202 -Message "auditpol set failed for Removable Storage" }

# RULE203
if (Set-SecAuditAuditpol -Subcategory "Audit Policy Change" -Setting "Success and Failure") { Write-RemDone -Id RULE203 -Message "auditpol Audit Policy Change => Success and Failure" } else { Write-RemSkip -Id RULE203 -Message "auditpol set failed for Audit Policy Change" }

# RULE204
if (Set-SecAuditAuditpol -Subcategory "Authentication Policy Change" -Setting "Success and Failure") { Write-RemDone -Id RULE204 -Message "auditpol Authentication Policy Change => Success and Failure" } else { Write-RemSkip -Id RULE204 -Message "auditpol set failed for Authentication Policy Change" }

# RULE205
if (Set-SecAuditAuditpol -Subcategory "Authorization Policy Change" -Setting "Success and Failure") { Write-RemDone -Id RULE205 -Message "auditpol Authorization Policy Change => Success and Failure" } else { Write-RemSkip -Id RULE205 -Message "auditpol set failed for Authorization Policy Change" }

# RULE206
if (Set-SecAuditAuditpol -Subcategory "Sensitive Privilege Use" -Setting "Success and Failure") { Write-RemDone -Id RULE206 -Message "auditpol Sensitive Privilege Use => Success and Failure" } else { Write-RemSkip -Id RULE206 -Message "auditpol set failed for Sensitive Privilege Use" }

# RULE207
if (Set-SecAuditAuditpol -Subcategory "IPsec Driver" -Setting "Success and Failure") { Write-RemDone -Id RULE207 -Message "auditpol IPsec Driver => Success and Failure" } else { Write-RemSkip -Id RULE207 -Message "auditpol set failed for IPsec Driver" }

# RULE208
if (Set-SecAuditAuditpol -Subcategory "Other System Events" -Setting "Success and Failure") { Write-RemDone -Id RULE208 -Message "auditpol Other System Events => Success and Failure" } else { Write-RemSkip -Id RULE208 -Message "auditpol set failed for Other System Events" }

# RULE209
if (Set-SecAuditAuditpol -Subcategory "Security State Change" -Setting "Success and Failure") { Write-RemDone -Id RULE209 -Message "auditpol Security State Change => Success and Failure" } else { Write-RemSkip -Id RULE209 -Message "auditpol set failed for Security State Change" }

# RULE210
if (Set-SecAuditAuditpol -Subcategory "Security System Extension" -Setting "Success and Failure") { Write-RemDone -Id RULE210 -Message "auditpol Security System Extension => Success and Failure" } else { Write-RemSkip -Id RULE210 -Message "auditpol set failed for Security System Extension" }

# RULE211
if (Set-SecAuditAuditpol -Subcategory "System Integrity" -Setting "Success and Failure") { Write-RemDone -Id RULE211 -Message "auditpol System Integrity => Success and Failure" } else { Write-RemSkip -Id RULE211 -Message "auditpol set failed for System Integrity" }

# RULE049
if (Set-SecAuditAccountDisabled -Which "LocalAdministrator" -Disabled $true) { Write-RemDone -Id RULE049 -Message "disabled LocalAdministrator" } else { Write-RemSkip -Id RULE049 -Message "could not disable LocalAdministrator" }

# RULE051
if (Set-SecAuditAccountDisabled -Which "LocalGuest" -Disabled $true) { Write-RemDone -Id RULE051 -Message "disabled LocalGuest" } else { Write-RemSkip -Id RULE051 -Message "could not disable LocalGuest" }

# RULE053
if (Rename-SecAuditBuiltIn -Which "LocalAdministrator" -NewName "SecAuditAdmin") { Write-RemDone -Id RULE053 -Message "renamed LocalAdministrator to SecAuditAdmin" } else { Write-RemSkip -Id RULE053 -Message "could not rename LocalAdministrator" }

# RULE054
if (Rename-SecAuditBuiltIn -Which "LocalGuest" -NewName "SecAuditGuest") { Write-RemDone -Id RULE054 -Message "renamed LocalGuest to SecAuditGuest" } else { Write-RemSkip -Id RULE054 -Message "could not rename LocalGuest" }

# RULE465
Write-RemSkip -Id RULE465 -Message "HKU/ScreenSaveActive is per-user; apply via default user hive or GPO manually"

# RULE466
Write-RemSkip -Id RULE466 -Message "HKU/SCRNSAVE.EXE is per-user; apply via default user hive or GPO manually"

# RULE467
Write-RemSkip -Id RULE467 -Message "HKU/ScreenSaverIsSecure is per-user; apply via default user hive or GPO manually"

# RULE468
Write-RemSkip -Id RULE468 -Message "HKU/ScreenSaveTimeOut is per-user; apply via default user hive or GPO manually"

# RULE469
Write-RemSkip -Id RULE469 -Message "HKU/NoToastApplicationNotificationOnLockScreen is per-user; apply via default user hive or GPO manually"

# RULE470
Write-RemSkip -Id RULE470 -Message "HKU/NoImplicitFeedback is per-user; apply via default user hive or GPO manually"

# RULE471
Write-RemSkip -Id RULE471 -Message "HKU/SaveZoneInformation is per-user; apply via default user hive or GPO manually"

# RULE472
Write-RemSkip -Id RULE472 -Message "HKU/ScanWithAntiVirus is per-user; apply via default user hive or GPO manually"

# RULE473
Write-RemSkip -Id RULE473 -Message "HKU/ConfigureWindowsSpotlight is per-user; apply via default user hive or GPO manually"

# RULE474
Write-RemSkip -Id RULE474 -Message "HKU/DisableThirdPartySuggestions is per-user; apply via default user hive or GPO manually"

# RULE475
Write-RemSkip -Id RULE475 -Message "HKU/DisableWindowsSpotlightFeatures is per-user; apply via default user hive or GPO manually"

# RULE476
Write-RemSkip -Id RULE476 -Message "HKU/NoInplaceSharing is per-user; apply via default user hive or GPO manually"

# RULE478
Write-RemSkip -Id RULE478 -Message "HKU/PreventCodecDownload is per-user; apply via default user hive or GPO manually"

# Apply queued secedit System Access + Privilege Rights in one pass
if (Apply-SecAuditSecedit) {
    Write-Output "[remediation] secedit configure applied (or DryRun/empty)"
} else {
    Write-Output "[remediation] secedit configure reported errors (see warnings)"
}

Write-Output "[remediation] remediation complete (Win2025_remediation.ps1)"
