# SecAudit rule allowlist — paste into audit/remediation PowerShell scripts.
# Unset/empty SECAUDIT_RULES and SECAUDIT_REMEDIATE_RULES => all rules enabled.
function Test-SecAuditRuleEnabled {
    param([Parameter(Mandatory=$true)][string]$Id)
    $raw = $env:SECAUDIT_RULES
    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = $env:SECAUDIT_REMEDIATE_RULES }
    if ([string]::IsNullOrWhiteSpace($raw)) { return $true }
    $want = $Id.Trim().ToUpperInvariant()
    if ($want -match '^RULE0*(\d+)$') { $want = "RULE$([int]$Matches[1])" }
    foreach ($token in ($raw -split ',')) {
        $t = $token.Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if ($t -match '^RULE0*(\d+)$') { $t = "RULE$([int]$Matches[1])" }
        if ($t -eq $want) { return $true }
    }
    return $false
}

function Get-SecAuditApplyValue {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Fallback,
        [ValidateSet('raw','high','low')][string]$Pick = 'raw'
    )
    $key = 'SECAUDIT_VAR_' + (($Id -replace '\s','').ToUpper())
    $raw = [Environment]::GetEnvironmentVariable($key)
    if ([string]::IsNullOrEmpty($raw)) { return $Fallback }
    if ($Pick -ne 'raw' -and $raw -match '^(-?\d+)\.\.(-?\d+)$') {
        if ($Pick -eq 'low') { return $Matches[1] }
        return $Matches[2]
    }
    return $raw
}


﻿# SecAudit Platform — Windows Server 2025 remediation
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
    if (-not (Test-SecAuditRuleEnabled -Id $Id)) { return }
    Write-Output ("REMEDIATE {0}= applied: {1}" -f $Id, $Message)
}

function Write-RemSkip {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Message)
    if (-not (Test-SecAuditRuleEnabled -Id $Id)) { return }
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
# RULE050
if (Test-SecAuditRuleEnabled -Id 'RULE050') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "noconnecteduser" -Value "$(Get-SecAuditApplyValue -Id 'RULE050' -Fallback '3' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE050 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\noconnecteduser=$(Get-SecAuditApplyValue -Id 'RULE050' -Fallback '3' -Pick raw)" } else { Write-RemSkip -Id RULE050 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\noconnecteduser" } }

# RULE052
# RULE052
if (Test-SecAuditRuleEnabled -Id 'RULE052') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value "$(Get-SecAuditApplyValue -Id 'RULE052' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE052 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=$(Get-SecAuditApplyValue -Id 'RULE052' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE052 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" } }

# RULE056
# RULE056
if (Test-SecAuditRuleEnabled -Id 'RULE056') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "crashonauditfail" -Value "$(Get-SecAuditApplyValue -Id 'RULE056' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE056 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\crashonauditfail=$(Get-SecAuditApplyValue -Id 'RULE056' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE056 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\crashonauditfail" } }

# RULE057
# RULE057
if (Test-SecAuditRuleEnabled -Id 'RULE057') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "allocatedasd" -Value "$(Get-SecAuditApplyValue -Id 'RULE057' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE057 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\allocatedasd=$(Get-SecAuditApplyValue -Id 'RULE057' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE057 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\allocatedasd" } }

# RULE058
# RULE058
if (Test-SecAuditRuleEnabled -Id 'RULE058') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value "$(Get-SecAuditApplyValue -Id 'RULE058' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE058 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=$(Get-SecAuditApplyValue -Id 'RULE058' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE058 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers" } }

# RULE059
# RULE059
if (Test-SecAuditRuleEnabled -Id 'RULE059') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value "$(Get-SecAuditApplyValue -Id 'RULE059' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE059 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=$(Get-SecAuditApplyValue -Id 'RULE059' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE059 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal" } }

# RULE060
# RULE060
if (Test-SecAuditRuleEnabled -Id 'RULE060') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value "$(Get-SecAuditApplyValue -Id 'RULE060' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE060 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=$(Get-SecAuditApplyValue -Id 'RULE060' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE060 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel" } }

# RULE062
# RULE062
if (Test-SecAuditRuleEnabled -Id 'RULE062') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value "$(Get-SecAuditApplyValue -Id 'RULE062' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE062 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=$(Get-SecAuditApplyValue -Id 'RULE062' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE062 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange" } }

# RULE063
# RULE063
if (Test-SecAuditRuleEnabled -Id 'RULE063') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -Value "$(Get-SecAuditApplyValue -Id 'RULE063' -Fallback '30' -Pick high)" -ValueType INTEGER) { Write-RemDone -Id RULE063 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=$(Get-SecAuditApplyValue -Id 'RULE063' -Fallback '30' -Pick high)" } else { Write-RemSkip -Id RULE063 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge" } }

# RULE064
# RULE064
if (Test-SecAuditRuleEnabled -Id 'RULE064') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value "$(Get-SecAuditApplyValue -Id 'RULE064' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE064 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=$(Get-SecAuditApplyValue -Id 'RULE064' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE064 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey" } }

# RULE065
# RULE065
if (Test-SecAuditRuleEnabled -Id 'RULE065') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "dontdisplaylastusername" -Value "$(Get-SecAuditApplyValue -Id 'RULE065' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE065 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\dontdisplaylastusername=$(Get-SecAuditApplyValue -Id 'RULE065' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE065 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\dontdisplaylastusername" } }

# RULE066
# RULE066
if (Test-SecAuditRuleEnabled -Id 'RULE066') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "disablecad" -Value "$(Get-SecAuditApplyValue -Id 'RULE066' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE066 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\disablecad=$(Get-SecAuditApplyValue -Id 'RULE066' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE066 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\disablecad" } }

# RULE068
# RULE068
if (Test-SecAuditRuleEnabled -Id 'RULE068') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "inactivitytimeoutsecs" -Value "$(Get-SecAuditApplyValue -Id 'RULE068' -Fallback '900' -Pick high)" -ValueType INTEGER) { Write-RemDone -Id RULE068 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\inactivitytimeoutsecs=$(Get-SecAuditApplyValue -Id 'RULE068' -Fallback '900' -Pick high)" } else { Write-RemSkip -Id RULE068 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\inactivitytimeoutsecs" } }

# RULE071
# RULE071
if (Test-SecAuditRuleEnabled -Id 'RULE071') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "$(Get-SecAuditApplyValue -Id 'RULE071' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE071 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=$(Get-SecAuditApplyValue -Id 'RULE071' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE071 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount" } }

# RULE072
# RULE072
if (Test-SecAuditRuleEnabled -Id 'RULE072') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "PasswordExpiryWarning" -Value "$(Get-SecAuditApplyValue -Id 'RULE072' -Fallback '14' -Pick high)" -ValueType INTEGER) { Write-RemDone -Id RULE072 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=$(Get-SecAuditApplyValue -Id 'RULE072' -Fallback '14' -Pick high)" } else { Write-RemSkip -Id RULE072 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning" } }

# RULE073
# RULE073
if (Test-SecAuditRuleEnabled -Id 'RULE073') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "scremoveoption" -Value "$(Get-SecAuditApplyValue -Id 'RULE073' -Fallback '1..2' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE073 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\scremoveoption=$(Get-SecAuditApplyValue -Id 'RULE073' -Fallback '1..2' -Pick raw)" } else { Write-RemSkip -Id RULE073 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\scremoveoption" } }

# RULE074
# RULE074
if (Test-SecAuditRuleEnabled -Id 'RULE074') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value "$(Get-SecAuditApplyValue -Id 'RULE074' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE074 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=$(Get-SecAuditApplyValue -Id 'RULE074' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE074 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature" } }

# RULE075
# RULE075
if (Test-SecAuditRuleEnabled -Id 'RULE075') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value "$(Get-SecAuditApplyValue -Id 'RULE075' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE075 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=$(Get-SecAuditApplyValue -Id 'RULE075' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE075 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature" } }

# RULE076
# RULE076
if (Test-SecAuditRuleEnabled -Id 'RULE076') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value "$(Get-SecAuditApplyValue -Id 'RULE076' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE076 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=$(Get-SecAuditApplyValue -Id 'RULE076' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE076 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword" } }

# RULE078
# RULE078
if (Test-SecAuditRuleEnabled -Id 'RULE078') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "requiresecuritysignature" -Value "$(Get-SecAuditApplyValue -Id 'RULE078' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE078 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\requiresecuritysignature=$(Get-SecAuditApplyValue -Id 'RULE078' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE078 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\requiresecuritysignature" } }

# RULE079
# RULE079
if (Test-SecAuditRuleEnabled -Id 'RULE079') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "enablesecuritysignature" -Value "$(Get-SecAuditApplyValue -Id 'RULE079' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE079 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enablesecuritysignature=$(Get-SecAuditApplyValue -Id 'RULE079' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE079 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enablesecuritysignature" } }

# RULE080
# RULE080
if (Test-SecAuditRuleEnabled -Id 'RULE080') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "enableforcedlogoff" -Value "$(Get-SecAuditApplyValue -Id 'RULE080' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE080 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enableforcedlogoff=$(Get-SecAuditApplyValue -Id 'RULE080' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE080 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enableforcedlogoff" } }

# RULE081
# RULE081
if (Test-SecAuditRuleEnabled -Id 'RULE081') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "smbservernamehardeninglevel" -Value "$(Get-SecAuditApplyValue -Id 'RULE081' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE081 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\smbservernamehardeninglevel=$(Get-SecAuditApplyValue -Id 'RULE081' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE081 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\smbservernamehardeninglevel" } }

# RULE083
# RULE083
if (Test-SecAuditRuleEnabled -Id 'RULE083') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymoussam" -Value "$(Get-SecAuditApplyValue -Id 'RULE083' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE083 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymoussam=$(Get-SecAuditApplyValue -Id 'RULE083' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE083 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymoussam" } }

# RULE084
# RULE084
if (Test-SecAuditRuleEnabled -Id 'RULE084') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value "$(Get-SecAuditApplyValue -Id 'RULE084' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE084 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymous=$(Get-SecAuditApplyValue -Id 'RULE084' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE084 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymous" } }

# RULE086
# RULE086
if (Test-SecAuditRuleEnabled -Id 'RULE086') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "everyoneincludesanonymous" -Value "$(Get-SecAuditApplyValue -Id 'RULE086' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE086 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\everyoneincludesanonymous=$(Get-SecAuditApplyValue -Id 'RULE086' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE086 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\everyoneincludesanonymous" } }

# RULE087
# RULE087
if (Test-SecAuditRuleEnabled -Id 'RULE087') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes" -Value "$(Get-SecAuditApplyValue -Id 'RULE087' -Fallback '' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE087 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes=" } else { Write-RemSkip -Id RULE087 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes" } }

# RULE090
# RULE090
if (Test-SecAuditRuleEnabled -Id 'RULE090') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "restrictnullsessaccess" -Value "$(Get-SecAuditApplyValue -Id 'RULE090' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE090 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\restrictnullsessaccess=$(Get-SecAuditApplyValue -Id 'RULE090' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE090 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\restrictnullsessaccess" } }

# RULE091
# RULE091
if (Test-SecAuditRuleEnabled -Id 'RULE091') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictremotesam" -Value "$(Get-SecAuditApplyValue -Id 'RULE091' -Fallback 'O:BAG:BAD:(A;;RC;;;BA)' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE091 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictremotesam=$(Get-SecAuditApplyValue -Id 'RULE091' -Fallback 'O:BAG:BAD:(A;;RC;;;BA)' -Pick raw)" } else { Write-RemSkip -Id RULE091 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictremotesam" } }

# RULE092
# RULE092
if (Test-SecAuditRuleEnabled -Id 'RULE092') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "nullsessionshares" -Value "$(Get-SecAuditApplyValue -Id 'RULE092' -Fallback '' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE092 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\nullsessionshares=" } else { Write-RemSkip -Id RULE092 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\nullsessionshares" } }

# RULE094
# RULE094
if (Test-SecAuditRuleEnabled -Id 'RULE094') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "usemachineid" -Value "$(Get-SecAuditApplyValue -Id 'RULE094' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE094 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\usemachineid=$(Get-SecAuditApplyValue -Id 'RULE094' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE094 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\usemachineid" } }

# RULE095
# RULE095
if (Test-SecAuditRuleEnabled -Id 'RULE095') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "allownullsessionfallback" -Value "$(Get-SecAuditApplyValue -Id 'RULE095' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE095 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback=$(Get-SecAuditApplyValue -Id 'RULE095' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE095 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback" } }

# RULE096
# RULE096
if (Test-SecAuditRuleEnabled -Id 'RULE096') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa\pku2u" -Name "allowonlineid" -Value "$(Get-SecAuditApplyValue -Id 'RULE096' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE096 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u\allowonlineid=$(Get-SecAuditApplyValue -Id 'RULE096' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE096 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u\allowonlineid" } }

# RULE097
# RULE097
if (Test-SecAuditRuleEnabled -Id 'RULE097') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "supportedencryptiontypes" -Value "$(Get-SecAuditApplyValue -Id 'RULE097' -Fallback '2147483640' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE097 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\supportedencryptiontypes=$(Get-SecAuditApplyValue -Id 'RULE097' -Fallback '2147483640' -Pick raw)" } else { Write-RemSkip -Id RULE097 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\supportedencryptiontypes" } }

# RULE098
# RULE098
if (Test-SecAuditRuleEnabled -Id 'RULE098') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLmHash" -Value "$(Get-SecAuditApplyValue -Id 'RULE098' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE098 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLmHash=$(Get-SecAuditApplyValue -Id 'RULE098' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE098 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLmHash" } }

# RULE099
# RULE099
if (Test-SecAuditRuleEnabled -Id 'RULE099') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "enableforcedlogoff" -Value "$(Get-SecAuditApplyValue -Id 'RULE099' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE099 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enableforcedlogoff=$(Get-SecAuditApplyValue -Id 'RULE099' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE099 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enableforcedlogoff" } }

# RULE100
# RULE100
if (Test-SecAuditRuleEnabled -Id 'RULE100') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "lmcompatibilitylevel" -Value "$(Get-SecAuditApplyValue -Id 'RULE100' -Fallback '5' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE100 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\lmcompatibilitylevel=$(Get-SecAuditApplyValue -Id 'RULE100' -Fallback '5' -Pick raw)" } else { Write-RemSkip -Id RULE100 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\lmcompatibilitylevel" } }

# RULE101
# RULE101
if (Test-SecAuditRuleEnabled -Id 'RULE101') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LDAP" -Name "ldapclientintegrity" -Value "$(Get-SecAuditApplyValue -Id 'RULE101' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE101 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LDAP\ldapclientintegrity=$(Get-SecAuditApplyValue -Id 'RULE101' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE101 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LDAP\ldapclientintegrity" } }

# RULE102
# RULE102
if (Test-SecAuditRuleEnabled -Id 'RULE102') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinClientSec" -Value "$(Get-SecAuditApplyValue -Id 'RULE102' -Fallback '537395200' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE102 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinClientSec=$(Get-SecAuditApplyValue -Id 'RULE102' -Fallback '537395200' -Pick raw)" } else { Write-RemSkip -Id RULE102 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinClientSec" } }

# RULE106
# RULE106
if (Test-SecAuditRuleEnabled -Id 'RULE106') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value "$(Get-SecAuditApplyValue -Id 'RULE106' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE106 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\ProtectionMode=$(Get-SecAuditApplyValue -Id 'RULE106' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE106 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\ProtectionMode" } }

# RULE107
# RULE107
if (Test-SecAuditRuleEnabled -Id 'RULE107') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value "$(Get-SecAuditApplyValue -Id 'RULE107' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE107 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=$(Get-SecAuditApplyValue -Id 'RULE107' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE107 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken" } }

# RULE109
# RULE109
if (Test-SecAuditRuleEnabled -Id 'RULE109') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "$(Get-SecAuditApplyValue -Id 'RULE109' -Fallback '2' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE109 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=$(Get-SecAuditApplyValue -Id 'RULE109' -Fallback '2' -Pick raw)" } else { Write-RemSkip -Id RULE109 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin" } }

# RULE110
# RULE110
if (Test-SecAuditRuleEnabled -Id 'RULE110') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value "$(Get-SecAuditApplyValue -Id 'RULE110' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE110 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=$(Get-SecAuditApplyValue -Id 'RULE110' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE110 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser" } }

# RULE111
# RULE111
if (Test-SecAuditRuleEnabled -Id 'RULE111') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Value "$(Get-SecAuditApplyValue -Id 'RULE111' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE111 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=$(Get-SecAuditApplyValue -Id 'RULE111' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE111 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection" } }

# RULE113
# RULE113
if (Test-SecAuditRuleEnabled -Id 'RULE113') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "$(Get-SecAuditApplyValue -Id 'RULE113' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE113 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=$(Get-SecAuditApplyValue -Id 'RULE113' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE113 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" } }

# RULE114
# RULE114
if (Test-SecAuditRuleEnabled -Id 'RULE114') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value "$(Get-SecAuditApplyValue -Id 'RULE114' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE114 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=$(Get-SecAuditApplyValue -Id 'RULE114' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE114 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop" } }

# RULE115
# RULE115
if (Test-SecAuditRuleEnabled -Id 'RULE115') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value "$(Get-SecAuditApplyValue -Id 'RULE115' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE115 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=$(Get-SecAuditApplyValue -Id 'RULE115' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE115 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization" } }

# RULE158
# RULE158
if (Test-SecAuditRuleEnabled -Id 'RULE158') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -Value "$(Get-SecAuditApplyValue -Id 'RULE158' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE158 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall=$(Get-SecAuditApplyValue -Id 'RULE158' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE158 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall" } }

# RULE160
# RULE160
if (Test-SecAuditRuleEnabled -Id 'RULE160') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultOutboundAction" -Value "$(Get-SecAuditApplyValue -Id 'RULE160' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE160 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction=$(Get-SecAuditApplyValue -Id 'RULE160' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE160 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction" } }

# RULE161
# RULE161
if (Test-SecAuditRuleEnabled -Id 'RULE161') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DisableNotifications" -Value "$(Get-SecAuditApplyValue -Id 'RULE161' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE161 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications=$(Get-SecAuditApplyValue -Id 'RULE161' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE161 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications" } }

# RULE164
# RULE164
if (Test-SecAuditRuleEnabled -Id 'RULE164') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogFilePath" -Value "$(Get-SecAuditApplyValue -Id 'RULE164' -Fallback '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE164 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath=$(Get-SecAuditApplyValue -Id 'RULE164' -Fallback '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log' -Pick raw)" } else { Write-RemSkip -Id RULE164 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath" } }

# RULE165
# RULE165
if (Test-SecAuditRuleEnabled -Id 'RULE165') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogFileSize" -Value "$(Get-SecAuditApplyValue -Id 'RULE165' -Fallback '16384' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE165 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize=$(Get-SecAuditApplyValue -Id 'RULE165' -Fallback '16384' -Pick raw)" } else { Write-RemSkip -Id RULE165 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize" } }

# RULE166
# RULE166
if (Test-SecAuditRuleEnabled -Id 'RULE166') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogDroppedPackets" -Value "$(Get-SecAuditApplyValue -Id 'RULE166' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE166 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets=$(Get-SecAuditApplyValue -Id 'RULE166' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE166 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets" } }

# RULE167
# RULE167
if (Test-SecAuditRuleEnabled -Id 'RULE167') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogSuccessfulConnections" -Value "$(Get-SecAuditApplyValue -Id 'RULE167' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE167 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections=$(Get-SecAuditApplyValue -Id 'RULE167' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE167 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections" } }

# RULE168
# RULE168
if (Test-SecAuditRuleEnabled -Id 'RULE168') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "EnableFirewall" -Value "$(Get-SecAuditApplyValue -Id 'RULE168' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE168 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall=$(Get-SecAuditApplyValue -Id 'RULE168' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE168 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall" } }

# RULE169
# RULE169
if (Test-SecAuditRuleEnabled -Id 'RULE169') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultInboundAction" -Value "$(Get-SecAuditApplyValue -Id 'RULE169' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE169 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction=$(Get-SecAuditApplyValue -Id 'RULE169' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE169 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction" } }

# RULE170
# RULE170
if (Test-SecAuditRuleEnabled -Id 'RULE170') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultOutboundAction" -Value "$(Get-SecAuditApplyValue -Id 'RULE170' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE170 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction=$(Get-SecAuditApplyValue -Id 'RULE170' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE170 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction" } }

# RULE171
# RULE171
if (Test-SecAuditRuleEnabled -Id 'RULE171') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DisableNotifications" -Value "$(Get-SecAuditApplyValue -Id 'RULE171' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE171 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications=$(Get-SecAuditApplyValue -Id 'RULE171' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE171 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications" } }

# RULE174
# RULE174
if (Test-SecAuditRuleEnabled -Id 'RULE174') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFilePath" -Value "$(Get-SecAuditApplyValue -Id 'RULE174' -Fallback '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE174 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFilePath=$(Get-SecAuditApplyValue -Id 'RULE174' -Fallback '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log' -Pick raw)" } else { Write-RemSkip -Id RULE174 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFilePath" } }

# RULE175
# RULE175
if (Test-SecAuditRuleEnabled -Id 'RULE175') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFileSize" -Value "$(Get-SecAuditApplyValue -Id 'RULE175' -Fallback '16384' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE175 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize=$(Get-SecAuditApplyValue -Id 'RULE175' -Fallback '16384' -Pick raw)" } else { Write-RemSkip -Id RULE175 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize" } }

# RULE176
# RULE176
if (Test-SecAuditRuleEnabled -Id 'RULE176') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogDroppedPackets" -Value "$(Get-SecAuditApplyValue -Id 'RULE176' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE176 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets=$(Get-SecAuditApplyValue -Id 'RULE176' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE176 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets" } }

# RULE177
# RULE177
if (Test-SecAuditRuleEnabled -Id 'RULE177') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogSuccessfulConnections" -Value "$(Get-SecAuditApplyValue -Id 'RULE177' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE177 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections=$(Get-SecAuditApplyValue -Id 'RULE177' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE177 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections" } }

# RULE178
# RULE178
if (Test-SecAuditRuleEnabled -Id 'RULE178') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "EnableFirewall" -Value "$(Get-SecAuditApplyValue -Id 'RULE178' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE178 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall=$(Get-SecAuditApplyValue -Id 'RULE178' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE178 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall" } }

# RULE179
# RULE179
if (Test-SecAuditRuleEnabled -Id 'RULE179') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DefaultInboundAction" -Value "$(Get-SecAuditApplyValue -Id 'RULE179' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE179 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction=$(Get-SecAuditApplyValue -Id 'RULE179' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE179 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction" } }

# RULE180
# RULE180
if (Test-SecAuditRuleEnabled -Id 'RULE180') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DefaultOutboundAction" -Value "$(Get-SecAuditApplyValue -Id 'RULE180' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE180 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction=$(Get-SecAuditApplyValue -Id 'RULE180' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE180 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction" } }

# RULE181
# RULE181
if (Test-SecAuditRuleEnabled -Id 'RULE181') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DisableNotifications" -Value "$(Get-SecAuditApplyValue -Id 'RULE181' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE181 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications=$(Get-SecAuditApplyValue -Id 'RULE181' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE181 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications" } }

# RULE182
# RULE182
if (Test-SecAuditRuleEnabled -Id 'RULE182') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalPolicyMerge" -Value "$(Get-SecAuditApplyValue -Id 'RULE182' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE182 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge=$(Get-SecAuditApplyValue -Id 'RULE182' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE182 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge" } }

# RULE183
# RULE183
if (Test-SecAuditRuleEnabled -Id 'RULE183') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalIPsecPolicyMerge" -Value "$(Get-SecAuditApplyValue -Id 'RULE183' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE183 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge=$(Get-SecAuditApplyValue -Id 'RULE183' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE183 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge" } }

# RULE184
# RULE184
if (Test-SecAuditRuleEnabled -Id 'RULE184') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFilePath" -Value "$(Get-SecAuditApplyValue -Id 'RULE184' -Fallback '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE184 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFilePath=$(Get-SecAuditApplyValue -Id 'RULE184' -Fallback '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log' -Pick raw)" } else { Write-RemSkip -Id RULE184 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFilePath" } }

# RULE185
# RULE185
if (Test-SecAuditRuleEnabled -Id 'RULE185') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFileSize" -Value "$(Get-SecAuditApplyValue -Id 'RULE185' -Fallback '16384' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE185 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize=$(Get-SecAuditApplyValue -Id 'RULE185' -Fallback '16384' -Pick raw)" } else { Write-RemSkip -Id RULE185 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize" } }

# RULE186
# RULE186
if (Test-SecAuditRuleEnabled -Id 'RULE186') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogDroppedPackets" -Value "$(Get-SecAuditApplyValue -Id 'RULE186' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE186 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets=$(Get-SecAuditApplyValue -Id 'RULE186' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE186 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets" } }

# RULE187
# RULE187
if (Test-SecAuditRuleEnabled -Id 'RULE187') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogSuccessfulConnections" -Value "$(Get-SecAuditApplyValue -Id 'RULE187' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE187 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections=$(Get-SecAuditApplyValue -Id 'RULE187' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE187 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections" } }

# RULE212
# RULE212
if (Test-SecAuditRuleEnabled -Id 'RULE212') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value "$(Get-SecAuditApplyValue -Id 'RULE212' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE212 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera=$(Get-SecAuditApplyValue -Id 'RULE212' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE212 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera" } }

# RULE213
# RULE213
if (Test-SecAuditRuleEnabled -Id 'RULE213') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Value "$(Get-SecAuditApplyValue -Id 'RULE213' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE213 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow=$(Get-SecAuditApplyValue -Id 'RULE213' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE213 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow" } }

# RULE216
# RULE216
if (Test-SecAuditRuleEnabled -Id 'RULE216') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PwdExpirationProtectionEnabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE216' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE216 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PwdExpirationProtectionEnabled=$(Get-SecAuditApplyValue -Id 'RULE216' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE216 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PwdExpirationProtectionEnabled" } }

# RULE217
# RULE217
if (Test-SecAuditRuleEnabled -Id 'RULE217') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "AdmPwdEnabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE217' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE217 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled=$(Get-SecAuditApplyValue -Id 'RULE217' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE217 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled" } }

# RULE218
# RULE218
if (Test-SecAuditRuleEnabled -Id 'RULE218') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordComplexity" -Value "$(Get-SecAuditApplyValue -Id 'RULE218' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE218 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordComplexity=$(Get-SecAuditApplyValue -Id 'RULE218' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE218 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordComplexity" } }

# RULE220
# RULE220
if (Test-SecAuditRuleEnabled -Id 'RULE220') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordAgeDays" -Value "$(Get-SecAuditApplyValue -Id 'RULE220' -Fallback '30' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE220 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays=$(Get-SecAuditApplyValue -Id 'RULE220' -Fallback '30' -Pick raw)" } else { Write-RemSkip -Id RULE220 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays" } }

# RULE221
# RULE221
if (Test-SecAuditRuleEnabled -Id 'RULE221') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "$(Get-SecAuditApplyValue -Id 'RULE221' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE221 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon=$(Get-SecAuditApplyValue -Id 'RULE221' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE221 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon" } }

# RULE223
# RULE223
if (Test-SecAuditRuleEnabled -Id 'RULE223') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value "$(Get-SecAuditApplyValue -Id 'RULE223' -Fallback '2' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE223 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting=$(Get-SecAuditApplyValue -Id 'RULE223' -Fallback '2' -Pick raw)" } else { Write-RemSkip -Id RULE223 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting" } }

# RULE225
# RULE225
if (Test-SecAuditRuleEnabled -Id 'RULE225') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value "$(Get-SecAuditApplyValue -Id 'RULE225' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE225 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect=$(Get-SecAuditApplyValue -Id 'RULE225' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE225 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect" } }

# RULE226
# RULE226
if (Test-SecAuditRuleEnabled -Id 'RULE226') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value "$(Get-SecAuditApplyValue -Id 'RULE226' -Fallback '300000' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE226 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime=$(Get-SecAuditApplyValue -Id 'RULE226' -Fallback '300000' -Pick raw)" } else { Write-RemSkip -Id RULE226 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime" } }

# RULE227
# RULE227
if (Test-SecAuditRuleEnabled -Id 'RULE227') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value "$(Get-SecAuditApplyValue -Id 'RULE227' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE227 -Message "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NoNameReleaseOnDemand=$(Get-SecAuditApplyValue -Id 'RULE227' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE227 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NoNameReleaseOnDemand" } }

# RULE228
# RULE228
if (Test-SecAuditRuleEnabled -Id 'RULE228') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "PerformRouterDiscovery" -Value "$(Get-SecAuditApplyValue -Id 'RULE228' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE228 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery=$(Get-SecAuditApplyValue -Id 'RULE228' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE228 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery" } }

# RULE229
# RULE229
if (Test-SecAuditRuleEnabled -Id 'RULE229') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value "$(Get-SecAuditApplyValue -Id 'RULE229' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE229 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode=$(Get-SecAuditApplyValue -Id 'RULE229' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE229 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode" } }

# RULE230
# RULE230
if (Test-SecAuditRuleEnabled -Id 'RULE230') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -Value "$(Get-SecAuditApplyValue -Id 'RULE230' -Fallback '5' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE230 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod=$(Get-SecAuditApplyValue -Id 'RULE230' -Fallback '5' -Pick raw)" } else { Write-RemSkip -Id RULE230 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod" } }

# RULE232
# RULE232
if (Test-SecAuditRuleEnabled -Id 'RULE232') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value "$(Get-SecAuditApplyValue -Id 'RULE232' -Fallback '3' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE232 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions=$(Get-SecAuditApplyValue -Id 'RULE232' -Fallback '3' -Pick raw)" } else { Write-RemSkip -Id RULE232 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions" } }

# RULE233
# RULE233
if (Test-SecAuditRuleEnabled -Id 'RULE233') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "WarningLevel" -Value "$(Get-SecAuditApplyValue -Id 'RULE233' -Fallback '90' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE233 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel=$(Get-SecAuditApplyValue -Id 'RULE233' -Fallback '90' -Pick raw)" } else { Write-RemSkip -Id RULE233 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel" } }

# RULE235
# RULE235
if (Test-SecAuditRuleEnabled -Id 'RULE235') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value "$(Get-SecAuditApplyValue -Id 'RULE235' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE235 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast=$(Get-SecAuditApplyValue -Id 'RULE235' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE235 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast" } }

# RULE236
# RULE236
if (Test-SecAuditRuleEnabled -Id 'RULE236') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableFontProviders" -Value "$(Get-SecAuditApplyValue -Id 'RULE236' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE236 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableFontProviders=$(Get-SecAuditApplyValue -Id 'RULE236' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE236 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableFontProviders" } }

# RULE237
# RULE237
if (Test-SecAuditRuleEnabled -Id 'RULE237') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value "$(Get-SecAuditApplyValue -Id 'RULE237' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE237 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth=$(Get-SecAuditApplyValue -Id 'RULE237' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE237 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth" } }

# RULE238
# RULE238
if (Test-SecAuditRuleEnabled -Id 'RULE238') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowLLTDIOOnDomain" -Value "$(Get-SecAuditApplyValue -Id 'RULE238' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE238 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain=$(Get-SecAuditApplyValue -Id 'RULE238' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE238 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain" } }

# RULE239
# RULE239
if (Test-SecAuditRuleEnabled -Id 'RULE239') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowRspndrOnDomain" -Value "$(Get-SecAuditApplyValue -Id 'RULE239' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE239 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain=$(Get-SecAuditApplyValue -Id 'RULE239' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE239 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain" } }

# RULE240
# RULE240
if (Test-SecAuditRuleEnabled -Id 'RULE240') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE240' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE240 -Message "HKLM\SOFTWARE\Policies\Microsoft\Peernet\Disabled=$(Get-SecAuditApplyValue -Id 'RULE240' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE240 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Peernet\Disabled" } }

# RULE241
# RULE241
if (Test-SecAuditRuleEnabled -Id 'RULE241') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -Value "$(Get-SecAuditApplyValue -Id 'RULE241' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE241 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA=$(Get-SecAuditApplyValue -Id 'RULE241' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE241 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA" } }

# RULE242
# RULE242
if (Test-SecAuditRuleEnabled -Id 'RULE242') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value "$(Get-SecAuditApplyValue -Id 'RULE242' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE242 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI=$(Get-SecAuditApplyValue -Id 'RULE242' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE242 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI" } }

# RULE243
# RULE243
if (Test-SecAuditRuleEnabled -Id 'RULE243') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -Value "$(Get-SecAuditApplyValue -Id 'RULE243' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE243 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation=$(Get-SecAuditApplyValue -Id 'RULE243' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE243 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation" } }

# RULE246
# RULE246
if (Test-SecAuditRuleEnabled -Id 'RULE246') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Value "$(Get-SecAuditApplyValue -Id 'RULE246' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE246 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars=$(Get-SecAuditApplyValue -Id 'RULE246' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE246 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars" } }

# RULE248
# RULE248
if (Test-SecAuditRuleEnabled -Id 'RULE248') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value "$(Get-SecAuditApplyValue -Id 'RULE248' -Fallback '3' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE248 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections=$(Get-SecAuditApplyValue -Id 'RULE248' -Fallback '3' -Pick raw)" } else { Write-RemSkip -Id RULE248 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections" } }

# RULE249
# RULE249
if (Test-SecAuditRuleEnabled -Id 'RULE249') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -Value "$(Get-SecAuditApplyValue -Id 'RULE249' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE249 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain=$(Get-SecAuditApplyValue -Id 'RULE249' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE249 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain" } }

# RULE251
# RULE251
if (Test-SecAuditRuleEnabled -Id 'RULE251') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE251' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE251 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy=$(Get-SecAuditApplyValue -Id 'RULE251' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE251 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy" } }

# RULE252
# RULE252
if (Test-SecAuditRuleEnabled -Id 'RULE252') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value "$(Get-SecAuditApplyValue -Id 'RULE252' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE252 -Message "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=$(Get-SecAuditApplyValue -Id 'RULE252' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE252 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential" } }

# RULE253
# RULE253
if (Test-SecAuditRuleEnabled -Id 'RULE253') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE253' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE253 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled=$(Get-SecAuditApplyValue -Id 'RULE253' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE253 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled" } }

# RULE260
# RULE260
if (Test-SecAuditRuleEnabled -Id 'RULE260') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE260' -Fallback '3' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE260 -Message "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy=$(Get-SecAuditApplyValue -Id 'RULE260' -Fallback '3' -Pick raw)" } else { Write-RemSkip -Id RULE260 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy" } }

# RULE261
# RULE261
if (Test-SecAuditRuleEnabled -Id 'RULE261') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE261' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE261 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy=$(Get-SecAuditApplyValue -Id 'RULE261' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE261 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy" } }

# RULE262
# RULE262
if (Test-SecAuditRuleEnabled -Id 'RULE262') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -Value "$(Get-SecAuditApplyValue -Id 'RULE262' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE262 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges=$(Get-SecAuditApplyValue -Id 'RULE262' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE262 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges" } }

# RULE263
# RULE263
if (Test-SecAuditRuleEnabled -Id 'RULE263') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value "$(Get-SecAuditApplyValue -Id 'RULE263' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE263 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp=$(Get-SecAuditApplyValue -Id 'RULE263' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE263 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp" } }

# RULE266
# RULE266
if (Test-SecAuditRuleEnabled -Id 'RULE266') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value "$(Get-SecAuditApplyValue -Id 'RULE266' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE266 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload=$(Get-SecAuditApplyValue -Id 'RULE266' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE266 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload" } }

# RULE268
# RULE268
if (Test-SecAuditRuleEnabled -Id 'RULE268') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value "$(Get-SecAuditApplyValue -Id 'RULE268' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE268 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports=$(Get-SecAuditApplyValue -Id 'RULE268' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE268 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports" } }

# RULE269
# RULE269
if (Test-SecAuditRuleEnabled -Id 'RULE269') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -Value "$(Get-SecAuditApplyValue -Id 'RULE269' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE269 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard\ExitOnMSICW=$(Get-SecAuditApplyValue -Id 'RULE269' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE269 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard\ExitOnMSICW" } }

# RULE272
# RULE272
if (Test-SecAuditRuleEnabled -Id 'RULE272') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Name "NoRegistration" -Value "$(Get-SecAuditApplyValue -Id 'RULE272' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE272 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control\NoRegistration=$(Get-SecAuditApplyValue -Id 'RULE272' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE272 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control\NoRegistration" } }

# RULE273
# RULE273
if (Test-SecAuditRuleEnabled -Id 'RULE273') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -Value "$(Get-SecAuditApplyValue -Id 'RULE273' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE273 -Message "HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion\DisableContentFileUpdates=$(Get-SecAuditApplyValue -Id 'RULE273' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE273 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion\DisableContentFileUpdates" } }

# RULE274
# RULE274
if (Test-SecAuditRuleEnabled -Id 'RULE274') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoOnlinePrintsWizard" -Value "$(Get-SecAuditApplyValue -Id 'RULE274' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE274 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoOnlinePrintsWizard=$(Get-SecAuditApplyValue -Id 'RULE274' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE274 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoOnlinePrintsWizard" } }

# RULE275
# RULE275
if (Test-SecAuditRuleEnabled -Id 'RULE275') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPublishingWizard" -Value "$(Get-SecAuditApplyValue -Id 'RULE275' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE275 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPublishingWizard=$(Get-SecAuditApplyValue -Id 'RULE275' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE275 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPublishingWizard" } }

# RULE276
# RULE276
if (Test-SecAuditRuleEnabled -Id 'RULE276') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Value "$(Get-SecAuditApplyValue -Id 'RULE276' -Fallback '2' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE276 -Message "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client\CEIP=$(Get-SecAuditApplyValue -Id 'RULE276' -Fallback '2' -Pick raw)" } else { Write-RemSkip -Id RULE276 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client\CEIP" } }

# RULE277
# RULE277
if (Test-SecAuditRuleEnabled -Id 'RULE277') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value "$(Get-SecAuditApplyValue -Id 'RULE277' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE277 -Message "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows\CEIPEnable=$(Get-SecAuditApplyValue -Id 'RULE277' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE277 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows\CEIPEnable" } }

# RULE278
# RULE278
if (Test-SecAuditRuleEnabled -Id 'RULE278') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE278' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE278 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled=$(Get-SecAuditApplyValue -Id 'RULE278' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE278 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled" } }

# RULE279
# RULE279
if (Test-SecAuditRuleEnabled -Id 'RULE279') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "DevicePKInitBehavior" -Value "$(Get-SecAuditApplyValue -Id 'RULE279' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE279 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitBehavior=$(Get-SecAuditApplyValue -Id 'RULE279' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE279 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitBehavior" } }

# RULE280
# RULE280
if (Test-SecAuditRuleEnabled -Id 'RULE280') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Control Panel\International" -Name "BlockUserInputMethodsForSignIn" -Value "$(Get-SecAuditApplyValue -Id 'RULE280' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE280 -Message "HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn=$(Get-SecAuditApplyValue -Id 'RULE280' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE280 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn" } }

# RULE382
# RULE382
if (Test-SecAuditRuleEnabled -Id 'RULE382') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Camera" -Name "AllowCamera" -Value "$(Get-SecAuditApplyValue -Id 'RULE382' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE382 -Message "HKLM\SOFTWARE\Policies\Microsoft\Camera\AllowCamera=$(Get-SecAuditApplyValue -Id 'RULE382' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE382 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Camera\AllowCamera" } }

# RULE383
# RULE383
if (Test-SecAuditRuleEnabled -Id 'RULE383') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value "$(Get-SecAuditApplyValue -Id 'RULE383' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE383 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures=$(Get-SecAuditApplyValue -Id 'RULE383' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE383 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures" } }

# RULE384
# RULE384
if (Test-SecAuditRuleEnabled -Id 'RULE384') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value "$(Get-SecAuditApplyValue -Id 'RULE384' -Fallback '2' -Pick high)" -ValueType INTEGER) { Write-RemDone -Id RULE384 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing=$(Get-SecAuditApplyValue -Id 'RULE384' -Fallback '2' -Pick high)" } else { Write-RemSkip -Id RULE384 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing" } }

# RULE387
# RULE387
if (Test-SecAuditRuleEnabled -Id 'RULE387') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value "$(Get-SecAuditApplyValue -Id 'RULE387' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE387 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry=$(Get-SecAuditApplyValue -Id 'RULE387' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE387 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry" } }

# RULE389
# RULE389
if (Test-SecAuditRuleEnabled -Id 'RULE389') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value "$(Get-SecAuditApplyValue -Id 'RULE389' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE389 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications=$(Get-SecAuditApplyValue -Id 'RULE389' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE389 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications" } }

# RULE390
# RULE390
if (Test-SecAuditRuleEnabled -Id 'RULE390') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value "$(Get-SecAuditApplyValue -Id 'RULE390' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE390 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview=$(Get-SecAuditApplyValue -Id 'RULE390' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE390 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview" } }

# RULE392
# RULE392
if (Test-SecAuditRuleEnabled -Id 'RULE392') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "Retention" -Value "$(Get-SecAuditApplyValue -Id 'RULE392' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE392 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention=$(Get-SecAuditApplyValue -Id 'RULE392' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE392 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention" } }

# RULE393
# RULE393
if (Test-SecAuditRuleEnabled -Id 'RULE393') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -Value "$(Get-SecAuditApplyValue -Id 'RULE393' -Fallback '32768' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE393 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize=$(Get-SecAuditApplyValue -Id 'RULE393' -Fallback '32768' -Pick raw)" } else { Write-RemSkip -Id RULE393 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize" } }

# RULE394
# RULE394
if (Test-SecAuditRuleEnabled -Id 'RULE394') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -Value "$(Get-SecAuditApplyValue -Id 'RULE394' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE394 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention=$(Get-SecAuditApplyValue -Id 'RULE394' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE394 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention" } }

# RULE395
# RULE395
if (Test-SecAuditRuleEnabled -Id 'RULE395') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Value "$(Get-SecAuditApplyValue -Id 'RULE395' -Fallback '192608' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE395 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize=$(Get-SecAuditApplyValue -Id 'RULE395' -Fallback '192608' -Pick raw)" } else { Write-RemSkip -Id RULE395 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize" } }

# RULE396
# RULE396
if (Test-SecAuditRuleEnabled -Id 'RULE396') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "Retention" -Value "$(Get-SecAuditApplyValue -Id 'RULE396' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE396 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\Retention=$(Get-SecAuditApplyValue -Id 'RULE396' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE396 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\Retention" } }

# RULE397
# RULE397
if (Test-SecAuditRuleEnabled -Id 'RULE397') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -Value "$(Get-SecAuditApplyValue -Id 'RULE397' -Fallback '32768' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE397 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\MaxSize=$(Get-SecAuditApplyValue -Id 'RULE397' -Fallback '32768' -Pick raw)" } else { Write-RemSkip -Id RULE397 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\MaxSize" } }

# RULE398
# RULE398
if (Test-SecAuditRuleEnabled -Id 'RULE398') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "Retention" -Value "$(Get-SecAuditApplyValue -Id 'RULE398' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE398 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\Retention=$(Get-SecAuditApplyValue -Id 'RULE398' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE398 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\Retention" } }

# RULE399
# RULE399
if (Test-SecAuditRuleEnabled -Id 'RULE399') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -Value "$(Get-SecAuditApplyValue -Id 'RULE399' -Fallback '32768' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE399 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize=$(Get-SecAuditApplyValue -Id 'RULE399' -Fallback '32768' -Pick raw)" } else { Write-RemSkip -Id RULE399 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize" } }

# RULE401
# RULE401
if (Test-SecAuditRuleEnabled -Id 'RULE401') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Value "$(Get-SecAuditApplyValue -Id 'RULE401' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE401 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention=$(Get-SecAuditApplyValue -Id 'RULE401' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE401 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention" } }

# RULE402
# RULE402
if (Test-SecAuditRuleEnabled -Id 'RULE402') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -Value "$(Get-SecAuditApplyValue -Id 'RULE402' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE402 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption=$(Get-SecAuditApplyValue -Id 'RULE402' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE402 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption" } }

# RULE403
# RULE403
if (Test-SecAuditRuleEnabled -Id 'RULE403') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "PreXPSP2ShellProtocolBehavior" -Value "$(Get-SecAuditApplyValue -Id 'RULE403' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE403 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior=$(Get-SecAuditApplyValue -Id 'RULE403' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE403 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior" } }

# RULE405
# RULE405
if (Test-SecAuditRuleEnabled -Id 'RULE405') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value "$(Get-SecAuditApplyValue -Id 'RULE405' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE405 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\DisableWindowsLocationProvider=$(Get-SecAuditApplyValue -Id 'RULE405' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE405 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\DisableWindowsLocationProvider" } }

# RULE417
# RULE417
if (Test-SecAuditRuleEnabled -Id 'RULE417') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value "$(Get-SecAuditApplyValue -Id 'RULE417' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE417 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC=$(Get-SecAuditApplyValue -Id 'RULE417' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE417 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC" } }

# RULE418
# RULE418
if (Test-SecAuditRuleEnabled -Id 'RULE418') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value "$(Get-SecAuditApplyValue -Id 'RULE418' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE418 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving=$(Get-SecAuditApplyValue -Id 'RULE418' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE418 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving" } }

# RULE420
# RULE420
if (Test-SecAuditRuleEnabled -Id 'RULE420') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value "$(Get-SecAuditApplyValue -Id 'RULE420' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE420 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCcm=$(Get-SecAuditApplyValue -Id 'RULE420' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE420 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCcm" } }

# RULE421
# RULE421
if (Test-SecAuditRuleEnabled -Id 'RULE421') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value "$(Get-SecAuditApplyValue -Id 'RULE421' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE421 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm=$(Get-SecAuditApplyValue -Id 'RULE421' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE421 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm" } }

# RULE422
# RULE422
if (Test-SecAuditRuleEnabled -Id 'RULE422') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLPT" -Value "$(Get-SecAuditApplyValue -Id 'RULE422' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE422 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableLPT=$(Get-SecAuditApplyValue -Id 'RULE422' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE422 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableLPT" } }

# RULE423
# RULE423
if (Test-SecAuditRuleEnabled -Id 'RULE423') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisablePNPRedir" -Value "$(Get-SecAuditApplyValue -Id 'RULE423' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE423 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir=$(Get-SecAuditApplyValue -Id 'RULE423' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE423 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir" } }

# RULE424
# RULE424
if (Test-SecAuditRuleEnabled -Id 'RULE424') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -Value "$(Get-SecAuditApplyValue -Id 'RULE424' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE424 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword=$(Get-SecAuditApplyValue -Id 'RULE424' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE424 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword" } }

# RULE425
# RULE425
if (Test-SecAuditRuleEnabled -Id 'RULE425') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value "$(Get-SecAuditApplyValue -Id 'RULE425' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE425 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic=$(Get-SecAuditApplyValue -Id 'RULE425' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE425 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic" } }

# RULE426
# RULE426
if (Test-SecAuditRuleEnabled -Id 'RULE426') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value "$(Get-SecAuditApplyValue -Id 'RULE426' -Fallback '3' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE426 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel=$(Get-SecAuditApplyValue -Id 'RULE426' -Fallback '3' -Pick raw)" } else { Write-RemSkip -Id RULE426 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel" } }

# RULE427
# RULE427
if (Test-SecAuditRuleEnabled -Id 'RULE427') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value "$(Get-SecAuditApplyValue -Id 'RULE427' -Fallback '900000' -Pick high)" -ValueType INTEGER) { Write-RemDone -Id RULE427 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime=$(Get-SecAuditApplyValue -Id 'RULE427' -Fallback '900000' -Pick high)" } else { Write-RemSkip -Id RULE427 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime" } }

# RULE428
# RULE428
if (Test-SecAuditRuleEnabled -Id 'RULE428') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value "$(Get-SecAuditApplyValue -Id 'RULE428' -Fallback '60000' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE428 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxDisconnectionTime=$(Get-SecAuditApplyValue -Id 'RULE428' -Fallback '60000' -Pick raw)" } else { Write-RemSkip -Id RULE428 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxDisconnectionTime" } }

# RULE429
# RULE429
if (Test-SecAuditRuleEnabled -Id 'RULE429') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DeleteTempDirsOnExit" -Value "$(Get-SecAuditApplyValue -Id 'RULE429' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE429 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit=$(Get-SecAuditApplyValue -Id 'RULE429' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE429 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit" } }

# RULE430
# RULE430
if (Test-SecAuditRuleEnabled -Id 'RULE430') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "PerSessionTempDir" -Value "$(Get-SecAuditApplyValue -Id 'RULE430' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE430 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir=$(Get-SecAuditApplyValue -Id 'RULE430' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE430 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir" } }

# RULE431
# RULE431
if (Test-SecAuditRuleEnabled -Id 'RULE431') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value "$(Get-SecAuditApplyValue -Id 'RULE431' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE431 -Message "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload=$(Get-SecAuditApplyValue -Id 'RULE431' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE431 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload" } }

# RULE434
# RULE434
if (Test-SecAuditRuleEnabled -Id 'RULE434') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value "$(Get-SecAuditApplyValue -Id 'RULE434' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE434 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems=$(Get-SecAuditApplyValue -Id 'RULE434' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE434 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems" } }

# RULE436
# RULE436
if (Test-SecAuditRuleEnabled -Id 'RULE436') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Value "$(Get-SecAuditApplyValue -Id 'RULE436' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE436 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\NoGenTicket=$(Get-SecAuditApplyValue -Id 'RULE436' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE436 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\NoGenTicket" } }

# RULE441
# RULE441
if (Test-SecAuditRuleEnabled -Id 'RULE441') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Value "$(Get-SecAuditApplyValue -Id 'RULE441' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE441 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting=$(Get-SecAuditApplyValue -Id 'RULE441' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE441 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting" } }

# RULE442
# RULE442
if (Test-SecAuditRuleEnabled -Id 'RULE442') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Value "$(Get-SecAuditApplyValue -Id 'RULE442' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE442 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts=$(Get-SecAuditApplyValue -Id 'RULE442' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE442 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts" } }

# RULE444
# RULE444
if (Test-SecAuditRuleEnabled -Id 'RULE444') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value "$(Get-SecAuditApplyValue -Id 'RULE444' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE444 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowSuggestedAppsInWindowsInkWorkspace=$(Get-SecAuditApplyValue -Id 'RULE444' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE444 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowSuggestedAppsInWindowsInkWorkspace" } }

# RULE446
# RULE446
if (Test-SecAuditRuleEnabled -Id 'RULE446') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "EnableUserControl" -Value "$(Get-SecAuditApplyValue -Id 'RULE446' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE446 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\EnableUserControl=$(Get-SecAuditApplyValue -Id 'RULE446' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE446 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\EnableUserControl" } }

# RULE447
# RULE447
if (Test-SecAuditRuleEnabled -Id 'RULE447') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value "$(Get-SecAuditApplyValue -Id 'RULE447' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE447 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated=$(Get-SecAuditApplyValue -Id 'RULE447' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE447 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated" } }

# RULE448
# RULE448
if (Test-SecAuditRuleEnabled -Id 'RULE448') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "SafeForScripting" -Value "$(Get-SecAuditApplyValue -Id 'RULE448' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE448 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\SafeForScripting=$(Get-SecAuditApplyValue -Id 'RULE448' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE448 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\SafeForScripting" } }

# RULE449
# RULE449
if (Test-SecAuditRuleEnabled -Id 'RULE449') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value "$(Get-SecAuditApplyValue -Id 'RULE449' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE449 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn=$(Get-SecAuditApplyValue -Id 'RULE449' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE449 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn" } }

# RULE450
# RULE450
if (Test-SecAuditRuleEnabled -Id 'RULE450') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value "$(Get-SecAuditApplyValue -Id 'RULE450' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE450 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging=$(Get-SecAuditApplyValue -Id 'RULE450' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE450 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging" } }

# RULE451
# RULE451
if (Test-SecAuditRuleEnabled -Id 'RULE451') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value "$(Get-SecAuditApplyValue -Id 'RULE451' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE451 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting=$(Get-SecAuditApplyValue -Id 'RULE451' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE451 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting" } }

# RULE452
# RULE452
if (Test-SecAuditRuleEnabled -Id 'RULE452') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value "$(Get-SecAuditApplyValue -Id 'RULE452' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE452 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic=$(Get-SecAuditApplyValue -Id 'RULE452' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE452 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic" } }

# RULE453
# RULE453
if (Test-SecAuditRuleEnabled -Id 'RULE453') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -Value "$(Get-SecAuditApplyValue -Id 'RULE453' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE453 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic=$(Get-SecAuditApplyValue -Id 'RULE453' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE453 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic" } }

# RULE454
# RULE454
if (Test-SecAuditRuleEnabled -Id 'RULE454') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value "$(Get-SecAuditApplyValue -Id 'RULE454' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE454 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest=$(Get-SecAuditApplyValue -Id 'RULE454' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE454 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest" } }

# RULE455
# RULE455
if (Test-SecAuditRuleEnabled -Id 'RULE455') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Value "$(Get-SecAuditApplyValue -Id 'RULE455' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE455 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic=$(Get-SecAuditApplyValue -Id 'RULE455' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE455 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic" } }

# RULE456
# RULE456
if (Test-SecAuditRuleEnabled -Id 'RULE456') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowAutoConfig" -Value "$(Get-SecAuditApplyValue -Id 'RULE456' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE456 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowAutoConfig=$(Get-SecAuditApplyValue -Id 'RULE456' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE456 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowAutoConfig" } }

# RULE457
# RULE457
if (Test-SecAuditRuleEnabled -Id 'RULE457') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value "$(Get-SecAuditApplyValue -Id 'RULE457' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE457 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic=$(Get-SecAuditApplyValue -Id 'RULE457' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE457 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic" } }

# RULE458
# RULE458
if (Test-SecAuditRuleEnabled -Id 'RULE458') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Value "$(Get-SecAuditApplyValue -Id 'RULE458' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE458 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs=$(Get-SecAuditApplyValue -Id 'RULE458' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE458 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs" } }

# RULE459
# RULE459
if (Test-SecAuditRuleEnabled -Id 'RULE459') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -Value "$(Get-SecAuditApplyValue -Id 'RULE459' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE459 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS\AllowRemoteShellAccess=$(Get-SecAuditApplyValue -Id 'RULE459' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE459 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS\AllowRemoteShellAccess" } }

# RULE461
# RULE461
if (Test-SecAuditRuleEnabled -Id 'RULE461') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Value "$(Get-SecAuditApplyValue -Id 'RULE461' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE461 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates=$(Get-SecAuditApplyValue -Id 'RULE461' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE461 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates" } }

# RULE462
# RULE462
if (Test-SecAuditRuleEnabled -Id 'RULE462') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value "$(Get-SecAuditApplyValue -Id 'RULE462' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE462 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate=$(Get-SecAuditApplyValue -Id 'RULE462' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE462 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate" } }

# RULE463
# RULE463
if (Test-SecAuditRuleEnabled -Id 'RULE463') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value "$(Get-SecAuditApplyValue -Id 'RULE463' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE463 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay=$(Get-SecAuditApplyValue -Id 'RULE463' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE463 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay" } }

# RULE464
# RULE464
if (Test-SecAuditRuleEnabled -Id 'RULE464') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value "$(Get-SecAuditApplyValue -Id 'RULE464' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE464 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers=$(Get-SecAuditApplyValue -Id 'RULE464' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE464 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers" } }

# RULE479
# RULE479
if (Test-SecAuditRuleEnabled -Id 'RULE479') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value "$(Get-SecAuditApplyValue -Id 'RULE479' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE479 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowCrossDeviceClipboard=$(Get-SecAuditApplyValue -Id 'RULE479' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE479 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowCrossDeviceClipboard" } }

# RULE480
# RULE480
if (Test-SecAuditRuleEnabled -Id 'RULE480') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE480' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE480 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy=$(Get-SecAuditApplyValue -Id 'RULE480' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE480 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy" } }

# RULE485
# RULE485
if (Test-SecAuditRuleEnabled -Id 'RULE485') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "autodisconnect" -Value "$(Get-SecAuditApplyValue -Id 'RULE485' -Fallback '15' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE485 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\autodisconnect=$(Get-SecAuditApplyValue -Id 'RULE485' -Fallback '15' -Pick raw)" } else { Write-RemSkip -Id RULE485 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\autodisconnect" } }

# RULE486
# RULE486
if (Test-SecAuditRuleEnabled -Id 'RULE486') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "disabledomaincreds" -Value "$(Get-SecAuditApplyValue -Id 'RULE486' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE486 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\disabledomaincreds=$(Get-SecAuditApplyValue -Id 'RULE486' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE486 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\disabledomaincreds" } }

# RULE487
# RULE487
if (Test-SecAuditRuleEnabled -Id 'RULE487') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" -Name "Machine" -Value "$(Get-SecAuditApplyValue -Id 'RULE487' -Fallback 'System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, Software\Microsoft\Windows NT\CurrentVersion' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE487 -Message "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=$(Get-SecAuditApplyValue -Id 'RULE487' -Fallback 'System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, Software\Microsoft\Windows NT\CurrentVersion' -Pick raw)" } else { Write-RemSkip -Id RULE487 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine" } }

# RULE488
# RULE488
if (Test-SecAuditRuleEnabled -Id 'RULE488') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "forceguest" -Value "$(Get-SecAuditApplyValue -Id 'RULE488' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE488 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\forceguest=$(Get-SecAuditApplyValue -Id 'RULE488' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE488 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\forceguest" } }

# RULE489
# RULE489
if (Test-SecAuditRuleEnabled -Id 'RULE489') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "shutdownwithoutlogon" -Value "$(Get-SecAuditApplyValue -Id 'RULE489' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE489 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\shutdownwithoutlogon=$(Get-SecAuditApplyValue -Id 'RULE489' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE489 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\shutdownwithoutlogon" } }

# RULE490
# RULE490
if (Test-SecAuditRuleEnabled -Id 'RULE490') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "obcaseinsensitive" -Value "$(Get-SecAuditApplyValue -Id 'RULE490' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE490 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\obcaseinsensitive=$(Get-SecAuditApplyValue -Id 'RULE490' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE490 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\obcaseinsensitive" } }

# RULE491
# RULE491
if (Test-SecAuditRuleEnabled -Id 'RULE491') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value "$(Get-SecAuditApplyValue -Id 'RULE491' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE491 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=$(Get-SecAuditApplyValue -Id 'RULE491' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE491 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths" } }

# RULE497
# RULE497
if (Test-SecAuditRuleEnabled -Id 'RULE497') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value "$(Get-SecAuditApplyValue -Id 'RULE497' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE497 -Message "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization=$(Get-SecAuditApplyValue -Id 'RULE497' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE497 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization" } }

# RULE498
# RULE498
if (Test-SecAuditRuleEnabled -Id 'RULE498') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value "$(Get-SecAuditApplyValue -Id 'RULE498' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE498 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\AllowOnlineTips=$(Get-SecAuditApplyValue -Id 'RULE498' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE498 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\AllowOnlineTips" } }

# RULE499
# RULE499
if (Test-SecAuditRuleEnabled -Id 'RULE499') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordLength" -Value "$(Get-SecAuditApplyValue -Id 'RULE499' -Fallback '15' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE499 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordLength=$(Get-SecAuditApplyValue -Id 'RULE499' -Fallback '15' -Pick raw)" } else { Write-RemSkip -Id RULE499 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordLength" } }

# RULE500
# RULE500
if (Test-SecAuditRuleEnabled -Id 'RULE500') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE500' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE500 -Message "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start=$(Get-SecAuditApplyValue -Id 'RULE500' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE500 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start" } }

# RULE501
# RULE501
if (Test-SecAuditRuleEnabled -Id 'RULE501') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value "$(Get-SecAuditApplyValue -Id 'RULE501' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE501 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1=$(Get-SecAuditApplyValue -Id 'RULE501' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE501 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1" } }

# RULE502
# RULE502
if (Test-SecAuditRuleEnabled -Id 'RULE502') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "DisableExceptionChainValidation" -Value "$(Get-SecAuditApplyValue -Id 'RULE502' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE502 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\DisableExceptionChainValidation=$(Get-SecAuditApplyValue -Id 'RULE502' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE502 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\DisableExceptionChainValidation" } }

# RULE503
# RULE503
if (Test-SecAuditRuleEnabled -Id 'RULE503') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value "$(Get-SecAuditApplyValue -Id 'RULE503' -Fallback '2' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE503 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting=$(Get-SecAuditApplyValue -Id 'RULE503' -Fallback '2' -Pick raw)" } else { Write-RemSkip -Id RULE503 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting" } }

# RULE504
# RULE504
if (Test-SecAuditRuleEnabled -Id 'RULE504') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\NETLOGON" -Value "$(Get-SecAuditApplyValue -Id 'RULE504' -Fallback 'RequireMutualAuthentication=1, RequireIntegrity=1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE504 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\NETLOGON=$(Get-SecAuditApplyValue -Id 'RULE504' -Fallback 'RequireMutualAuthentication=1, RequireIntegrity=1' -Pick raw)" } else { Write-RemSkip -Id RULE504 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\NETLOGON" } }

# RULE505
# RULE505
if (Test-SecAuditRuleEnabled -Id 'RULE505') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Value "$(Get-SecAuditApplyValue -Id 'RULE505' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE505 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI\DisableWcnUi=$(Get-SecAuditApplyValue -Id 'RULE505' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE505 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI\DisableWcnUi" } }

# RULE506
# RULE506
if (Test-SecAuditRuleEnabled -Id 'RULE506') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Value "$(Get-SecAuditApplyValue -Id 'RULE506' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE506 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds=$(Get-SecAuditApplyValue -Id 'RULE506' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE506 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds" } }

# RULE507
# RULE507
if (Test-SecAuditRuleEnabled -Id 'RULE507') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value "$(Get-SecAuditApplyValue -Id 'RULE507' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE507 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity=$(Get-SecAuditApplyValue -Id 'RULE507' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE507 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity" } }

# RULE508
# RULE508
if (Test-SecAuditRuleEnabled -Id 'RULE508') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value "$(Get-SecAuditApplyValue -Id 'RULE508' -Fallback '3' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE508 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures=$(Get-SecAuditApplyValue -Id 'RULE508' -Fallback '3' -Pick raw)" } else { Write-RemSkip -Id RULE508 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures" } }

# RULE509
# RULE509
if (Test-SecAuditRuleEnabled -Id 'RULE509') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HypervisorEnforcedCodeIntegrity" -Value "$(Get-SecAuditApplyValue -Id 'RULE509' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE509 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity=$(Get-SecAuditApplyValue -Id 'RULE509' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE509 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity" } }

# RULE511
# RULE511
if (Test-SecAuditRuleEnabled -Id 'RULE511') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value "$(Get-SecAuditApplyValue -Id 'RULE511' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE511 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags=$(Get-SecAuditApplyValue -Id 'RULE511' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE511 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags" } }

# RULE513
# RULE513
if (Test-SecAuditRuleEnabled -Id 'RULE513') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value "$(Get-SecAuditApplyValue -Id 'RULE513' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE513 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing=$(Get-SecAuditApplyValue -Id 'RULE513' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE513 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing" } }

# RULE514
# RULE514
if (Test-SecAuditRuleEnabled -Id 'RULE514') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Value "$(Get-SecAuditApplyValue -Id 'RULE514' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE514 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices=$(Get-SecAuditApplyValue -Id 'RULE514' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE514 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices" } }

# RULE515
# RULE515
if (Test-SecAuditRuleEnabled -Id 'RULE515') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Value "$(Get-SecAuditApplyValue -Id 'RULE515' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE515 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting=$(Get-SecAuditApplyValue -Id 'RULE515' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE515 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting" } }

# RULE516
# RULE516
if (Test-SecAuditRuleEnabled -Id 'RULE516') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value "$(Get-SecAuditApplyValue -Id 'RULE516' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE516 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin=$(Get-SecAuditApplyValue -Id 'RULE516' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE516 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin" } }

# RULE517
# RULE517
if (Test-SecAuditRuleEnabled -Id 'RULE517') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value "$(Get-SecAuditApplyValue -Id 'RULE517' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE517 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers=$(Get-SecAuditApplyValue -Id 'RULE517' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE517 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers" } }

# RULE518
# RULE518
if (Test-SecAuditRuleEnabled -Id 'RULE518') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value "$(Get-SecAuditApplyValue -Id 'RULE518' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE518 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockDomainPicturePassword=$(Get-SecAuditApplyValue -Id 'RULE518' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE518 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockDomainPicturePassword" } }

# RULE519
# RULE519
if (Test-SecAuditRuleEnabled -Id 'RULE519') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value "$(Get-SecAuditApplyValue -Id 'RULE519' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE519 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex=$(Get-SecAuditApplyValue -Id 'RULE519' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE519 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex" } }

# RULE520
# RULE520
if (Test-SecAuditRuleEnabled -Id 'RULE520') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value "$(Get-SecAuditApplyValue -Id 'RULE520' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE520 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex=$(Get-SecAuditApplyValue -Id 'RULE520' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE520 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex" } }

# RULE521
# RULE521
if (Test-SecAuditRuleEnabled -Id 'RULE521') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE521' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE521 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo\DisabledByGroupPolicy=$(Get-SecAuditApplyValue -Id 'RULE521' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE521 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo\DisabledByGroupPolicy" } }

# RULE522
# RULE522
if (Test-SecAuditRuleEnabled -Id 'RULE522') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -Name "Enabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE522' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE522 -Message "HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient\Enabled=$(Get-SecAuditApplyValue -Id 'RULE522' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE522 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient\Enabled" } }

# RULE523
# RULE523
if (Test-SecAuditRuleEnabled -Id 'RULE523') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer" -Name "Enabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE523' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE523 -Message "HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled=$(Get-SecAuditApplyValue -Id 'RULE523' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE523 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled" } }

# RULE525
# RULE525
if (Test-SecAuditRuleEnabled -Id 'RULE525') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value "$(Get-SecAuditApplyValue -Id 'RULE525' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE525 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal=$(Get-SecAuditApplyValue -Id 'RULE525' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE525 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal" } }

# RULE526
# RULE526
if (Test-SecAuditRuleEnabled -Id 'RULE526') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Value "$(Get-SecAuditApplyValue -Id 'RULE526' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE526 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators=$(Get-SecAuditApplyValue -Id 'RULE526' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE526 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators" } }

# RULE527
# RULE527
if (Test-SecAuditRuleEnabled -Id 'RULE527') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableEnterpriseAuthProxy" -Value "$(Get-SecAuditApplyValue -Id 'RULE527' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE527 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DisableEnterpriseAuthProxy=$(Get-SecAuditApplyValue -Id 'RULE527' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE527 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DisableEnterpriseAuthProxy" } }

# RULE528
# RULE528
if (Test-SecAuditRuleEnabled -Id 'RULE528') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value "$(Get-SecAuditApplyValue -Id 'RULE528' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE528 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging\AllowMessageSync=$(Get-SecAuditApplyValue -Id 'RULE528' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE528 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging\AllowMessageSync" } }

# RULE529
# RULE529
if (Test-SecAuditRuleEnabled -Id 'RULE529') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -Value "$(Get-SecAuditApplyValue -Id 'RULE529' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE529 -Message "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount\DisableUserAuth=$(Get-SecAuditApplyValue -Id 'RULE529' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE529 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount\DisableUserAuth" } }

# RULE530
# RULE530
if (Test-SecAuditRuleEnabled -Id 'RULE530') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fSingleSessionPerUser" -Value "$(Get-SecAuditApplyValue -Id 'RULE530' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE530 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fSingleSessionPerUser=$(Get-SecAuditApplyValue -Id 'RULE530' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE530 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fSingleSessionPerUser" } }

# RULE531
# RULE531
if (Test-SecAuditRuleEnabled -Id 'RULE531') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value "$(Get-SecAuditApplyValue -Id 'RULE531' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE531 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCloudSearch=$(Get-SecAuditApplyValue -Id 'RULE531' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE531 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCloudSearch" } }

# RULE532
# RULE532
if (Test-SecAuditRuleEnabled -Id 'RULE532') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Value "$(Get-SecAuditApplyValue -Id 'RULE532' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE532 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting=$(Get-SecAuditApplyValue -Id 'RULE532' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE532 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting" } }

# RULE533
# RULE533
if (Test-SecAuditRuleEnabled -Id 'RULE533') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value "$(Get-SecAuditApplyValue -Id 'RULE533' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE533 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring=$(Get-SecAuditApplyValue -Id 'RULE533' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE533 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring" } }

# RULE534
# RULE534
if (Test-SecAuditRuleEnabled -Id 'RULE534') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value "$(Get-SecAuditApplyValue -Id 'RULE534' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE534 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning=$(Get-SecAuditApplyValue -Id 'RULE534' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE534 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning" } }

# RULE535
# RULE535
if (Test-SecAuditRuleEnabled -Id 'RULE535') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value "$(Get-SecAuditApplyValue -Id 'RULE535' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE535 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning=$(Get-SecAuditApplyValue -Id 'RULE535' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE535 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning" } }

# RULE536
# RULE536
if (Test-SecAuditRuleEnabled -Id 'RULE536') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value "$(Get-SecAuditApplyValue -Id 'RULE536' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE536 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection=$(Get-SecAuditApplyValue -Id 'RULE536' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE536 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection" } }

# RULE537
# RULE537
if (Test-SecAuditRuleEnabled -Id 'RULE537') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value "$(Get-SecAuditApplyValue -Id 'RULE537' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE537 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware=$(Get-SecAuditApplyValue -Id 'RULE537' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE537 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware" } }

# RULE538
# RULE538
if (Test-SecAuditRuleEnabled -Id 'RULE538') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "DisallowExploitProtectionOverride" -Value "$(Get-SecAuditApplyValue -Id 'RULE538' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE538 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\DisallowExploitProtectionOverride=$(Get-SecAuditApplyValue -Id 'RULE538' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE538 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\DisallowExploitProtectionOverride" } }

# RULE540
# RULE540
if (Test-SecAuditRuleEnabled -Id 'RULE540') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -Value "$(Get-SecAuditApplyValue -Id 'RULE540' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE540 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuilds=$(Get-SecAuditApplyValue -Id 'RULE540' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE540 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuilds" } }

# RULE543
# RULE543
if (Test-SecAuditRuleEnabled -Id 'RULE543') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value "$(Get-SecAuditApplyValue -Id 'RULE543' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE543 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI=$(Get-SecAuditApplyValue -Id 'RULE543' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE543 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI" } }

# RULE544
# RULE544
if (Test-SecAuditRuleEnabled -Id 'RULE544') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnumerateLocalUsers" -Value "$(Get-SecAuditApplyValue -Id 'RULE544' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE544 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers=$(Get-SecAuditApplyValue -Id 'RULE544' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE544 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers" } }

# RULE545
# RULE545
if (Test-SecAuditRuleEnabled -Id 'RULE545') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value "$(Get-SecAuditApplyValue -Id 'RULE545' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE545 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications=$(Get-SecAuditApplyValue -Id 'RULE545' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE545 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications" } }

# RULE546
# RULE546
if (Test-SecAuditRuleEnabled -Id 'RULE546') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Value "$(Get-SecAuditApplyValue -Id 'RULE546' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE546 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon=$(Get-SecAuditApplyValue -Id 'RULE546' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE546 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon" } }

# RULE548
# RULE548
if (Test-SecAuditRuleEnabled -Id 'RULE548') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "DCSettingIndex" -Value "$(Get-SecAuditApplyValue -Id 'RULE548' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE548 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex=$(Get-SecAuditApplyValue -Id 'RULE548' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE548 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex" } }

# RULE549
# RULE549
if (Test-SecAuditRuleEnabled -Id 'RULE549') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "ACSettingIndex" -Value "$(Get-SecAuditApplyValue -Id 'RULE549' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE549 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex=$(Get-SecAuditApplyValue -Id 'RULE549' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE549 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex" } }

# RULE550
# RULE550
if (Test-SecAuditRuleEnabled -Id 'RULE550') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value "$(Get-SecAuditApplyValue -Id 'RULE550' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE550 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited=$(Get-SecAuditApplyValue -Id 'RULE550' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE550 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited" } }

# RULE551
# RULE551
if (Test-SecAuditRuleEnabled -Id 'RULE551') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value "$(Get-SecAuditApplyValue -Id 'RULE551' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE551 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp=$(Get-SecAuditApplyValue -Id 'RULE551' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE551 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp" } }

# RULE552
# RULE552
if (Test-SecAuditRuleEnabled -Id 'RULE552') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value "$(Get-SecAuditApplyValue -Id 'RULE552' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE552 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution=$(Get-SecAuditApplyValue -Id 'RULE552' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE552 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution" } }

# RULE553
# RULE553
if (Test-SecAuditRuleEnabled -Id 'RULE553') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Value "$(Get-SecAuditApplyValue -Id 'RULE553' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE553 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients=$(Get-SecAuditApplyValue -Id 'RULE553' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE553 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients" } }

# RULE554
# RULE554
if (Test-SecAuditRuleEnabled -Id 'RULE554') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -Value "$(Get-SecAuditApplyValue -Id 'RULE554' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE554 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer=$(Get-SecAuditApplyValue -Id 'RULE554' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE554 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer" } }

# RULE555
# RULE555
if (Test-SecAuditRuleEnabled -Id 'RULE555') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name "ScenarioExecutionEnabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE555' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE555 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled=$(Get-SecAuditApplyValue -Id 'RULE555' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE555 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled" } }

# RULE556
# RULE556
if (Test-SecAuditRuleEnabled -Id 'RULE556') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" -Name "AllowSharedLocalAppData" -Value "$(Get-SecAuditApplyValue -Id 'RULE556' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE556 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\AllowSharedLocalAppData=$(Get-SecAuditApplyValue -Id 'RULE556' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE556 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\AllowSharedLocalAppData" } }

# RULE557
# RULE557
if (Test-SecAuditRuleEnabled -Id 'RULE557') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -Value "$(Get-SecAuditApplyValue -Id 'RULE557' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE557 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional=$(Get-SecAuditApplyValue -Id 'RULE557' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE557 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional" } }

# RULE558
# RULE558
if (Test-SecAuditRuleEnabled -Id 'RULE558') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value "$(Get-SecAuditApplyValue -Id 'RULE558' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE558 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume=$(Get-SecAuditApplyValue -Id 'RULE558' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE558 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume" } }

# RULE559
# RULE559
if (Test-SecAuditRuleEnabled -Id 'RULE559') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value "$(Get-SecAuditApplyValue -Id 'RULE559' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE559 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun=$(Get-SecAuditApplyValue -Id 'RULE559' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE559 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun" } }

# RULE560
# RULE560
if (Test-SecAuditRuleEnabled -Id 'RULE560') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value "$(Get-SecAuditApplyValue -Id 'RULE560' -Fallback '255' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE560 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun=$(Get-SecAuditApplyValue -Id 'RULE560' -Fallback '255' -Pick raw)" } else { Write-RemSkip -Id RULE560 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun" } }

# RULE562
# RULE562
if (Test-SecAuditRuleEnabled -Id 'RULE562') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "submitcontrol" -Value "$(Get-SecAuditApplyValue -Id 'RULE562' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE562 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\submitcontrol=$(Get-SecAuditApplyValue -Id 'RULE562' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE562 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\submitcontrol" } }

# RULE564
# RULE564
if (Test-SecAuditRuleEnabled -Id 'RULE564') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "refusepasswordchange" -Value "$(Get-SecAuditApplyValue -Id 'RULE564' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE564 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\refusepasswordchange=$(Get-SecAuditApplyValue -Id 'RULE564' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE564 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\refusepasswordchange" } }

# RULE565
# RULE565
if (Test-SecAuditRuleEnabled -Id 'RULE565') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE565 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\legalnoticetext=0" } else { Write-RemSkip -Id RULE565 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\legalnoticetext" } }

# RULE566
# RULE566
if (Test-SecAuditRuleEnabled -Id 'RULE566') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceUnlockLogon" -Value "$(Get-SecAuditApplyValue -Id 'RULE566' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE566 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=$(Get-SecAuditApplyValue -Id 'RULE566' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE566 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon" } }

# RULE567
# RULE567
if (Test-SecAuditRuleEnabled -Id 'RULE567') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" -Name "Machine" -Value "$(Get-SecAuditApplyValue -Id 'RULE567' -Fallback 'System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE567 -Message "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=$(Get-SecAuditApplyValue -Id 'RULE567' -Fallback 'System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog' -Pick raw)" } else { Write-RemSkip -Id RULE567 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine" } }

# RULE569
# RULE569
if (Test-SecAuditRuleEnabled -Id 'RULE569') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value "$(Get-SecAuditApplyValue -Id 'RULE569' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE569 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp=$(Get-SecAuditApplyValue -Id 'RULE569' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE569 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp" } }

# RULE889
# RULE889
if (Test-SecAuditRuleEnabled -Id 'RULE889') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Value "$(Get-SecAuditApplyValue -Id 'RULE889' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE889 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuildsPolicyValue=$(Get-SecAuditApplyValue -Id 'RULE889' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE889 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuildsPolicyValue" } }

# RULE890
# RULE890
if (Test-SecAuditRuleEnabled -Id 'RULE890') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value "$(Get-SecAuditApplyValue -Id 'RULE890' -Fallback '180' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE890 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays=$(Get-SecAuditApplyValue -Id 'RULE890' -Fallback '180' -Pick raw)" } else { Write-RemSkip -Id RULE890 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays" } }

# RULE5041
# RULE5041
if (Test-SecAuditRuleEnabled -Id 'RULE5041') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\SYSVOL" -Value "$(Get-SecAuditApplyValue -Id 'RULE5041' -Fallback 'RequireMutualAuthentication=1, RequireIntegrity=1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE5041 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\SYSVOL=$(Get-SecAuditApplyValue -Id 'RULE5041' -Fallback 'RequireMutualAuthentication=1, RequireIntegrity=1' -Pick raw)" } else { Write-RemSkip -Id RULE5041 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\SYSVOL" } }

# RULE891
# RULE891
if (Test-SecAuditRuleEnabled -Id 'RULE891') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "RedirectionguardPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE891' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE891 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RedirectionguardPolicy=$(Get-SecAuditApplyValue -Id 'RULE891' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE891 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RedirectionguardPolicy" } }

# RULE892
# RULE892
if (Test-SecAuditRuleEnabled -Id 'RULE892') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value "$(Get-SecAuditApplyValue -Id 'RULE892' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE892 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators=$(Get-SecAuditApplyValue -Id 'RULE892' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE892 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators" } }

# RULE893
# RULE893
if (Test-SecAuditRuleEnabled -Id 'RULE893') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCustomSSPsAPs" -Value "$(Get-SecAuditApplyValue -Id 'RULE893' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE893 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowCustomSSPsAPs=$(Get-SecAuditApplyValue -Id 'RULE893' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE893 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowCustomSSPsAPs" } }

# RULE999
# RULE999
if (Test-SecAuditRuleEnabled -Id 'RULE999') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value "$(Get-SecAuditApplyValue -Id 'RULE999' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE999 -Message "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity=$(Get-SecAuditApplyValue -Id 'RULE999' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE999 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity" } }

# RULE998
# RULE998
if (Test-SecAuditRuleEnabled -Id 'RULE998') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value "$(Get-SecAuditApplyValue -Id 'RULE998' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE998 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen=$(Get-SecAuditApplyValue -Id 'RULE998' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE998 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen" } }

# RULE997
# RULE997
if (Test-SecAuditRuleEnabled -Id 'RULE997') { if (Set-SecAuditReg -RelativeKey "Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value "$(Get-SecAuditApplyValue -Id 'RULE997' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE997 -Message "HKLM\Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck=$(Get-SecAuditApplyValue -Id 'RULE997' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE997 -Message "failed to set HKLM\Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck" } }

# RULE996
# RULE996
if (Test-SecAuditRuleEnabled -Id 'RULE996') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "ExpectedDialupDelay" -Value "$(Get-SecAuditApplyValue -Id 'RULE996' -Fallback '2000' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE996 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ExpectedDialupDelay=$(Get-SecAuditApplyValue -Id 'RULE996' -Fallback '2000' -Pick raw)" } else { Write-RemSkip -Id RULE996 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ExpectedDialupDelay" } }

# RULE991
# RULE991
if (Test-SecAuditRuleEnabled -Id 'RULE991') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Bowser" -Name "EnableMailslots" -Value "$(Get-SecAuditApplyValue -Id 'RULE991' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE991 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Bowser\EnableMailslots=$(Get-SecAuditApplyValue -Id 'RULE991' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE991 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Bowser\EnableMailslots" } }

# RULE990
# RULE990
if (Test-SecAuditRuleEnabled -Id 'RULE990') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LanmanServer" -Name "AuditClientDoesNotSupportEncryption" -Value "$(Get-SecAuditApplyValue -Id 'RULE990' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE990 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\AuditClientDoesNotSupportEncryption=$(Get-SecAuditApplyValue -Id 'RULE990' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE990 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\AuditClientDoesNotSupportEncryption" } }

# RULE989
# RULE989
if (Test-SecAuditRuleEnabled -Id 'RULE989') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Netlogon\Parameters" -Name "BlockNetbiosDiscovery" -Value "$(Get-SecAuditApplyValue -Id 'RULE989' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE989 -Message "HKLM\SOFTWARE\Policies\Microsoft\Netlogon\Parameters\BlockNetbiosDiscovery=$(Get-SecAuditApplyValue -Id 'RULE989' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE989 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Netlogon\Parameters\BlockNetbiosDiscovery" } }

# RULE985
# RULE985
if (Test-SecAuditRuleEnabled -Id 'RULE985') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "DevicePKInitEnabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE985' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE985 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled=$(Get-SecAuditApplyValue -Id 'RULE985' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE985 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled" } }

# RULE984
# RULE984
if (Test-SecAuditRuleEnabled -Id 'RULE984') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableBkGndGroupPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE984' -Fallback '' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE984 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy=" } else { Write-RemSkip -Id RULE984 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy" } }

# RULE981
# RULE981
if (Test-SecAuditRuleEnabled -Id 'RULE981') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE981' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE981 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled=$(Get-SecAuditApplyValue -Id 'RULE981' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE981 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled" } }

# RULE980
# RULE980
if (Test-SecAuditRuleEnabled -Id 'RULE980') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -Value "$(Get-SecAuditApplyValue -Id 'RULE980' -Fallback '255' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE980 -Message "HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\DisabledComponents=$(Get-SecAuditApplyValue -Id 'RULE980' -Fallback '255' -Pick raw)" } else { Write-RemSkip -Id RULE980 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\DisabledComponents" } }

# RULE979
# RULE979
if (Test-SecAuditRuleEnabled -Id 'RULE979') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "RunAsPPL " -Value "$(Get-SecAuditApplyValue -Id 'RULE979' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE979 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\RunAsPPL =$(Get-SecAuditApplyValue -Id 'RULE979' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE979 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\RunAsPPL " } }

# RULE978
# RULE978
if (Test-SecAuditRuleEnabled -Id 'RULE978') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "$(Get-SecAuditApplyValue -Id 'RULE978' -Fallback 'Block' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE978 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ShellSmartScreenLevel=$(Get-SecAuditApplyValue -Id 'RULE978' -Fallback 'Block' -Pick raw)" } else { Write-RemSkip -Id RULE978 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ShellSmartScreenLevel" } }

# RULE977
# RULE977
if (Test-SecAuditRuleEnabled -Id 'RULE977') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LanmanServer" -Name "InvalidAuthenticationDelayTimeInMs" -Value "$(Get-SecAuditApplyValue -Id 'RULE977' -Fallback '2000' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE977 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\InvalidAuthenticationDelayTimeInMs=$(Get-SecAuditApplyValue -Id 'RULE977' -Fallback '2000' -Pick raw)" } else { Write-RemSkip -Id RULE977 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer\InvalidAuthenticationDelayTimeInMs" } }

# RULE975
# RULE975
if (Test-SecAuditRuleEnabled -Id 'RULE975') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" -Name "RpcUseNamedPipeProtocol" -Value "$(Get-SecAuditApplyValue -Id 'RULE975' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE975 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC\RpcUseNamedPipeProtocol=$(Get-SecAuditApplyValue -Id 'RULE975' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE975 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC\RpcUseNamedPipeProtocol" } }

# RULE974
# RULE974
if (Test-SecAuditRuleEnabled -Id 'RULE974') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Value "$(Get-SecAuditApplyValue -Id 'RULE974' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE974 -Message "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DoReport=$(Get-SecAuditApplyValue -Id 'RULE974' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE974 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DoReport" } }

# RULE001
Queue-SecAuditSysAccess -Name "PasswordHistorySize" -Value "$(Get-SecAuditApplyValue -Id 'RULE001' -Fallback '24' -Pick raw)"
Write-RemDone -Id RULE001 -Message "queued System Access PasswordHistorySize=$(Get-SecAuditApplyValue -Id 'RULE001' -Fallback '24' -Pick raw)"

# RULE002
Queue-SecAuditSysAccess -Name "MaximumPasswordAge" -Value "$(Get-SecAuditApplyValue -Id 'RULE002' -Fallback '60' -Pick high)"
Write-RemDone -Id RULE002 -Message "queued System Access MaximumPasswordAge=$(Get-SecAuditApplyValue -Id 'RULE002' -Fallback '60' -Pick high)"

# RULE003
Queue-SecAuditSysAccess -Name "MinimumPasswordAge" -Value "$(Get-SecAuditApplyValue -Id 'RULE003' -Fallback '1' -Pick raw)"
Write-RemDone -Id RULE003 -Message "queued System Access MinimumPasswordAge=$(Get-SecAuditApplyValue -Id 'RULE003' -Fallback '1' -Pick raw)"

# RULE004
Queue-SecAuditSysAccess -Name "MinimumPasswordLength" -Value "$(Get-SecAuditApplyValue -Id 'RULE004' -Fallback '14' -Pick raw)"
Write-RemDone -Id RULE004 -Message "queued System Access MinimumPasswordLength=$(Get-SecAuditApplyValue -Id 'RULE004' -Fallback '14' -Pick raw)"

# RULE005
Queue-SecAuditSysAccess -Name "PasswordComplexity" -Value "$(Get-SecAuditApplyValue -Id 'RULE005' -Fallback '1' -Pick raw)"
Write-RemDone -Id RULE005 -Message "queued System Access PasswordComplexity=1"

# RULE007
Queue-SecAuditSysAccess -Name "LockoutDuration" -Value "$(Get-SecAuditApplyValue -Id 'RULE007' -Fallback '15' -Pick raw)"
Write-RemDone -Id RULE007 -Message "queued System Access LockoutDuration=$(Get-SecAuditApplyValue -Id 'RULE007' -Fallback '15' -Pick raw)"

# RULE008
Queue-SecAuditSysAccess -Name "LockoutBadCount" -Value "$(Get-SecAuditApplyValue -Id 'RULE008' -Fallback '10' -Pick high)"
Write-RemDone -Id RULE008 -Message "queued System Access LockoutBadCount=$(Get-SecAuditApplyValue -Id 'RULE008' -Fallback '10' -Pick high)"

# RULE009
Queue-SecAuditSysAccess -Name "ResetLockoutCount" -Value "$(Get-SecAuditApplyValue -Id 'RULE009' -Fallback '15' -Pick raw)"
Write-RemDone -Id RULE009 -Message "queued System Access ResetLockoutCount=$(Get-SecAuditApplyValue -Id 'RULE009' -Fallback '15' -Pick raw)"

# RULE010
Queue-SecAuditPrivilege -Name "SeTrustedCredManAccessPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE010' -Fallback '' -Pick raw)"
Write-RemDone -Id RULE010 -Message "queued privilege SeTrustedCredManAccessPrivilege"

# RULE011
Queue-SecAuditPrivilege -Name "SeNetworkLogonRight" -Value "$(Get-SecAuditApplyValue -Id 'RULE011' -Fallback 'Administrators,Authenticated Users' -Pick raw)"
Write-RemDone -Id RULE011 -Message "queued privilege SeNetworkLogonRight"

# RULE012
Queue-SecAuditPrivilege -Name "SeTcbPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE012' -Fallback '' -Pick raw)"
Write-RemDone -Id RULE012 -Message "queued privilege SeTcbPrivilege"

# RULE013
Queue-SecAuditPrivilege -Name "SeIncreaseQuotaPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE013' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE013 -Message "queued privilege SeIncreaseQuotaPrivilege"

# RULE014
Queue-SecAuditPrivilege -Name "SeInteractiveLogonRight" -Value "$(Get-SecAuditApplyValue -Id 'RULE014' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE014 -Message "queued privilege SeInteractiveLogonRight"

# RULE015
Queue-SecAuditPrivilege -Name "SeRemoteInteractiveLogonRight" -Value "$(Get-SecAuditApplyValue -Id 'RULE015' -Fallback 'Administrators,Remote Desktop Users' -Pick raw)"
Write-RemDone -Id RULE015 -Message "queued privilege SeRemoteInteractiveLogonRight"

# RULE016
Queue-SecAuditPrivilege -Name "SeBackupPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE016' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE016 -Message "queued privilege SeBackupPrivilege"

# RULE017
Queue-SecAuditPrivilege -Name "SeSystemtimePrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE017' -Fallback 'Administrators, LOCAL SERVICE' -Pick raw)"
Write-RemDone -Id RULE017 -Message "queued privilege SeSystemtimePrivilege"

# RULE018
Queue-SecAuditPrivilege -Name "SeTimeZonePrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE018' -Fallback 'Administrators, LOCAL SERVICE' -Pick raw)"
Write-RemDone -Id RULE018 -Message "queued privilege SeTimeZonePrivilege"

# RULE019
Queue-SecAuditPrivilege -Name "SeCreatePagefilePrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE019' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE019 -Message "queued privilege SeCreatePagefilePrivilege"

# RULE020
Queue-SecAuditPrivilege -Name "SeCreateTokenPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE020' -Fallback '' -Pick raw)"
Write-RemDone -Id RULE020 -Message "queued privilege SeCreateTokenPrivilege"

# RULE021
Queue-SecAuditPrivilege -Name "SeCreateGlobalPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE021' -Fallback 'Administrators,LOCAL SERVICE,NETWORK SERVICE' -Pick raw)"
Write-RemDone -Id RULE021 -Message "queued privilege SeCreateGlobalPrivilege"

# RULE022
Queue-SecAuditPrivilege -Name "SeCreatePermanentPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE022' -Fallback '' -Pick raw)"
Write-RemDone -Id RULE022 -Message "queued privilege SeCreatePermanentPrivilege"

# RULE023
Queue-SecAuditPrivilege -Name "SeCreateSymbolicLinkPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE023' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE023 -Message "queued privilege SeCreateSymbolicLinkPrivilege"

# RULE024
Queue-SecAuditPrivilege -Name "SeDebugPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE024' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE024 -Message "queued privilege SeDebugPrivilege"

# RULE025
Queue-SecAuditPrivilege -Name "SeDenyNetworkLogonRight" -Value "$(Get-SecAuditApplyValue -Id 'RULE025' -Fallback 'Guests,Local account' -Pick raw)"
Write-RemDone -Id RULE025 -Message "queued privilege SeDenyNetworkLogonRight"

# RULE026
Queue-SecAuditPrivilege -Name "SeDenyBatchLogonRight" -Value "$(Get-SecAuditApplyValue -Id 'RULE026' -Fallback 'Guests' -Pick raw)"
Write-RemDone -Id RULE026 -Message "queued privilege SeDenyBatchLogonRight"

# RULE027
Queue-SecAuditPrivilege -Name "SeDenyServiceLogonRight" -Value "$(Get-SecAuditApplyValue -Id 'RULE027' -Fallback 'Guests' -Pick raw)"
Write-RemDone -Id RULE027 -Message "queued privilege SeDenyServiceLogonRight"

# RULE028
Queue-SecAuditPrivilege -Name "SeDenyInteractiveLogonRight" -Value "$(Get-SecAuditApplyValue -Id 'RULE028' -Fallback 'Guests' -Pick raw)"
Write-RemDone -Id RULE028 -Message "queued privilege SeDenyInteractiveLogonRight"

# RULE030
Queue-SecAuditPrivilege -Name "SeEnableDelegationPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE030' -Fallback '' -Pick raw)"
Write-RemDone -Id RULE030 -Message "queued privilege SeEnableDelegationPrivilege"

# RULE031
Queue-SecAuditPrivilege -Name "SeRemoteShutdownPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE031' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE031 -Message "queued privilege SeRemoteShutdownPrivilege"

# RULE032
Queue-SecAuditPrivilege -Name "SeAuditPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE032' -Fallback 'LOCAL SERVICE,NETWORK SERVICE' -Pick raw)"
Write-RemDone -Id RULE032 -Message "queued privilege SeAuditPrivilege"

# RULE033
Queue-SecAuditPrivilege -Name "SeImpersonatePrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE033' -Fallback 'Administrators,LOCAL SERVICE,NETWORK SERVICE' -Pick raw)"
Write-RemDone -Id RULE033 -Message "queued privilege SeImpersonatePrivilege"

# RULE034
Queue-SecAuditPrivilege -Name "SeIncreaseBasePriorityPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE034' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE034 -Message "queued privilege SeIncreaseBasePriorityPrivilege"

# RULE035
Queue-SecAuditPrivilege -Name "SeLoadDriverPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE035' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE035 -Message "queued privilege SeLoadDriverPrivilege"

# RULE036
Queue-SecAuditPrivilege -Name "SeLockMemoryPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE036' -Fallback '' -Pick raw)"
Write-RemDone -Id RULE036 -Message "queued privilege SeLockMemoryPrivilege"

# RULE037
Queue-SecAuditPrivilege -Name "SeBatchLogonRight" -Value "$(Get-SecAuditApplyValue -Id 'RULE037' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE037 -Message "queued privilege SeBatchLogonRight"

# RULE039
Queue-SecAuditPrivilege -Name "SeSecurityPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE039' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE039 -Message "queued privilege SeSecurityPrivilege"

# RULE040
Queue-SecAuditPrivilege -Name "SeRelabelPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE040' -Fallback '' -Pick raw)"
Write-RemDone -Id RULE040 -Message "queued privilege SeRelabelPrivilege"

# RULE041
Queue-SecAuditPrivilege -Name "SeSystemEnvironmentPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE041' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE041 -Message "queued privilege SeSystemEnvironmentPrivilege"

# RULE042
Queue-SecAuditPrivilege -Name "SeManageVolumePrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE042' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE042 -Message "queued privilege SeManageVolumePrivilege"

# RULE043
Queue-SecAuditPrivilege -Name "SeProfileSingleProcessPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE043' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE043 -Message "queued privilege SeProfileSingleProcessPrivilege"

# RULE045
Queue-SecAuditPrivilege -Name "SeAssignPrimaryTokenPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE045' -Fallback 'LOCAL SERVICE,NETWORK SERVICE' -Pick raw)"
Write-RemDone -Id RULE045 -Message "queued privilege SeAssignPrimaryTokenPrivilege"

# RULE046
Queue-SecAuditPrivilege -Name "SeRestorePrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE046' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE046 -Message "queued privilege SeRestorePrivilege"

# RULE047
Queue-SecAuditPrivilege -Name "SeShutdownPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE047' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE047 -Message "queued privilege SeShutdownPrivilege"

# RULE048
Queue-SecAuditPrivilege -Name "SeTakeOwnershipPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE048' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE048 -Message "queued privilege SeTakeOwnershipPrivilege"

# RULE188
# RULE188
if (Test-SecAuditRuleEnabled -Id 'RULE188') { if (Set-SecAuditAuditpol -Subcategory "Credential Validation" -Setting "$(Get-SecAuditApplyValue -Id 'RULE188' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE188 -Message "auditpol Credential Validation => Success and Failure" } else { Write-RemSkip -Id RULE188 -Message "auditpol set failed for Credential Validation" } }

# RULE189
# RULE189
if (Test-SecAuditRuleEnabled -Id 'RULE189') { if (Set-SecAuditAuditpol -Subcategory "Application Group Management" -Setting "$(Get-SecAuditApplyValue -Id 'RULE189' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE189 -Message "auditpol Application Group Management => Success and Failure" } else { Write-RemSkip -Id RULE189 -Message "auditpol set failed for Application Group Management" } }

# RULE192
# RULE192
if (Test-SecAuditRuleEnabled -Id 'RULE192') { if (Set-SecAuditAuditpol -Subcategory "Security Group Management" -Setting "Success and Failure") { Write-RemDone -Id RULE192 -Message "auditpol Security Group Management => Success and Failure" } else { Write-RemSkip -Id RULE192 -Message "auditpol set failed for Security Group Management" } }

# RULE193
# RULE193
if (Test-SecAuditRuleEnabled -Id 'RULE193') { if (Set-SecAuditAuditpol -Subcategory "User Account Management" -Setting "$(Get-SecAuditApplyValue -Id 'RULE193' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE193 -Message "auditpol User Account Management => Success and Failure" } else { Write-RemSkip -Id RULE193 -Message "auditpol set failed for User Account Management" } }

# RULE195
# RULE195
if (Test-SecAuditRuleEnabled -Id 'RULE195') { if (Set-SecAuditAuditpol -Subcategory "Process Creation" -Setting "Success and Failure") { Write-RemDone -Id RULE195 -Message "auditpol Process Creation => Success and Failure" } else { Write-RemSkip -Id RULE195 -Message "auditpol set failed for Process Creation" } }

# RULE196
# RULE196
if (Test-SecAuditRuleEnabled -Id 'RULE196') { if (Set-SecAuditAuditpol -Subcategory "Account Lockout" -Setting "Success and Failure") { Write-RemDone -Id RULE196 -Message "auditpol Account Lockout => Success and Failure" } else { Write-RemSkip -Id RULE196 -Message "auditpol set failed for Account Lockout" } }

# RULE197
# RULE197
if (Test-SecAuditRuleEnabled -Id 'RULE197') { if (Set-SecAuditAuditpol -Subcategory "Group Membership" -Setting "Success and Failure") { Write-RemDone -Id RULE197 -Message "auditpol Group Membership => Success and Failure" } else { Write-RemSkip -Id RULE197 -Message "auditpol set failed for Group Membership" } }

# RULE198
# RULE198
if (Test-SecAuditRuleEnabled -Id 'RULE198') { if (Set-SecAuditAuditpol -Subcategory "Logoff" -Setting "Success and Failure") { Write-RemDone -Id RULE198 -Message "auditpol Logoff => Success and Failure" } else { Write-RemSkip -Id RULE198 -Message "auditpol set failed for Logoff" } }

# RULE199
# RULE199
if (Test-SecAuditRuleEnabled -Id 'RULE199') { if (Set-SecAuditAuditpol -Subcategory "Logon" -Setting "$(Get-SecAuditApplyValue -Id 'RULE199' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE199 -Message "auditpol Logon => Success and Failure" } else { Write-RemSkip -Id RULE199 -Message "auditpol set failed for Logon" } }

# RULE200
# RULE200
if (Test-SecAuditRuleEnabled -Id 'RULE200') { if (Set-SecAuditAuditpol -Subcategory "Other Logon/Logoff Events" -Setting "$(Get-SecAuditApplyValue -Id 'RULE200' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE200 -Message "auditpol Other Logon/Logoff Events => Success and Failure" } else { Write-RemSkip -Id RULE200 -Message "auditpol set failed for Other Logon/Logoff Events" } }

# RULE201
# RULE201
if (Test-SecAuditRuleEnabled -Id 'RULE201') { if (Set-SecAuditAuditpol -Subcategory "Special Logon" -Setting "Success and Failure") { Write-RemDone -Id RULE201 -Message "auditpol Special Logon => Success and Failure" } else { Write-RemSkip -Id RULE201 -Message "auditpol set failed for Special Logon" } }

# RULE202
# RULE202
if (Test-SecAuditRuleEnabled -Id 'RULE202') { if (Set-SecAuditAuditpol -Subcategory "Removable Storage" -Setting "$(Get-SecAuditApplyValue -Id 'RULE202' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE202 -Message "auditpol Removable Storage => Success and Failure" } else { Write-RemSkip -Id RULE202 -Message "auditpol set failed for Removable Storage" } }

# RULE203
# RULE203
if (Test-SecAuditRuleEnabled -Id 'RULE203') { if (Set-SecAuditAuditpol -Subcategory "Audit Policy Change" -Setting "Success and Failure") { Write-RemDone -Id RULE203 -Message "auditpol Audit Policy Change => Success and Failure" } else { Write-RemSkip -Id RULE203 -Message "auditpol set failed for Audit Policy Change" } }

# RULE204
# RULE204
if (Test-SecAuditRuleEnabled -Id 'RULE204') { if (Set-SecAuditAuditpol -Subcategory "Authentication Policy Change" -Setting "Success and Failure") { Write-RemDone -Id RULE204 -Message "auditpol Authentication Policy Change => Success and Failure" } else { Write-RemSkip -Id RULE204 -Message "auditpol set failed for Authentication Policy Change" } }

# RULE205
# RULE205
if (Test-SecAuditRuleEnabled -Id 'RULE205') { if (Set-SecAuditAuditpol -Subcategory "Authorization Policy Change" -Setting "Success and Failure") { Write-RemDone -Id RULE205 -Message "auditpol Authorization Policy Change => Success and Failure" } else { Write-RemSkip -Id RULE205 -Message "auditpol set failed for Authorization Policy Change" } }

# RULE206
# RULE206
if (Test-SecAuditRuleEnabled -Id 'RULE206') { if (Set-SecAuditAuditpol -Subcategory "Sensitive Privilege Use" -Setting "$(Get-SecAuditApplyValue -Id 'RULE206' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE206 -Message "auditpol Sensitive Privilege Use => Success and Failure" } else { Write-RemSkip -Id RULE206 -Message "auditpol set failed for Sensitive Privilege Use" } }

# RULE207
# RULE207
if (Test-SecAuditRuleEnabled -Id 'RULE207') { if (Set-SecAuditAuditpol -Subcategory "IPsec Driver" -Setting "$(Get-SecAuditApplyValue -Id 'RULE207' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE207 -Message "auditpol IPsec Driver => Success and Failure" } else { Write-RemSkip -Id RULE207 -Message "auditpol set failed for IPsec Driver" } }

# RULE208
# RULE208
if (Test-SecAuditRuleEnabled -Id 'RULE208') { if (Set-SecAuditAuditpol -Subcategory "Other System Events" -Setting "$(Get-SecAuditApplyValue -Id 'RULE208' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE208 -Message "auditpol Other System Events => Success and Failure" } else { Write-RemSkip -Id RULE208 -Message "auditpol set failed for Other System Events" } }

# RULE209
# RULE209
if (Test-SecAuditRuleEnabled -Id 'RULE209') { if (Set-SecAuditAuditpol -Subcategory "Security State Change" -Setting "Success and Failure") { Write-RemDone -Id RULE209 -Message "auditpol Security State Change => Success and Failure" } else { Write-RemSkip -Id RULE209 -Message "auditpol set failed for Security State Change" } }

# RULE210
# RULE210
if (Test-SecAuditRuleEnabled -Id 'RULE210') { if (Set-SecAuditAuditpol -Subcategory "Security System Extension" -Setting "Success and Failure") { Write-RemDone -Id RULE210 -Message "auditpol Security System Extension => Success and Failure" } else { Write-RemSkip -Id RULE210 -Message "auditpol set failed for Security System Extension" } }

# RULE211
# RULE211
if (Test-SecAuditRuleEnabled -Id 'RULE211') { if (Set-SecAuditAuditpol -Subcategory "System Integrity" -Setting "$(Get-SecAuditApplyValue -Id 'RULE211' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE211 -Message "auditpol System Integrity => Success and Failure" } else { Write-RemSkip -Id RULE211 -Message "auditpol set failed for System Integrity" } }

# RULE049
# RULE049
if (Test-SecAuditRuleEnabled -Id 'RULE049') { if (Set-SecAuditAccountDisabled -Which "LocalAdministrator" -Disabled $true) { Write-RemDone -Id RULE049 -Message "disabled LocalAdministrator" } else { Write-RemSkip -Id RULE049 -Message "could not disable LocalAdministrator" } }

# RULE051
# RULE051
if (Test-SecAuditRuleEnabled -Id 'RULE051') { if (Set-SecAuditAccountDisabled -Which "LocalGuest" -Disabled $true) { Write-RemDone -Id RULE051 -Message "disabled LocalGuest" } else { Write-RemSkip -Id RULE051 -Message "could not disable LocalGuest" } }

# RULE053
# RULE053
if (Test-SecAuditRuleEnabled -Id 'RULE053') { if (Rename-SecAuditBuiltIn -Which "LocalAdministrator" -NewName "SecAuditAdmin") { Write-RemDone -Id RULE053 -Message "renamed LocalAdministrator to SecAuditAdmin" } else { Write-RemSkip -Id RULE053 -Message "could not rename LocalAdministrator" } }

# RULE054
# RULE054
if (Test-SecAuditRuleEnabled -Id 'RULE054') { if (Rename-SecAuditBuiltIn -Which "LocalGuest" -NewName "SecAuditGuest") { Write-RemDone -Id RULE054 -Message "renamed LocalGuest to SecAuditGuest" } else { Write-RemSkip -Id RULE054 -Message "could not rename LocalGuest" } }

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
