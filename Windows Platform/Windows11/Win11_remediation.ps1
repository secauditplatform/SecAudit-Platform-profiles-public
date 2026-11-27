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


﻿# SecAudit Platform — Windows 11 remediation
# Generated from audit check_rule expectations.
# Output: REMEDIATE RULExxx= applied|SKIP: ...
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File .\Win11_remediation.ps1 [-DryRun]
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
    $inf = Join-Path $env:TEMP ('secaudit_win11_rem_{0}.inf' -f (Get-Date).ToFileTime())
    $db = Join-Path $env:TEMP ('secaudit_win11_rem_{0}.sdb' -f (Get-Date).ToFileTime())
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

Write-Output ("[remediation] starting Windows 11 remediation" + $(if ($DryRun) { " (DryRun)" } else { "" }))

# RULE050
# RULE050
if (Test-SecAuditRuleEnabled -Id 'RULE050') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "noconnecteduser" -Value "$(Get-SecAuditApplyValue -Id 'RULE050' -Fallback '3' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE050 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\noconnecteduser=$(Get-SecAuditApplyValue -Id 'RULE050' -Fallback '3' -Pick raw)" } else { Write-RemSkip -Id RULE050 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\noconnecteduser" } }

# RULE052
# RULE052
if (Test-SecAuditRuleEnabled -Id 'RULE052') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value "$(Get-SecAuditApplyValue -Id 'RULE052' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE052 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=$(Get-SecAuditApplyValue -Id 'RULE052' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE052 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" } }

# RULE055
# RULE055
if (Test-SecAuditRuleEnabled -Id 'RULE055') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "scenoapplylegacyauditpolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE055' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE055 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\scenoapplylegacyauditpolicy=$(Get-SecAuditApplyValue -Id 'RULE055' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE055 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\scenoapplylegacyauditpolicy" } }

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

# RULE061
# RULE061
if (Test-SecAuditRuleEnabled -Id 'RULE061') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value "$(Get-SecAuditApplyValue -Id 'RULE061' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE061 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=$(Get-SecAuditApplyValue -Id 'RULE061' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE061 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel" } }

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
if (Test-SecAuditRuleEnabled -Id 'RULE073') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "scremoveoption" -Value "$(Get-SecAuditApplyValue -Id 'RULE073' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE073 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\scremoveoption=$(Get-SecAuditApplyValue -Id 'RULE073' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE073 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\scremoveoption" } }

# RULE074
# RULE074
if (Test-SecAuditRuleEnabled -Id 'RULE074') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value "$(Get-SecAuditApplyValue -Id 'RULE074' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE074 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=$(Get-SecAuditApplyValue -Id 'RULE074' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE074 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature" } }

# RULE075
# RULE075
if (Test-SecAuditRuleEnabled -Id 'RULE075') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value "$(Get-SecAuditApplyValue -Id 'RULE075' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE075 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=$(Get-SecAuditApplyValue -Id 'RULE075' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE075 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature" } }

# RULE076
# RULE076
if (Test-SecAuditRuleEnabled -Id 'RULE076') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value "$(Get-SecAuditApplyValue -Id 'RULE076' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE076 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=$(Get-SecAuditApplyValue -Id 'RULE076' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE076 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword" } }

# RULE077
# RULE077
if (Test-SecAuditRuleEnabled -Id 'RULE077') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "autodisconnect" -Value "$(Get-SecAuditApplyValue -Id 'RULE077' -Fallback '15' -Pick high)" -ValueType INTEGER) { Write-RemDone -Id RULE077 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\autodisconnect=$(Get-SecAuditApplyValue -Id 'RULE077' -Fallback '15' -Pick high)" } else { Write-RemSkip -Id RULE077 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\autodisconnect" } }

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

# RULE085
# RULE085
if (Test-SecAuditRuleEnabled -Id 'RULE085') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "disabledomaincreds" -Value "$(Get-SecAuditApplyValue -Id 'RULE085' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE085 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\disabledomaincreds=$(Get-SecAuditApplyValue -Id 'RULE085' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE085 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\disabledomaincreds" } }

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
if (Test-SecAuditRuleEnabled -Id 'RULE091') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictremotesam" -Value "$(Get-SecAuditApplyValue -Id 'RULE091' -Fallback 'O:BAG:BAD:(A,,RC,,,BA)' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE091 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictremotesam=$(Get-SecAuditApplyValue -Id 'RULE091' -Fallback 'O:BAG:BAD:(A,,RC,,,BA)' -Pick raw)" } else { Write-RemSkip -Id RULE091 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictremotesam" } }

# RULE092
# RULE092
if (Test-SecAuditRuleEnabled -Id 'RULE092') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "nullsessionshares" -Value "$(Get-SecAuditApplyValue -Id 'RULE092' -Fallback '' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE092 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\nullsessionshares=" } else { Write-RemSkip -Id RULE092 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\nullsessionshares" } }

# RULE093
# RULE093
if (Test-SecAuditRuleEnabled -Id 'RULE093') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "forceguest" -Value "$(Get-SecAuditApplyValue -Id 'RULE093' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE093 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\forceguest=$(Get-SecAuditApplyValue -Id 'RULE093' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE093 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\forceguest" } }

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

# RULE103
# RULE103
if (Test-SecAuditRuleEnabled -Id 'RULE103') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinServerSec" -Value "$(Get-SecAuditApplyValue -Id 'RULE103' -Fallback '537395200' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE103 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinServerSec=$(Get-SecAuditApplyValue -Id 'RULE103' -Fallback '537395200' -Pick raw)" } else { Write-RemSkip -Id RULE103 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinServerSec" } }

# RULE104
# RULE104
if (Test-SecAuditRuleEnabled -Id 'RULE104') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Cryptography" -Name "forcekeyprotection" -Value "$(Get-SecAuditApplyValue -Id 'RULE104' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE104 -Message "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\forcekeyprotection=$(Get-SecAuditApplyValue -Id 'RULE104' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE104 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Cryptography\forcekeyprotection" } }

# RULE105
# RULE105
if (Test-SecAuditRuleEnabled -Id 'RULE105') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "obcaseinsensitive" -Value "$(Get-SecAuditApplyValue -Id 'RULE105' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE105 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\obcaseinsensitive=$(Get-SecAuditApplyValue -Id 'RULE105' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE105 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\obcaseinsensitive" } }

# RULE106
# RULE106
if (Test-SecAuditRuleEnabled -Id 'RULE106') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value "$(Get-SecAuditApplyValue -Id 'RULE106' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE106 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\ProtectionMode=$(Get-SecAuditApplyValue -Id 'RULE106' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE106 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\ProtectionMode" } }

# RULE107
# RULE107
if (Test-SecAuditRuleEnabled -Id 'RULE107') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value "$(Get-SecAuditApplyValue -Id 'RULE107' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE107 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=$(Get-SecAuditApplyValue -Id 'RULE107' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE107 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken" } }

# RULE108
# RULE108
if (Test-SecAuditRuleEnabled -Id 'RULE108') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableUIADesktopToggle" -Value "$(Get-SecAuditApplyValue -Id 'RULE108' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE108 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle=$(Get-SecAuditApplyValue -Id 'RULE108' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE108 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle" } }

# RULE109
# RULE109
if (Test-SecAuditRuleEnabled -Id 'RULE109') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "$(Get-SecAuditApplyValue -Id 'RULE109' -Fallback '2' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE109 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=$(Get-SecAuditApplyValue -Id 'RULE109' -Fallback '2' -Pick raw)" } else { Write-RemSkip -Id RULE109 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin" } }

# RULE110
# RULE110
if (Test-SecAuditRuleEnabled -Id 'RULE110') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value "$(Get-SecAuditApplyValue -Id 'RULE110' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE110 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=$(Get-SecAuditApplyValue -Id 'RULE110' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE110 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser" } }

# RULE111
# RULE111
if (Test-SecAuditRuleEnabled -Id 'RULE111') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Value "$(Get-SecAuditApplyValue -Id 'RULE111' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE111 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=$(Get-SecAuditApplyValue -Id 'RULE111' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE111 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection" } }

# RULE112
# RULE112
if (Test-SecAuditRuleEnabled -Id 'RULE112') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value "$(Get-SecAuditApplyValue -Id 'RULE112' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE112 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=$(Get-SecAuditApplyValue -Id 'RULE112' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE112 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths" } }

# RULE113
# RULE113
if (Test-SecAuditRuleEnabled -Id 'RULE113') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "$(Get-SecAuditApplyValue -Id 'RULE113' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE113 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=$(Get-SecAuditApplyValue -Id 'RULE113' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE113 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" } }

# RULE114
# RULE114
if (Test-SecAuditRuleEnabled -Id 'RULE114') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value "$(Get-SecAuditApplyValue -Id 'RULE114' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE114 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=$(Get-SecAuditApplyValue -Id 'RULE114' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE114 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop" } }

# RULE115
# RULE115
if (Test-SecAuditRuleEnabled -Id 'RULE115') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value "$(Get-SecAuditApplyValue -Id 'RULE115' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE115 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=$(Get-SecAuditApplyValue -Id 'RULE115' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE115 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization" } }

# RULE117
# RULE117
if (Test-SecAuditRuleEnabled -Id 'RULE117') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\bthserv" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE117' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE117 -Message "HKLM\SYSTEM\CurrentControlSet\Services\bthserv\Start=$(Get-SecAuditApplyValue -Id 'RULE117' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE117 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\bthserv\Start" } }

# RULE118
# RULE118
if (Test-SecAuditRuleEnabled -Id 'RULE118') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\browser" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE118' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE118 -Message "HKLM\SYSTEM\CurrentControlSet\Services\browser\Start=$(Get-SecAuditApplyValue -Id 'RULE118' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE118 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\browser\Start" } }

# RULE119
# RULE119
if (Test-SecAuditRuleEnabled -Id 'RULE119') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\MapsBroker" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE119' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE119 -Message "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker\Start=$(Get-SecAuditApplyValue -Id 'RULE119' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE119 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker\Start" } }

# RULE120
# RULE120
if (Test-SecAuditRuleEnabled -Id 'RULE120') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\lfsvc" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE120' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE120 -Message "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Start=$(Get-SecAuditApplyValue -Id 'RULE120' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE120 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Start" } }

# RULE123
# RULE123
if (Test-SecAuditRuleEnabled -Id 'RULE123') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\IISADMIN" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE123' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE123 -Message "HKLM\SYSTEM\CurrentControlSet\Services\IISADMIN\Start=$(Get-SecAuditApplyValue -Id 'RULE123' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE123 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\IISADMIN\Start" } }

# RULE124
# RULE124
if (Test-SecAuditRuleEnabled -Id 'RULE124') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\irmon" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE124' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE124 -Message "HKLM\SYSTEM\CurrentControlSet\Services\irmon\Start=$(Get-SecAuditApplyValue -Id 'RULE124' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE124 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\irmon\Start" } }

# RULE125
# RULE125
if (Test-SecAuditRuleEnabled -Id 'RULE125') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\SharedAccess" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE125' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE125 -Message "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Start=$(Get-SecAuditApplyValue -Id 'RULE125' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE125 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Start" } }

# RULE126
# RULE126
if (Test-SecAuditRuleEnabled -Id 'RULE126') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\lltdsvc" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE126' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE126 -Message "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc\Start=$(Get-SecAuditApplyValue -Id 'RULE126' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE126 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc\Start" } }

# RULE127
# RULE127
if (Test-SecAuditRuleEnabled -Id 'RULE127') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LxssManager" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE127' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE127 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LxssManager\Start=$(Get-SecAuditApplyValue -Id 'RULE127' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE127 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LxssManager\Start" } }

# RULE128
# RULE128
if (Test-SecAuditRuleEnabled -Id 'RULE128') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\FTPSVC" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE128' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE128 -Message "HKLM\SYSTEM\CurrentControlSet\Services\FTPSVC\Start=$(Get-SecAuditApplyValue -Id 'RULE128' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE128 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\FTPSVC\Start" } }

# RULE129
# RULE129
if (Test-SecAuditRuleEnabled -Id 'RULE129') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\MSiSCSI" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE129' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE129 -Message "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI\Start=$(Get-SecAuditApplyValue -Id 'RULE129' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE129 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI\Start" } }

# RULE130
# RULE130
if (Test-SecAuditRuleEnabled -Id 'RULE130') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\PNRPsvc" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE130' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE130 -Message "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc\Start=$(Get-SecAuditApplyValue -Id 'RULE130' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE130 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc\Start" } }

# RULE131
# RULE131
if (Test-SecAuditRuleEnabled -Id 'RULE131') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\p2psvc" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE131' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE131 -Message "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc\Start=$(Get-SecAuditApplyValue -Id 'RULE131' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE131 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\p2psvc\Start" } }

# RULE132
# RULE132
if (Test-SecAuditRuleEnabled -Id 'RULE132') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\p2pimsvc" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE132' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE132 -Message "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc\Start=$(Get-SecAuditApplyValue -Id 'RULE132' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE132 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc\Start" } }

# RULE133
# RULE133
if (Test-SecAuditRuleEnabled -Id 'RULE133') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\PNRPAutoReg" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE133' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE133 -Message "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoReg\Start=$(Get-SecAuditApplyValue -Id 'RULE133' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE133 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoReg\Start" } }

# RULE134
# RULE134
if (Test-SecAuditRuleEnabled -Id 'RULE134') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\wercplsupport" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE134' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE134 -Message "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport\Start=$(Get-SecAuditApplyValue -Id 'RULE134' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE134 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport\Start" } }

# RULE135
# RULE135
if (Test-SecAuditRuleEnabled -Id 'RULE135') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\RasAuto" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE135' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE135 -Message "HKLM\SYSTEM\CurrentControlSet\Services\RasAuto\Start=$(Get-SecAuditApplyValue -Id 'RULE135' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE135 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\RasAuto\Start" } }

# RULE136
# RULE136
if (Test-SecAuditRuleEnabled -Id 'RULE136') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\SessionEnv" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE136' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE136 -Message "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv\Start=$(Get-SecAuditApplyValue -Id 'RULE136' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE136 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv\Start" } }

# RULE137
# RULE137
if (Test-SecAuditRuleEnabled -Id 'RULE137') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\TermService" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE137' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE137 -Message "HKLM\SYSTEM\CurrentControlSet\Services\TermService\Start=$(Get-SecAuditApplyValue -Id 'RULE137' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE137 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\TermService\Start" } }

# RULE138
# RULE138
if (Test-SecAuditRuleEnabled -Id 'RULE138') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\UmRdpService" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE138' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE138 -Message "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService\Start=$(Get-SecAuditApplyValue -Id 'RULE138' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE138 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService\Start" } }

# RULE139
# RULE139
if (Test-SecAuditRuleEnabled -Id 'RULE139') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\RpcLocator" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE139' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE139 -Message "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator\Start=$(Get-SecAuditApplyValue -Id 'RULE139' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE139 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator\Start" } }

# RULE140
# RULE140
if (Test-SecAuditRuleEnabled -Id 'RULE140') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE140' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE140 -Message "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry\Start=$(Get-SecAuditApplyValue -Id 'RULE140' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE140 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry\Start" } }

# RULE141
# RULE141
if (Test-SecAuditRuleEnabled -Id 'RULE141') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\RemoteAccess" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE141' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE141 -Message "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Start=$(Get-SecAuditApplyValue -Id 'RULE141' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE141 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Start" } }

# RULE143
# RULE143
if (Test-SecAuditRuleEnabled -Id 'RULE143') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\simptcp" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE143' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE143 -Message "HKLM\SYSTEM\CurrentControlSet\Services\simptcp\Start=$(Get-SecAuditApplyValue -Id 'RULE143' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE143 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\simptcp\Start" } }

# RULE144
# RULE144
if (Test-SecAuditRuleEnabled -Id 'RULE144') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\SNMP" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE144' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE144 -Message "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Start=$(Get-SecAuditApplyValue -Id 'RULE144' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE144 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Start" } }

# RULE145
# RULE145
if (Test-SecAuditRuleEnabled -Id 'RULE145') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\SSDPSRV" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE145' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE145 -Message "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV\Start=$(Get-SecAuditApplyValue -Id 'RULE145' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE145 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV\Start" } }

# RULE146
# RULE146
if (Test-SecAuditRuleEnabled -Id 'RULE146') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\upnphost" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE146' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE146 -Message "HKLM\SYSTEM\CurrentControlSet\Services\upnphost\Start=$(Get-SecAuditApplyValue -Id 'RULE146' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE146 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\upnphost\Start" } }

# RULE147
# RULE147
if (Test-SecAuditRuleEnabled -Id 'RULE147') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\WMSvc" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE147' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE147 -Message "HKLM\SYSTEM\CurrentControlSet\Services\WMSvc\Start=$(Get-SecAuditApplyValue -Id 'RULE147' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE147 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\WMSvc\Start" } }

# RULE148
# RULE148
if (Test-SecAuditRuleEnabled -Id 'RULE148') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\WerSvc" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE148' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE148 -Message "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc\Start=$(Get-SecAuditApplyValue -Id 'RULE148' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE148 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\WerSvc\Start" } }

# RULE149
# RULE149
if (Test-SecAuditRuleEnabled -Id 'RULE149') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Wecsvc" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE149' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE149 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc\Start=$(Get-SecAuditApplyValue -Id 'RULE149' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE149 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc\Start" } }

# RULE150
# RULE150
if (Test-SecAuditRuleEnabled -Id 'RULE150') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE150' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE150 -Message "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc\Start=$(Get-SecAuditApplyValue -Id 'RULE150' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE150 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc\Start" } }

# RULE151
# RULE151
if (Test-SecAuditRuleEnabled -Id 'RULE151') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\icssvc" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE151' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE151 -Message "HKLM\SYSTEM\CurrentControlSet\Services\icssvc\Start=$(Get-SecAuditApplyValue -Id 'RULE151' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE151 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\icssvc\Start" } }

# RULE152
# RULE152
if (Test-SecAuditRuleEnabled -Id 'RULE152') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\WinRM" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE152' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE152 -Message "HKLM\SYSTEM\CurrentControlSet\Services\WinRM\Start=$(Get-SecAuditApplyValue -Id 'RULE152' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE152 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\WinRM\Start" } }

# RULE154
# RULE154
if (Test-SecAuditRuleEnabled -Id 'RULE154') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\W3SVC" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE154' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE154 -Message "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Start=$(Get-SecAuditApplyValue -Id 'RULE154' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE154 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Start" } }

# RULE155
# RULE155
if (Test-SecAuditRuleEnabled -Id 'RULE155') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\XblAuthManager" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE155' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE155 -Message "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager\Start=$(Get-SecAuditApplyValue -Id 'RULE155' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE155 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager\Start" } }

# RULE156
# RULE156
if (Test-SecAuditRuleEnabled -Id 'RULE156') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\XblGameSave" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE156' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE156 -Message "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave\Start=$(Get-SecAuditApplyValue -Id 'RULE156' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE156 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave\Start" } }

# RULE157
# RULE157
if (Test-SecAuditRuleEnabled -Id 'RULE157') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" -Name "Start" -Value "$(Get-SecAuditApplyValue -Id 'RULE157' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE157 -Message "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc\Start=$(Get-SecAuditApplyValue -Id 'RULE157' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE157 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc\Start" } }

# RULE158
# RULE158
if (Test-SecAuditRuleEnabled -Id 'RULE158') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "EnableFirewall" -Value "$(Get-SecAuditApplyValue -Id 'RULE158' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE158 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall=$(Get-SecAuditApplyValue -Id 'RULE158' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE158 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall" } }

# RULE159
# RULE159
if (Test-SecAuditRuleEnabled -Id 'RULE159') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultInboundAction" -Value "$(Get-SecAuditApplyValue -Id 'RULE159' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE159 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction=$(Get-SecAuditApplyValue -Id 'RULE159' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE159 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction" } }

# RULE160
# RULE160
if (Test-SecAuditRuleEnabled -Id 'RULE160') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultOutboundAction" -Value "$(Get-SecAuditApplyValue -Id 'RULE160' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE160 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction=$(Get-SecAuditApplyValue -Id 'RULE160' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE160 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction" } }

# RULE161
# RULE161
if (Test-SecAuditRuleEnabled -Id 'RULE161') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DisableNotifications" -Value "$(Get-SecAuditApplyValue -Id 'RULE161' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE161 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications=$(Get-SecAuditApplyValue -Id 'RULE161' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE161 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications" } }

# RULE162
# RULE162
if (Test-SecAuditRuleEnabled -Id 'RULE162') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalPolicyMerge" -Value "$(Get-SecAuditApplyValue -Id 'RULE162' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE162 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge=$(Get-SecAuditApplyValue -Id 'RULE162' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE162 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge" } }

# RULE163
# RULE163
if (Test-SecAuditRuleEnabled -Id 'RULE163') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalIPsecPolicyMerge" -Value "$(Get-SecAuditApplyValue -Id 'RULE163' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE163 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge=$(Get-SecAuditApplyValue -Id 'RULE163' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE163 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge" } }

# RULE164
# RULE164
if (Test-SecAuditRuleEnabled -Id 'RULE164') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFilePath" -Value "$(Get-SecAuditApplyValue -Id 'RULE164' -Fallback '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE164 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFilePath=$(Get-SecAuditApplyValue -Id 'RULE164' -Fallback '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log' -Pick raw)" } else { Write-RemSkip -Id RULE164 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFilePath" } }

# RULE165
# RULE165
if (Test-SecAuditRuleEnabled -Id 'RULE165') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFileSize" -Value "$(Get-SecAuditApplyValue -Id 'RULE165' -Fallback '16384' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE165 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize=$(Get-SecAuditApplyValue -Id 'RULE165' -Fallback '16384' -Pick raw)" } else { Write-RemSkip -Id RULE165 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize" } }

# RULE166
# RULE166
if (Test-SecAuditRuleEnabled -Id 'RULE166') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogDroppedPackets" -Value "$(Get-SecAuditApplyValue -Id 'RULE166' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE166 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets=$(Get-SecAuditApplyValue -Id 'RULE166' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE166 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets" } }

# RULE167
# RULE167
if (Test-SecAuditRuleEnabled -Id 'RULE167') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogSuccessfulConnections" -Value "$(Get-SecAuditApplyValue -Id 'RULE167' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE167 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections=$(Get-SecAuditApplyValue -Id 'RULE167' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE167 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections" } }

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

# RULE172
# RULE172
if (Test-SecAuditRuleEnabled -Id 'RULE172') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "AllowLocalPolicyMerge" -Value "$(Get-SecAuditApplyValue -Id 'RULE172' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE172 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalPolicyMerge=$(Get-SecAuditApplyValue -Id 'RULE172' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE172 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalPolicyMerge" } }

# RULE173
# RULE173
if (Test-SecAuditRuleEnabled -Id 'RULE173') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "AllowLocalIPsecPolicyMerge" -Value "$(Get-SecAuditApplyValue -Id 'RULE173' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE173 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalIPsecPolicyMerge=$(Get-SecAuditApplyValue -Id 'RULE173' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE173 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalIPsecPolicyMerge" } }

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

# RULE214
# RULE214
if (Test-SecAuditRuleEnabled -Id 'RULE214') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value "$(Get-SecAuditApplyValue -Id 'RULE214' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE214 -Message "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization=$(Get-SecAuditApplyValue -Id 'RULE214' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE214 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization" } }

# RULE215
# RULE215
if (Test-SecAuditRuleEnabled -Id 'RULE215') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}" -Name "DllName" -Value "$(Get-SecAuditApplyValue -Id 'RULE215' -Fallback 'C:\Program Files\LAPS\CSE\AdmPwd.dll' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE215 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}\DllName=$(Get-SecAuditApplyValue -Id 'RULE215' -Fallback 'C:\Program Files\LAPS\CSE\AdmPwd.dll' -Pick raw)" } else { Write-RemSkip -Id RULE215 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}\DllName" } }

# RULE216
# RULE216
if (Test-SecAuditRuleEnabled -Id 'RULE216') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PwdExpirationProtectionEnabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE216' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE216 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PwdExpirationProtectionEnabled=$(Get-SecAuditApplyValue -Id 'RULE216' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE216 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PwdExpirationProtectionEnabled" } }

# RULE217
# RULE217
if (Test-SecAuditRuleEnabled -Id 'RULE217') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "AdmPwdEnabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE217' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE217 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled=$(Get-SecAuditApplyValue -Id 'RULE217' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE217 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled" } }

# RULE218
# RULE218
if (Test-SecAuditRuleEnabled -Id 'RULE218') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordComplexity" -Value "$(Get-SecAuditApplyValue -Id 'RULE218' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE218 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordComplexity=$(Get-SecAuditApplyValue -Id 'RULE218' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE218 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordComplexity" } }

# RULE219
# RULE219
if (Test-SecAuditRuleEnabled -Id 'RULE219') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordLength" -Value "$(Get-SecAuditApplyValue -Id 'RULE219' -Fallback '15' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE219 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordLength=$(Get-SecAuditApplyValue -Id 'RULE219' -Fallback '15' -Pick raw)" } else { Write-RemSkip -Id RULE219 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordLength" } }

# RULE220
# RULE220
if (Test-SecAuditRuleEnabled -Id 'RULE220') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordAgeDays" -Value "$(Get-SecAuditApplyValue -Id 'RULE220' -Fallback '30' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE220 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays=$(Get-SecAuditApplyValue -Id 'RULE220' -Fallback '30' -Pick raw)" } else { Write-RemSkip -Id RULE220 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays" } }

# RULE221
# RULE221
if (Test-SecAuditRuleEnabled -Id 'RULE221') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "$(Get-SecAuditApplyValue -Id 'RULE221' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE221 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon=$(Get-SecAuditApplyValue -Id 'RULE221' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE221 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon" } }

# RULE222
# RULE222
if (Test-SecAuditRuleEnabled -Id 'RULE222') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value "$(Get-SecAuditApplyValue -Id 'RULE222' -Fallback '2' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE222 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting=$(Get-SecAuditApplyValue -Id 'RULE222' -Fallback '2' -Pick raw)" } else { Write-RemSkip -Id RULE222 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting" } }

# RULE223
# RULE223
if (Test-SecAuditRuleEnabled -Id 'RULE223') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value "$(Get-SecAuditApplyValue -Id 'RULE223' -Fallback '2' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE223 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting=$(Get-SecAuditApplyValue -Id 'RULE223' -Fallback '2' -Pick raw)" } else { Write-RemSkip -Id RULE223 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting" } }

# RULE224
# RULE224
if (Test-SecAuditRuleEnabled -Id 'RULE224') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -Name "DisableSavePassword" -Value "$(Get-SecAuditApplyValue -Id 'RULE224' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE224 -Message "HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\DisableSavePassword=$(Get-SecAuditApplyValue -Id 'RULE224' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE224 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\DisableSavePassword" } }

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

# RULE231
# RULE231
if (Test-SecAuditRuleEnabled -Id 'RULE231') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value "$(Get-SecAuditApplyValue -Id 'RULE231' -Fallback '3' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE231 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions=$(Get-SecAuditApplyValue -Id 'RULE231' -Fallback '3' -Pick raw)" } else { Write-RemSkip -Id RULE231 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions" } }

# RULE232
# RULE232
if (Test-SecAuditRuleEnabled -Id 'RULE232') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value "$(Get-SecAuditApplyValue -Id 'RULE232' -Fallback '3' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE232 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions=$(Get-SecAuditApplyValue -Id 'RULE232' -Fallback '3' -Pick raw)" } else { Write-RemSkip -Id RULE232 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions" } }

# RULE233
# RULE233
if (Test-SecAuditRuleEnabled -Id 'RULE233') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "WarningLevel" -Value "$(Get-SecAuditApplyValue -Id 'RULE233' -Fallback '90' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE233 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel=$(Get-SecAuditApplyValue -Id 'RULE233' -Fallback '90' -Pick raw)" } else { Write-RemSkip -Id RULE233 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel" } }

# RULE234
# RULE234
if (Test-SecAuditRuleEnabled -Id 'RULE234') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value "$(Get-SecAuditApplyValue -Id 'RULE234' -Fallback '2' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE234 -Message "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NodeType=$(Get-SecAuditApplyValue -Id 'RULE234' -Fallback '2' -Pick raw)" } else { Write-RemSkip -Id RULE234 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NodeType" } }

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

# RULE245
# RULE245
if (Test-SecAuditRuleEnabled -Id 'RULE245') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value "$(Get-SecAuditApplyValue -Id 'RULE245' -Fallback '255' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE245 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents=$(Get-SecAuditApplyValue -Id 'RULE245' -Fallback '255' -Pick raw)" } else { Write-RemSkip -Id RULE245 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents" } }

# RULE246
# RULE246
if (Test-SecAuditRuleEnabled -Id 'RULE246') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Value "$(Get-SecAuditApplyValue -Id 'RULE246' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE246 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars=$(Get-SecAuditApplyValue -Id 'RULE246' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE246 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars" } }

# RULE247
# RULE247
if (Test-SecAuditRuleEnabled -Id 'RULE247') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Value "$(Get-SecAuditApplyValue -Id 'RULE247' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE247 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI\DisableWcnUi=$(Get-SecAuditApplyValue -Id 'RULE247' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE247 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI\DisableWcnUi" } }

# RULE248
# RULE248
if (Test-SecAuditRuleEnabled -Id 'RULE248') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value "$(Get-SecAuditApplyValue -Id 'RULE248' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE248 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections=$(Get-SecAuditApplyValue -Id 'RULE248' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE248 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections" } }

# RULE249
# RULE249
if (Test-SecAuditRuleEnabled -Id 'RULE249') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -Value "$(Get-SecAuditApplyValue -Id 'RULE249' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE249 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain=$(Get-SecAuditApplyValue -Id 'RULE249' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE249 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain" } }

# RULE250
# RULE250
if (Test-SecAuditRuleEnabled -Id 'RULE250') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value "$(Get-SecAuditApplyValue -Id 'RULE250' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE250 -Message "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\AutoConnectAllowedOEM=$(Get-SecAuditApplyValue -Id 'RULE250' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE250 -Message "failed to set HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\AutoConnectAllowedOEM" } }

# RULE251
# RULE251
if (Test-SecAuditRuleEnabled -Id 'RULE251') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE251' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE251 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy=$(Get-SecAuditApplyValue -Id 'RULE251' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE251 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy" } }

# RULE252
# RULE252
if (Test-SecAuditRuleEnabled -Id 'RULE252') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value "$(Get-SecAuditApplyValue -Id 'RULE252' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE252 -Message "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=$(Get-SecAuditApplyValue -Id 'RULE252' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE252 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential" } }

# RULE253
# RULE253
if (Test-SecAuditRuleEnabled -Id 'RULE253') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE253' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE253 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled=$(Get-SecAuditApplyValue -Id 'RULE253' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE253 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled" } }

# RULE260
# RULE260
if (Test-SecAuditRuleEnabled -Id 'RULE260') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE260' -Fallback '3' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE260 -Message "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy=$(Get-SecAuditApplyValue -Id 'RULE260' -Fallback '3' -Pick raw)" } else { Write-RemSkip -Id RULE260 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy" } }

# RULE261
# RULE261
if (Test-SecAuditRuleEnabled -Id 'RULE261') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE261' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE261 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy=$(Get-SecAuditApplyValue -Id 'RULE261' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE261 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy" } }

# RULE262
# RULE262
if (Test-SecAuditRuleEnabled -Id 'RULE262') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -Value "$(Get-SecAuditApplyValue -Id 'RULE262' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE262 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges=$(Get-SecAuditApplyValue -Id 'RULE262' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE262 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges" } }

# RULE263
# RULE263
if (Test-SecAuditRuleEnabled -Id 'RULE263') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value "$(Get-SecAuditApplyValue -Id 'RULE263' -Fallback '0' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE263 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp=$(Get-SecAuditApplyValue -Id 'RULE263' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE263 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp" } }

# RULE265
# RULE265
if (Test-SecAuditRuleEnabled -Id 'RULE265') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value "$(Get-SecAuditApplyValue -Id 'RULE265' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE265 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith=$(Get-SecAuditApplyValue -Id 'RULE265' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE265 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith" } }

# RULE266
# RULE266
if (Test-SecAuditRuleEnabled -Id 'RULE266') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value "$(Get-SecAuditApplyValue -Id 'RULE266' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE266 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload=$(Get-SecAuditApplyValue -Id 'RULE266' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE266 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload" } }

# RULE267
# RULE267
if (Test-SecAuditRuleEnabled -Id 'RULE267') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value "$(Get-SecAuditApplyValue -Id 'RULE267' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE267 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing=$(Get-SecAuditApplyValue -Id 'RULE267' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE267 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing" } }

# RULE268
# RULE268
if (Test-SecAuditRuleEnabled -Id 'RULE268') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value "$(Get-SecAuditApplyValue -Id 'RULE268' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE268 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports=$(Get-SecAuditApplyValue -Id 'RULE268' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE268 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports" } }

# RULE269
# RULE269
if (Test-SecAuditRuleEnabled -Id 'RULE269') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -Value "$(Get-SecAuditApplyValue -Id 'RULE269' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE269 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard\ExitOnMSICW=$(Get-SecAuditApplyValue -Id 'RULE269' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE269 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard\ExitOnMSICW" } }

# RULE270
# RULE270
if (Test-SecAuditRuleEnabled -Id 'RULE270') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Value "$(Get-SecAuditApplyValue -Id 'RULE270' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE270 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices=$(Get-SecAuditApplyValue -Id 'RULE270' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE270 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices" } }

# RULE271
# RULE271
if (Test-SecAuditRuleEnabled -Id 'RULE271') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Value "$(Get-SecAuditApplyValue -Id 'RULE271' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE271 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting=$(Get-SecAuditApplyValue -Id 'RULE271' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE271 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting" } }

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

# RULE281
# RULE281
if (Test-SecAuditRuleEnabled -Id 'RULE281') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value "$(Get-SecAuditApplyValue -Id 'RULE281' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE281 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin=$(Get-SecAuditApplyValue -Id 'RULE281' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE281 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin" } }

# RULE282
# RULE282
if (Test-SecAuditRuleEnabled -Id 'RULE282') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value "$(Get-SecAuditApplyValue -Id 'RULE282' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE282 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI=$(Get-SecAuditApplyValue -Id 'RULE282' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE282 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI" } }

# RULE283
# RULE283
if (Test-SecAuditRuleEnabled -Id 'RULE283') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value "$(Get-SecAuditApplyValue -Id 'RULE283' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE283 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers=$(Get-SecAuditApplyValue -Id 'RULE283' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE283 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers" } }

# RULE284
# RULE284
if (Test-SecAuditRuleEnabled -Id 'RULE284') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnumerateLocalUsers" -Value "$(Get-SecAuditApplyValue -Id 'RULE284' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE284 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers=$(Get-SecAuditApplyValue -Id 'RULE284' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE284 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers" } }

# RULE285
# RULE285
if (Test-SecAuditRuleEnabled -Id 'RULE285') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value "$(Get-SecAuditApplyValue -Id 'RULE285' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE285 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications=$(Get-SecAuditApplyValue -Id 'RULE285' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE285 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications" } }

# RULE286
# RULE286
if (Test-SecAuditRuleEnabled -Id 'RULE286') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Value "$(Get-SecAuditApplyValue -Id 'RULE286' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE286 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon=$(Get-SecAuditApplyValue -Id 'RULE286' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE286 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon" } }

# RULE288
# RULE288
if (Test-SecAuditRuleEnabled -Id 'RULE288') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value "$(Get-SecAuditApplyValue -Id 'RULE288' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE288 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex=$(Get-SecAuditApplyValue -Id 'RULE288' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE288 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex" } }

# RULE289
# RULE289
if (Test-SecAuditRuleEnabled -Id 'RULE289') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value "$(Get-SecAuditApplyValue -Id 'RULE289' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE289 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex=$(Get-SecAuditApplyValue -Id 'RULE289' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE289 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex" } }

# RULE292
# RULE292
if (Test-SecAuditRuleEnabled -Id 'RULE292') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "DCSettingIndex" -Value "$(Get-SecAuditApplyValue -Id 'RULE292' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE292 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex=$(Get-SecAuditApplyValue -Id 'RULE292' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE292 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex" } }

# RULE293
# RULE293
if (Test-SecAuditRuleEnabled -Id 'RULE293') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "ACSettingIndex" -Value "$(Get-SecAuditApplyValue -Id 'RULE293' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE293 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex=$(Get-SecAuditApplyValue -Id 'RULE293' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE293 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex" } }

# RULE294
# RULE294
if (Test-SecAuditRuleEnabled -Id 'RULE294') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value "$(Get-SecAuditApplyValue -Id 'RULE294' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE294 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited=$(Get-SecAuditApplyValue -Id 'RULE294' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE294 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited" } }

# RULE295
# RULE295
if (Test-SecAuditRuleEnabled -Id 'RULE295') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value "$(Get-SecAuditApplyValue -Id 'RULE295' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE295 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp=$(Get-SecAuditApplyValue -Id 'RULE295' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE295 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp" } }

# RULE296
# RULE296
if (Test-SecAuditRuleEnabled -Id 'RULE296') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value "$(Get-SecAuditApplyValue -Id 'RULE296' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE296 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution=$(Get-SecAuditApplyValue -Id 'RULE296' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE296 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution" } }

# RULE297
# RULE297
if (Test-SecAuditRuleEnabled -Id 'RULE297') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Value "$(Get-SecAuditApplyValue -Id 'RULE297' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE297 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients=$(Get-SecAuditApplyValue -Id 'RULE297' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE297 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients" } }

# RULE298
# RULE298
if (Test-SecAuditRuleEnabled -Id 'RULE298') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -Value "$(Get-SecAuditApplyValue -Id 'RULE298' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE298 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer=$(Get-SecAuditApplyValue -Id 'RULE298' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE298 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer" } }

# RULE299
# RULE299
if (Test-SecAuditRuleEnabled -Id 'RULE299') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name "ScenarioExecutionEnabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE299' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE299 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled=$(Get-SecAuditApplyValue -Id 'RULE299' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE299 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled" } }

# RULE300
# RULE300
if (Test-SecAuditRuleEnabled -Id 'RULE300') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE300' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE300 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo\DisabledByGroupPolicy=$(Get-SecAuditApplyValue -Id 'RULE300' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE300 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo\DisabledByGroupPolicy" } }

# RULE301
# RULE301
if (Test-SecAuditRuleEnabled -Id 'RULE301') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -Name "Enabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE301' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE301 -Message "HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient\Enabled=$(Get-SecAuditApplyValue -Id 'RULE301' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE301 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient\Enabled" } }

# RULE302
# RULE302
if (Test-SecAuditRuleEnabled -Id 'RULE302') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer" -Name "Enabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE302' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE302 -Message "HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled=$(Get-SecAuditApplyValue -Id 'RULE302' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE302 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled" } }

# RULE303
# RULE303
if (Test-SecAuditRuleEnabled -Id 'RULE303') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" -Name "AllowSharedLocalAppData" -Value "$(Get-SecAuditApplyValue -Id 'RULE303' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE303 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\AllowSharedLocalAppData=$(Get-SecAuditApplyValue -Id 'RULE303' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE303 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\AllowSharedLocalAppData" } }

# RULE319
# RULE319
if (Test-SecAuditRuleEnabled -Id 'RULE319') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -Value "$(Get-SecAuditApplyValue -Id 'RULE319' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE319 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional=$(Get-SecAuditApplyValue -Id 'RULE319' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE319 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional" } }

# RULE320
# RULE320
if (Test-SecAuditRuleEnabled -Id 'RULE320') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "BlockHostedAppAccessWinRT" -Value "$(Get-SecAuditApplyValue -Id 'RULE320' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE320 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\BlockHostedAppAccessWinRT=$(Get-SecAuditApplyValue -Id 'RULE320' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE320 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\BlockHostedAppAccessWinRT" } }

# RULE321
# RULE321
if (Test-SecAuditRuleEnabled -Id 'RULE321') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value "$(Get-SecAuditApplyValue -Id 'RULE321' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE321 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume=$(Get-SecAuditApplyValue -Id 'RULE321' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE321 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume" } }

# RULE322
# RULE322
if (Test-SecAuditRuleEnabled -Id 'RULE322') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value "$(Get-SecAuditApplyValue -Id 'RULE322' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE322 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun=$(Get-SecAuditApplyValue -Id 'RULE322' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE322 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun" } }

# RULE323
# RULE323
if (Test-SecAuditRuleEnabled -Id 'RULE323') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value "$(Get-SecAuditApplyValue -Id 'RULE323' -Fallback '255' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE323 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun=$(Get-SecAuditApplyValue -Id 'RULE323' -Fallback '255' -Pick raw)" } else { Write-RemSkip -Id RULE323 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun" } }

# RULE324
# RULE324
if (Test-SecAuditRuleEnabled -Id 'RULE324') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value "$(Get-SecAuditApplyValue -Id 'RULE324' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE324 -Message "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing=$(Get-SecAuditApplyValue -Id 'RULE324' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE324 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing" } }

# RULE382
# RULE382
if (Test-SecAuditRuleEnabled -Id 'RULE382') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Camera" -Name "AllowCamera" -Value "$(Get-SecAuditApplyValue -Id 'RULE382' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE382 -Message "HKLM\SOFTWARE\Policies\Microsoft\Camera\AllowCamera=$(Get-SecAuditApplyValue -Id 'RULE382' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE382 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Camera\AllowCamera" } }

# RULE383
# RULE383
if (Test-SecAuditRuleEnabled -Id 'RULE383') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value "$(Get-SecAuditApplyValue -Id 'RULE383' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE383 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures=$(Get-SecAuditApplyValue -Id 'RULE383' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE383 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures" } }

# RULE384
# RULE384
if (Test-SecAuditRuleEnabled -Id 'RULE384') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value "$(Get-SecAuditApplyValue -Id 'RULE384' -Fallback '2' -Pick high)" -ValueType INTEGER) { Write-RemDone -Id RULE384 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing=$(Get-SecAuditApplyValue -Id 'RULE384' -Fallback '2' -Pick high)" } else { Write-RemSkip -Id RULE384 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing" } }

# RULE385
# RULE385
if (Test-SecAuditRuleEnabled -Id 'RULE385') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value "$(Get-SecAuditApplyValue -Id 'RULE385' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE385 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal=$(Get-SecAuditApplyValue -Id 'RULE385' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE385 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal" } }

# RULE386
# RULE386
if (Test-SecAuditRuleEnabled -Id 'RULE386') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Value "$(Get-SecAuditApplyValue -Id 'RULE386' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE386 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators=$(Get-SecAuditApplyValue -Id 'RULE386' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE386 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators" } }

# RULE387
# RULE387
if (Test-SecAuditRuleEnabled -Id 'RULE387') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value "$(Get-SecAuditApplyValue -Id 'RULE387' -Fallback '1' -Pick high)" -ValueType INTEGER) { Write-RemDone -Id RULE387 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry=$(Get-SecAuditApplyValue -Id 'RULE387' -Fallback '1' -Pick high)" } else { Write-RemSkip -Id RULE387 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry" } }

# RULE389
# RULE389
if (Test-SecAuditRuleEnabled -Id 'RULE389') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value "$(Get-SecAuditApplyValue -Id 'RULE389' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE389 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications=$(Get-SecAuditApplyValue -Id 'RULE389' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE389 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications" } }

# RULE390
# RULE390
if (Test-SecAuditRuleEnabled -Id 'RULE390') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value "$(Get-SecAuditApplyValue -Id 'RULE390' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE390 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview=$(Get-SecAuditApplyValue -Id 'RULE390' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE390 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview" } }

# RULE391
# RULE391
if (Test-SecAuditRuleEnabled -Id 'RULE391') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value "$(Get-SecAuditApplyValue -Id 'RULE391' -Fallback '3' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE391 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode=$(Get-SecAuditApplyValue -Id 'RULE391' -Fallback '3' -Pick raw)" } else { Write-RemSkip -Id RULE391 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode" } }

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

# RULE404
# RULE404
if (Test-SecAuditRuleEnabled -Id 'RULE404') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Value "$(Get-SecAuditApplyValue -Id 'RULE404' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE404 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup\DisableHomeGroup=$(Get-SecAuditApplyValue -Id 'RULE404' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE404 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup\DisableHomeGroup" } }

# RULE405
# RULE405
if (Test-SecAuditRuleEnabled -Id 'RULE405') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value "$(Get-SecAuditApplyValue -Id 'RULE405' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE405 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\DisableLocation=$(Get-SecAuditApplyValue -Id 'RULE405' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE405 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\DisableLocation" } }

# RULE409
# RULE409
if (Test-SecAuditRuleEnabled -Id 'RULE409') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "FormSuggest Passwords" -Value "$(Get-SecAuditApplyValue -Id 'RULE409' -Fallback 'no' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE409 -Message "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\FormSuggest Passwords=$(Get-SecAuditApplyValue -Id 'RULE409' -Fallback 'no' -Pick raw)" } else { Write-RemSkip -Id RULE409 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\FormSuggest Passwords" } }

# RULE410
# RULE410
if (Test-SecAuditRuleEnabled -Id 'RULE410') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPopups" -Value "$(Get-SecAuditApplyValue -Id 'RULE410' -Fallback 'yes' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE410 -Message "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\AllowPopups=$(Get-SecAuditApplyValue -Id 'RULE410' -Fallback 'yes' -Pick raw)" } else { Write-RemSkip -Id RULE410 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\AllowPopups" } }

# RULE411
# RULE411
if (Test-SecAuditRuleEnabled -Id 'RULE411') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -Name "ShowSearchSuggestionsGlobal" -Value "$(Get-SecAuditApplyValue -Id 'RULE411' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE411 -Message "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes\ShowSearchSuggestionsGlobal=$(Get-SecAuditApplyValue -Id 'RULE411' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE411 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes\ShowSearchSuggestionsGlobal" } }

# RULE412
# RULE412
if (Test-SecAuditRuleEnabled -Id 'RULE412') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value "$(Get-SecAuditApplyValue -Id 'RULE412' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE412 -Message "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9=$(Get-SecAuditApplyValue -Id 'RULE412' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE412 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9" } }

# RULE417
# RULE417
if (Test-SecAuditRuleEnabled -Id 'RULE417') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value "$(Get-SecAuditApplyValue -Id 'RULE417' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE417 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC=$(Get-SecAuditApplyValue -Id 'RULE417' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE417 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC" } }

# RULE418
# RULE418
if (Test-SecAuditRuleEnabled -Id 'RULE418') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value "$(Get-SecAuditApplyValue -Id 'RULE418' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE418 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving=$(Get-SecAuditApplyValue -Id 'RULE418' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE418 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving" } }

# RULE419
# RULE419
if (Test-SecAuditRuleEnabled -Id 'RULE419') { if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value "$(Get-SecAuditApplyValue -Id 'RULE419' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE419 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections=$(Get-SecAuditApplyValue -Id 'RULE419' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE419 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections" } }

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

# RULE432
# RULE432
if (Test-SecAuditRuleEnabled -Id 'RULE432') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value "$(Get-SecAuditApplyValue -Id 'RULE432' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE432 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortana=$(Get-SecAuditApplyValue -Id 'RULE432' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE432 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortana" } }

# RULE433
# RULE433
if (Test-SecAuditRuleEnabled -Id 'RULE433') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value "$(Get-SecAuditApplyValue -Id 'RULE433' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE433 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortanaAboveLock=$(Get-SecAuditApplyValue -Id 'RULE433' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE433 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortanaAboveLock" } }

# RULE434
# RULE434
if (Test-SecAuditRuleEnabled -Id 'RULE434') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value "$(Get-SecAuditApplyValue -Id 'RULE434' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE434 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems=$(Get-SecAuditApplyValue -Id 'RULE434' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE434 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems" } }

# RULE435
# RULE435
if (Test-SecAuditRuleEnabled -Id 'RULE435') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value "$(Get-SecAuditApplyValue -Id 'RULE435' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE435 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowSearchToUseLocation=$(Get-SecAuditApplyValue -Id 'RULE435' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE435 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowSearchToUseLocation" } }

# RULE436
# RULE436
if (Test-SecAuditRuleEnabled -Id 'RULE436') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Value "$(Get-SecAuditApplyValue -Id 'RULE436' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE436 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\NoGenTicket=$(Get-SecAuditApplyValue -Id 'RULE436' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE436 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\NoGenTicket" } }

# RULE437
# RULE437
if (Test-SecAuditRuleEnabled -Id 'RULE437') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -Value "$(Get-SecAuditApplyValue -Id 'RULE437' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE437 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\DisableStoreApps=$(Get-SecAuditApplyValue -Id 'RULE437' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE437 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\DisableStoreApps" } }

# RULE438
# RULE438
if (Test-SecAuditRuleEnabled -Id 'RULE438') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value "$(Get-SecAuditApplyValue -Id 'RULE438' -Fallback '4' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE438 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\AutoDownload=$(Get-SecAuditApplyValue -Id 'RULE438' -Fallback '4' -Pick raw)" } else { Write-RemSkip -Id RULE438 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\AutoDownload" } }

# RULE439
# RULE439
if (Test-SecAuditRuleEnabled -Id 'RULE439') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value "$(Get-SecAuditApplyValue -Id 'RULE439' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE439 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\DisableOSUpgrade=$(Get-SecAuditApplyValue -Id 'RULE439' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE439 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\DisableOSUpgrade" } }

# RULE440
# RULE440
if (Test-SecAuditRuleEnabled -Id 'RULE440') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value "$(Get-SecAuditApplyValue -Id 'RULE440' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE440 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\RemoveWindowsStore=$(Get-SecAuditApplyValue -Id 'RULE440' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE440 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\RemoveWindowsStore" } }

# RULE441
# RULE441
if (Test-SecAuditRuleEnabled -Id 'RULE441') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value "$(Get-SecAuditApplyValue -Id 'RULE441' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE441 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpyNetReporting=$(Get-SecAuditApplyValue -Id 'RULE441' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE441 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpyNetReporting" } }

# RULE442
# RULE442
if (Test-SecAuditRuleEnabled -Id 'RULE442') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Value "$(Get-SecAuditApplyValue -Id 'RULE442' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE442 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts=$(Get-SecAuditApplyValue -Id 'RULE442' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE442 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts" } }

# RULE443
# RULE443
if (Test-SecAuditRuleEnabled -Id 'RULE443') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value "$(Get-SecAuditApplyValue -Id 'RULE443' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE443 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR=$(Get-SecAuditApplyValue -Id 'RULE443' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE443 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR" } }

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

# RULE460
# RULE460
if (Test-SecAuditRuleEnabled -Id 'RULE460') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value "$(Get-SecAuditApplyValue -Id 'RULE460' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE460 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdates=$(Get-SecAuditApplyValue -Id 'RULE460' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE460 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdates" } }

# RULE461
# RULE461
if (Test-SecAuditRuleEnabled -Id 'RULE461') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Value "$(Get-SecAuditApplyValue -Id 'RULE461' -Fallback '1' -Pick raw)" -ValueType STRING) { Write-RemDone -Id RULE461 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates=$(Get-SecAuditApplyValue -Id 'RULE461' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE461 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates" } }

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
if (Test-SecAuditRuleEnabled -Id 'RULE479') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowLLTDIOOnPublicNet" -Value "$(Get-SecAuditApplyValue -Id 'RULE479' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE479 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet=$(Get-SecAuditApplyValue -Id 'RULE479' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE479 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet" } }

# RULE480
# RULE480
if (Test-SecAuditRuleEnabled -Id 'RULE480') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "EnableLLTDIO" -Value "$(Get-SecAuditApplyValue -Id 'RULE480' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE480 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableLLTDIO=$(Get-SecAuditApplyValue -Id 'RULE480' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE480 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableLLTDIO" } }

# RULE481
# RULE481
if (Test-SecAuditRuleEnabled -Id 'RULE481') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "ProhibitLLTDIOOnPrivateNet" -Value "$(Get-SecAuditApplyValue -Id 'RULE481' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE481 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet=$(Get-SecAuditApplyValue -Id 'RULE481' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE481 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet" } }

# RULE482
# RULE482
if (Test-SecAuditRuleEnabled -Id 'RULE482') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowRspndrOnPublicNet" -Value "$(Get-SecAuditApplyValue -Id 'RULE482' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE482 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet=$(Get-SecAuditApplyValue -Id 'RULE482' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE482 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet" } }

# RULE483
# RULE483
if (Test-SecAuditRuleEnabled -Id 'RULE483') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "EnableRspndr" -Value "$(Get-SecAuditApplyValue -Id 'RULE483' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE483 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableRspndr=$(Get-SecAuditApplyValue -Id 'RULE483' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE483 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableRspndr" } }

# RULE484
# RULE484
if (Test-SecAuditRuleEnabled -Id 'RULE484') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "ProhibitRspndrOnPrivateNet" -Value "$(Get-SecAuditApplyValue -Id 'RULE484' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE484 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet=$(Get-SecAuditApplyValue -Id 'RULE484' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE484 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet" } }

# RULE485
# RULE485
if (Test-SecAuditRuleEnabled -Id 'RULE485') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableUPnPRegistrar" -Value "$(Get-SecAuditApplyValue -Id 'RULE485' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE485 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar=$(Get-SecAuditApplyValue -Id 'RULE485' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE485 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar" } }

# RULE486
# RULE486
if (Test-SecAuditRuleEnabled -Id 'RULE486') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableInBand802DOT11Registrar" -Value "$(Get-SecAuditApplyValue -Id 'RULE486' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE486 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar=$(Get-SecAuditApplyValue -Id 'RULE486' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE486 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar" } }

# RULE487
# RULE487
if (Test-SecAuditRuleEnabled -Id 'RULE487') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableFlashConfigRegistrar" -Value "$(Get-SecAuditApplyValue -Id 'RULE487' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE487 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar=$(Get-SecAuditApplyValue -Id 'RULE487' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE487 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar" } }

# RULE488
# RULE488
if (Test-SecAuditRuleEnabled -Id 'RULE488') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableWPDRegistrar" -Value "$(Get-SecAuditApplyValue -Id 'RULE488' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE488 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar=$(Get-SecAuditApplyValue -Id 'RULE488' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE488 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar" } }

# RULE489
# RULE489
if (Test-SecAuditRuleEnabled -Id 'RULE489') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "DevicePKInitEnabled" -Value "$(Get-SecAuditApplyValue -Id 'RULE489' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE489 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled=$(Get-SecAuditApplyValue -Id 'RULE489' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE489 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled" } }

# RULE492
# RULE492
if (Test-SecAuditRuleEnabled -Id 'RULE492') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value "$(Get-SecAuditApplyValue -Id 'RULE492' -Fallback '180' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE492 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays=$(Get-SecAuditApplyValue -Id 'RULE492' -Fallback '180' -Pick raw)" } else { Write-RemSkip -Id RULE492 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays" } }

# RULE494
# RULE494
if (Test-SecAuditRuleEnabled -Id 'RULE494') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Value "$(Get-SecAuditApplyValue -Id 'RULE494' -Fallback '0' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE494 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdatesPeriodInDays=$(Get-SecAuditApplyValue -Id 'RULE494' -Fallback '0' -Pick raw)" } else { Write-RemSkip -Id RULE494 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdatesPeriodInDays" } }

# RULE495
# RULE495
if (Test-SecAuditRuleEnabled -Id 'RULE495') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DoHPolicy" -Value "$(Get-SecAuditApplyValue -Id 'RULE495' -Fallback '3' -Pick high)" -ValueType INTEGER) { Write-RemDone -Id RULE495 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DoHPolicy=$(Get-SecAuditApplyValue -Id 'RULE495' -Fallback '3' -Pick high)" } else { Write-RemSkip -Id RULE495 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DoHPolicy" } }

# RULE496
# RULE496
if (Test-SecAuditRuleEnabled -Id 'RULE496') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyPasswordReuse" -Value "$(Get-SecAuditApplyValue -Id 'RULE496' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE496 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\NotifyPasswordReuse=$(Get-SecAuditApplyValue -Id 'RULE496' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE496 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\NotifyPasswordReuse" } }

# RULE497
# RULE497
if (Test-SecAuditRuleEnabled -Id 'RULE497') { if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyUnsafeApp" -Value "$(Get-SecAuditApplyValue -Id 'RULE497' -Fallback '1' -Pick raw)" -ValueType INTEGER) { Write-RemDone -Id RULE497 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\NotifyUnsafeApp=$(Get-SecAuditApplyValue -Id 'RULE497' -Fallback '1' -Pick raw)" } else { Write-RemSkip -Id RULE497 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\NotifyUnsafeApp" } }

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

# RULE082
Queue-SecAuditSysAccess -Name "LSAAnonymousNameLookup" -Value "$(Get-SecAuditApplyValue -Id 'RULE082' -Fallback '0' -Pick raw)"
Write-RemDone -Id RULE082 -Message "queued System Access LSAAnonymousNameLookup=0"

# RULE010
Queue-SecAuditPrivilege -Name "SeTrustedCredManAccessPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE010' -Fallback '' -Pick raw)"
Write-RemDone -Id RULE010 -Message "queued privilege SeTrustedCredManAccessPrivilege"

# RULE011
Queue-SecAuditPrivilege -Name "SeNetworkLogonRight" -Value "$(Get-SecAuditApplyValue -Id 'RULE011' -Fallback 'Administrators,Remote Desktop Users' -Pick raw)"
Write-RemDone -Id RULE011 -Message "queued privilege SeNetworkLogonRight"

# RULE012
Queue-SecAuditPrivilege -Name "SeTcbPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE012' -Fallback '' -Pick raw)"
Write-RemDone -Id RULE012 -Message "queued privilege SeTcbPrivilege"

# RULE013
Queue-SecAuditPrivilege -Name "SeIncreaseQuotaPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE013' -Fallback 'Administrators,LOCAL SERVICE,NETWORK SERVICE' -Pick raw)"
Write-RemDone -Id RULE013 -Message "queued privilege SeIncreaseQuotaPrivilege"

# RULE014
Queue-SecAuditPrivilege -Name "SeInteractiveLogonRight" -Value "$(Get-SecAuditApplyValue -Id 'RULE014' -Fallback 'Administrators,Users' -Pick raw)"
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
Queue-SecAuditPrivilege -Name "SeTimeZonePrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE018' -Fallback 'Administrators,LOCAL SERVICE, Users' -Pick raw)"
Write-RemDone -Id RULE018 -Message "queued privilege SeTimeZonePrivilege"

# RULE019
Queue-SecAuditPrivilege -Name "SeCreatePagefilePrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE019' -Fallback 'Administrators' -Pick raw)"
Write-RemDone -Id RULE019 -Message "queued privilege SeCreatePagefilePrivilege"

# RULE020
Queue-SecAuditPrivilege -Name "SeCreateTokenPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE020' -Fallback '' -Pick raw)"
Write-RemDone -Id RULE020 -Message "queued privilege SeCreateTokenPrivilege"

# RULE021
Queue-SecAuditPrivilege -Name "SeCreateGlobalPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE021' -Fallback 'Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE' -Pick raw)"
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
Queue-SecAuditPrivilege -Name "SeImpersonatePrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE033' -Fallback 'Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE' -Pick raw)"
Write-RemDone -Id RULE033 -Message "queued privilege SeImpersonatePrivilege"

# RULE034
Queue-SecAuditPrivilege -Name "SeIncreaseBasePriorityPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE034' -Fallback 'Administrators, Window Manager\Window Manager Group' -Pick raw)"
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

# RULE038
Queue-SecAuditPrivilege -Name "SeServiceLogonRight" -Value "$(Get-SecAuditApplyValue -Id 'RULE038' -Fallback '' -Pick raw)"
Write-RemDone -Id RULE038 -Message "queued privilege SeServiceLogonRight"

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
Queue-SecAuditPrivilege -Name "SeShutdownPrivilege" -Value "$(Get-SecAuditApplyValue -Id 'RULE047' -Fallback 'Administrators,Users' -Pick raw)"
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

# RULE190
# RULE190
if (Test-SecAuditRuleEnabled -Id 'RULE190') { if (Set-SecAuditAuditpol -Subcategory "Computer Account Management" -Setting "$(Get-SecAuditApplyValue -Id 'RULE190' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE190 -Message "auditpol Computer Account Management => Success and Failure" } else { Write-RemSkip -Id RULE190 -Message "auditpol set failed for Computer Account Management" } }

# RULE191
# RULE191
if (Test-SecAuditRuleEnabled -Id 'RULE191') { if (Set-SecAuditAuditpol -Subcategory "Other Account Management Events" -Setting "$(Get-SecAuditApplyValue -Id 'RULE191' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE191 -Message "auditpol Other Account Management Events => Success" } else { Write-RemSkip -Id RULE191 -Message "auditpol set failed for Other Account Management Events" } }

# RULE192
# RULE192
if (Test-SecAuditRuleEnabled -Id 'RULE192') { if (Set-SecAuditAuditpol -Subcategory "Security Group Management" -Setting "$(Get-SecAuditApplyValue -Id 'RULE192' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE192 -Message "auditpol Security Group Management => Success" } else { Write-RemSkip -Id RULE192 -Message "auditpol set failed for Security Group Management" } }

# RULE193
# RULE193
if (Test-SecAuditRuleEnabled -Id 'RULE193') { if (Set-SecAuditAuditpol -Subcategory "User Account Management" -Setting "$(Get-SecAuditApplyValue -Id 'RULE193' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE193 -Message "auditpol User Account Management => Success and Failure" } else { Write-RemSkip -Id RULE193 -Message "auditpol set failed for User Account Management" } }

# RULE194
# RULE194
if (Test-SecAuditRuleEnabled -Id 'RULE194') { if (Set-SecAuditAuditpol -Subcategory "Plug and Play Events" -Setting "$(Get-SecAuditApplyValue -Id 'RULE194' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE194 -Message "auditpol Plug and Play Events => Success" } else { Write-RemSkip -Id RULE194 -Message "auditpol set failed for Plug and Play Events" } }

# RULE195
# RULE195
if (Test-SecAuditRuleEnabled -Id 'RULE195') { if (Set-SecAuditAuditpol -Subcategory "Process Creation" -Setting "$(Get-SecAuditApplyValue -Id 'RULE195' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE195 -Message "auditpol Process Creation => Success" } else { Write-RemSkip -Id RULE195 -Message "auditpol set failed for Process Creation" } }

# RULE196
# RULE196
if (Test-SecAuditRuleEnabled -Id 'RULE196') { if (Set-SecAuditAuditpol -Subcategory "Account Lockout" -Setting "$(Get-SecAuditApplyValue -Id 'RULE196' -Fallback 'Failure' -Pick raw)") { Write-RemDone -Id RULE196 -Message "auditpol Account Lockout => Failure" } else { Write-RemSkip -Id RULE196 -Message "auditpol set failed for Account Lockout" } }

# RULE197
# RULE197
if (Test-SecAuditRuleEnabled -Id 'RULE197') { if (Set-SecAuditAuditpol -Subcategory "Group Membership" -Setting "$(Get-SecAuditApplyValue -Id 'RULE197' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE197 -Message "auditpol Group Membership => Success" } else { Write-RemSkip -Id RULE197 -Message "auditpol set failed for Group Membership" } }

# RULE198
# RULE198
if (Test-SecAuditRuleEnabled -Id 'RULE198') { if (Set-SecAuditAuditpol -Subcategory "Logoff" -Setting "$(Get-SecAuditApplyValue -Id 'RULE198' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE198 -Message "auditpol Logoff => Success" } else { Write-RemSkip -Id RULE198 -Message "auditpol set failed for Logoff" } }

# RULE199
# RULE199
if (Test-SecAuditRuleEnabled -Id 'RULE199') { if (Set-SecAuditAuditpol -Subcategory "Logon" -Setting "$(Get-SecAuditApplyValue -Id 'RULE199' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE199 -Message "auditpol Logon => Success and Failure" } else { Write-RemSkip -Id RULE199 -Message "auditpol set failed for Logon" } }

# RULE200
# RULE200
if (Test-SecAuditRuleEnabled -Id 'RULE200') { if (Set-SecAuditAuditpol -Subcategory "Other Logon/Logoff Events" -Setting "$(Get-SecAuditApplyValue -Id 'RULE200' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE200 -Message "auditpol Other Logon/Logoff Events => Success and Failure" } else { Write-RemSkip -Id RULE200 -Message "auditpol set failed for Other Logon/Logoff Events" } }

# RULE201
# RULE201
if (Test-SecAuditRuleEnabled -Id 'RULE201') { if (Set-SecAuditAuditpol -Subcategory "Special Logon" -Setting "$(Get-SecAuditApplyValue -Id 'RULE201' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE201 -Message "auditpol Special Logon => Success" } else { Write-RemSkip -Id RULE201 -Message "auditpol set failed for Special Logon" } }

# RULE202
# RULE202
if (Test-SecAuditRuleEnabled -Id 'RULE202') { if (Set-SecAuditAuditpol -Subcategory "Removable Storage" -Setting "$(Get-SecAuditApplyValue -Id 'RULE202' -Fallback 'Success and Failure' -Pick raw)") { Write-RemDone -Id RULE202 -Message "auditpol Removable Storage => Success and Failure" } else { Write-RemSkip -Id RULE202 -Message "auditpol set failed for Removable Storage" } }

# RULE203
# RULE203
if (Test-SecAuditRuleEnabled -Id 'RULE203') { if (Set-SecAuditAuditpol -Subcategory "Audit Policy Change" -Setting "$(Get-SecAuditApplyValue -Id 'RULE203' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE203 -Message "auditpol Audit Policy Change => Success" } else { Write-RemSkip -Id RULE203 -Message "auditpol set failed for Audit Policy Change" } }

# RULE204
# RULE204
if (Test-SecAuditRuleEnabled -Id 'RULE204') { if (Set-SecAuditAuditpol -Subcategory "Authentication Policy Change" -Setting "$(Get-SecAuditApplyValue -Id 'RULE204' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE204 -Message "auditpol Authentication Policy Change => Success" } else { Write-RemSkip -Id RULE204 -Message "auditpol set failed for Authentication Policy Change" } }

# RULE205
# RULE205
if (Test-SecAuditRuleEnabled -Id 'RULE205') { if (Set-SecAuditAuditpol -Subcategory "Authorization Policy Change" -Setting "$(Get-SecAuditApplyValue -Id 'RULE205' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE205 -Message "auditpol Authorization Policy Change => Success" } else { Write-RemSkip -Id RULE205 -Message "auditpol set failed for Authorization Policy Change" } }

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
if (Test-SecAuditRuleEnabled -Id 'RULE209') { if (Set-SecAuditAuditpol -Subcategory "Security State Change" -Setting "$(Get-SecAuditApplyValue -Id 'RULE209' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE209 -Message "auditpol Security State Change => Success" } else { Write-RemSkip -Id RULE209 -Message "auditpol set failed for Security State Change" } }

# RULE210
# RULE210
if (Test-SecAuditRuleEnabled -Id 'RULE210') { if (Set-SecAuditAuditpol -Subcategory "Security System Extension" -Setting "$(Get-SecAuditApplyValue -Id 'RULE210' -Fallback 'Success' -Pick raw)") { Write-RemDone -Id RULE210 -Message "auditpol Security System Extension => Success" } else { Write-RemSkip -Id RULE210 -Message "auditpol set failed for Security System Extension" } }

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

# RULE474
Write-RemSkip -Id RULE474 -Message "HKU/DisableThirdPartySuggestions is per-user; apply via default user hive or GPO manually"

# RULE475
Write-RemSkip -Id RULE475 -Message "HKU/DisableWindowsSpotlightFeatures is per-user; apply via default user hive or GPO manually"

# RULE476
Write-RemSkip -Id RULE476 -Message "HKU/NoInplaceSharing is per-user; apply via default user hive or GPO manually"

# RULE477
Write-RemSkip -Id RULE477 -Message "HKU/AlwaysInstallElevated is per-user; apply via default user hive or GPO manually"

# RULE478
Write-RemSkip -Id RULE478 -Message "HKU/PreventCodecDownload is per-user; apply via default user hive or GPO manually"

# Apply queued secedit System Access + Privilege Rights in one pass
if (Apply-SecAuditSecedit) {
    Write-Output "[remediation] secedit configure applied (or DryRun/empty)"
} else {
    Write-Output "[remediation] secedit configure reported errors (see warnings)"
}

Write-Output "[remediation] remediation complete (Win11_remediation.ps1)"
