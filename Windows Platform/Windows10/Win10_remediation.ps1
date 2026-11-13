# SecAudit Platform — Windows 10 Enterprise 22H2 remediation
# Generated from audit check_rule expectations.
# Output: REMEDIATE RULExxx= applied|SKIP: ...
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File .\Win10_remediation.ps1 [-DryRun]
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
    $inf = Join-Path $env:TEMP ('secaudit_win10_rem_{0}.inf' -f (Get-Date).ToFileTime())
    $db = Join-Path $env:TEMP ('secaudit_win10_rem_{0}.sdb' -f (Get-Date).ToFileTime())
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

Write-Output ("[remediation] starting Windows 10 Enterprise 22H2 remediation" + $(if ($DryRun) { " (DryRun)" } else { "" }))

# RULE050
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "noconnecteduser" -Value "3" -ValueType STRING) { Write-RemDone -Id RULE050 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\noconnecteduser=3" } else { Write-RemSkip -Id RULE050 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\noconnecteduser" }

# RULE052
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE052 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=1" } else { Write-RemSkip -Id RULE052 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" }

# RULE055
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "scenoapplylegacyauditpolicy" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE055 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\scenoapplylegacyauditpolicy=1" } else { Write-RemSkip -Id RULE055 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\scenoapplylegacyauditpolicy" }

# RULE056
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "crashonauditfail" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE056 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\crashonauditfail=0" } else { Write-RemSkip -Id RULE056 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\crashonauditfail" }

# RULE057
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "allocatedasd" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE057 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\allocatedasd=0" } else { Write-RemSkip -Id RULE057 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\allocatedasd" }

# RULE058
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE058 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=1" } else { Write-RemSkip -Id RULE058 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers" }

# RULE059
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE059 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=1" } else { Write-RemSkip -Id RULE059 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal" }

# RULE060
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE060 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=1" } else { Write-RemSkip -Id RULE060 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel" }

# RULE061
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE061 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=1" } else { Write-RemSkip -Id RULE061 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel" }

# RULE062
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE062 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=0" } else { Write-RemSkip -Id RULE062 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange" }

# RULE063
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -Value "30" -ValueType INTEGER) { Write-RemDone -Id RULE063 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=30" } else { Write-RemSkip -Id RULE063 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge" }

# RULE064
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE064 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=1" } else { Write-RemSkip -Id RULE064 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey" }

# RULE065
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE065 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=1" } else { Write-RemSkip -Id RULE065 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName" }

# RULE066
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "disablecad" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE066 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\disablecad=0" } else { Write-RemSkip -Id RULE066 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\disablecad" }

# RULE068
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "inactivitytimeoutsecs" -Value "900" -ValueType INTEGER) { Write-RemDone -Id RULE068 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\inactivitytimeoutsecs=900" } else { Write-RemSkip -Id RULE068 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\inactivitytimeoutsecs" }

# RULE071
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE071 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=4" } else { Write-RemSkip -Id RULE071 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount" }

# RULE072
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "PasswordExpiryWarning" -Value "14" -ValueType INTEGER) { Write-RemDone -Id RULE072 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=14" } else { Write-RemSkip -Id RULE072 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning" }

# RULE073
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "scremoveoption" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE073 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\scremoveoption=1" } else { Write-RemSkip -Id RULE073 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\scremoveoption" }

# RULE074
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE074 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=1" } else { Write-RemSkip -Id RULE074 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature" }

# RULE075
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE075 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=1" } else { Write-RemSkip -Id RULE075 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature" }

# RULE076
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE076 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=0" } else { Write-RemSkip -Id RULE076 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword" }

# RULE077
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "autodisconnect" -Value "15" -ValueType INTEGER) { Write-RemDone -Id RULE077 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\autodisconnect=15" } else { Write-RemSkip -Id RULE077 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\autodisconnect" }

# RULE078
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "requiresecuritysignature" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE078 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\requiresecuritysignature=1" } else { Write-RemSkip -Id RULE078 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\requiresecuritysignature" }

# RULE079
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "enablesecuritysignature" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE079 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enablesecuritysignature=1" } else { Write-RemSkip -Id RULE079 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\enablesecuritysignature" }

# RULE080
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableForcedLogoff" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE080 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\EnableForcedLogoff=1" } else { Write-RemSkip -Id RULE080 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\EnableForcedLogoff" }

# RULE081
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "smbservernamehardeninglevel" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE081 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\smbservernamehardeninglevel=1" } else { Write-RemSkip -Id RULE081 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\smbservernamehardeninglevel" }

# RULE083
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymoussam" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE083 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymoussam=1" } else { Write-RemSkip -Id RULE083 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymoussam" }

# RULE084
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE084 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymous=1" } else { Write-RemSkip -Id RULE084 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymous" }

# RULE085
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "disabledomaincreds" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE085 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\disabledomaincreds=1" } else { Write-RemSkip -Id RULE085 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\disabledomaincreds" }

# RULE086
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "everyoneincludesanonymous" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE086 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\everyoneincludesanonymous=0" } else { Write-RemSkip -Id RULE086 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\everyoneincludesanonymous" }

# RULE087
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes" -Value "" -ValueType STRING) { Write-RemDone -Id RULE087 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes=" } else { Write-RemSkip -Id RULE087 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes" }

# RULE090
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "restrictnullsessaccess" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE090 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\restrictnullsessaccess=1" } else { Write-RemSkip -Id RULE090 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\restrictnullsessaccess" }

# RULE091
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Value "O:BAG:BAD:(A;;RC;;;BA)" -ValueType STRING) { Write-RemDone -Id RULE091 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictRemoteSAM=O:BAG:BAD:(A;;RC;;;BA)" } else { Write-RemSkip -Id RULE091 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictRemoteSAM" }

# RULE092
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "nullsessionshares" -Value "" -ValueType STRING) { Write-RemDone -Id RULE092 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\nullsessionshares=" } else { Write-RemSkip -Id RULE092 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\nullsessionshares" }

# RULE093
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa" -Name "forceguest" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE093 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\forceguest=0" } else { Write-RemSkip -Id RULE093 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\forceguest" }

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

# RULE103
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinServerSec" -Value "537395200" -ValueType STRING) { Write-RemDone -Id RULE103 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinServerSec=537395200" } else { Write-RemSkip -Id RULE103 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinServerSec" }

# RULE104
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Cryptography" -Name "forcekeyprotection" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE104 -Message "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\forcekeyprotection=1" } else { Write-RemSkip -Id RULE104 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Cryptography\forcekeyprotection" }

# RULE105
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "obcaseinsensitive" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE105 -Message "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\obcaseinsensitive=1" } else { Write-RemSkip -Id RULE105 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\obcaseinsensitive" }

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

# RULE112
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE112 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=1" } else { Write-RemSkip -Id RULE112 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths" }

# RULE113
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE113 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=1" } else { Write-RemSkip -Id RULE113 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" }

# RULE114
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE114 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=1" } else { Write-RemSkip -Id RULE114 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop" }

# RULE115
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE115 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=1" } else { Write-RemSkip -Id RULE115 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization" }

# RULE117
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\bthserv" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE117 -Message "HKLM\SYSTEM\CurrentControlSet\Services\bthserv\Start=4" } else { Write-RemSkip -Id RULE117 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\bthserv\Start" }

# RULE118
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\browser" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE118 -Message "HKLM\SYSTEM\CurrentControlSet\Services\browser\Start=4" } else { Write-RemSkip -Id RULE118 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\browser\Start" }

# RULE119
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\MapsBroker" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE119 -Message "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker\Start=4" } else { Write-RemSkip -Id RULE119 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker\Start" }

# RULE120
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\lfsvc" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE120 -Message "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Start=4" } else { Write-RemSkip -Id RULE120 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Start" }

# RULE123
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\IISADMIN" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE123 -Message "HKLM\SYSTEM\CurrentControlSet\Services\IISADMIN\Start=4" } else { Write-RemSkip -Id RULE123 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\IISADMIN\Start" }

# RULE124
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\irmon" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE124 -Message "HKLM\SYSTEM\CurrentControlSet\Services\irmon\Start=4" } else { Write-RemSkip -Id RULE124 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\irmon\Start" }

# RULE125
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\SharedAccess" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE125 -Message "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Start=4" } else { Write-RemSkip -Id RULE125 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Start" }

# RULE126
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\lltdsvc" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE126 -Message "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc\Start=4" } else { Write-RemSkip -Id RULE126 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc\Start" }

# RULE127
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\LxssManager" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE127 -Message "HKLM\SYSTEM\CurrentControlSet\Services\LxssManager\Start=4" } else { Write-RemSkip -Id RULE127 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\LxssManager\Start" }

# RULE128
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\FTPSVC" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE128 -Message "HKLM\SYSTEM\CurrentControlSet\Services\FTPSVC\Start=4" } else { Write-RemSkip -Id RULE128 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\FTPSVC\Start" }

# RULE129
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\MSiSCSI" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE129 -Message "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI\Start=4" } else { Write-RemSkip -Id RULE129 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI\Start" }

# RULE130
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\PNRPsvc" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE130 -Message "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc\Start=4" } else { Write-RemSkip -Id RULE130 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc\Start" }

# RULE131
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\p2psvc" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE131 -Message "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc\Start=4" } else { Write-RemSkip -Id RULE131 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\p2psvc\Start" }

# RULE132
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\p2pimsvc" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE132 -Message "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc\Start=4" } else { Write-RemSkip -Id RULE132 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc\Start" }

# RULE133
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\PNRPAutoReg" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE133 -Message "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoReg\Start=4" } else { Write-RemSkip -Id RULE133 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoReg\Start" }

# RULE134
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\wercplsupport" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE134 -Message "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport\Start=4" } else { Write-RemSkip -Id RULE134 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport\Start" }

# RULE135
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\RasAuto" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE135 -Message "HKLM\SYSTEM\CurrentControlSet\Services\RasAuto\Start=4" } else { Write-RemSkip -Id RULE135 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\RasAuto\Start" }

# RULE136
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\SessionEnv" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE136 -Message "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv\Start=4" } else { Write-RemSkip -Id RULE136 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv\Start" }

# RULE137
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\TermService" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE137 -Message "HKLM\SYSTEM\CurrentControlSet\Services\TermService\Start=4" } else { Write-RemSkip -Id RULE137 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\TermService\Start" }

# RULE138
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\UmRdpService" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE138 -Message "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService\Start=4" } else { Write-RemSkip -Id RULE138 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService\Start" }

# RULE139
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\RpcLocator" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE139 -Message "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator\Start=4" } else { Write-RemSkip -Id RULE139 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator\Start" }

# RULE140
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE140 -Message "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry\Start=4" } else { Write-RemSkip -Id RULE140 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry\Start" }

# RULE141
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\RemoteAccess" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE141 -Message "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Start=4" } else { Write-RemSkip -Id RULE141 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Start" }

# RULE143
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\simptcp" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE143 -Message "HKLM\SYSTEM\CurrentControlSet\Services\simptcp\Start=4" } else { Write-RemSkip -Id RULE143 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\simptcp\Start" }

# RULE144
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\SNMP" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE144 -Message "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Start=4" } else { Write-RemSkip -Id RULE144 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Start" }

# RULE145
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\SSDPSRV" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE145 -Message "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV\Start=4" } else { Write-RemSkip -Id RULE145 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV\Start" }

# RULE146
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\upnphost" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE146 -Message "HKLM\SYSTEM\CurrentControlSet\Services\upnphost\Start=4" } else { Write-RemSkip -Id RULE146 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\upnphost\Start" }

# RULE147
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\WMSvc" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE147 -Message "HKLM\SYSTEM\CurrentControlSet\Services\WMSvc\Start=4" } else { Write-RemSkip -Id RULE147 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\WMSvc\Start" }

# RULE148
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\WerSvc" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE148 -Message "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc\Start=4" } else { Write-RemSkip -Id RULE148 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\WerSvc\Start" }

# RULE149
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Wecsvc" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE149 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc\Start=4" } else { Write-RemSkip -Id RULE149 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc\Start" }

# RULE150
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE150 -Message "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc\Start=4" } else { Write-RemSkip -Id RULE150 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc\Start" }

# RULE151
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\icssvc" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE151 -Message "HKLM\SYSTEM\CurrentControlSet\Services\icssvc\Start=4" } else { Write-RemSkip -Id RULE151 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\icssvc\Start" }

# RULE152
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\WinRM" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE152 -Message "HKLM\SYSTEM\CurrentControlSet\Services\WinRM\Start=4" } else { Write-RemSkip -Id RULE152 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\WinRM\Start" }

# RULE154
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\W3SVC" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE154 -Message "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Start=4" } else { Write-RemSkip -Id RULE154 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Start" }

# RULE155
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\XblAuthManager" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE155 -Message "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager\Start=4" } else { Write-RemSkip -Id RULE155 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager\Start" }

# RULE156
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\XblGameSave" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE156 -Message "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave\Start=4" } else { Write-RemSkip -Id RULE156 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave\Start" }

# RULE157
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" -Name "Start" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE157 -Message "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc\Start=4" } else { Write-RemSkip -Id RULE157 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc\Start" }

# RULE158
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE158 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall=1" } else { Write-RemSkip -Id RULE158 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall" }

# RULE159
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultInboundAction" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE159 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction=1" } else { Write-RemSkip -Id RULE159 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction" }

# RULE160
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultOutboundAction" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE160 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction=0" } else { Write-RemSkip -Id RULE160 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction" }

# RULE161
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DisableNotifications" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE161 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications=1" } else { Write-RemSkip -Id RULE161 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications" }

# RULE162
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "AllowLocalPolicyMerge" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE162 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalPolicyMerge=0" } else { Write-RemSkip -Id RULE162 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalPolicyMerge" }

# RULE163
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "AllowLocalIPsecPolicyMerge" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE163 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalIPsecPolicyMerge=0" } else { Write-RemSkip -Id RULE163 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalIPsecPolicyMerge" }

# RULE164
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogFilePath" -Value "%SystemRoot%\System32\logfiles\firewall\domainfw.log" -ValueType STRING) { Write-RemDone -Id RULE164 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath=%SystemRoot%\System32\logfiles\firewall\domainfw.log" } else { Write-RemSkip -Id RULE164 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath" }

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

# RULE172
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "AllowLocalPolicyMerge" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE172 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalPolicyMerge=0" } else { Write-RemSkip -Id RULE172 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalPolicyMerge" }

# RULE173
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "AllowLocalIPsecPolicyMerge" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE173 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalIPsecPolicyMerge=0" } else { Write-RemSkip -Id RULE173 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalIPsecPolicyMerge" }

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
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DisableNotifications" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE181 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications=1" } else { Write-RemSkip -Id RULE181 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications" }

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

# RULE214
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE214 -Message "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization=0" } else { Write-RemSkip -Id RULE214 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization" }

# RULE215
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}" -Name "DllName" -Value "C:\Program Files\LAPS\CSE\AdmPwd.dll" -ValueType STRING) { Write-RemDone -Id RULE215 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}\DllName=C:\Program Files\LAPS\CSE\AdmPwd.dll" } else { Write-RemSkip -Id RULE215 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}\DllName" }

# RULE216
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PwdExpirationProtectionEnabled" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE216 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PwdExpirationProtectionEnabled=1" } else { Write-RemSkip -Id RULE216 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PwdExpirationProtectionEnabled" }

# RULE217
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "AdmPwdEnabled" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE217 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled=1" } else { Write-RemSkip -Id RULE217 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled" }

# RULE218
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordComplexity" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE218 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordComplexity=4" } else { Write-RemSkip -Id RULE218 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordComplexity" }

# RULE219
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordLength" -Value "15" -ValueType INTEGER) { Write-RemDone -Id RULE219 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordLength=15" } else { Write-RemSkip -Id RULE219 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordLength" }

# RULE220
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordAgeDays" -Value "30" -ValueType INTEGER) { Write-RemDone -Id RULE220 -Message "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays=30" } else { Write-RemSkip -Id RULE220 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays" }

# RULE221
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE221 -Message "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon=0" } else { Write-RemSkip -Id RULE221 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon" }

# RULE222
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value "2" -ValueType INTEGER) { Write-RemDone -Id RULE222 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting=2" } else { Write-RemSkip -Id RULE222 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting" }

# RULE223
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value "2" -ValueType INTEGER) { Write-RemDone -Id RULE223 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting=2" } else { Write-RemSkip -Id RULE223 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting" }

# RULE224
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -Name "DisableSavePassword" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE224 -Message "HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\DisableSavePassword=1" } else { Write-RemSkip -Id RULE224 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\DisableSavePassword" }

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

# RULE231
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "TcpMaxDataRetransmissions" -Value "3" -ValueType INTEGER) { Write-RemDone -Id RULE231 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions=3" } else { Write-RemSkip -Id RULE231 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions" }

# RULE232
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value "3" -ValueType INTEGER) { Write-RemDone -Id RULE232 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions=3" } else { Write-RemSkip -Id RULE232 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions" }

# RULE233
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "WarningLevel" -Value "90" -ValueType INTEGER) { Write-RemDone -Id RULE233 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel=90" } else { Write-RemSkip -Id RULE233 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel" }

# RULE234
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value "2" -ValueType INTEGER) { Write-RemDone -Id RULE234 -Message "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NodeType=2" } else { Write-RemSkip -Id RULE234 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NodeType" }

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

# RULE245
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value "255" -ValueType STRING) { Write-RemDone -Id RULE245 -Message "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents=255" } else { Write-RemSkip -Id RULE245 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents" }

# RULE246
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE246 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars=0" } else { Write-RemSkip -Id RULE246 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars" }

# RULE247
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE247 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI\DisableWcnUi=1" } else { Write-RemSkip -Id RULE247 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI\DisableWcnUi" }

# RULE248
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE248 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections=1" } else { Write-RemSkip -Id RULE248 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections" }

# RULE249
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE249 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain=1" } else { Write-RemSkip -Id RULE249 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain" }

# RULE250
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE250 -Message "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\AutoConnectAllowedOEM=0" } else { Write-RemSkip -Id RULE250 -Message "failed to set HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\AutoConnectAllowedOEM" }

# RULE251
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE251 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy=0" } else { Write-RemSkip -Id RULE251 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy" }

# RULE252
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE252 -Message "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=0" } else { Write-RemSkip -Id RULE252 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential" }

# RULE253
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE253 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled=0" } else { Write-RemSkip -Id RULE253 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled" }

# RULE260
if (Set-SecAuditReg -RelativeKey "SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value "3" -ValueType STRING) { Write-RemDone -Id RULE260 -Message "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy=3" } else { Write-RemSkip -Id RULE260 -Message "failed to set HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy" }

# RULE261
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE261 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy=0" } else { Write-RemSkip -Id RULE261 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy" }

# RULE262
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE262 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges=0" } else { Write-RemSkip -Id RULE262 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges" }

# RULE263
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE263 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp=0" } else { Write-RemSkip -Id RULE263 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp" }

# RULE265
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE265 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith=1" } else { Write-RemSkip -Id RULE265 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith" }

# RULE266
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE266 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload=1" } else { Write-RemSkip -Id RULE266 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload" }

# RULE267
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE267 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing=1" } else { Write-RemSkip -Id RULE267 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing" }

# RULE268
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE268 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports=1" } else { Write-RemSkip -Id RULE268 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports" }

# RULE269
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE269 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard\ExitOnMSICW=1" } else { Write-RemSkip -Id RULE269 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard\ExitOnMSICW" }

# RULE270
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE270 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices=1" } else { Write-RemSkip -Id RULE270 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices" }

# RULE271
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE271 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting=1" } else { Write-RemSkip -Id RULE271 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting" }

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

# RULE281
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE281 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin=1" } else { Write-RemSkip -Id RULE281 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin" }

# RULE282
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE282 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI=1" } else { Write-RemSkip -Id RULE282 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI" }

# RULE283
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE283 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers=1" } else { Write-RemSkip -Id RULE283 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers" }

# RULE284
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnumerateLocalUsers" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE284 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers=0" } else { Write-RemSkip -Id RULE284 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers" }

# RULE285
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE285 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications=1" } else { Write-RemSkip -Id RULE285 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications" }

# RULE286
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE286 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon=0" } else { Write-RemSkip -Id RULE286 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon" }

# RULE288
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE288 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex=0" } else { Write-RemSkip -Id RULE288 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex" }

# RULE289
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE289 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex=0" } else { Write-RemSkip -Id RULE289 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex" }

# RULE292
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "DCSettingIndex" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE292 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex=1" } else { Write-RemSkip -Id RULE292 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex" }

# RULE293
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "ACSettingIndex" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE293 -Message "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex=1" } else { Write-RemSkip -Id RULE293 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex" }

# RULE294
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE294 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited=0" } else { Write-RemSkip -Id RULE294 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited" }

# RULE295
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE295 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp=0" } else { Write-RemSkip -Id RULE295 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp" }

# RULE296
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE296 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution=1" } else { Write-RemSkip -Id RULE296 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution" }

# RULE297
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE297 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients=1" } else { Write-RemSkip -Id RULE297 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients" }

# RULE298
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE298 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer=0" } else { Write-RemSkip -Id RULE298 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer" }

# RULE299
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name "ScenarioExecutionEnabled" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE299 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled=0" } else { Write-RemSkip -Id RULE299 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled" }

# RULE300
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE300 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo\DisabledByGroupPolicy=1" } else { Write-RemSkip -Id RULE300 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo\DisabledByGroupPolicy" }

# RULE301
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -Name "Enabled" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE301 -Message "HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient\Enabled=1" } else { Write-RemSkip -Id RULE301 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient\Enabled" }

# RULE302
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer" -Name "Enabled" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE302 -Message "HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled=0" } else { Write-RemSkip -Id RULE302 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled" }

# RULE303
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" -Name "AllowSharedLocalAppData" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE303 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\AllowSharedLocalAppData=0" } else { Write-RemSkip -Id RULE303 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\AllowSharedLocalAppData" }

# RULE319
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE319 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional=1" } else { Write-RemSkip -Id RULE319 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional" }

# RULE320
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "BlockHostedAppAccessWinRT" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE320 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\BlockHostedAppAccessWinRT=1" } else { Write-RemSkip -Id RULE320 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\BlockHostedAppAccessWinRT" }

# RULE321
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE321 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume=1" } else { Write-RemSkip -Id RULE321 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume" }

# RULE322
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE322 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun=1" } else { Write-RemSkip -Id RULE322 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun" }

# RULE323
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value "255" -ValueType INTEGER) { Write-RemDone -Id RULE323 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun=255" } else { Write-RemSkip -Id RULE323 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun" }

# RULE324
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE324 -Message "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing=1" } else { Write-RemSkip -Id RULE324 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing" }

# RULE382
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Camera" -Name "AllowCamera" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE382 -Message "HKLM\SOFTWARE\Policies\Microsoft\Camera\AllowCamera=0" } else { Write-RemSkip -Id RULE382 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Camera\AllowCamera" }

# RULE383
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE383 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures=1" } else { Write-RemSkip -Id RULE383 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures" }

# RULE384
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value "2" -ValueType INTEGER) { Write-RemDone -Id RULE384 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing=2" } else { Write-RemSkip -Id RULE384 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing" }

# RULE385
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE385 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal=1" } else { Write-RemSkip -Id RULE385 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal" }

# RULE386
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE386 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators=0" } else { Write-RemSkip -Id RULE386 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators" }

# RULE387
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE387 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry=1" } else { Write-RemSkip -Id RULE387 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry" }

# RULE389
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE389 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications=1" } else { Write-RemSkip -Id RULE389 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications" }

# RULE390
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE390 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview=0" } else { Write-RemSkip -Id RULE390 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview" }

# RULE391
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE391 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode=1" } else { Write-RemSkip -Id RULE391 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode" }

# RULE392
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "Retention" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE392 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention=0" } else { Write-RemSkip -Id RULE392 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention" }

# RULE393
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -Value "32768" -ValueType INTEGER) { Write-RemDone -Id RULE393 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize=32768" } else { Write-RemSkip -Id RULE393 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize" }

# RULE394
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE394 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention=0" } else { Write-RemSkip -Id RULE394 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention" }

# RULE395
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Value "196608" -ValueType INTEGER) { Write-RemDone -Id RULE395 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize=196608" } else { Write-RemSkip -Id RULE395 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize" }

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

# RULE404
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE404 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup\DisableHomeGroup=1" } else { Write-RemSkip -Id RULE404 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup\DisableHomeGroup" }

# RULE405
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE405 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\DisableLocation=1" } else { Write-RemSkip -Id RULE405 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\DisableLocation" }

# RULE417
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE417 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC=1" } else { Write-RemSkip -Id RULE417 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC" }

# RULE418
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE418 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving=1" } else { Write-RemSkip -Id RULE418 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving" }

# RULE419
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE419 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDenyTSConnections=1" } else { Write-RemSkip -Id RULE419 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDenyTSConnections" }

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

# RULE431
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE431 -Message "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload=1" } else { Write-RemSkip -Id RULE431 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload" }

# RULE432
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE432 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortana=0" } else { Write-RemSkip -Id RULE432 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortana" }

# RULE433
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE433 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortanaAboveLock=0" } else { Write-RemSkip -Id RULE433 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortanaAboveLock" }

# RULE434
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE434 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems=0" } else { Write-RemSkip -Id RULE434 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems" }

# RULE435
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE435 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowSearchToUseLocation=0" } else { Write-RemSkip -Id RULE435 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowSearchToUseLocation" }

# RULE436
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE436 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\NoGenTicket=1" } else { Write-RemSkip -Id RULE436 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\NoGenTicket" }

# RULE437
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE437 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\DisableStoreApps=1" } else { Write-RemSkip -Id RULE437 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\DisableStoreApps" }

# RULE438
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value "4" -ValueType INTEGER) { Write-RemDone -Id RULE438 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\AutoDownload=4" } else { Write-RemSkip -Id RULE438 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\AutoDownload" }

# RULE439
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE439 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\DisableOSUpgrade=1" } else { Write-RemSkip -Id RULE439 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\DisableOSUpgrade" }

# RULE440
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE440 -Message "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\RemoveWindowsStore=1" } else { Write-RemSkip -Id RULE440 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\RemoveWindowsStore" }

# RULE441
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE441 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpyNetReporting=0" } else { Write-RemSkip -Id RULE441 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpyNetReporting" }

# RULE442
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE442 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts=1" } else { Write-RemSkip -Id RULE442 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts" }

# RULE443
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE443 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR=0" } else { Write-RemSkip -Id RULE443 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR" }

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

# RULE460
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE460 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdates=1" } else { Write-RemSkip -Id RULE460 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdates" }

# RULE461
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Value "1" -ValueType STRING) { Write-RemDone -Id RULE461 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates=1" } else { Write-RemSkip -Id RULE461 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates" }

# RULE462
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE462 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate=0" } else { Write-RemSkip -Id RULE462 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate" }

# RULE463
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value "0" -ValueType STRING) { Write-RemDone -Id RULE463 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay=0" } else { Write-RemSkip -Id RULE463 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay" }

# RULE464
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE464 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers=0" } else { Write-RemSkip -Id RULE464 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers" }

# RULE479
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowLLTDIOOnPublicNet" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE479 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet=0" } else { Write-RemSkip -Id RULE479 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet" }

# RULE480
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "EnableLLTDIO" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE480 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableLLTDIO=0" } else { Write-RemSkip -Id RULE480 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableLLTDIO" }

# RULE481
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "ProhibitLLTDIOOnPrivateNet" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE481 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet=0" } else { Write-RemSkip -Id RULE481 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet" }

# RULE482
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowRspndrOnPublicNet" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE482 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet=0" } else { Write-RemSkip -Id RULE482 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet" }

# RULE483
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "EnableRspndr" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE483 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableRspndr=0" } else { Write-RemSkip -Id RULE483 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableRspndr" }

# RULE484
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "ProhibitRspndrOnPrivateNet" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE484 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet=0" } else { Write-RemSkip -Id RULE484 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet" }

# RULE485
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableUPnPRegistrar" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE485 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar=0" } else { Write-RemSkip -Id RULE485 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar" }

# RULE486
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableInBand802DOT11Registrar" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE486 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar=0" } else { Write-RemSkip -Id RULE486 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar" }

# RULE487
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableFlashConfigRegistrar" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE487 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar=0" } else { Write-RemSkip -Id RULE487 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar" }

# RULE488
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableWPDRegistrar" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE488 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar=0" } else { Write-RemSkip -Id RULE488 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar" }

# RULE489
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "DevicePKInitEnabled" -Value "1" -ValueType INTEGER) { Write-RemDone -Id RULE489 -Message "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled=1" } else { Write-RemSkip -Id RULE489 -Message "failed to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled" }

# RULE492
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value "180" -ValueType STRING) { Write-RemDone -Id RULE492 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays=180" } else { Write-RemSkip -Id RULE492 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays" }

# RULE494
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE494 -Message "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdatesPeriodInDays=0" } else { Write-RemSkip -Id RULE494 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdatesPeriodInDays" }

# RULE495
if (Set-SecAuditReg -RelativeKey "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Value "0" -ValueType INTEGER) { Write-RemDone -Id RULE495 -Message "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DoReport=0" } else { Write-RemSkip -Id RULE495 -Message "failed to set HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DoReport" }

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
Queue-SecAuditSysAccess -Name "LockoutBadCount" -Value "5"
Write-RemDone -Id RULE008 -Message "queued System Access LockoutBadCount=5"

# RULE009
Queue-SecAuditSysAccess -Name "ResetLockoutCount" -Value "15"
Write-RemDone -Id RULE009 -Message "queued System Access ResetLockoutCount=15"

# RULE082
Queue-SecAuditSysAccess -Name "LSAAnonymousNameLookup" -Value "0"
Write-RemDone -Id RULE082 -Message "queued System Access LSAAnonymousNameLookup=0"

# RULE010
Queue-SecAuditPrivilege -Name "SeTrustedCredManAccessPrivilege" -Value ""
Write-RemDone -Id RULE010 -Message "queued privilege SeTrustedCredManAccessPrivilege"

# RULE011
Queue-SecAuditPrivilege -Name "SeNetworkLogonRight" -Value "Administrators,Remote Desktop Users"
Write-RemDone -Id RULE011 -Message "queued privilege SeNetworkLogonRight"

# RULE012
Queue-SecAuditPrivilege -Name "SeTcbPrivilege" -Value ""
Write-RemDone -Id RULE012 -Message "queued privilege SeTcbPrivilege"

# RULE013
Queue-SecAuditPrivilege -Name "SeIncreaseQuotaPrivilege" -Value "Administrators,LOCAL SERVICE,NETWORK SERVICE"
Write-RemDone -Id RULE013 -Message "queued privilege SeIncreaseQuotaPrivilege"

# RULE014
Queue-SecAuditPrivilege -Name "SeInteractiveLogonRight" -Value "Administrators,Users"
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
Queue-SecAuditPrivilege -Name "SeTimeZonePrivilege" -Value "Administrators,LOCAL SERVICE, Users"
Write-RemDone -Id RULE018 -Message "queued privilege SeTimeZonePrivilege"

# RULE019
Queue-SecAuditPrivilege -Name "SeCreatePagefilePrivilege" -Value "Administrators"
Write-RemDone -Id RULE019 -Message "queued privilege SeCreatePagefilePrivilege"

# RULE020
Queue-SecAuditPrivilege -Name "SeCreateTokenPrivilege" -Value ""
Write-RemDone -Id RULE020 -Message "queued privilege SeCreateTokenPrivilege"

# RULE021
Queue-SecAuditPrivilege -Name "SeCreateGlobalPrivilege" -Value "Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE"
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
Queue-SecAuditPrivilege -Name "SeImpersonatePrivilege" -Value "Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE"
Write-RemDone -Id RULE033 -Message "queued privilege SeImpersonatePrivilege"

# RULE034
Queue-SecAuditPrivilege -Name "SeIncreaseBasePriorityPrivilege" -Value "Administrators, Window Manager\Window Manager Group"
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

# RULE038
Queue-SecAuditPrivilege -Name "SeServiceLogonRight" -Value ""
Write-RemDone -Id RULE038 -Message "queued privilege SeServiceLogonRight"

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
Queue-SecAuditPrivilege -Name "SeShutdownPrivilege" -Value "Administrators,Users"
Write-RemDone -Id RULE047 -Message "queued privilege SeShutdownPrivilege"

# RULE048
Queue-SecAuditPrivilege -Name "SeTakeOwnershipPrivilege" -Value "Administrators"
Write-RemDone -Id RULE048 -Message "queued privilege SeTakeOwnershipPrivilege"

# RULE188
if (Set-SecAuditAuditpol -Subcategory "Credential Validation" -Setting "Success and Failure") { Write-RemDone -Id RULE188 -Message "auditpol Credential Validation => Success and Failure" } else { Write-RemSkip -Id RULE188 -Message "auditpol set failed for Credential Validation" }

# RULE189
if (Set-SecAuditAuditpol -Subcategory "Application Group Management" -Setting "Success and Failure") { Write-RemDone -Id RULE189 -Message "auditpol Application Group Management => Success and Failure" } else { Write-RemSkip -Id RULE189 -Message "auditpol set failed for Application Group Management" }

# RULE190
if (Set-SecAuditAuditpol -Subcategory "Computer Account Management" -Setting "Success and Failure") { Write-RemDone -Id RULE190 -Message "auditpol Computer Account Management => Success and Failure" } else { Write-RemSkip -Id RULE190 -Message "auditpol set failed for Computer Account Management" }

# RULE191
if (Set-SecAuditAuditpol -Subcategory "Other Account Management Events" -Setting "Success") { Write-RemDone -Id RULE191 -Message "auditpol Other Account Management Events => Success" } else { Write-RemSkip -Id RULE191 -Message "auditpol set failed for Other Account Management Events" }

# RULE192
if (Set-SecAuditAuditpol -Subcategory "Security Group Management" -Setting "Success") { Write-RemDone -Id RULE192 -Message "auditpol Security Group Management => Success" } else { Write-RemSkip -Id RULE192 -Message "auditpol set failed for Security Group Management" }

# RULE193
if (Set-SecAuditAuditpol -Subcategory "User Account Management" -Setting "Success and Failure") { Write-RemDone -Id RULE193 -Message "auditpol User Account Management => Success and Failure" } else { Write-RemSkip -Id RULE193 -Message "auditpol set failed for User Account Management" }

# RULE194
if (Set-SecAuditAuditpol -Subcategory "Plug and Play Events" -Setting "Success") { Write-RemDone -Id RULE194 -Message "auditpol Plug and Play Events => Success" } else { Write-RemSkip -Id RULE194 -Message "auditpol set failed for Plug and Play Events" }

# RULE195
if (Set-SecAuditAuditpol -Subcategory "Process Creation" -Setting "Success") { Write-RemDone -Id RULE195 -Message "auditpol Process Creation => Success" } else { Write-RemSkip -Id RULE195 -Message "auditpol set failed for Process Creation" }

# RULE196
if (Set-SecAuditAuditpol -Subcategory "Account Lockout" -Setting "Failure") { Write-RemDone -Id RULE196 -Message "auditpol Account Lockout => Failure" } else { Write-RemSkip -Id RULE196 -Message "auditpol set failed for Account Lockout" }

# RULE197
if (Set-SecAuditAuditpol -Subcategory "Group Membership" -Setting "Success") { Write-RemDone -Id RULE197 -Message "auditpol Group Membership => Success" } else { Write-RemSkip -Id RULE197 -Message "auditpol set failed for Group Membership" }

# RULE198
if (Set-SecAuditAuditpol -Subcategory "Logoff" -Setting "Success") { Write-RemDone -Id RULE198 -Message "auditpol Logoff => Success" } else { Write-RemSkip -Id RULE198 -Message "auditpol set failed for Logoff" }

# RULE199
if (Set-SecAuditAuditpol -Subcategory "Logon" -Setting "Success and Failure") { Write-RemDone -Id RULE199 -Message "auditpol Logon => Success and Failure" } else { Write-RemSkip -Id RULE199 -Message "auditpol set failed for Logon" }

# RULE200
if (Set-SecAuditAuditpol -Subcategory "Other Logon/Logoff Events" -Setting "Success and Failure") { Write-RemDone -Id RULE200 -Message "auditpol Other Logon/Logoff Events => Success and Failure" } else { Write-RemSkip -Id RULE200 -Message "auditpol set failed for Other Logon/Logoff Events" }

# RULE201
if (Set-SecAuditAuditpol -Subcategory "Special Logon" -Setting "Success") { Write-RemDone -Id RULE201 -Message "auditpol Special Logon => Success" } else { Write-RemSkip -Id RULE201 -Message "auditpol set failed for Special Logon" }

# RULE202
if (Set-SecAuditAuditpol -Subcategory "Removable Storage" -Setting "Success and Failure") { Write-RemDone -Id RULE202 -Message "auditpol Removable Storage => Success and Failure" } else { Write-RemSkip -Id RULE202 -Message "auditpol set failed for Removable Storage" }

# RULE203
if (Set-SecAuditAuditpol -Subcategory "Audit Policy Change" -Setting "Success") { Write-RemDone -Id RULE203 -Message "auditpol Audit Policy Change => Success" } else { Write-RemSkip -Id RULE203 -Message "auditpol set failed for Audit Policy Change" }

# RULE204
if (Set-SecAuditAuditpol -Subcategory "Authentication Policy Change" -Setting "Success") { Write-RemDone -Id RULE204 -Message "auditpol Authentication Policy Change => Success" } else { Write-RemSkip -Id RULE204 -Message "auditpol set failed for Authentication Policy Change" }

# RULE205
if (Set-SecAuditAuditpol -Subcategory "Authorization Policy Change" -Setting "Success") { Write-RemDone -Id RULE205 -Message "auditpol Authorization Policy Change => Success" } else { Write-RemSkip -Id RULE205 -Message "auditpol set failed for Authorization Policy Change" }

# RULE206
if (Set-SecAuditAuditpol -Subcategory "Sensitive Privilege Use" -Setting "Success and Failure") { Write-RemDone -Id RULE206 -Message "auditpol Sensitive Privilege Use => Success and Failure" } else { Write-RemSkip -Id RULE206 -Message "auditpol set failed for Sensitive Privilege Use" }

# RULE207
if (Set-SecAuditAuditpol -Subcategory "IPsec Driver" -Setting "Success and Failure") { Write-RemDone -Id RULE207 -Message "auditpol IPsec Driver => Success and Failure" } else { Write-RemSkip -Id RULE207 -Message "auditpol set failed for IPsec Driver" }

# RULE208
if (Set-SecAuditAuditpol -Subcategory "Other System Events" -Setting "Success and Failure") { Write-RemDone -Id RULE208 -Message "auditpol Other System Events => Success and Failure" } else { Write-RemSkip -Id RULE208 -Message "auditpol set failed for Other System Events" }

# RULE209
if (Set-SecAuditAuditpol -Subcategory "Security State Change" -Setting "Success") { Write-RemDone -Id RULE209 -Message "auditpol Security State Change => Success" } else { Write-RemSkip -Id RULE209 -Message "auditpol set failed for Security State Change" }

# RULE210
if (Set-SecAuditAuditpol -Subcategory "Security System Extension" -Setting "Success") { Write-RemDone -Id RULE210 -Message "auditpol Security System Extension => Success" } else { Write-RemSkip -Id RULE210 -Message "auditpol set failed for Security System Extension" }

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

Write-Output "[remediation] remediation complete (Win10_remediation.ps1)"
