[CmdletBinding()]
param(
    [ValidateRange(1, 720)]
    [int]$LastHours = 24,

    [string]$ExportPath
)

$ErrorActionPreference = 'Stop'
$startTime = (Get-Date).AddHours(-$LastHours)

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = $startTime
    } -MaxEvents 10000 -ErrorAction Stop
}
catch {
    throw "Could not query Security Event ID 4625. Run PowerShell elevated and verify that logon auditing is enabled. Details: $($_.Exception.Message)"
}

$accountAliases = @{}
$aliasNumber = 0
$rows = foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $fields = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        $name = $node.GetAttribute('Name')
        if ($name) { $fields[$name] = $node.InnerText }
    }

    $account = [string]$fields['TargetUserName']
    if ([string]::IsNullOrWhiteSpace($account) -or $account -eq '-') {
        $accountLabel = 'Unknown'
    }
    else {
        if (-not $accountAliases.ContainsKey($account)) {
            $aliasNumber++
            $accountAliases[$account] = "Account-$aliasNumber"
        }
        $accountLabel = $accountAliases[$account]
    }

    $logonType = switch ([string]$fields['LogonType']) {
        '2'  { 'Interactive' }
        '3'  { 'Network' }
        '4'  { 'Batch' }
        '5'  { 'Service' }
        '7'  { 'Unlock' }
        '10' { 'RemoteInteractive' }
        '11' { 'CachedInteractive' }
        default { 'Other/Unknown' }
    }

    $subStatus = ([string]$fields['SubStatus']).ToLowerInvariant()
    $failureReason = switch ($subStatus) {
        '0xc000006a' { 'Incorrect password' }
        '0xc0000064' { 'Unknown account' }
        '0xc0000234' { 'Account locked' }
        default { 'Other/Unknown failure' }
    }

    $ip = [string]$fields['IpAddress']
    $source = 'Not supplied'
    if (-not [string]::IsNullOrWhiteSpace($ip) -and $ip -ne '-') {
        $parsedIp = $null
        if ([System.Net.IPAddress]::TryParse($ip, [ref]$parsedIp)) {
            if ([System.Net.IPAddress]::IsLoopback($parsedIp)) {
                $source = 'Loopback'
            }
            else {
                $source = 'Address supplied (redacted)'
            }
        }
        else {
            $source = 'Unparsed address (redacted)'
        }
    }

    $caller = [string]$fields['ProcessName']
    if ($caller) { $caller = Split-Path -Path $caller -Leaf }

    $callerPid = [string]$fields['ProcessId']
    if ($callerPid -match '^0x([0-9a-fA-F]+)$') {
        $callerPid = [string][Convert]::ToInt64($Matches[1], 16)
    }

    [PSCustomObject]@{
        Timestamp = $event.TimeCreated
        RecordId = $event.RecordId
        Account = $accountLabel
        LogonType = $logonType
        FailureReason = $failureReason
        Status = $fields['Status']
        SubStatus = $fields['SubStatus']
        CallerProcess = $caller
        CallerProcessId = $callerPid
        LogonProcess = $fields['LogonProcessName']
        AuthenticationPackage = $fields['AuthenticationPackageName']
        Source = $source
    }
}

$rows = @($rows | Sort-Object Timestamp)
Write-Host "Failed logon events found: $($rows.Count) in the last $LastHours hour(s)."
if ($rows.Count -gt 0) {
    $rows | Format-Table -AutoSize
    Write-Warning 'Account names and network addresses are anonymised. Review the results in context; failed logons alone do not establish an attack.'
}
else {
    Write-Host 'No failed logon events were returned for the selected time range.'
}

if ($ExportPath) {
    $parent = Split-Path -Path $ExportPath -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $rows | Export-Csv -LiteralPath $ExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $ExportPath"
}
