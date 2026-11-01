[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ProcessGuid,

    [datetime]$StartTime = (Get-Date).AddDays(-30),

    [string]$ExportPath
)

$ErrorActionPreference = 'Stop'
$logName = 'Microsoft-Windows-Sysmon/Operational'
$normalizedGuid = $ProcessGuid.Trim().Trim('{', '}')

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = $logName
        Id        = @(1, 5)
        StartTime = $StartTime
    } -MaxEvents 10000 -ErrorAction Stop
}
catch {
    throw "Could not query the Sysmon Operational log. Verify that Sysmon is installed, the log exists, and you have permission. Details: $($_.Exception.Message)"
}

$rows = foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $fields = @{}

    foreach ($node in $xml.Event.EventData.Data) {
        $name = $node.GetAttribute('Name')
        if ($name) { $fields[$name] = $node.InnerText }
    }

    $eventGuid = [string]$fields['ProcessGuid']
    if ($eventGuid.Trim().Trim('{', '}') -ieq $normalizedGuid) {
        [PSCustomObject]@{
            TimestampUtc = $fields['UtcTime']
            EventRecordTime = $event.TimeCreated
            EventId = $event.Id
            Process = if ($fields['Image']) { Split-Path -Path $fields['Image'] -Leaf } else { '' }
            Image = $fields['Image']
            ProcessId = $fields['ProcessId']
            ProcessGuid = $fields['ProcessGuid']
            ParentProcess = if ($fields['ParentImage']) { Split-Path -Path $fields['ParentImage'] -Leaf } else { '' }
            ParentProcessId = $fields['ParentProcessId']
            CommandLine = $fields['CommandLine']
            User = '[REDACTED]'
        }
    }
}

$rows = @($rows | Sort-Object EventRecordTime)
if ($rows.Count -eq 0) {
    Write-Warning "No Sysmon Event ID 1 or 5 records found for Process GUID $ProcessGuid since $StartTime. Check the GUID and search window."
    return
}

$rows | Format-Table TimestampUtc, EventId, Process, ProcessId, ParentProcess -AutoSize

$foundIds = @($rows | Select-Object -ExpandProperty EventId -Unique)
if (($foundIds -contains 1) -and ($foundIds -contains 5)) {
    Write-Host 'Both process creation (Event ID 1) and termination (Event ID 5) were found.' -ForegroundColor Green
}
else {
    Write-Warning 'Only part of the process lifecycle was found. The process may still be running, events may have aged out, or telemetry may be incomplete.'
}

if ($ExportPath) {
    $parent = Split-Path -Path $ExportPath -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $rows | Export-Csv -LiteralPath $ExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "Evidence exported to: $ExportPath" -ForegroundColor Green
}
