[CmdletBinding()]
param(
    [string]$TaskName = 'SOC-Lab-Test',

    [datetime]$StartTime = (Get-Date).AddDays(-7),

    [string]$ExportDirectory
)

$ErrorActionPreference = 'Stop'
$taskPathName = if ($TaskName.StartsWith('\')) { $TaskName } else { "\$TaskName" }

Write-Host "Searching task events for $taskPathName since $StartTime"

$securityRows = @()
try {
    $securityEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = @(4698, 4699)
        StartTime = $StartTime
    } -MaxEvents 10000 -ErrorAction Stop

    foreach ($event in $securityEvents) {
        [xml]$xml = $event.ToXml()
        $fields = @{}
        foreach ($node in $xml.Event.EventData.Data) {
            $name = $node.GetAttribute('Name')
            if ($name) { $fields[$name] = $node.InnerText }
        }

        if ([string]$fields['TaskName'] -ieq $taskPathName) {
            $securityRows += [PSCustomObject]@{
                Timestamp = $event.TimeCreated
                EventId = $event.Id
                RecordId = $event.RecordId
                TaskName = $fields['TaskName']
                Account = '[REDACTED]'
            }
        }
    }
}
catch {
    Write-Warning "Security task events could not be queried: $($_.Exception.Message)"
}

$taskSchedulerRows = @()
try {
    $taskEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-TaskScheduler/Operational'
        Id        = @(100, 102, 129, 200, 201)
        StartTime = $StartTime
    } -MaxEvents 10000 -ErrorAction Stop

    foreach ($event in $taskEvents) {
        if ($event.Message.IndexOf($taskPathName, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $processId = ''
            if ($event.Message -match 'process ID\s+(\d+)') {
                $processId = $Matches[1]
            }
            $taskSchedulerRows += [PSCustomObject]@{
                Timestamp = $event.TimeCreated
                EventId = $event.Id
                RecordId = $event.RecordId
                TaskName = $taskPathName
                ProcessId = $processId
            }
        }
    }
}
catch {
    Write-Warning "Task Scheduler Operational events could not be queried. The channel may be disabled or unavailable. Details: $($_.Exception.Message)"
}

Write-Host "`nWindows Security task events: $($securityRows.Count)"
$securityRows | Sort-Object Timestamp | Format-Table -AutoSize

Write-Host "`nTask Scheduler Operational events: $($taskSchedulerRows.Count)"
$taskSchedulerRows | Sort-Object Timestamp | Format-Table -AutoSize

if ($ExportDirectory) {
    if (-not (Test-Path -LiteralPath $ExportDirectory)) {
        New-Item -ItemType Directory -Path $ExportDirectory -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $securityPath = Join-Path $ExportDirectory "task-security-$stamp.csv"
    $schedulerPath = Join-Path $ExportDirectory "task-scheduler-$stamp.csv"
    $securityRows | Export-Csv -LiteralPath $securityPath -NoTypeInformation -Encoding UTF8
    $taskSchedulerRows | Export-Csv -LiteralPath $schedulerPath -NoTypeInformation -Encoding UTF8
    Write-Host "Security results exported to: $securityPath"
    Write-Host "Task Scheduler results exported to: $schedulerPath"
}

Write-Warning 'These event summaries are evidence leads. Validate task definitions, process telemetry and surrounding context before drawing conclusions.'
