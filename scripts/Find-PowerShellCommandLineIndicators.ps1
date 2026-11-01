[CmdletBinding()]
param(
    [ValidateRange(1, 720)]
    [int]$LastHours = 24,

    [string]$ExportPath
)

$ErrorActionPreference = 'Stop'
$logName = 'Microsoft-Windows-Sysmon/Operational'
$startTime = (Get-Date).AddHours(-$LastHours)

# These patterns are investigative leads, not verdicts. Legitimate administration
# tools can use some of the same command-line options.
$indicators = @(
    [PSCustomObject]@{ Name = 'EncodedCommand'; Pattern = '(?i)(?:^|\s)-(?:enc|encodedcommand)(?:\s|:)' }
    [PSCustomObject]@{ Name = 'ExecutionPolicyBypass'; Pattern = '(?i)-executionpolicy\s+bypass' }
    [PSCustomObject]@{ Name = 'HiddenWindow'; Pattern = '(?i)(?:-windowstyle\s+hidden|-w\s+hidden)' }
    [PSCustomObject]@{ Name = 'NonInteractive'; Pattern = '(?i)-noninteractive' }
    [PSCustomObject]@{ Name = 'Base64Decoding'; Pattern = '(?i)FromBase64String' }
    [PSCustomObject]@{ Name = 'DynamicExecution'; Pattern = '(?i)Invoke-Expression|\bIEX\b' }
    [PSCustomObject]@{ Name = 'RemoteDownload'; Pattern = '(?i)DownloadString|Invoke-WebRequest' }
    [PSCustomObject]@{ Name = 'WebClient'; Pattern = '(?i)System\.Net\.WebClient' }
)

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = $logName
        Id        = 1
        StartTime = $startTime
    } -MaxEvents 10000 -ErrorAction Stop
}
catch {
    throw "Could not query Sysmon Event ID 1. Verify Sysmon and log access. Details: $($_.Exception.Message)"
}

$findings = foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $fields = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        $name = $node.GetAttribute('Name')
        if ($name) { $fields[$name] = $node.InnerText }
    }

    $image = [string]$fields['Image']
    $commandLine = [string]$fields['CommandLine']
    if ($image -match '\\(powershell|pwsh)\.exe$') {
        $matched = @(
            foreach ($indicator in $indicators) {
                if ($commandLine -match $indicator.Pattern) { $indicator.Name }
            }
        )

        if ($matched.Count -gt 0) {
            [PSCustomObject]@{
                Timestamp = $event.TimeCreated
                EventRecordId = $event.RecordId
                Process = Split-Path -Path $image -Leaf
                ProcessId = $fields['ProcessId']
                ProcessGuid = $fields['ProcessGuid']
                ParentProcess = if ($fields['ParentImage']) { Split-Path -Path $fields['ParentImage'] -Leaf } else { '' }
                Indicators = $matched -join ', '
                CommandLine = $commandLine
            }
        }
    }
}

$findings = @($findings | Sort-Object Timestamp)
if ($findings.Count -eq 0) {
    Write-Host "No selected command-line indicators matched in the last $LastHours hour(s). This does not prove the endpoint is free of suspicious activity."
}
else {
    $findings | Format-List
    Write-Warning 'Review each match in context. An indicator match is not proof of malicious activity.'
}

if ($ExportPath) {
    $parent = Split-Path -Path $ExportPath -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $findings | Export-Csv -LiteralPath $ExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $ExportPath"
}
