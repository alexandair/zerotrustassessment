<#
.SYNOPSIS
    All eligible endpoints are onboarded to Microsoft Defender for Endpoint.

.NOTES
    Test ID: 41045
    Workshop Task: SECOPS-045
    Pillar: SecOps
    Category: Endpoint threat protection
    Required permission: ThreatHunting.Read.All
#>

function Test-Assessment-41045 {
    [ZtTest(
        Category           = 'Endpoint threat protection',
        CompatibleLicense  = ('WINDEFATP', 'MDE_LITE'),
        ImplementationCost = 'Medium',
        Pillar             = 'SecOps',
        RiskLevel          = 'High',
        Service            = ('Graph'),
        SfiPillar          = 'Monitor and detect cyberthreats',
        TenantType         = ('Workforce'),
        TestId             = 41045,
        Title              = 'All eligible endpoints are onboarded to Microsoft Defender for Endpoint',
        UserImpact         = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity  = 'Checking Microsoft Defender for Endpoint onboarding coverage'
    $testTitle = 'All eligible endpoints are onboarded to Microsoft Defender for Endpoint'

    # Q1: Enumerate all devices from the DeviceInfo advanced hunting table (last 30 days).
    # arg_max(Timestamp, *) deduplicates to the most recent snapshot per DeviceId.
    # serviceSource filter is deliberately omitted; the KQL result covers all onboarded services.
    $kqlQuery = 'DeviceInfo | summarize arg_max(Timestamp, *) by DeviceId | project DeviceId, DeviceName, OSPlatform, OnboardingStatus, SensorHealthState, LastSeen=Timestamp'

    Write-ZtProgress -Activity $activity -Status 'Querying MDE device onboarding status via advanced hunting'
    $devices = $null
    try {
        $requestBody = @{ query = $kqlQuery; timespan = 'P30D' } | ConvertTo-Json -Compress
        $rawResult = Invoke-ZtGraphRequest -RelativeUri 'security/runHuntingQuery' -ApiVersion beta `
            -Method POST -Body $requestBody -ErrorAction Stop
        $devices   = if ($rawResult -and $rawResult.results) { @($rawResult.results) } else { @() }
    }
    catch {
        $httpStatus = Get-ZtHttpStatusCode -ErrorRecord $_
        Write-PSFMessage "Advanced hunting query failed (HTTP $httpStatus): $_" -Tag Test -Level Warning
        $msg = if ($httpStatus -in @(401, 403)) {
            '⚠️ **ThreatHunting.Read.All** permission is required to run advanced hunting queries. Verify the permission is consented and the assessment identity has Security Reader or Security Operator role, then re-run.'
        } elseif ($httpStatus -eq 429) {
            '⚠️ The advanced hunting quota was exceeded. Retry when the quota window resets (typically a few minutes).'
        } else {
            '⚠️ Microsoft Graph returned an unexpected error while running the advanced hunting query. Re-run after 5–10 minutes; file a support ticket if this persists.'
        }
        $params = @{
            TestId       = '41045'
            Title        = $testTitle
            Status       = $false
            Result       = $msg
            CustomStatus = 'Investigate'
        }
        Add-ZtTestResultDetail @params
        return
    }
    #endregion Data Collection

    #region Assessment Logic
    if ($devices.Count -eq 0) {
        $params = @{
            TestId       = '41045'
            Title        = $testTitle
            Status       = $false
            Result       = '⚠️ No devices were returned by the advanced hunting query. Microsoft Defender for Endpoint may not be licensed, no devices have ever been onboarded, or the tenant has no DeviceInfo data within the 30-day lookback window. Verify MDE onboarding and re-run.'
            CustomStatus = 'Investigate'
        }
        Add-ZtTestResultDetail @params
        return
    }

    $unhealthySensorStates = @('Inactive', 'ImpairedCommunications', 'NoSensorData', 'NoSensorDataImpairedCommunications')

    # Classify each device; first matching rule wins (mirrors spec evaluation logic)
    $classifiedDevices = foreach ($device in $devices) {
        $onboarding = $device.OnboardingStatus
        $health     = $device.SensorHealthState

        $classification = if ($onboarding -eq 'Can be onboarded') {
            'Eligible but not onboarded'
        } elseif ($onboarding -eq 'Onboarded' -and $health -in $unhealthySensorStates) {
            'Onboarded but unhealthy'
        } elseif ($onboarding -eq 'Onboarded' -and $health -eq 'Active') {
            'Onboarded and healthy'
        } else {
            'Out of scope'
        }

        $rowResult = switch ($classification) {
            'Eligible but not onboarded' { 'Fail' }
            'Onboarded but unhealthy'    { 'Fail' }
            'Onboarded and healthy'      { 'Pass' }
            default                      { '—' }
        }

        [PSCustomObject]@{
            DeviceName        = if ($device.DeviceName) { $device.DeviceName } else { '—' }
            OSPlatform        = if ($device.OSPlatform) { $device.OSPlatform } else { '—' }
            OnboardingStatus  = if ($onboarding) { $onboarding } else { '—' }
            SensorHealthState = if ($health) { $health } else { '—' }
            LastSeen          = if ($device.LastSeen) { $device.LastSeen } else { '—' }
            Classification    = $classification
            RowResult         = $rowResult
        }
    }
    $classifiedDevices = @($classifiedDevices)

    $passed = (@($classifiedDevices | Where-Object { $_.RowResult -eq 'Fail' }).Count) -eq 0
    #endregion Assessment Logic

    #region Report Generation
    $portalUrl  = 'https://security.microsoft.com/machines'
    $maxDisplay = 10
    $totalCount = $classifiedDevices.Count

    # Table order per spec: Onboarded and healthy → Eligible but not onboarded → Onboarded but unhealthy → Out of scope
    $classOrder = @{
        'Onboarded and healthy'       = 0
        'Eligible but not onboarded'  = 1
        'Onboarded but unhealthy'     = 2
        'Out of scope'                = 3
    }
    $sortedDevices  = @($classifiedDevices | Sort-Object { if ($classOrder.ContainsKey($_.Classification)) { $classOrder[$_.Classification] } else { 99 } })
    $displayDevices = @($sortedDevices | Select-Object -First $maxDisplay)
    $isTruncated    = $totalCount -gt $maxDisplay

    $tableRows = ''
    foreach ($row in $displayDevices) {
        $nameMd    = Get-SafeMarkdown -Text $row.DeviceName
        $tableRows += "| $nameMd | $($row.OSPlatform) | $($row.OnboardingStatus) | $($row.SensorHealthState) | $($row.LastSeen) | $($row.Classification) | $($row.RowResult) |`n"
    }
    if ($isTruncated) {
        $tableRows += "| ... | ... | ... | ... | ... | ... | ... |`n"
    }

    $preTableNote = if ($isTruncated) { "Showing $maxDisplay of $totalCount devices. [View all in Defender XDR > Assets > Devices]($portalUrl)`n`n" } else { '' }

    $formatTemplate = @'


{0}### [Defender XDR > Assets > Devices]({1})

| Device Name | OS Platform | Onboarding Status | Sensor Health State | Last Seen | Classification | Result |
| :---------- | :---------- | :---------------- | :------------------ | :-------- | :------------- | :----- |
{2}
'@
    $mdInfo = $formatTemplate -f $preTableNote, $portalUrl, $tableRows

    if ($passed) {
        $testResultMarkdown = "✅ All Microsoft Defender for Endpoint sensors are onboarded and healthy.`n`n%TestResult%"
    } else {
        $testResultMarkdown = "❌ One or more devices are missing the Microsoft Defender for Endpoint sensor or the sensor is not communicating.`n`n%TestResult%"
    }
    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '41045'
        Title  = $testTitle
        Status = $passed
        Result = $testResultMarkdown
    }
    Add-ZtTestResultDetail @params
}
