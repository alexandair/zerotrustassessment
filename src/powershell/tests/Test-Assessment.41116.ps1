<#
.SYNOPSIS
    Threat hunting against Email and Collaboration tables in Microsoft 365 Defender Advanced Hunting is operational.

.NOTES
    Test ID: 41116
    Workshop Task: SECOPS-116
    Pillar: SecOps
    Category: Email and collaboration security
    Required permission: ThreatHunting.Read.All
#>

function Test-Assessment-41116 {
    [ZtTest(
        Category = 'Email and collaboration security',
        CompatibleLicense = ('THREAT_INTELLIGENCE'),
        ImplementationCost = 'Medium',
        Pillar = 'SecOps',
        RiskLevel = 'Medium',
        Service = ('Graph'),
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 41116,
        Title = 'Threat hunting against Email and Collaboration tables in Microsoft 365 Defender Advanced Hunting is operational',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $title    = 'Threat hunting against Email and Collaboration tables in Microsoft 365 Defender Advanced Hunting is operational'
    $activity = 'Checking Microsoft Defender XDR EmailEvents hunting availability'
    Write-ZtProgress -Activity $activity -Status 'Running EmailEvents probe query'

    $endpoint    = 'https://graph.microsoft.com/v1.0/security/runHuntingQuery'
    $requestBody = @{
        Query    = 'EmailEvents | where Timestamp > ago(1d) | summarize Count=count()'
        Timespan = 'P1D'
    } | ConvertTo-Json -Depth 4

    $queryResponse = $null
    $queryError    = $null

    try {
        # runHuntingQuery is a POST action — must use Invoke-MgGraphRequest directly.
        $queryResponse = Microsoft.Graph.Authentication\Invoke-MgGraphRequest `
            -Method Post `
            -Uri $endpoint `
            -Body $requestBody `
            -ContentType 'application/json' `
            -ErrorAction Stop
    }
    catch {
        $queryError = $_
        Write-PSFMessage "Failed to run EmailEvents hunting query: $_" -Tag Test -Level Warning
    }
    #endregion Data Collection

    #region Assessment Logic
    # Output table variables — tracked for the single-row result table.
    $httpStatus       = $null
    $errorMessage     = $null
    $emailEventsCount = $null

    if ($queryError) {
        $httpStatus = Get-ZtHttpStatusCode -ErrorRecord $queryError

        # Parse Graph error body for a human-readable message.
        try {
            if ($queryError.ErrorDetails -and $queryError.ErrorDetails.Message) {
                $errorBody    = $queryError.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
                $errorMessage = $errorBody.error.message
            }
        }
        catch { }
        if (-not $errorMessage) {
            $errorMessage = $queryError.Exception.Message
        }

        if ($httpStatus -eq 403) {
            # License errors → Skipped.  Permission / access errors → Investigate.
            if ($errorMessage -match '(?i)(not licensed|license|advanced hunting|plan 2)') {
                Write-PSFMessage 'Test-Assessment-41116: SKIPPED — Advanced Hunting is not licensed for this tenant.' -Tag Test -Level VeryVerbose
                Add-ZtTestResultDetail -SkippedBecause NotApplicable
                return
            }
            Add-ZtTestResultDetail -TestId '41116' -Title $title -Status $false -CustomStatus 'Investigate' `
                -Result "⚠️ The Microsoft Defender XDR Advanced Hunting API rejected the probe with HTTP 403. Verify the caller has the ``ThreatHunting.Read.All`` Graph permission and a supported delegated role such as Security Reader, then re-run."
            return
        }

        if ($httpStatus -eq 400 -and $errorMessage -match '(?i)(unknown table|unknown schema|EmailEvents)') {
            # Schema unavailable → Fail.
            Add-ZtTestResultDetail -TestId '41116' -Title $title -Status $false `
                -Result '❌ The Microsoft Defender XDR Advanced Hunting API is reachable, but the EmailEvents table or Email and Collaboration schema is unavailable in this tenant.'
            return
        }

        # Any other error → Investigate.
        $httpStatusText = if ($null -ne $httpStatus) { " HTTP $httpStatus." } else { '' }
        Add-ZtTestResultDetail -TestId '41116' -Title $title -Status $false -CustomStatus 'Investigate' `
            -Result "⚠️ The Microsoft Defender XDR Advanced Hunting API returned an unexpected error.$httpStatusText Re-run the assessment after verifying connectivity and permissions."
        return
    }

    # Q1 succeeded — extract the count from the first result row.
    $firstRow = @($queryResponse.results)[0]
    if ($firstRow) {
        foreach ($col in @('Count', 'count_', 'count')) {
            if ($firstRow.PSObject.Properties.Name -contains $col -and $null -ne $firstRow.$col) {
                $emailEventsCount = [int]$firstRow.$col
                break
            }
        }
    }

    if ($null -eq $emailEventsCount) {
        Add-ZtTestResultDetail -TestId '41116' -Title $title -Status $false -CustomStatus 'Investigate' `
            -Result '⚠️ The Microsoft Defender XDR Advanced Hunting API returned a response, but the EmailEvents probe result could not be parsed.'
        return
    }

    $passed = $emailEventsCount -gt 0
    if ($passed) {
        $testResultMarkdown = "✅ The Microsoft Defender XDR Advanced Hunting API is reachable and Email and Collaboration data is queryable from automation.`n`n%TestResult%"
    }
    else {
        $testResultMarkdown = "⚠️ The Microsoft Defender XDR Advanced Hunting API is reachable, but the probe returned zero recent EmailEvents. Verify that email is flowing through Microsoft 365 and that the Advanced Hunting data pipeline is active.`n`n%TestResult%"
    }
    #endregion Assessment Logic

    #region Report Generation
    $statusDisplay = if ($passed) { '✅ Pass' } else { '⚠️ Investigate' }

    $formatTemplate = @'

| Endpoint | HTTP Status | Error Code | Error Message | EmailEvents Count (24h) | Result |
| :------- | ----------: | :--------- | :------------ | ----------------------: | :----- |
| {0} | 200 | — | — | {1} | {2} |
'@

    $mdInfo = $formatTemplate -f (Get-SafeMarkdown $endpoint), $emailEventsCount, $statusDisplay
    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{ TestId = '41116'; Title = $title; Status = $passed; Result = $testResultMarkdown }
    if (-not $passed) { $params.CustomStatus = 'Investigate' }
    Add-ZtTestResultDetail @params
}
