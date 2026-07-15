<#
.SYNOPSIS
    Checks that Automated Investigation and Response (AIR) recommendations in Microsoft Defender for Endpoint are reviewed and actioned.

.NOTES
    Test ID: 41062
    Workshop Task: SECOPS-062
    Pillar: SecOps
    Category: Threat investigation and response
    Required permission: SecurityAlert.Read.All
#>

function Test-Assessment-41062 {
    [ZtTest(
        Category           = 'Threat investigation and response',
        CompatibleLicense  = ('WINDEFATP'),
        ImplementationCost = 'Low',
        Pillar             = 'SecOps',
        RiskLevel          = 'High',
        Service            = ('Graph'),
        SfiPillar          = 'Accelerate response and remediation',
        TenantType         = ('Workforce'),
        TestId             = 41062,
        Title              = 'Automated Investigation and Response (AIR) recommendations are reviewed and actioned',
        UserImpact         = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking Microsoft Defender for Endpoint AIR action review status'
    $now = Get-Date

    # Server-side filter: scope to active MDE alerts only.
    # investigationState is NOT in the supported $filter properties for alerts_v2 (returns HTTP 400);
    # all investigationState evaluation is applied client-side in Assessment Logic.
    $alertFilter = "serviceSource eq 'microsoftDefenderForEndpoint' and (status eq 'new' or status eq 'inProgress')"
    $alertSelect = 'title,severity,serviceSource,investigationState,incidentId,createdDateTime,lastUpdateDateTime,alertWebUrl,incidentWebUrl'

    Write-ZtProgress -Activity $activity -Status 'Querying Microsoft Defender for Endpoint alerts'
    $allAlerts = $null
    try {
        # Q1: Retrieve all active MDE alerts paged at 500 per request; auto-paging follows nextLink.
        $allAlerts = Invoke-ZtGraphRequest -RelativeUri 'security/alerts_v2' -ApiVersion beta -Filter $alertFilter -Select $alertSelect -Top 500 -ErrorAction Stop
    }
    catch {
        $httpStatus = Get-ZtHttpStatusCode -ErrorRecord $_
        if ($httpStatus -in @(401, 403)) {
            Write-PSFMessage "Insufficient permissions to query MDE alerts (HTTP $httpStatus): $_" -Tag Test -Level Warning
            $params = @{
                TestId       = '41062'
                Title        = 'Automated Investigation and Response (AIR) recommendations are reviewed and actioned'
                Status       = $false
                Result       = '⚠️ Insufficient Graph permission; the assessment runtime cannot read security alerts. Ensure the account has SecurityAlert.Read.All.'
                CustomStatus = 'Investigate'
            }
            Add-ZtTestResultDetail @params
            return
        }
        Write-PSFMessage "Failed to query MDE alerts (HTTP $httpStatus): $_" -Tag Test -Level Warning
        $params = @{
            TestId       = '41062'
            Title        = 'Automated Investigation and Response (AIR) recommendations are reviewed and actioned'
            Status       = $false
            Result       = '⚠️ Transient Microsoft Graph error or unexpected response shape; re-run after 5–10 minutes.'
            CustomStatus = 'Investigate'
        }
        Add-ZtTestResultDetail @params
        return
    }
    #endregion Data Collection

    #region Assessment Logic
    $allAlerts    = @($allAlerts)
    # Empty result: AIR may not be enabled on any device group, or there has been no recent MDE alert activity.
    if ($allAlerts.Count -eq 0) {
        $params = @{
            TestId       = '41062'
            Title        = 'Automated Investigation and Response (AIR) recommendations are reviewed and actioned'
            Status       = $false
            Result       = '⚠️ No endpoint alerts with AIR investigation state were returned; verify Microsoft Defender for Endpoint Plan 2 is licensed and that AIR is enabled on device groups.'
            CustomStatus = 'Investigate'
        }
        Add-ZtTestResultDetail @params
        return
    }

    $threshold24h = $now.AddHours(-24)

    # Q1 client-side: pendingApproval alerts whose last update is more than 24 hours ago.
    # lastUpdateDateTime is used (not createdDateTime) per spec — a recently re-queued action
    # resets the clock and should not count as stale until the analyst has had 24 h to act on it.
    $pendingApprovalAlerts = @($allAlerts | Where-Object {
        $_.investigationState -eq 'pendingApproval' -and
        $null -ne $_.lastUpdateDateTime -and
        $_.lastUpdateDateTime -lt $threshold24h
    })

    # Q2 client-side: medium/high-severity alerts in AIR failure states older than 24 hours.
    # Informational and low-severity alerts are excluded because AIR investigations on those
    # frequently land in partiallyInvestigated or terminatedBySystem by design and do not
    # represent an uncontained threat on the host.
    $airFailureStates = @('failed', 'innerFailure', 'partiallyRemediated', 'partiallyInvestigated')
    $failedAirAlerts  = @($allAlerts | Where-Object {
        $_.investigationState -in $airFailureStates -and
        $_.severity -in @('medium', 'high') -and
        $null -ne $_.createdDateTime -and
        $_.createdDateTime -lt $threshold24h
    })

    # pendingApproval and the failure-state values are mutually exclusive investigationState values;
    # a single alert cannot appear in both result sets.
    $failingAlerts = @($pendingApprovalAlerts) + @($failedAirAlerts)
    $passed        = ($failingAlerts.Count -eq 0)

    if ($passed) {
        $testResultMarkdown = '✅ Microsoft Defender for Endpoint AIR actions are being reviewed and remediated within 24 hours.'
    }
    else {
        $testResultMarkdown = "❌ One or more endpoint AIR actions are stuck in ``pendingApproval`` or failed, and the malicious artifact remains active on the host.`n`n%TestResult%"
    }

    # Build per-alert result rows with rule-aware cell decoration.
    # Q1 rows: severity is NOT part of the fail predicate → plain severity; state and hours decorated.
    # Q2 rows: severity IS part of the fail predicate → severity also decorated.
    $alertResults = @()

    $alertResults += foreach ($alert in $pendingApprovalAlerts) {
        $hoursOpen = [math]::Round(($now - [datetime]$alert.createdDateTime).TotalHours, 1)
        [PSCustomObject]@{
            Title                     = $alert.title
            Severity                  = $alert.severity
            InvestigationState        = $alert.investigationState
            IncidentId                = $alert.incidentId
            IncidentWebUrl            = $alert.incidentWebUrl
            Created                   = $alert.createdDateTime
            HoursOpen                 = $hoursOpen
            ServiceSource             = $alert.serviceSource
            AlertWebUrl               = $alert.alertWebUrl
            SeverityDisplay           = $alert.severity
            InvestigationStateDisplay = "❌ $($alert.investigationState)"
            HoursOpenDisplay          = "❌ $hoursOpen"
            StatusDisplay             = '❌ Fail'
        }
    }

    $alertResults += foreach ($alert in $failedAirAlerts) {
        $hoursOpen = [math]::Round(($now - [datetime]$alert.createdDateTime).TotalHours, 1)
        [PSCustomObject]@{
            Title                     = $alert.title
            Severity                  = $alert.severity
            InvestigationState        = $alert.investigationState
            IncidentId                = $alert.incidentId
            IncidentWebUrl            = $alert.incidentWebUrl
            Created                   = $alert.createdDateTime
            HoursOpen                 = $hoursOpen
            ServiceSource             = $alert.serviceSource
            AlertWebUrl               = $alert.alertWebUrl
            SeverityDisplay           = "❌ $($alert.severity)"
            InvestigationStateDisplay = "❌ $($alert.investigationState)"
            HoursOpenDisplay          = "❌ $hoursOpen"
            StatusDisplay             = '❌ Fail'
        }
    }

    $alertResults = @($alertResults)
    #endregion Assessment Logic

    #region Report Generation
    if (-not $passed) {
        $actionCenterUrl = 'https://security.microsoft.com/action-center'
        $maxDisplay      = 10
        $totalCount      = $alertResults.Count
        $hasMoreItems    = $totalCount -gt $maxDisplay
        $displayAlerts   = @($alertResults | Select-Object -First $maxDisplay)

        $tableRows = ''
        foreach ($row in $displayAlerts) {
            $titleMd    = if ($row.AlertWebUrl) { "[$(Get-SafeMarkdown $row.Title)]($($row.AlertWebUrl))" } else { Get-SafeMarkdown $row.Title }
            # Use the incidentWebUrl returned directly by the API (includes tenant context and correct path).
            $incidentMd = if ($row.IncidentWebUrl) { "[$($row.IncidentId)]($($row.IncidentWebUrl))" } elseif ($row.IncidentId) { $row.IncidentId } else { '—' }
            $createdMd  = Get-FormattedDate -DateString $row.Created.ToString()
            $tableRows += "| $titleMd | $($row.SeverityDisplay) | $($row.InvestigationStateDisplay) | $incidentMd | $createdMd | $($row.HoursOpenDisplay) | $($row.ServiceSource) | $($row.StatusDisplay) |`n"
        }

        if ($hasMoreItems) {
            $remaining  = $totalCount - $maxDisplay
            $tableRows += "`n... and $remaining more. [Defender XDR > Action center]($actionCenterUrl)`n"
        }

        $formatTemplate = @'


## [Defender XDR > Action center]({0})

| Alert title | Severity | Investigation state | Incident | Created | Hours open | Service source | Status |
| :---------- | :------- | :------------------ | :------- | :------ | ---------: | :------------- | :----- |
{1}
'@

        $mdInfo             = $formatTemplate -f $actionCenterUrl, $tableRows
        $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    }
    #endregion Report Generation

    $params = @{
        TestId = '41062'
        Title  = 'Automated Investigation and Response (AIR) recommendations are reviewed and actioned'
        Status = $passed
        Result = $testResultMarkdown
    }
    Add-ZtTestResultDetail @params
}
