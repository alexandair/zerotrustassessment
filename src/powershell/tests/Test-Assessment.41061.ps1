<#
.SYNOPSIS
    Checks that all active Microsoft Defender XDR incidents from the last 24 hours are triaged and remediated.

.NOTES
    Test ID: 41061
    Workshop Task: SECOPS-061
    Pillar: SecOps
    Category: Threat investigation and response
    Required permission: SecurityIncident.Read.All
#>

function Test-Assessment-41061 {
    [ZtTest(
        Category           = 'Threat investigation and response',
        CompatibleLicense  = ('WINDEFATP', 'MDE_LITE', 'ATP_ENTERPRISE', 'THREAT_INTELLIGENCE', 'ATA', 'ADALLOM_S_STANDALONE', 'MDE_SMB'),
        ImplementationCost = 'Medium',
        Pillar             = 'SecOps',
        RiskLevel          = 'High',
        Service            = ('Graph'),
        SfiPillar          = 'Accelerate response and remediation',
        TenantType         = ('Workforce'),
        TestId             = 41061,
        Title              = 'All active Microsoft Defender XDR incidents are triaged and remediated',
        UserImpact         = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking Microsoft Defender XDR incident triage and remediation'

    $windowStart    = (Get-Date).AddHours(-24).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $incidentFilter = "createdDateTime ge $windowStart"
    $incidentSelect = 'displayName,severity,status,assignedTo,classification,determination,createdDateTime,incidentWebUrl'

    $allIncidents = $null

    Write-ZtProgress -Activity $activity -Status 'Querying Microsoft Defender XDR incidents from the last 24 hours'

    try {
        # Q1: List all incidents created in the last 24 hours with assignment, classification, and determination.
        # Prefer: include-unknown-enum-members is required so that awaitingAction (set exclusively by
        # Defender Experts) is returned as its real string rather than collapsing to unknownFutureValue.
        $allIncidents = Invoke-ZtGraphRequest -RelativeUri 'security/incidents' -ApiVersion beta -Filter $incidentFilter -Select $incidentSelect -Headers @{ Prefer = 'include-unknown-enum-members' } -ErrorAction Stop
    }
    catch {
        $httpStatus = Get-ZtHttpStatusCode -ErrorRecord $_
        if ($httpStatus -in @(401, 403)) {
            $params = @{
                TestId       = '41061'
                Title        = 'All active Microsoft Defender XDR incidents are triaged and remediated'
                Status       = $false
                Result       = '⚠️ Insufficient Graph permission; the assessment runtime cannot read Defender XDR incidents. Ensure the account has SecurityIncident.Read.All.'
                CustomStatus = 'Investigate'
            }
            Add-ZtTestResultDetail @params
            return
        }
        $params = @{
            TestId       = '41061'
            Title        = 'All active Microsoft Defender XDR incidents are triaged and remediated'
            Status       = $false
            Result       = '⚠️ Transient Microsoft Graph error or unexpected response shape; re-run after 5–10 minutes.'
            CustomStatus = 'Investigate'
        }
        Add-ZtTestResultDetail @params
        return
    }

    #endregion Data Collection

    #region Assessment Logic

    $allIncidents = @($allIncidents)

    # No incidents in the last 24 hours — cannot distinguish healthy-zero from unlicensed or not-onboarded.
    if ($allIncidents.Count -eq 0) {
        $params = @{
            TestId       = '41061'
            Title        = 'All active Microsoft Defender XDR incidents are triaged and remediated'
            Status       = $false
            Result       = '⚠️ No incidents were returned for the last 24 hours; verify Defender XDR is licensed and producing incidents.'
            CustomStatus = 'Investigate'
        }
        Add-ZtTestResultDetail @params
        return
    }

    $now = Get-Date

    $incidentResults = foreach ($incident in $allIncidents) {
        $createdAt  = $incident.createdDateTime
        $hoursOpen  = [math]::Round(($now - $createdAt).TotalHours, 1)
        $isAssigned = -not [string]::IsNullOrWhiteSpace($incident.assignedTo)

        # Condition (a): unassigned, excluding redirected incidents — a redirected duplicate is
        # assignedTo:null by design; the surviving incident in redirectIncidentId carries the assignment.
        $failUnassigned = (-not $isAssigned) -and ($incident.status -ne 'redirected')

        # Condition (b): high-severity incident still active beyond the 4-hour SLA.
        # Non-high-severity active incidents are not SLA-checked and pass this condition by default.
        $failSla = $incident.severity -eq 'high' -and $incident.status -eq 'active' -and $hoursOpen -gt 4

        # Condition (c): resolved incident closed without a meaningful classification or determination.
        $failClassification = $incident.status -eq 'resolved' -and ($incident.classification -eq 'unknown' -or $incident.determination -eq 'unknown')

        $rowResult = if ($failUnassigned -or $failSla -or $failClassification) { 'Fail' } else { 'Pass' }

        [PSCustomObject]@{
            DisplayName       = $incident.displayName
            Severity          = $incident.severity
            Status            = $incident.status
            AssignedTo        = if ($isAssigned) { $incident.assignedTo } else { '—' }
            Classification    = $incident.classification
            Determination     = $incident.determination
            Created           = $incident.createdDateTime
            HoursOpen         = $hoursOpen
            IncidentWebUrl    = $incident.incidentWebUrl
            RowResult         = $rowResult
            FailUnassigned    = $failUnassigned
            FailSla           = $failSla
            FailClassification = $failClassification
        }
    }
    $incidentResults = @($incidentResults)

    $failItems = @($incidentResults | Where-Object { $_.RowResult -eq 'Fail' })
    $passed   = $failItems.Count -eq 0

    if ($passed) {
        $testResultMarkdown = "✅ All Microsoft Defender XDR incidents from the last 24 hours are triaged, assigned, and (when closed) classified.`n`n%TestResult%"
    }
    else {
        $testResultMarkdown = "❌ One or more incidents are unassigned, exceed SLA in ``active`` status, or were closed without classification.`n`n%TestResult%"
    }

    #endregion Assessment Logic

    #region Report Generation

    $incidentsPortalUrl = 'https://security.microsoft.com/incidents'
    $maxDisplay         = 10

    # Sort Fail rows first, then by hours open descending to surface the most neglected incidents.
    $sortedResults  = @($incidentResults | Sort-Object -Property RowResult, @{ Expression = { $_.HoursOpen }; Descending = $true })
    $totalCount     = $sortedResults.Count
    $displayResults = @($sortedResults | Select-Object -First $maxDisplay)
    $isTruncated    = $totalCount -gt $maxDisplay

    $tableRows = ''
    foreach ($row in $displayResults) {
        $nameMd           = if ($row.IncidentWebUrl) { "[$(Get-SafeMarkdown $row.DisplayName)]($($row.IncidentWebUrl))" } else { Get-SafeMarkdown $row.DisplayName }
        # Decorate the specific cell that caused failure so the user knows exactly why the row failed.
        $assignedMd       = if ($row.FailUnassigned)                                              { '❌ —' }
                            elseif ($row.AssignedTo -eq '—')                                     { '—' }
                            else                                                                   { Get-SafeMarkdown $row.AssignedTo }
        $hoursOpenMd      = if ($row.FailSla)                                                     { "❌ $($row.HoursOpen)" } else { $row.HoursOpen }
        $classificationMd = if ($row.FailClassification -and $row.Classification -eq 'unknown')   { '❌ unknown' } else { $row.Classification }
        $determinationMd  = if ($row.FailClassification -and $row.Determination  -eq 'unknown')   { '❌ unknown' } else { $row.Determination }
        $createdMd        = Get-FormattedDate -DateString $row.Created
        $resultMd         = if ($row.RowResult -eq 'Fail') { '❌ Fail' } else { '✅ Pass' }

        $tableRows += "| $nameMd | $($row.Severity) | $($row.Status) | $assignedMd | $classificationMd | $determinationMd | $createdMd | $hoursOpenMd | $resultMd |`n"
    }

    if ($isTruncated) {
        $remaining  = $totalCount - $maxDisplay
        $tableRows += "`n... and $remaining more. [Defender XDR > Incidents & alerts > Incidents]($incidentsPortalUrl)`n"
    }

    $formatTemplate = @'


## [Defender XDR > Incidents & alerts > Incidents]({0})

| Incident name | Severity | Status | Assigned to | Classification | Determination | Created | Hours open | Result |
| :------------ | :------- | :----- | :---------- | :------------- | :------------ | :------ | ---------: | :----- |
{1}
'@

    $mdInfo             = $formatTemplate -f $incidentsPortalUrl, $tableRows
    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo

    #endregion Report Generation

    $params = @{
        TestId = '41061'
        Title  = 'All active Microsoft Defender XDR incidents are triaged and remediated'
        Status = $passed
        Result = $testResultMarkdown
    }
    Add-ZtTestResultDetail @params
}
