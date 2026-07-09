<#
.SYNOPSIS
    Checks that MDI sensor health is reviewed weekly by detecting health issues open longer than 7 days.

.NOTES
    Test ID: 41020
    Pillar: SecOps
    Category: Identity threat protection
    Required permission: SecurityIdentitiesHealth.Read.All
#>

function Test-Assessment-41020 {
    [ZtTest(
        Category = 'Identity threat protection',
        CompatibleLicense = ('ATA'),
        ImplementationCost = 'Low',
        Pillar = 'SecOps',
        RiskLevel = 'Medium',
        Service = ('Graph'),
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 41020,
        Title = 'Microsoft Defender for Identity sensor deployment is validated by reviewing the Health Issues page',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    # Invariant result metadata — TestId and Title are declared once; each branch sets only the varying fields.
    $params = @{
        TestId = '41020'
        Title  = 'Microsoft Defender for Identity sensor deployment is validated by reviewing the Health Issues page'
    }

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $activity     = 'Checking Microsoft Defender for Identity health issue review cadence'
    $queryError   = $null
    $healthIssues = $null

    Write-ZtProgress -Activity $activity -Status 'Querying open MDI health issues'

    try {
        # Q1: List all open MDI health issues; Invoke-ZtGraphRequest follows @odata.nextLink automatically.
        $healthIssues = Invoke-ZtGraphRequest -RelativeUri 'security/identities/healthIssues' -Filter "status eq 'open'" -ApiVersion beta -ErrorAction Stop
    }
    catch {
        $queryError = $_
        Write-PSFMessage "Failed to retrieve MDI health issues: $_" -Tag Test -Level Warning
    }
    #endregion Data Collection

    #region Assessment Logic
    if ($queryError) {
        $httpStatus = Get-ZtHttpStatusCode -ErrorRecord $queryError

        # 403 → distinguish SecurityIdentitiesHealth.Read.All not consented (UnknownError) from
        # MDI not licensed or caller denied (any other 403).
        if ($httpStatus -eq 403) {
            $errorCode = $null
            try {
                $errStr = $queryError.ToString()
                if ($errStr -match '(\{"error".*\})') {
                    $errorCode = ($Matches[1] | ConvertFrom-Json).error.code
                }
            }
            catch {
                Write-PSFMessage "Failed to parse 403 error response; treating as MDI not onboarded." -Tag Test -Level VeryVerbose
            }

            if ($errorCode -eq 'UnknownError') {
                # SecurityIdentitiesHealth.Read.All scope has not been consented.
                $params.Status       = $false
                $params.Result       = "⚠️ The check could not produce a definitive verdict. HTTP status: 403, error code: UnknownError — the ``SecurityIdentitiesHealth.Read.All`` scope has not been consented. Re-run the assessment after granting that permission to the assessment service principal."
                $params.CustomStatus = 'Investigate'
                Add-ZtTestResultDetail @params
                return
            }

            # Fall through to NotApplicable check below.
        }

        # 404 or 403 (non-UnknownError) → MDI not onboarded.
        if ($httpStatus -in (403, 404)) {
            Add-ZtTestResultDetail -SkippedBecause NotApplicable
            return
        }

        # Other errors → transient; Investigate.
        $httpStatusStr       = if ($null -ne $httpStatus) { " HTTP status: $httpStatus." } else { '' }
        $params.Status       = $false
        $params.Result       = "⚠️ The check could not produce a definitive verdict.$httpStatusStr Re-run the assessment after verifying connectivity to Microsoft Graph."
        $params.CustomStatus = 'Investigate'
        Add-ZtTestResultDetail @params
        return
    }

    $healthIssues = @($healthIssues)
    $now          = [datetime]::UtcNow
    $staleDays = 7

    # Classify each open issue against the 7-day review SLA.
    # Stale: age > 7 days AND lastModifiedDateTime also > 7 days old (no evidence of active work).
    # In remediation: age > 7 days AND lastModifiedDateTime within the last 7 days (active work evident).
    $classifiedIssues = foreach ($issue in $healthIssues) {
        $created  = if ($issue.createdDateTime)      { [datetime]$issue.createdDateTime }      else { $now }
        $modified = if ($issue.lastModifiedDateTime) { [datetime]$issue.lastModifiedDateTime } else { $created }
        $ageTotalDays = ($now - $created).TotalDays
        $ageDays     = [int][math]::Floor($ageTotalDays)

        $rowStatus = if ($ageTotalDays -le $staleDays) {
            'OK'
        } elseif (($now - $modified).TotalDays -le $staleDays) {
            'In remediation'
        } else {
            'Stale'
        }

        [PSCustomObject]@{
            Issue     = $issue
            AgeDays   = $ageDays
            Created   = $created
            Modified  = $modified
            RowStatus = $rowStatus
        }
    }

    $staleIssues         = @($classifiedIssues | Where-Object RowStatus -eq 'Stale')
    $inRemediationIssues = @($classifiedIssues | Where-Object RowStatus -eq 'In remediation')

    # Fail wins: any stale issue drives Fail; in-remediation issues are included in the table for triage.
    if ($staleIssues.Count -gt 0) {
        $passed       = $false
        $customStatus = $null
        $testResultMarkdown = "❌ One or more Microsoft Defender for Identity health issues have remained open longer than seven days without being modified, suggesting the weekly health review was missed. Issues showing recent modification are annotated separately for triage.`n`n%TestResult%"
    } elseif ($inRemediationIssues.Count -gt 0) {
        $passed       = $false
        $customStatus = 'Investigate'
        $testResultMarkdown = "⚠️ The check could not produce a definitive verdict. Open health issues older than seven days exist but all show recent modification indicating active remediation.`n`n%TestResult%"
    } else {
        $passed       = $true
        $customStatus = $null
        $testResultMarkdown = "✅ No Microsoft Defender for Identity health issues have remained open longer than seven days.`n`n%TestResult%"
    }
    #endregion Assessment Logic

    #region Report Generation
    $healthPageUrl = 'https://security.microsoft.com/securitysettings/identities'
    $mdInfo        = ''

    # For Investigate (recent-modification case), show only the long-open in-remediation issues.
    # For Pass and Fail, show the full collection.
    $issuesForTable = if ($customStatus -eq 'Investigate') {
        $inRemediationIssues
    } else {
        $classifiedIssues
    }

    if ($issuesForTable.Count -gt 0) {
        $sortedIssues  = @($issuesForTable | Sort-Object AgeDays -Descending)
        $maxDisplay    = 10
        $totalCount    = $sortedIssues.Count
        $displayIssues = if ($totalCount -gt $maxDisplay) { $sortedIssues | Select-Object -First $maxDisplay } else { $sortedIssues }

        $tableRows = ''
        foreach ($entry in $displayIssues) {
            $issue       = $entry.Issue
            $displayName = "[$(Get-SafeMarkdown $issue.displayName)]($healthPageUrl)"
            $severity    = $issue.severity
            $created     = Get-FormattedDate -DateString $issue.createdDateTime
            $modified    = Get-FormattedDate -DateString $issue.lastModifiedDateTime
            $ageDays     = $entry.AgeDays
            $sensors     = if ($issue.sensorDNSNames -and $issue.sensorDNSNames.Count -gt 0) {
                ($issue.sensorDNSNames | ForEach-Object { Get-SafeMarkdown $_ }) -join ', '
            } else {
                '—'
            }
            # In a Fail result, in-remediation rows are labelled Investigate to preserve triage context.
            $rowIcon = switch ($entry.RowStatus) {
                'OK'             { '✅ OK' }
                'Stale'          { '❌ Stale' }
                'In remediation' { if ($staleIssues.Count -gt 0) { '⚠️ Investigate' } else { '⚠️ In remediation' } }
            }
            $tableRows += "| $displayName | $severity | $created | $modified | $ageDays | $sensors | $rowIcon |`n"
        }

        $preTableLines = ''
        if ($totalCount -gt $maxDisplay) {
            $tableRows     += "| ... | ... | ... | ... | ... | ... | ... |`n"
            $preTableLines  = "Showing $maxDisplay of $totalCount issues`n`n"
        }

        $formatTemplate = @'


### [Defender XDR > Settings > Identities > Health issues]({0})

{1}| Display name | Severity | Created | Last modified | Age (days) | Affected sensors | Status |
| :----------- | :------- | :------ | :------------ | ---------: | :--------------- | :----- |
{2}
'@
        $mdInfo = $formatTemplate -f $healthPageUrl, $preTableLines, $tableRows
    } elseif ($passed) {
        # Pass with no open issues — omit the empty table per convention.
        $mdInfo = "`n`n[Defender XDR > Settings > Identities > Health issues]($healthPageUrl)"
    }

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params.Status = $passed
    $params.Result = $testResultMarkdown
    if ($customStatus) {
        $params.CustomStatus = $customStatus
    }
    Add-ZtTestResultDetail @params
}
