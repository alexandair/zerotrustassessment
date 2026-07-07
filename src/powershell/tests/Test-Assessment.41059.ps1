<#
.SYNOPSIS
    EDR in block mode is enabled when Microsoft Defender Antivirus is not the primary antivirus.

.DESCRIPTION
    Validates the Microsoft Defender for Endpoint "Enable EDR in block mode" Secure Score
    recommendation via Microsoft Secure Score.

    EDR in block mode adds Microsoft Defender for Endpoint blocking when Microsoft Defender
    Antivirus is running in passive mode alongside a non-Microsoft antivirus solution.
    Malicious artifacts that the third-party antivirus misses may not be remediated without it.

    The check reads the Secure Score control profile for scid_2004 and the latest per-control
    score snapshot, then returns:
      Pass        – EDR in block mode is enabled.
      Fail        – EDR in block mode is disabled or the Secure Score control is ignored.
      Investigate – The control profile or Secure Score snapshot could not be located.
      Skipped     – Microsoft Graph returned HTTP 401 or 403 (insufficient permissions).

.NOTES
    Test ID: 41059
    Workshop Task: SECOPS-059
    Pillar: SecOps
    Category: Endpoint threat protection
    Risk Level: High
    Supported Clouds: Global, USGov, USGovDoD
    Required Permission: SecurityEvents.Read.All (Application or Delegated)
#>

function Test-Assessment-41059 {
    [ZtTest(
        Category = 'Endpoint threat protection',
        CompatibleLicense = ('WINDEFATP'),
        ImplementationCost = 'Low',
        Pillar = 'SecOps',
        RiskLevel = 'High',
        Service = ('Graph'),
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 41059,
        Title = 'EDR in block mode is enabled when Microsoft Defender Antivirus is not the primary antivirus',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity  = 'Checking EDR in block mode Secure Score control'
    $controlId = 'scid_2004'
    Write-ZtProgress -Activity $activity -Status 'Retrieving EDR in block mode Secure Score control profile'

    # Q1 – Retrieve the pinned MDATP "Enable EDR in block mode" control profile.
    # An empty result set indicates the profile is absent from this tenant's Secure Score.
    $controlProfile = $null
    $errorMsgQ1     = $null
    $httpStatusQ1   = $null

    try {
        $profileResults = Invoke-ZtGraphRequest -RelativeUri 'security/secureScoreControlProfiles' -Filter "service eq 'MDATP' and id eq '$controlId'" -ApiVersion beta -ErrorAction Stop
        $controlProfile = $profileResults | Select-Object -First 1
    }
    catch {
        $errorMsgQ1   = $_
        $httpStatusQ1 = Get-ZtHttpStatusCode -ErrorRecord $_
        Write-PSFMessage "Failed to retrieve EDR in block mode control profile: $errorMsgQ1" -Level Warning
    }

    # Q2 – Retrieve the most recent Secure Score snapshot (only if Q1 succeeded).
    $latestSecureScore = $null

    if ($null -ne $controlProfile) {
        Write-ZtProgress -Activity $activity -Status 'Retrieving latest Microsoft Secure Score'
        try {
            $scoreResponse     = Invoke-ZtGraphRequest -RelativeUri 'security/secureScores' -Top 1 -ApiVersion beta -DisablePaging -ErrorAction Stop
            $latestSecureScore = $scoreResponse.value | Select-Object -First 1
        }
        catch {
            Write-PSFMessage "Failed to retrieve Secure Score snapshot: $_" -Level Warning
        }
    }

    #endregion Data Collection

    #region Assessment Logic

    $passed       = $false
    $customStatus = $null

    # ── Q1 failed: 401/403 → Skipped; missing profile or unexpected error → Investigate ──
    if ($null -eq $controlProfile) {
        if ($httpStatusQ1 -in @(401, 403)) {
            Add-ZtTestResultDetail -SkippedBecause NotApplicable
            return
        }
        elseif ($null -ne $errorMsgQ1) {
            $investigateReason = "Microsoft Graph returned an unexpected error retrieving the EDR in block mode Secure Score control profile. Re-run the assessment in 5–10 minutes and verify ``SecurityEvents.Read.All`` is consented."
        }
        else {
            $investigateReason = "The EDR in block mode Secure Score control profile (``$controlId``) was not found in this tenant's Microsoft Secure Score. Verify that Microsoft Defender for Endpoint Plan 2 is licensed and onboarded."
        }

        $testResultMarkdown = "⚠️ $investigateReason"
        $customStatus       = 'Investigate'

        $params = @{
            TestId       = '41059'
            Title        = 'EDR in block mode is enabled when Microsoft Defender Antivirus is not the primary antivirus'
            Status       = $passed
            Result       = $testResultMarkdown
            CustomStatus = $customStatus
        }
        Add-ZtTestResultDetail @params
        return
    }

    $profileTitle = $controlProfile.title
    $maxScore     = $controlProfile.maxScore

    # ── Investigate: Q2 returned no snapshot ──
    if ($null -eq $latestSecureScore) {
        $testResultMarkdown = "⚠️ The EDR in block mode control profile exists but the current Microsoft Secure Score snapshot could not be retrieved."
        $customStatus       = 'Investigate'

        $params = @{
            TestId       = '41059'
            Title        = 'EDR in block mode is enabled when Microsoft Defender Antivirus is not the primary antivirus'
            Status       = $passed
            Result       = $testResultMarkdown
            CustomStatus = $customStatus
        }
        Add-ZtTestResultDetail @params
        return
    }

    # ── Locate the per-control entry inside controlScores[] ──
    $controlScoreEntry = $null
    if ($latestSecureScore.controlScores) {
        $controlScoreEntry = $latestSecureScore.controlScores |
            Where-Object { $_.controlName -eq $controlId } |
            Select-Object -First 1
    }

    # ── Investigate: profile exists but snapshot has no scored entry for this control ──
    if ($null -eq $controlScoreEntry) {
        $testResultMarkdown = "⚠️ The EDR in block mode control profile (``$controlId``) exists but the latest Secure Score snapshot has no scored entry for this control."
        $customStatus       = 'Investigate'

        $params = @{
            TestId       = '41059'
            Title        = 'EDR in block mode is enabled when Microsoft Defender Antivirus is not the primary antivirus'
            Status       = $passed
            Result       = $testResultMarkdown
            CustomStatus = $customStatus
        }
        Add-ZtTestResultDetail @params
        return
    }

    # ── Determine ignored state from the most recent controlStateUpdates entry ──
    $latestStateUpdate = @($controlProfile.controlStateUpdates | Sort-Object { if ($_.updatedDateTime) { [datetime]$_.updatedDateTime } else { [datetime]::MinValue } } -Descending) | Select-Object -First 1
    $isIgnored         = $latestStateUpdate -and $latestStateUpdate.state -eq 'Ignored'

    $score = $controlScoreEntry.score

    if (($score -ge $maxScore) -and (-not $isIgnored)) {
        $passed             = $true
        $testResultMarkdown = "✅ EDR in block mode is enabled.`n`n%TestResult%"
    }
    else {
        $passed             = $false
        $testResultMarkdown = "❌ EDR in block mode is disabled or the Secure Score control is ignored.`n`n%TestResult%"
    }

    #endregion Assessment Logic

    #region Report Generation

    $secureScoreUrl = 'https://security.microsoft.com/securescore'
    $ignoredDisplay = if ($isIgnored) { '⚠️ Yes' } else { '✅ No' }
    $rowStatus      = if ($passed) { '✅ Pass' } else { '❌ Fail' }
    $lastModified   = if ($controlProfile.lastModifiedDateTime) { Get-FormattedDate -DateString $controlProfile.lastModifiedDateTime } else { '—' }

    $mdFailLink = ''
    if (-not $passed) {
        $mdFailLink = "`n## [Defender XDR > Secure Score > Recommendations]($secureScoreUrl)`n"
    }

    $tableRows = "| $(Get-SafeMarkdown $profileTitle) | $controlId | $score | $maxScore | $ignoredDisplay | $lastModified | $rowStatus |`n"

    $mdTable = @"

$mdFailLink
| Control title | Control id | Score | Max Score | Ignored | Last modified | Status |
| :------------ | :--------- | :---- | :-------- | :------ | :------------ | :----- |
$tableRows
"@

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdTable

    #endregion Report Generation

    $params = @{
        TestId = '41059'
        Title  = 'EDR in block mode is enabled when Microsoft Defender Antivirus is not the primary antivirus'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($customStatus) {
        $params.CustomStatus = $customStatus
    }

    Add-ZtTestResultDetail @params
}
