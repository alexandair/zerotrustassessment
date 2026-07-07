<#
.SYNOPSIS
    Network protection is enabled in block mode.

.NOTES
    Test ID: 41053
    Workshop Task: SECOPS-053
    Pillar: SecOps
    Category: Endpoint threat protection
    Required permission: SecurityEvents.Read.All
#>

function Test-Assessment-41053 {
    [ZtTest(
        Category = 'Endpoint threat protection',
        CompatibleLicense = ('ATA'),
        ImplementationCost = 'Low',
        Pillar = 'SecOps',
        RiskLevel = 'High',
        Service = ('Graph'),
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 41053,
        Title = 'Network protection is enabled in block mode',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $activity       = 'Checking network protection Secure Score control'
    $controlId      = 'scid_96'
    $controlProfile = $null
    $secureScore    = $null
    $q1Error        = $null
    $q2Error        = $null

    Write-ZtProgress -Activity $activity -Status 'Reading Secure Score control profile (Q1)'
    try {
        # Q1: Read the Secure Score control profile for the pinned network protection control.
        $profileResults = Invoke-ZtGraphRequest -RelativeUri 'security/secureScoreControlProfiles' -Filter "service eq 'MDATP' and id eq '$controlId'" -ApiVersion beta -ErrorAction Stop
        $controlProfile = $profileResults | Select-Object -First 1
    }
    catch {
        $q1Error = $_
        Write-PSFMessage "Failed to retrieve Secure Score control profile: $_" -Tag Test -Level Warning
    }

    Write-ZtProgress -Activity $activity -Status 'Reading latest Secure Score snapshot (Q2)'
    try {
        # Q2: Read the latest Secure Score snapshot.
        $response = Invoke-ZtGraphRequest -RelativeUri 'security/secureScores' -Top '1' -ApiVersion beta -DisablePaging -ErrorAction Stop
        # DisablePaging returns the raw response; unwrap the value array.
        $secureScore = if ($response.value) { $response.value | Select-Object -First 1 } else { $response }
    }
    catch {
        $q2Error = $_
        Write-PSFMessage "Failed to retrieve Secure Score snapshot: $_" -Tag Test -Level Warning
    }
    #endregion Data Collection

    #region Assessment Logic
    # 401/403 on either query → Skipped (SecurityEvents.Read.All not consented or insufficient role).
    foreach ($queryErr in @($q1Error, $q2Error) | Where-Object { $null -ne $_ }) {
        if ((Get-ZtHttpStatusCode -ErrorRecord $queryErr) -in (401, 403)) {
            Add-ZtTestResultDetail -SkippedBecause NotApplicable -Result 'Microsoft Graph returned HTTP 401 or 403; grant `SecurityEvents.Read.All` and assign Security Reader or Security Administrator for delegated runs.'
            return
        }
    }

    # Extract the score entry for scid_96 from the latest snapshot.
    $scoreEntry = $null
    if ($secureScore) {
        $scoreEntry = @($secureScore.controlScores | Where-Object { $_.controlName -eq $controlId }) | Select-Object -First 1
    }

    # Any query error, missing profile, missing snapshot, or missing score entry → Investigate.
    if ($q1Error -or $q2Error -or $null -eq $controlProfile -or $null -eq $secureScore -or $null -eq $scoreEntry) {
        $params = @{
            TestId       = '41053'
            Title        = 'Network protection is enabled in block mode'
            Status       = $false
            Result       = '⚠️ The network protection Secure Score control or latest Secure Score snapshot could not be located, or Microsoft Graph returned an unexpected error.'
            CustomStatus = 'Investigate'
        }
        Add-ZtTestResultDetail @params
        return
    }

    # Determine ignored state from the most recent controlStateUpdates entry.
    $latestStateUpdate = @($controlProfile.controlStateUpdates | Sort-Object { if ($_.updatedDateTime) { [datetime]$_.updatedDateTime } else { [datetime]::MinValue } } -Descending) | Select-Object -First 1
    $isIgnored = $latestStateUpdate -and $latestStateUpdate.state -eq 'ignored'

    $score    = $scoreEntry.score
    $maxScore = $controlProfile.maxScore
    $passed   = ($score -ge $maxScore) -and (-not $isIgnored)

    if ($passed) {
        $testResultMarkdown = "✅ Network protection is enabled in block mode across the eligible Defender for Endpoint estate.`n`n%TestResult%"
    }
    else {
        $testResultMarkdown = "❌ Network protection is disabled, not fully scored, ignored, or set to audit mode.`n`n%TestResult%"
    }
    #endregion Assessment Logic

    #region Report Generation
    $secureScoreUrl  = 'https://security.microsoft.com/securescore'
    $ignoredDisplay  = if ($isIgnored) { '⚠️ Yes' } else { '✅ No' }
    $rowStatus       = if ($passed) { '✅ Pass' } else { '❌ Fail' }
    $lastModified    = if ($controlProfile.lastModifiedDateTime) { Get-FormattedDate -DateString $controlProfile.lastModifiedDateTime } else { '—' }
    $implStatus      = if ($scoreEntry.implementationStatus) { $scoreEntry.implementationStatus } else { '—' }

    $formatTemplate = @'


### [Microsoft Secure Score]({0})

| Control title | Control ID | Score | Max score | Implementation status | Ignored | Last modified | Status |
| :------------ | :--------- | :---- | :-------- | :-------------------- | :------ | :------------ | :----- |
| {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} |
'@
    $mdInfo = $formatTemplate -f $secureScoreUrl, (Get-SafeMarkdown $controlProfile.title), $controlId, $score, $maxScore, $implStatus, $ignoredDisplay, $lastModified, $rowStatus

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '41053'
        Title  = 'Network protection is enabled in block mode'
        Status = $passed
        Result = $testResultMarkdown
    }
    Add-ZtTestResultDetail @params
}
