<#
.SYNOPSIS
    Checks that Safe Links policies in Microsoft Defender for Office 365 are configured to scan and block malicious URLs.

.DESCRIPTION
    Validates that Safe Links protection in Microsoft Defender for Office 365 checks URLs against
    Microsoft's reputation service at time of click across email, Teams, and Office apps. The check
    reads Safe Links policies and rules from Exchange Online and evaluates every policy referenced by
    an enabled rule against the Standard/Strict recommended baseline. Built-in Protection is reported
    for transparency but is intentionally weaker than Standard/Strict and does not meet the baseline
    on its own.

.NOTES
    Test ID: 41032
    Category: Email and collaboration security
    Pillar: SecOps
    Required Module: ExchangeOnlineManagement
    Required Connection: Connect-ExchangeOnline
#>

function Test-Assessment-41032 {
    [ZtTest(
        Category = 'Email and collaboration security',
        CompatibleLicense = ('ATP_ENTERPRISE'),
        ImplementationCost = 'Low',
        Pillar = 'SecOps',
        RiskLevel = 'High',
        Service = ('ExchangeOnline'),
        SfiPillar = 'Protect tenants and isolate production systems',
        TenantType = ('Workforce'),
        TestId = 41032,
        Title = 'Safe Links policies in Microsoft Defender for Office 365 are configured to scan and block malicious URLs',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    # Invariant result metadata — TestId and Title are defined once here. Each return path only sets
    # the varying fields (Status, Result, and optionally CustomStatus) before Add-ZtTestResultDetail.
    $params = @{
        TestId = '41032'
        Title  = 'Safe Links policies in Microsoft Defender for Office 365 are configured to scan and block malicious URLs'
        Status = $false
    }

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking Safe Links policies in Microsoft Defender for Office 365'
    Write-ZtProgress -Activity $activity -Status 'Retrieving Safe Links policies'

    # Q1a: Retrieve all Safe Links policies from Exchange Online (no Graph/REST API exists for Safe Links).
    $allPolicies = $null
    try {
        $allPolicies = @(Get-SafeLinksPolicy -ErrorAction Stop | Select-Object Identity, IsBuiltInProtection, IsDefault, EnableSafeLinksForEmail, EnableSafeLinksForTeams, EnableSafeLinksForOffice, ScanUrls, EnableForInternalSenders, DeliverMessageAfterScan, DisableUrlRewrite, AllowClickThrough, TrackClicks)
    }
    catch {
        Write-PSFMessage "Failed to retrieve Safe Links policies: $_" -Tag Test -Level Warning
        # Spec: ATP_ENTERPRISE gates this test, so a cmdlet failure points to an Exchange Online
        # permission or connectivity issue rather than an unlicensed tenant.
        $params.Status       = $false
        $params.Result       = '⚠️ Safe Links policies could not be retrieved (no policies were returned, the cmdlet is unavailable, or the Exchange Online rule set cannot be read); because MDO licensing gates this test, an empty or failed result points to an Exchange Online permission or connectivity issue rather than absence of protection — verify Exchange Online access and re-run.'
        $params.CustomStatus = 'Investigate'
        Add-ZtTestResultDetail @params
        Write-PSFMessage 'Test-Assessment-41032: INVESTIGATE — Get-SafeLinksPolicy failed' -Tag Test -Level VeryVerbose
        return
    }

    if ($allPolicies.Count -eq 0) {
        # Spec: Built-in Protection is always present in every MDO-licensed tenant, so zero rows
        # indicates an Exchange Online permission or connectivity anomaly, not an unlicensed tenant.
        $params.Status       = $false
        $params.Result       = '⚠️ Safe Links policies could not be retrieved (no policies were returned, the cmdlet is unavailable, or the Exchange Online rule set cannot be read); because MDO licensing gates this test, an empty or failed result points to an Exchange Online permission or connectivity issue rather than absence of protection — verify Exchange Online access and re-run.'
        $params.CustomStatus = 'Investigate'
        Add-ZtTestResultDetail @params
        Write-PSFMessage 'Test-Assessment-41032: INVESTIGATE — Get-SafeLinksPolicy returned zero rows' -Tag Test -Level VeryVerbose
        return
    }

    Write-ZtProgress -Activity $activity -Status 'Retrieving Safe Links rules'

    # Q1b: Retrieve all Safe Links rules to determine which policies are actively applied.
    $allRules = $null
    try {
        $allRules = @(Get-SafeLinksRule -ErrorAction Stop | Select-Object Name, SafeLinksPolicy, State)
    }
    catch {
        Write-PSFMessage "Failed to retrieve Safe Links rules: $_" -Tag Test -Level Warning
        # Spec: if Get-SafeLinksRule fails while policies succeeded, return Investigate —
        # the rule set needed to determine which policies are actively applied cannot be read.
        $params.Status       = $false
        $params.Result       = '⚠️ Safe Links policies were retrieved but the associated rules could not be read; the set of actively applied policies cannot be determined. Verify Exchange Online permissions and re-run.'
        $params.CustomStatus = 'Investigate'
        Add-ZtTestResultDetail @params
        Write-PSFMessage 'Test-Assessment-41032: INVESTIGATE — Get-SafeLinksRule failed' -Tag Test -Level VeryVerbose
        return
    }
    #endregion Data Collection

    #region Assessment Logic
    # Standard/Strict recommended baseline. Built-in Protection is intentionally weaker on three of
    # these (EnableForInternalSenders, DisableUrlRewrite, AllowClickThrough) and does not meet it.
    $baseline = [ordered]@{
        EnableSafeLinksForEmail  = $true
        EnableSafeLinksForTeams  = $true
        EnableSafeLinksForOffice = $true
        ScanUrls                 = $true
        DeliverMessageAfterScan  = $true
        EnableForInternalSenders = $true
        DisableUrlRewrite        = $false
        AllowClickThrough        = $false
        TrackClicks              = $true
    }

    # Lookup: policy Identity → policy object
    $policyByIdentity = @{}
    foreach ($policy in $allPolicies) {
        $policyByIdentity[$policy.Identity] = $policy
    }

    # Enabled rules and the distinct policies they reference (these drive the verdict).
    $enabledRules  = @($allRules | Where-Object { $_.State -eq 'Enabled' })
    $anyRuleEnabled = $enabledRules.Count -gt 0

    # Map: policy identity → enabled rule name (join key: rule.SafeLinksPolicy == policy.Identity)
    $rulesForPolicy = @{}
    foreach ($rule in $enabledRules) {
        $rulesForPolicy[$rule.SafeLinksPolicy] = $rule.Name
    }

    # Built-in Protection policy (IsBuiltInProtection == True) — reported for transparency only.
    $builtInPolicy = $allPolicies | Where-Object { $_.IsBuiltInProtection -eq $true } | Select-Object -First 1

    # In-scope policy identities: built-in first (transparency), then all referenced by enabled rules.
    $inScopeIdentities = [System.Collections.Generic.List[string]]::new()
    if ($builtInPolicy) {
        $inScopeIdentities.Add($builtInPolicy.Identity)
    }
    foreach ($policyName in $rulesForPolicy.Keys) {
        if (-not $inScopeIdentities.Contains($policyName)) {
            $inScopeIdentities.Add($policyName)
        }
    }

    # Spec verdict:
    #   Pass  = at least one enabled rule AND every rule-referenced policy fully meets the baseline.
    #   Fail  = no enabled rule, or any rule-referenced policy diverges from the baseline.
    #   Investigate = an enabled rule references a policy that no longer exists (orphan rule).
    $passed         = $anyRuleEnabled
    $hasInvestigate = $false

    $policyRows = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($identity in $inScopeIdentities) {
        $policy       = $policyByIdentity[$identity]
        $isRuleScoped = $rulesForPolicy.ContainsKey($identity)
        $ruleName     = if ($isRuleScoped) { $rulesForPolicy[$identity] } else { '' }

        if ($null -eq $policy) {
            # Orphan rule: enabled rule references a policy deleted from Get-SafeLinksPolicy → Investigate.
            $hasInvestigate = $true
            $policyRows.Add([PSCustomObject]@{
                Identity       = $identity
                IsBuiltIn      = $false
                AppliedViaRule = $ruleName
                NonCompliant   = 'Referenced policy not found in Get-SafeLinksPolicy'
                RowResult      = 'Investigate'
            })
            continue
        }

        # Evaluate the nine baseline properties.
        $nonCompliant = [System.Collections.Generic.List[string]]::new()
        foreach ($prop in $baseline.Keys) {
            if ($policy.$prop -ne $baseline[$prop]) {
                $nonCompliant.Add("$prop=$($policy.$prop)")
            }
        }

        $rowResult = if ($nonCompliant.Count -eq 0) { 'Pass' } else { 'Fail' }

        # Only rule-referenced policies drive the overall verdict; Built-in is transparency only.
        if ($isRuleScoped -and $rowResult -eq 'Fail') {
            $passed = $false
        }

        $policyRows.Add([PSCustomObject]@{
            Identity       = $identity
            IsBuiltIn      = [bool]$policy.IsBuiltInProtection
            # Built-in Protection applies as a preset with no explicit rule; Applied via Rule is blank.
            AppliedViaRule = if ($policy.IsBuiltInProtection) { '' } else { $ruleName }
            NonCompliant   = ($nonCompliant -join ', ')
            RowResult      = $rowResult
        })
    }

    $customStatus = $null
    if (-not $passed) {
        $testResultMarkdown = "❌ Either no custom or preset Safe Links rule is enabled (Built-in Protection alone does not meet the Standard/Strict baseline) or one or more enabled rule-referenced policies disables a scanning surface, allows click-through, skips internal senders, or disables URL rewriting; users can encounter weaponized URLs in collaboration surfaces.`n`n%TestResult%"
    }
    elseif ($hasInvestigate) {
        $passed       = $false
        $customStatus = 'Investigate'
        $testResultMarkdown = "⚠️ An enabled Safe Links rule references a policy that does not exist in Get-SafeLinksPolicy; manual review is required.`n`n%TestResult%"
    }
    else {
        $testResultMarkdown = "✅ Every Safe Links policy in use scans URLs for email, Teams, and Office apps at time of click; rewrites URLs in email; covers internal senders; and prevents users from clicking through warnings.`n`n%TestResult%"
    }
    #endregion Assessment Logic

    #region Report Generation
    $portalUrl  = 'https://security.microsoft.com/safelinksv2'
    $maxDisplay = 10
    $totalCount = $policyRows.Count

    # Sort: worst verdict first (Fail > Investigate > Pass), then alphabetically by identity.
    $statusPriority = @{ Fail = 0; Investigate = 1; Pass = 2 }
    $sortedRows  = @($policyRows | Sort-Object { $statusPriority[$_.RowResult] }, Identity)
    $displayRows = @($sortedRows | Select-Object -First $maxDisplay)

    $tableRows = ''
    foreach ($row in $displayRows) {
        $resultDisplay = switch ($row.RowResult) {
            'Pass'        { '✅ Pass' }
            'Fail'        { '❌ Fail' }
            'Investigate' { '⚠️ Investigate' }
        }
        $policyName = if ($row.IsBuiltIn) { "(Built-in) $($row.Identity)" } else { $row.Identity }
        $policyMd   = Get-SafeMarkdown $policyName
        $ruleMd     = if ($row.AppliedViaRule) { Get-SafeMarkdown $row.AppliedViaRule } else { '' }
        $issuesMd   = if ($row.NonCompliant) { Get-SafeMarkdown $row.NonCompliant } else { '' }
        $tableRows += "| $resultDisplay | $policyMd | $ruleMd | $issuesMd |`n"
    }

    if ($totalCount -gt $maxDisplay) {
        $tableRows += "| ... | ... | ... | ... |`n"
    }

    $preTableLines = ''
    if ($totalCount -gt $maxDisplay) {
        $preTableLines = "Showing $maxDisplay of $totalCount policies. [View all in Microsoft 365 Defender > Policies & rules > Threat policies > Safe Links]($portalUrl)`n`n"
    }

    $formatTemplate = @'
{0}
| Result | Policy | Applied via rule | Non-compliant settings |
| :----- | :----- | :--------------- | :--------------------- |
{1}
'@

    $mdInfo             = $formatTemplate -f $preTableLines, $tableRows
    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params.Status = $passed
    $params.Result = $testResultMarkdown
    if ($customStatus) {
        $params.CustomStatus = $customStatus
    }
    Add-ZtTestResultDetail @params

    if ($customStatus -eq 'Investigate') {
        Write-PSFMessage "Test-Assessment-41032: INVESTIGATE — orphan enabled rule references a missing policy ($totalCount policies in scope)" -Tag Test -Level VeryVerbose
    }
    elseif ($passed) {
        Write-PSFMessage "Test-Assessment-41032: PASS — all $totalCount in-scope policies meet the Standard/Strict baseline" -Tag Test -Level VeryVerbose
    }
    else {
        Write-PSFMessage "Test-Assessment-41032: FAIL — no enabled rule or a rule-referenced policy diverges from the baseline ($totalCount policies in scope)" -Tag Test -Level VeryVerbose
    }
}
