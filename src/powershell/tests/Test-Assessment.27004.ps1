<#
.SYNOPSIS
    Validates that custom TLS inspection bypass rules do not duplicate system bypass destinations.

.DESCRIPTION
    This test checks whether custom TLS inspection bypass rules contain destinations that are
    already covered by Microsoft's system bypass list. Redundant rules:
    - Consume policy capacity unnecessarily
    - Create administrative overhead
    - May cause confusion about necessary vs. duplicated rules

    The test identifies exact matches, subdomain matches, and wildcard overlaps between
    custom bypass rules and the system bypass list.

.NOTES
    Test ID: 27004
    Category: Global Secure Access
    Required API: networkAccess/tlsInspectionPolicies (beta) with $expand=policyRules
    System Bypass List: assets/27004-system-bypass-fqdns.json (sourced from GSA backend team; manually maintained until API is available)
#>

function Test-Assessment-27004 {
    [ZtTest(
        Category = 'Global Secure Access',
        ImplementationCost = 'Low',
        MinimumLicense = ('Entra_Premium_Internet_Access'),
        Pillar = 'Network',
        RiskLevel = 'Low',
        SfiPillar = 'Protect networks',
        TenantType = ('Workforce'),
        TestId = 27004,
        Title = 'TLS inspection custom bypass rules do not duplicate system bypass destinations',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $activity = 'Checking TLS inspection bypass rules for redundant system destinations'
    Write-ZtProgress -Activity $activity -Status 'Loading system bypass reference list'

    # Load system bypass FQDN list from config file.
    # The JSON is sourced from the GSA backend team because the API does not expose these FQDNs.
    # Spec: 27004-system-bypass-fqdns.json must be kept up to date manually until an API is available.
    $dataFilePath = Join-Path $PSScriptRoot '..' 'assets' '27004-system-bypass-fqdns.json' | Resolve-Path -ErrorAction SilentlyContinue
    if (-not $dataFilePath -or -not (Test-Path $dataFilePath)) {
        Write-PSFMessage "System bypass FQDN config file not found: $dataFilePath" -Tag Test -Level Warning
        Add-ZtTestResultDetail -SkippedBecause NotSupported
        return
    }

    $bypassConfig = Get-Content $dataFilePath -Raw | ConvertFrom-Json
    $systemFqdns = @($bypassConfig.fqdns)
    $systemFqdnsLower = $systemFqdns | ForEach-Object { $_.ToLower() }
    Write-PSFMessage "Loaded $($systemFqdns.Count) system bypass FQDNs from config (last updated: $($bypassConfig.metadata.lastUpdated))" -Tag Test -Level VeryVerbose

    Write-ZtProgress -Activity $activity -Status 'Querying TLS inspection policies and rules'

    $tlsPolicies = @()
    $errorMsg = $null

    try {
        $tlsPolicies = Invoke-ZtGraphRequest `
            -RelativeUri 'networkAccess/tlsInspectionPolicies' `
            -QueryParameters @{ '$expand' = 'policyRules' } `
            -ApiVersion beta
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage "Failed to retrieve TLS inspection policies: $errorMsg" -Tag Test -Level Warning
    }
    #endregion Data Collection

    #region Assessment Logic
    $testResultMarkdown = ''
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        # API call failed - unable to determine status
        $passed = $false
        $customStatus = 'Investigate'
        $testResultMarkdown = "⚠️ Unable to retrieve TLS inspection policies due to API error or insufficient permissions.`n`n%TestResult%"
    }
    elseif ($null -eq $tlsPolicies -or $tlsPolicies.Count -eq 0) {
        # No TLS inspection policies configured - prerequisite not met
        Write-PSFMessage 'TLS inspection is not configured in this tenant.' -Tag Test -Level Verbose
        Add-ZtTestResultDetail -SkippedBecause NotApplicable -Result 'TLS inspection is not configured in this tenant. This check is not applicable until a TLS inspection policy is created.'
        return
    }
    else {

    Write-ZtProgress -Activity $activity -Status 'Analyzing bypass rules for redundancies'

    $allBypassRules = [System.Collections.Generic.List[object]]::new()
    $redundantRules = [System.Collections.Generic.List[object]]::new()
    $uniqueRules = [System.Collections.Generic.List[object]]::new()

    foreach ($policy in $tlsPolicies) {
        if ($null -eq $policy.policyRules) {
            continue
        }

        $bypassRules = @($policy.policyRules | Where-Object { $_.action -eq 'bypass' })

        foreach ($rule in $bypassRules) {
            # Skip auto-created system rules
            if ($rule.description -like 'Auto-created TLS rule*') {
                continue
            }

            $destinations = @()
            $destinationTypeMap = @{}
            $matchedPairs = [System.Collections.Generic.List[object]]::new()

            # Extract destinations from matchingConditions, tracking type per value
            if ($null -ne $rule.matchingConditions -and $null -ne $rule.matchingConditions.destinations) {
                foreach ($dest in $rule.matchingConditions.destinations) {
                    if ($null -ne $dest.values) {
                        $destType = if ($dest.'@odata.type' -like '*tlsInspectionFqdnDestination*') { 'FQDN' }
                                    elseif ($dest.'@odata.type' -like '*tlsInspectionWebCategoryDestination*') { 'Category' }
                                    else { 'Unknown' }
                        foreach ($v in $dest.values) {
                            $destinations += $v
                            $destinationTypeMap[$v] = $destType
                        }
                    }
                }
            }

            # Check each destination FQDN against the system bypass FQDN list.
            # Matching rules per spec:
            #   Exact:              custom 'dropbox.com'       matches system 'dropbox.com'
            #   Subdomain wildcard: custom 'www.dropbox.com'   matches system '*.dropbox.com'
            #   Wildcard root:      custom 'dropbox.com'       matches system '*.dropbox.com'
            #   Wildcard-wildcard:  custom '*.dropbox.com'     matches system '*.dropbox.com'
            #   Double-wildcard:    custom 'x.britishairways.com' matches system '*.britishairways.*'
            foreach ($destination in $destinations) {
                $destLower = $destination.ToLower().Trim()

                for ($i = 0; $i -lt $systemFqdnsLower.Count; $i++) {
                    $sysFqdn = $systemFqdnsLower[$i]
                    $isMatch = $false
                    $matchType = ''

                    if ($destLower -eq $sysFqdn) {
                        # Exact match (covers wildcard-to-wildcard too)
                        $isMatch = $true; $matchType = 'Exact'
                    }
                    elseif ($sysFqdn -match '^\*\.([^.]+)\.\*$') {
                        # Double-wildcard: *.domain.* — match any FQDN containing 'domain' as a segment
                        $mid = [regex]::Escape($Matches[1])
                        if ($destLower -match "(^|\.)$mid\.") { $isMatch = $true; $matchType = 'Wildcard' }
                    }
                    elseif ($sysFqdn -match '^\*\.(.+)$') {
                        # Standard wildcard: *.domain.com
                        $suffix = $Matches[1]
                        if ($destLower -like "*.$suffix" -or $destLower -eq $suffix) { $isMatch = $true; $matchType = 'Subdomain' }
                        elseif ($destLower -eq "*.$suffix") { $isMatch = $true; $matchType = 'Wildcard' }
                    }
                    elseif ($destLower -match '^\*\.(.+)$') {
                        # Custom is wildcard: *.domain.com — check if system covers the base domain
                        $customSuffix = $Matches[1]
                        if ($sysFqdn -eq $customSuffix -or $sysFqdn -eq "*.$customSuffix") { $isMatch = $true; $matchType = 'Wildcard' }
                    }

                    if ($isMatch) {
                        $matchedPairs.Add([PSCustomObject]@{
                            CustomFqdn = $destination
                            SystemFqdn = $systemFqdns[$i]
                            MatchType  = $matchType
                            DestType   = if ($destinationTypeMap.ContainsKey($destination)) { $destinationTypeMap[$destination] } else { 'FQDN' }
                        })
                        break  # move to next destination once a system match is found for this one
                    }
                }
            }

            $ruleStatus = if ($matchedPairs.Count -eq 0) { 'No Overlap' }
                          elseif ($matchedPairs.Count -ge $destinations.Count) { 'Redundant' }
                          else { 'Partial' }

            $ruleInfo = [PSCustomObject]@{
                PolicyName        = $policy.name
                PolicyId          = $policy.id
                RuleName          = $rule.name
                RuleId            = $rule.id
                Destinations      = $destinations
                TotalDestinations = $destinations.Count
                RedundantCount    = $matchedPairs.Count
                MatchedPairs      = $matchedPairs
                Status            = $ruleStatus
            }

            $allBypassRules.Add($ruleInfo)

            if ($ruleStatus -ne 'No Overlap') {
                $redundantRules.Add($ruleInfo)
            }
            else {
                $uniqueRules.Add($ruleInfo)
            }
        }
    }

    # Evaluate test result per spec evaluation logic
    if ($redundantRules.Count -eq 0) {
        # No custom bypass rules OR custom rules exist but none are redundant - pass
        $passed = $true
        $testResultMarkdown = "✅ All custom TLS inspection bypass rules target unique destinations not covered by the system bypass list.`n`n%TestResult%"
    }
    else {
        # Any matches found - fail with list of redundant rules
        $passed = $false
        $testResultMarkdown = "❌ Found custom bypass rules that duplicate system bypass destinations; these rules are redundant and can be removed to simplify policy management.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($allBypassRules.Count -gt 0) {
        $reportTitle = 'TLS Inspection Bypass Rule Analysis'
        $portalLink = 'https://entra.microsoft.com/#view/Microsoft_Azure_Network_Access/TLSInspectionPolicy.ReactView'

        # Calculate totals
        $totalDestinations = ($allBypassRules | ForEach-Object { $_.TotalDestinations } | Measure-Object -Sum).Sum
        $totalRedundantDestinations = ($allBypassRules | ForEach-Object { $_.RedundantCount } | Measure-Object -Sum).Sum
        $totalUniqueDestinations = $totalDestinations - $totalRedundantDestinations

        # Build rule-level summary table
        $rulesTable = "#### Rule-Level Summary`n`n"
        $rulesTable += "| Policy name | Rule name | Total destinations | Redundant destinations | Status |`n"
        $rulesTable += "| :---------- | :-------- | :----------------- | :--------------------- | :----- |`n"

        foreach ($rule in $allBypassRules) {
            $policyName = Get-SafeMarkdown -Text $rule.PolicyName
            $ruleName = Get-SafeMarkdown -Text $rule.RuleName
            $rulesTable += "| $policyName | $ruleName | $($rule.TotalDestinations) | $($rule.RedundantCount) | $($rule.Status) |`n"
        }

        # Build redundant destination detail grouped by rule
        $redundantDetail = ''
        if ($redundantRules.Count -gt 0) {
            $redundantDetail = "#### Redundant Destination Detail`n`n"

            foreach ($rule in $redundantRules) {
                $policyName = Get-SafeMarkdown -Text $rule.PolicyName
                $ruleName = Get-SafeMarkdown -Text $rule.RuleName
                $redundantDetail += "**Rule: $ruleName** (Policy: $policyName) — $($rule.RedundantCount) of $($rule.TotalDestinations) destinations redundant`n`n"
                $redundantDetail += "| # | Custom bypass destination | Destination type | Matched system bypass entry | Match type |`n"
                $redundantDetail += "| :- | :----------------------- | :--------------- | :-------------------------- | :--------- |`n"

                $rowNum = 1
                foreach ($pair in $rule.MatchedPairs) {
                    $customDest = Get-SafeMarkdown -Text $pair.CustomFqdn
                    $sysDest = Get-SafeMarkdown -Text $pair.SystemFqdn
                    $redundantDetail += "| $rowNum | $customDest | $($pair.DestType) | $sysDest | $($pair.MatchType) |`n"
                    $rowNum++
                }
                $redundantDetail += "`n"
            }
        }

        $formatTemplate = @'

## [{0}]({1})

**Overview:**
- Total custom bypass rules: {2}
- Total custom bypass destinations: {3}
- Redundant destinations found: {4}
- Unique destinations: {5}

{6}

{7}
'@

        $mdInfo = $formatTemplate -f $reportTitle, $portalLink, $allBypassRules.Count, $totalDestinations, $totalRedundantDestinations, $totalUniqueDestinations, $rulesTable, $redundantDetail
    }

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '27004'
        Title  = 'TLS inspection custom bypass rules do not duplicate system bypass destinations'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($customStatus) {
        $params.CustomStatus = $customStatus
    }
    Add-ZtTestResultDetail @params
}
