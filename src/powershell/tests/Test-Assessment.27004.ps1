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
            $destinationTypes = @()
            $isRedundant = $false
            $matchedPairs = [System.Collections.Generic.List[object]]::new()

            # Extract destinations from matchingConditions
            if ($null -ne $rule.matchingConditions -and $null -ne $rule.matchingConditions.destinations) {
                foreach ($dest in $rule.matchingConditions.destinations) {
                    if ($null -ne $dest.values) {
                        $destinations += $dest.values

                        # Determine destination type from @odata.type
                        if ($dest.'@odata.type' -like '*tlsInspectionFqdnDestination*') {
                            $destinationTypes += 'FQDN'
                        }
                        elseif ($dest.'@odata.type' -like '*tlsInspectionWebCategoryDestination*') {
                            $destinationTypes += 'Category'
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

                    if ($destLower -eq $sysFqdn) {
                        # Exact match (covers wildcard-to-wildcard too)
                        $isMatch = $true
                    }
                    elseif ($sysFqdn -match '^\*\.([^.]+)\.\*$') {
                        # Double-wildcard: *.domain.* — match any FQDN containing 'domain' as a segment
                        $mid = [regex]::Escape($Matches[1])
                        if ($destLower -match "(^|\.)$mid\.") { $isMatch = $true }
                    }
                    elseif ($sysFqdn -match '^\*\.(.+)$') {
                        # Standard wildcard: *.domain.com
                        $suffix = $Matches[1]
                        # Subdomain or root domain both considered redundant
                        if ($destLower -like "*.$suffix" -or $destLower -eq $suffix) { $isMatch = $true }
                        # Custom wildcard for the same domain: *.domain.com
                        elseif ($destLower -eq "*.$suffix") { $isMatch = $true }
                    }
                    elseif ($destLower -match '^\*\.(.+)$') {
                        # Custom is wildcard: *.domain.com — check if system covers the base domain
                        $customSuffix = $Matches[1]
                        if ($sysFqdn -eq $customSuffix -or $sysFqdn -eq "*.$customSuffix") { $isMatch = $true }
                    }

                    if ($isMatch) {
                        $matchedPairs.Add([PSCustomObject]@{
                            CustomFqdn = $destination
                            SystemFqdn = $systemFqdns[$i]
                        })
                        break  # move to next destination once a system match is found for this one
                    }
                }
            }

            $isRedundant = $matchedPairs.Count -gt 0

            $ruleInfo = [PSCustomObject]@{
                PolicyName          = $policy.name
                PolicyId            = $policy.id
                RuleName            = $rule.name
                RuleId              = $rule.id
                DestinationType     = if ($destinationTypes.Count -gt 0) {
                    ($destinationTypes | Select-Object -Unique) -join ' / '
                } else { 'None' }
                Destinations        = $destinations
                DestinationSummary  = if ($destinations.Count -gt 0) {
                    $first5 = ($destinations | Select-Object -First 5) -join ', '
                    if ($destinations.Count -gt 5) { "$first5 (+$($destinations.Count - 5) more)" } else { $first5 }
                } else { 'None' }
                IsRedundant         = $isRedundant
                MatchedPairs        = $matchedPairs
                Status              = if ($isRedundant) { 'Redundant' } else { 'Unique' }
            }

            $allBypassRules.Add($ruleInfo)

            if ($isRedundant) {
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
        $reportTitle = 'TLS Inspection Bypass Rules'
        $portalLink = 'https://entra.microsoft.com/#view/Microsoft_Azure_Network_Access/TLSInspectionPolicy.ReactView'

        $formatTemplate = @'

## [{0}]({1})

{5}

**Summary:**
- Total custom bypass rules: {2}
- Total custom bypass destinations: {7}
- Redundant destinations found: {3}
- Unique destinations: {4}

{6}
'@

        # Build main rules table
        $rulesTable = "**All custom bypass rules:**`n`n"
        $rulesTable += "| Policy name | Rule name | Destination type | Destination value | System bypass match | Status |`n"
        $rulesTable += "| :---------- | :-------- | :--------------- | :---------------- | :------------------ | :----- |`n"

        foreach ($rule in $allBypassRules) {
            $policyName = Get-SafeMarkdown -Text $rule.PolicyName
            $ruleName = Get-SafeMarkdown -Text $rule.RuleName
            $destType = Get-SafeMarkdown -Text $rule.DestinationType
            $destValue = Get-SafeMarkdown -Text $rule.DestinationSummary
            $systemMatch = if ($rule.IsRedundant) { 'Yes' } else { 'No' }
            $statusIcon = if ($rule.IsRedundant) { 'Redundant' } else { 'Unique' }

            $rulesTable += "| $policyName | $ruleName | $destType | $destValue | $systemMatch | $statusIcon |`n"
        }

        # Build redundant rules detail table if any found
        $redundantTable = ''
        if ($redundantRules.Count -gt 0) {
            $redundantTable = "`n**Redundant rules detail:**`n`n"
            $redundantTable += "| Policy name | Rule name | Redundant destination | Matched system bypass |`n"
            $redundantTable += "| :---------- | :-------- | :-------------------- | :-------------------- |`n"

            foreach ($rule in $redundantRules) {
                $policyName = Get-SafeMarkdown -Text $rule.PolicyName
                $ruleName = Get-SafeMarkdown -Text $rule.RuleName
                $redundantDests = ($rule.MatchedPairs | ForEach-Object { Get-SafeMarkdown -Text $_.CustomFqdn }) -join ', '
                $matchedBypasses = ($rule.MatchedPairs | ForEach-Object { Get-SafeMarkdown -Text $_.SystemFqdn }) -join ', '
                $redundantTable += "| $policyName | $ruleName | $redundantDests | $matchedBypasses |`n"
            }
        }

        # Calculate total destinations across all bypass rules
        $totalDestinations = ($allBypassRules | ForEach-Object { $_.Destinations.Count } | Measure-Object -Sum).Sum

        $mdInfo = $formatTemplate -f $reportTitle, $portalLink, $allBypassRules.Count, $redundantRules.Count, $uniqueRules.Count, $rulesTable, $redundantTable, $totalDestinations
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
