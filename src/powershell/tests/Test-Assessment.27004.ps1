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
    System Bypass List: Maintained by Microsoft, documented in FAQ
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

    # System bypass list maintained by Microsoft
    # Reference: https://learn.microsoft.com/en-us/entra/global-secure-access/faq-transport-layer-security#what-destinations-are-included-in-the-system-bypass
    $systemBypassList = @(
        'Adobe CRS',
        'AplusPC UCC Regions',
        'App Center',
        'Apple ESS Push Services',
        'Azure Diagnostics',
        'Azure IoT Hub',
        'Azure Management',
        'Azure WAN Listener',
        'Centanet',
        'Central Plaza e-Order',
        'Cisco Umbrella Proxy',
        'DocuSign',
        'Dropbox',
        'e-Szigno',
        'Global Secure Access Diagnostics',
        'Guardz Device Agent',
        'iCloud',
        'Likr Load Balancer',
        'MediaTek',
        'Microsigner',
        'Microsoft Graph',
        'Microsoft Login Services',
        'O2 Moje Login',
        'OpenSpace Solutions',
        'Power BI External',
        'Signal',
        'TeamViewer',
        'Visual Studio Telemetry',
        'Webex',
        'WhatsApp',
        'Windows Update',
        'ZDX Cloud',
        'Zscaler Beta',
        'Zscaler Two',
        'Zoom'
    )

    # Convert to lowercase for case-insensitive comparison
    $systemBypassLower = $systemBypassList | ForEach-Object { $_.ToLower() }

    Write-ZtProgress -Activity $activity -Status 'Querying TLS inspection policies and rules'

    $tlsPolicies = @()

    try {
        $tlsPolicies = Invoke-ZtGraphRequest `
            -RelativeUri 'networkAccess/tlsInspectionPolicies' `
            -QueryParameters @{ '$expand' = 'policyRules' } `
            -ApiVersion beta
    }
    catch {
        Write-PSFMessage "Failed to retrieve TLS inspection policies: $_" -Tag Test -Level Error
        return
    }
    #endregion Data Collection

    #region Assessment Logic
    $testResultMarkdown = ''
    $passed = $false

    if ($null -eq $tlsPolicies -or $tlsPolicies.Count -eq 0) {
        # No TLS inspection policies configured - prerequisite not met
        Write-PSFMessage 'TLS inspection is not configured in this tenant.' -Tag Test -Level Verbose
        Add-ZtTestResultDetail -SkippedBecause NotApplicable -Result 'TLS inspection is not configured in this tenant. This check is not applicable until a TLS inspection policy is created.'
        return
    }

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
                $matchedSystemBypass = ''

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

                # Check each destination against system bypass list
                foreach ($destination in $destinations) {
                    $destLower = $destination.ToLower()

                    # Check for matches in system bypass list
                    foreach ($systemBypass in $systemBypassLower) {
                        # Exact match or substring match (indicating overlap)
                        if ($destLower -like "*$systemBypass*" -or $systemBypass -like "*$destLower*") {
                            $isRedundant = $true
                            $matchedSystemBypass = $systemBypassList[$systemBypassLower.IndexOf($systemBypass)]
                            break
                        }
                    }

                    if ($isRedundant) {
                        break
                    }
                }

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
                        ($destinations | Select-Object -First 3) -join ', ' + $(if ($destinations.Count -gt 3) { " (+$($destinations.Count - 3) more)" } else { '' })
                    } else { 'None' }
                    IsRedundant         = $isRedundant
                    MatchedSystemBypass = $matchedSystemBypass
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
                $redundantDest = Get-SafeMarkdown -Text ($rule.Destinations -join ', ')
                $matchedBypass = Get-SafeMarkdown -Text $rule.MatchedSystemBypass

                $redundantTable += "| $policyName | $ruleName | $redundantDest | $matchedBypass |`n"
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
    Add-ZtTestResultDetail @params
}
