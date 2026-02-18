<#
.SYNOPSIS
    Validates that Request Body Inspection is enabled in Application Gateway WAF.

.DESCRIPTION
    This test validates that Azure Application Gateway Web Application Firewall policies
    have request body inspection enabled to analyze HTTP POST, PUT, and PATCH request bodies
    for malicious patterns. Only evaluates WAF policies that are attached to Application Gateways.

.NOTES
    Test ID: 26879
    Category: Azure Network Security
    Pillar: Network
    Required API: Application Gateway WAF Policies
#>

function Test-Assessment-26879 {
    [ZtTest(
        Category = 'Azure Network Security',
        ImplementationCost = 'Low',
        MinimumLicense = ('Azure WAF'),
        Pillar = 'Network',
        RiskLevel = 'High',
        SfiPillar = 'Protect networks',
        TenantType = ('Workforce'),
        TestId = 26879,
        Title = 'Request Body Inspection is enabled in Application Gateway WAF',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $activity = 'Checking Application Gateway WAF request body inspection configuration'

    # Check if connected to Azure
    Write-ZtProgress -Activity $activity -Status 'Checking Azure connection'

    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azContext) {
        Write-PSFMessage 'Not connected to Azure.' -Level Warning
        Add-ZtTestResultDetail -SkippedBecause NotConnectedAzure
        return
    }

    Write-ZtProgress -Activity $activity -Status 'Enumerating subscriptions'

    # Initialize variables
    $subscriptions = @()
    $policies = @()
    $anySuccessfulAccess = 0
    $apiVersion = "2025-03-01"

    try {
        $subscriptions = Get-AzSubscription -ErrorAction Stop
    }
    catch {
        Write-PSFMessage "Unable to retrieve Azure subscriptions: $_" -Level Warning
    }

    if ($subscriptions.Count -eq 0) {
        Write-PSFMessage "No Azure subscriptions found." -Level Warning
        Add-ZtTestResultDetail -SkippedBecause NoAzureAccess
        return
    }

    # Collect WAF policies from all subscriptions
    foreach ($sub in $subscriptions) {
        Write-ZtProgress -Activity $activity -Status "Checking subscription: $($sub.Name)"

        $path = "/subscriptions/$($sub.Id)/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies?api-version=$apiVersion"
        $response = Invoke-AzRestMethod -Path $path -ErrorAction SilentlyContinue

        # Skip if request failed completely
        if (-not $response -or $null -eq $response.StatusCode) {
            Write-PSFMessage "Failed to query subscription '$($sub.Name)'. Skipping." -Level Warning
            continue
        }

        # Handle access denied for this subscription - skip and continue to next
        if ($response.StatusCode -eq 403) {
            Write-PSFMessage "Access denied to subscription '$($sub.Name)': HTTP $($response.StatusCode). Skipping." -Level Verbose
            continue
        }

        # Handle other HTTP errors - skip this subscription
        if ($response.StatusCode -ge 400) {
            Write-PSFMessage "Error querying subscription '$($sub.Name)': HTTP $($response.StatusCode). Skipping." -Level Warning
            continue
        }

        # Count successful accesses
        $anySuccessfulAccess++

        # No content or no policies in this subscription
        if (-not $response.Content) {
            continue
        }

        $policiesJson = $response.Content | ConvertFrom-Json

        if (-not $policiesJson.value -or $policiesJson.value.Count -eq 0) {
            continue
        }

        # Collect policies from this subscription - only those attached to Application Gateways
        foreach ($policyResource in $policiesJson.value) {
            # Filter: Only include policies attached to at least one Application Gateway
            $appGateways = $policyResource.properties.applicationGateways
            if (-not $appGateways -or $appGateways.Count -eq 0) {
                Write-PSFMessage "Excluding unattached WAF policy '$($policyResource.name)' from evaluation." -Level Verbose
                continue
            }

            # Extract Application Gateway names
            $appGatewayNames = @()
            foreach ($gw in $appGateways) {
                $gwName = ($gw.id -split '/')[-1]
                $appGatewayNames += $gwName
            }

            $policies += [PSCustomObject]@{
                SubscriptionId        = $sub.Id
                SubscriptionName      = $sub.Name
                PolicyName            = $policyResource.name
                PolicyId              = $policyResource.id
                Location              = $policyResource.location
                EnabledState          = $policyResource.properties.policySettings.state
                Mode                  = $policyResource.properties.policySettings.mode
                RequestBodyCheck      = $policyResource.properties.policySettings.requestBodyCheck
                ApplicationGateways   = $appGatewayNames -join ', '
                ApplicationGatewayCount = $appGateways.Count
            }
        }
    }
    #endregion Data Collection

    #region Assessment Logic
    $passed = $false

    # Skip test if no policies found
    if ($policies.Count -eq 0) {
        if ($anySuccessfulAccess -eq 0) {
            # All subscriptions were inaccessible
            Write-PSFMessage "No accessible Azure subscriptions found." -Level Warning
            Add-ZtTestResultDetail -SkippedBecause NoAzureAccess
        } else {
            # Subscriptions accessible but no WAF policies attached to Application Gateways
            Write-PSFMessage "No Application Gateway WAF policies attached to Application Gateways found across subscriptions." -Tag Test -Level Verbose
            Add-ZtTestResultDetail -SkippedBecause NotApplicable
        }
        return
    }

    # Check if all policies have request body inspection enabled
    $allCompliant = $true
    foreach ($policy in $policies) {
        if ($policy.RequestBodyCheck -ne $true) {
            $allCompliant = $false
            break
        }
    }

    if ($allCompliant) {
        $passed = $true
        $testResultMarkdown = "✅ All Application Gateway WAF policies attached to Application Gateways have request body inspection enabled.`n`n%TestResult%"
    }
    else {
        $passed = $false
        $testResultMarkdown = "❌ One or more Application Gateway WAF policies attached to Application Gateways have request body inspection disabled.`n`n%TestResult%"
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    # Table title
    $reportTitle = 'Application Gateway WAF Policies'
    $portalLink = "https://portal.azure.com/#view/Microsoft_Azure_HybridNetworking/FirewallManagerMenuBlade/~/wafMenuItem"

    # Prepare table rows
    $tableRows = ''
    foreach ($item in $policies) {
        $policyLink = "https://portal.azure.com/#resource$($item.PolicyId)"
        $subLink = "https://portal.azure.com/#resource/subscriptions/$($item.SubscriptionId)"
        $policyMd = "[$(Get-SafeMarkdown $item.PolicyName)]($policyLink)"
        $subMd = "[$(Get-SafeMarkdown $item.SubscriptionName)]($subLink)"
        $appGwMd = Get-SafeMarkdown $item.ApplicationGateways

        # Calculate status indicators
        $requestBodyCheckDisplay = if ($item.RequestBodyCheck -eq $true) { '✅ Enabled' } else { '❌ Disabled' }
        $enabledStateDisplay = if ($item.EnabledState -eq 'Enabled') { '✅ Enabled' } else { '❌ Disabled' }
        $modeDisplay = if ($item.Mode -eq 'Prevention') { '✅ Prevention' } else { "⚠️ $($item.Mode)" }
        $status = if ($item.RequestBodyCheck -eq $true) { '✅ Pass' } else { '❌ Fail' }

        $tableRows += "| $policyMd | $subMd | $appGwMd | $enabledStateDisplay | $modeDisplay | $requestBodyCheckDisplay | $status |`n"
    }

    $formatTemplate = @'


## [{0}]({1})

| Policy name | Subscription name | Attached Application Gateway | Enabled state | WAF mode | Request body check | Status |
| :---------- | :---------------- | :--------------------------- | :-----------: | :------: | :----------------: | :----: |
{2}

'@

    $mdInfo = $formatTemplate -f $reportTitle, $portalLink, $tableRows.TrimEnd("`n")

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '26879'
        Title  = 'Request Body Inspection is enabled in Application Gateway WAF'
        Status = $passed
        Result = $testResultMarkdown
    }

    Add-ZtTestResultDetail @params
}
