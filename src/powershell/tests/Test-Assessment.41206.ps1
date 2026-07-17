<#
.SYNOPSIS
    Checks that at least one Microsoft Sentinel workbook is deployed in every Sentinel-onboarded Log Analytics workspace.

.NOTES
    Test ID: 41206
    Workshop Task: SECOPS_099
    Pillar: SecOps
    Category: Security information and event management
    Required API: Azure Resource Manager (management.azure.com)
#>
function Test-Assessment-41206 {
    [ZtTest(
        Category = 'Security information and event management',
        ImplementationCost = 'Low',
        MinimumLicense = ('Consumption-based: Microsoft Sentinel'),
        Pillar = 'SecOps',
        RiskLevel = 'Low',
        Service = ('Azure'),
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 41206,
        Title = 'At least one workbook is deployed in every Microsoft Sentinel workspace for visualization and operational reporting',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking workbooks deployed in Microsoft Sentinel workspaces'

    # Q1 + Q2 + onboarding check via shared helper.
    # Returns 'Forbidden'        on ARG 401/403 (Investigate).
    # Returns $null              on unexpected ARG failure (Investigate).
    # Returns 'NoSubscriptions'  when no enabled subscriptions are accessible (Skip).
    # Returns 'NoWorkspaces'     when no Log Analytics workspaces exist in scope (Skip).
    $allWorkspaces = Get-SentinelWorkspaceData -Activity $activity

    if ($null -eq $allWorkspaces) {
        $params = @{
            TestId       = '41206'
            Title        = 'At least one workbook is deployed in every Microsoft Sentinel workspace for visualization and operational reporting'
            Status       = $false
            Result       = '⚠️ Azure Resource Graph returned an unexpected error while querying subscriptions or Log Analytics workspaces. This is likely a transient issue, please re-run the assessment.'
            CustomStatus = 'Investigate'
        }
        Add-ZtTestResultDetail @params
        return
    }

    if ($allWorkspaces -eq 'Forbidden') {
        $params = @{
            TestId       = '41206'
            Title        = 'At least one workbook is deployed in every Microsoft Sentinel workspace for visualization and operational reporting'
            Status       = $false
            Result       = '⚠️ Azure Resource Graph returned insufficient permissions when querying subscriptions or workspaces. Ensure you have at least Reader access to the Azure subscriptions being tested.'
            CustomStatus = 'Investigate'
        }
        Add-ZtTestResultDetail @params
        return
    }

    if ($allWorkspaces -eq 'NoSubscriptions') {
        Write-PSFMessage 'No enabled subscriptions found — skipping Sentinel workbooks check.' -Tag Test -Level VeryVerbose
        Add-ZtTestResultDetail -SkippedBecause NotApplicable
        return
    }

    if ($allWorkspaces -eq 'NoWorkspaces') {
        Write-PSFMessage 'No Log Analytics workspaces found across accessible subscriptions — skipping Sentinel workbooks check.' -Tag Test -Level VeryVerbose
        Add-ZtTestResultDetail -SkippedBecause NotApplicable
        return
    }

    $checkableWorkspaces = @($allWorkspaces | Where-Object { -not $_.PermissionError })
    $forbiddenWorkspaces = @($allWorkspaces | Where-Object { $_.PermissionError })
    $onboardedWorkspaces = @($checkableWorkspaces | Where-Object { $_.SentinelOnboarded })

    if ($onboardedWorkspaces.Count -eq 0) {
        if ($forbiddenWorkspaces.Count -gt 0) {
            # Auth errors mean we cannot confirm whether those workspaces have Sentinel onboarded;
            # a passing workspace may exist among the inaccessible ones.
            $params = @{
                TestId       = '41206'
                Title        = 'At least one workbook is deployed in every Microsoft Sentinel workspace for visualization and operational reporting'
                Status       = $false
                Result       = '⚠️ One or more Log Analytics workspaces returned insufficient permissions when checking Sentinel onboarding state. No Sentinel-onboarded workspace was confirmed among accessible workspaces — the overall state cannot be determined. Ensure Microsoft Sentinel Reader is granted on all workspaces and re-run the assessment.'
                CustomStatus = 'Investigate'
            }
        }
        else {
            # Spec: no Sentinel-onboarded workspaces with full visibility — Skipped.
            Write-PSFMessage 'No Sentinel-onboarded workspaces found — skipping Sentinel workbooks check.' -Tag Test -Level VeryVerbose
            Add-ZtTestResultDetail -SkippedBecause NotApplicable
            return
        }
        Add-ZtTestResultDetail @params
        return
    }

    # Q1 (spec): Enumerate Sentinel workbooks at subscription scope (category=sentinel) for each
    # unique subscription. Results are cached per subscription to minimise ARM round-trips.
    # Per-workspace filtering is applied below using properties.sourceId, which captures workbooks
    # deployed outside the workspace's own resource group (spec: Challenges).
    $workbooksBySubscription = @{}

    foreach ($workspace in $onboardedWorkspaces) {
        $subId = $workspace.SubscriptionId
        if ($workbooksBySubscription.ContainsKey($subId)) {
            continue
        }

        Write-ZtProgress -Activity $activity -Status "Fetching Sentinel workbooks for subscription '$($workspace.SubscriptionName)'"
        $workbooksPath = "/subscriptions/$subId/providers/Microsoft.Insights/workbooks?api-version=2023-06-01&category=sentinel"

        try {
            $workbooksBySubscription[$subId] = @(Invoke-ZtAzureRequest -Path $workbooksPath -ErrorAction Stop)
        }
        catch {
            $workbooksBySubscription[$subId] = $null
            Write-PSFMessage "Error querying workbooks for subscription '$($workspace.SubscriptionName)': $_" -Tag Test -Level Warning
        }
    }

    #endregion Data Collection

    #region Assessment Logic

    $workspaceResults = foreach ($workspace in $onboardedWorkspaces) {
        $rawWorkbooks = $workbooksBySubscription[$workspace.SubscriptionId]

        $workbookCount = 0
        $workbookNames = @()
        $rowStatus     = 'Fail'

        if ($null -eq $rawWorkbooks) {
            $rowStatus = 'Investigate'
        }
        else {
            # Filter to workbooks whose sourceId matches the workspace resource ID
            # (case-insensitive) per spec evaluation logic. The API already filters by
            # category=sentinel, so no additional category check is required here.
            $matchedWorkbooks = @($rawWorkbooks | Where-Object {
                $_.properties.sourceId -ieq $workspace.WorkspaceId
            })
            $workbookCount = $matchedWorkbooks.Count
            $workbookNames = @($matchedWorkbooks | ForEach-Object { $_.properties.displayName } | Where-Object { $_ })
            $rowStatus     = if ($workbookCount -ge 1) { 'Pass' } else { 'Fail' }
        }

        [PSCustomObject]@{
            SubscriptionName = $workspace.SubscriptionName
            SubscriptionId   = $workspace.SubscriptionId
            WorkspaceName    = $workspace.WorkspaceName
            ResourceGroup    = $workspace.ResourceGroup
            WorkspaceId      = $workspace.WorkspaceId
            WorkbookCount    = $workbookCount
            WorkbookNames    = $workbookNames
            RowStatus        = $rowStatus
        }
    }
    $workspaceResults = @($workspaceResults)

    $investigateItems = @($workspaceResults | Where-Object { $_.RowStatus -eq 'Investigate' })
    $failedItems      = @($workspaceResults | Where-Object { $_.RowStatus -eq 'Fail' })

    # Pass only when every onboarded workspace has at least one workbook (no failures, no investigate,
    # and no inaccessible workspaces whose onboarding state could not be confirmed).
    $passed       = $failedItems.Count -eq 0 -and $investigateItems.Count -eq 0 -and $forbiddenWorkspaces.Count -eq 0
    $customStatus = $null

    if ($investigateItems.Count -gt 0 -or $forbiddenWorkspaces.Count -gt 0) {
        $customStatus       = 'Investigate'
        $testResultMarkdown = "⚠️ Workbooks API returned an unexpected response for one or more workspaces, or one or more workspaces could not be checked due to insufficient permissions. Re-run after verifying access on each affected workspace.`n`n%TestResult%"
    }
    elseif ($passed) {
        $testResultMarkdown = "✅ Microsoft Sentinel workbooks are deployed for the workspace.`n`n%TestResult%"
    }
    else {
        $testResultMarkdown = "❌ No Microsoft Sentinel workbooks are deployed for the workspace.`n`n%TestResult%"
    }

    #endregion Assessment Logic

    #region Report Generation

    $azContext          = Get-AzContext -ErrorAction SilentlyContinue
    $portalHost         = if ($azContext -and $azContext.Environment.Name -eq 'AzureUSGovernment') { 'https://portal.azure.us' } else { 'https://portal.azure.com' }
    $portalSentinelLink = "$portalHost/#view/HubsExtension/BrowseResource/resourceType/microsoft.securityinsightsarg%2Fsentinel"
    $tableTitle         = 'Workbooks per Sentinel workspace'

    $formatTemplate = @'


## [{0}]({1})

| Subscription | Workspace | Workbooks deployed | Workbook names | Status |
| :----------- | :-------- | :------------------ | :------------- | :----- |
{2}
'@

    $tableRows      = ''
    $maxDisplay     = 10
    $statusPriority = @{ Fail = 0; Investigate = 1; Pass = 2 }
    $displayResults = @($workspaceResults | Sort-Object { $statusPriority[$_.RowStatus] }, SubscriptionName, WorkspaceName)
    $hasMoreItems   = $false
    if ($workspaceResults.Count -gt $maxDisplay) {
        $displayResults = @($displayResults | Select-Object -First $maxDisplay)
        $hasMoreItems   = $true
    }

    foreach ($result in $displayResults) {
        $subLink       = "$portalHost/#resource/subscriptions/$($result.SubscriptionId)"
        $sentinelId    = "/subscriptions/$($result.SubscriptionId)/resourcegroups/$($result.ResourceGroup)/providers/microsoft.securityinsightsarg/sentinel/$($result.WorkspaceName)"
        $workbooksLink = "$portalHost/#view/Microsoft_Azure_Security_Insights/MainMenuBlade/~/Workbooks/id/$($sentinelId -replace '/', '%2F')"
        $subMd         = "[$(Get-SafeMarkdown $result.SubscriptionName)]($subLink)"
        $workspaceMd   = "[$(Get-SafeMarkdown $result.WorkspaceName)]($workbooksLink)"
        $namesMd       = if ($result.WorkbookNames.Count -gt 0) {
            ($result.WorkbookNames | ForEach-Object { Get-SafeMarkdown $_ }) -join ', '
        } else { '—' }
        $statusDisplay = switch ($result.RowStatus) {
            'Pass'        { '✅ Pass' }
            'Fail'        { '❌ Fail' }
            'Investigate' { '⚠️ Investigate' }
        }
        $tableRows += "| $subMd | $workspaceMd | $($result.WorkbookCount) | $namesMd | $statusDisplay |`n"
    }

    if ($hasMoreItems) {
        $remainingCount = $workspaceResults.Count - $maxDisplay
        $tableRows += "`n... and $remainingCount more. [View all in Microsoft Sentinel]($portalSentinelLink)`n"
    }

    $mdInfo             = $formatTemplate -f $tableTitle, $portalSentinelLink, $tableRows
    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo

    #endregion Report Generation

    $params = @{
        TestId = '41206'
        Title  = 'At least one workbook is deployed in every Microsoft Sentinel workspace for visualization and operational reporting'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($customStatus) {
        $params.CustomStatus = $customStatus
    }

    Add-ZtTestResultDetail @params
}
