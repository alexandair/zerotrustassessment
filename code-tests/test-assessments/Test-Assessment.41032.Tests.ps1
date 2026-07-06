Describe "Test-Assessment-41032" {
    BeforeAll {
        $here = $PSScriptRoot
        $srcRoot = Join-Path $here "../../src/powershell"

        # global:-stub every module-provided command the SUT calls so the test also runs
        # standalone (harness debug tree) where the ZeroTrustAssessment module is not imported.
        if (-not (Get-Command Write-PSFMessage -ErrorAction SilentlyContinue)) {
            function global:Write-PSFMessage {}
        }
        if (-not (Get-Command Write-ZtProgress -ErrorAction SilentlyContinue)) {
            function global:Write-ZtProgress {}
        }
        if (-not (Get-Command Get-SafeLinksPolicy -ErrorAction SilentlyContinue)) {
            function global:Get-SafeLinksPolicy { param([switch]$ErrorAction) }
        }
        if (-not (Get-Command Get-SafeLinksRule -ErrorAction SilentlyContinue)) {
            function global:Get-SafeLinksRule { param([switch]$ErrorAction) }
        }
        # Add-ZtTestResultDetail needs a faithful param block: Should -Invoke -ParameterFilter can
        # only bind named args if the mocked command exposes those parameters.
        if (-not (Get-Command Add-ZtTestResultDetail -ErrorAction SilentlyContinue)) {
            function global:Add-ZtTestResultDetail {
                param(
                    [string]   $Description, [bool]     $Status,    [string]   $Result,
                    [Object[]] $GraphObjects,[string]   $GraphObjectType,
                    [string]   $TestId,      [string]   $Title,     [string]   $SkippedBecause,
                    [string]   $UserImpact,  [string]   $Risk,      [string]   $ImplementationCost,
                    [string[]] $AppliesTo,   [string[]] $Tag,       [string]   $CustomStatus,
                    [string[]] $NotConnectedService,    [string]   $Pillar,    [string]   $Category
                )
            }
        }
        if (-not (Get-Command Get-SafeMarkdown -ErrorAction SilentlyContinue)) {
            function global:Get-SafeMarkdown { param($Text) return $Text }
        }

        $classPath = Join-Path $srcRoot "classes/ZtTest.ps1"
        if (-not ("ZtTest" -as [type])) { . $classPath }

        . (Join-Path $srcRoot "tests/Test-Assessment.41032.ps1")

        $script:outputFile = Join-Path $here "../TestResults/Report-Test-Assessment.41032.md"
        $outputDir = Split-Path $script:outputFile
        if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
        "# Test Results for 41032`n" | Set-Content $script:outputFile

        # A policy that fully meets the Standard/Strict baseline.
        function global:New-CompliantPolicy {
            param($Identity, [bool]$BuiltIn = $false)
            [PSCustomObject]@{
                Identity                 = $Identity
                IsBuiltInProtection      = $BuiltIn
                IsDefault                = $false
                EnableSafeLinksForEmail  = $true
                EnableSafeLinksForTeams  = $true
                EnableSafeLinksForOffice = $true
                ScanUrls                 = $true
                EnableForInternalSenders = $true
                DeliverMessageAfterScan  = $true
                DisableUrlRewrite        = $false
                AllowClickThrough        = $false
                TrackClicks              = $true
            }
        }

        # The Built-in Protection policy: intentionally weaker on three properties.
        $script:builtInPolicy = [PSCustomObject]@{
            Identity                 = 'Built-In Protection Policy'
            IsBuiltInProtection      = $true
            IsDefault                = $false
            EnableSafeLinksForEmail  = $true
            EnableSafeLinksForTeams  = $true
            EnableSafeLinksForOffice = $true
            ScanUrls                 = $true
            EnableForInternalSenders = $false
            DeliverMessageAfterScan  = $true
            DisableUrlRewrite        = $true
            AllowClickThrough        = $true
            TrackClicks              = $true
        }
    }

    BeforeEach {
        Mock Write-PSFMessage {}
        Mock Write-ZtProgress {}
        Mock Get-SafeMarkdown { param($Text) return $Text }
    }

    Context "When an enabled rule references a fully compliant policy" {
        It "Should pass" {
            Mock Get-SafeLinksPolicy {
                @(
                    $script:builtInPolicy,
                    (New-CompliantPolicy -Identity 'Strict Preset Policy')
                )
            }
            Mock Get-SafeLinksRule {
                @([PSCustomObject]@{ Name = 'Strict Preset Rule'; SafeLinksPolicy = 'Strict Preset Policy'; State = 'Enabled' })
            }

            $script:capturedStatus = $null
            $script:capturedResult = $null
            $script:capturedCustom = 'unset'
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus)
                $script:capturedStatus = $Status
                $script:capturedResult = $Result
                $script:capturedCustom = $CustomStatus
                "## Scenario: Compliant enabled policy`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-41032

            $script:capturedStatus | Should -Be $true
            $script:capturedCustom | Should -Be $null
            $script:capturedResult | Should -Match ([regex]::Escape('✅ Every Safe Links policy in use'))
            $script:capturedResult | Should -Match 'Strict Preset Policy'
        }
    }

    Context "When no Safe Links rule is enabled (Built-in Protection only)" {
        It "Should fail" {
            Mock Get-SafeLinksPolicy { @($script:builtInPolicy) }
            Mock Get-SafeLinksRule { @() }

            $script:capturedStatus = $null
            $script:capturedResult = $null
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus)
                $script:capturedStatus = $Status
                $script:capturedResult = $Result
                "## Scenario: Built-in only`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-41032

            $script:capturedStatus | Should -Be $false
            $script:capturedResult | Should -Match ([regex]::Escape('❌ Either no custom or preset Safe Links rule is enabled'))
        }
    }

    Context "When an enabled rule references a non-compliant policy" {
        It "Should fail and list the divergent settings" {
            $nonCompliant = New-CompliantPolicy -Identity 'Custom Weak Policy'
            $nonCompliant.AllowClickThrough = $true
            $nonCompliant.EnableForInternalSenders = $false

            Mock Get-SafeLinksPolicy { @($script:builtInPolicy, $nonCompliant) }
            Mock Get-SafeLinksRule {
                @([PSCustomObject]@{ Name = 'Custom Rule'; SafeLinksPolicy = 'Custom Weak Policy'; State = 'Enabled' })
            }

            $script:capturedStatus = $null
            $script:capturedResult = $null
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus)
                $script:capturedStatus = $Status
                $script:capturedResult = $Result
                "## Scenario: Non-compliant enabled policy`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-41032

            $script:capturedStatus | Should -Be $false
            $script:capturedResult | Should -Match 'AllowClickThrough=True'
            $script:capturedResult | Should -Match 'EnableForInternalSenders=False'
        }
    }

    Context "When an enabled rule references a policy that does not exist" {
        It "Should return Investigate" {
            Mock Get-SafeLinksPolicy {
                @($script:builtInPolicy, (New-CompliantPolicy -Identity 'Good Policy'))
            }
            Mock Get-SafeLinksRule {
                @([PSCustomObject]@{ Name = 'Orphan Rule'; SafeLinksPolicy = 'Deleted Policy'; State = 'Enabled' })
            }

            $script:capturedStatus = $null
            $script:capturedCustom = $null
            $script:capturedResult = $null
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus)
                $script:capturedStatus = $Status
                $script:capturedCustom = $CustomStatus
                $script:capturedResult = $Result
                "## Scenario: Orphan rule`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-41032

            $script:capturedStatus | Should -Be $false
            $script:capturedCustom | Should -Be 'Investigate'
            $script:capturedResult | Should -Match ([regex]::Escape('⚠️ An enabled Safe Links rule references a policy that does not exist'))
        }
    }

    Context "When Get-SafeLinksPolicy throws" {
        It "Should return Investigate" {
            Mock Get-SafeLinksPolicy { throw 'Access denied' }
            Mock Get-SafeLinksRule { @() }

            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus)
                "## Scenario: Policy query throws`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-41032

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $false -and $CustomStatus -eq 'Investigate'
            }
        }
    }

    Context "When Get-SafeLinksPolicy returns no rows" {
        It "Should return Investigate" {
            Mock Get-SafeLinksPolicy { @() }
            Mock Get-SafeLinksRule { @() }

            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus)
                "## Scenario: Zero policies`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-41032

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $false -and $CustomStatus -eq 'Investigate'
            }
        }
    }

    Context "When Get-SafeLinksRule throws after policies succeed" {
        It "Should return Investigate" {
            Mock Get-SafeLinksPolicy { @($script:builtInPolicy) }
            Mock Get-SafeLinksRule { throw 'Access denied' }

            $script:capturedResult = $null
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result, $CustomStatus)
                $script:capturedResult = $Result
                "## Scenario: Rule query throws`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-41032

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $false -and $CustomStatus -eq 'Investigate'
            }
            $script:capturedResult | Should -Match 'associated rules could not be read'
        }
    }
}
