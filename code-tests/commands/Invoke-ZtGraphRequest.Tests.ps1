Describe 'Invoke-ZtGraphRequest POST support' {
	BeforeAll {
		$srcRoot = Join-Path $PSScriptRoot '../../src/powershell'

		function global:Write-PSFMessage { param($Message, $Level, $Tag) }
		function global:Get-ObjectProperty {
			param($InputObjects, $Property)
			$InputObjects.PSObject.Properties[$Property].Value
		}
		function global:ConvertTo-QueryString { param($InputObject) return $null }
		function global:ConvertFrom-QueryString { param($InputStrings, $AsHashtable) return @{} }
		function global:Get-MgContext { throw 'Graph context should not be resolved for validation failures.' }
		function global:Get-MgEnvironment { param($Name) throw 'Graph environment should not be resolved for validation failures.' }

		. (Join-Path $srcRoot 'public/Invoke-ZtGraphRequest.ps1')
	}

	BeforeEach {
		$script:requests = [System.Collections.Generic.List[hashtable]]::new()
		Mock Invoke-ZtGraphRequestCache {
			param($Method, $Uri, $Headers, $Body, $OutputType, $DisableCache, $OutputFilePath, $PageIndex)
			$script:requests.Add(@{
				Method = $Method
				Uri = $Uri
				Headers = $Headers
				Body = $Body
				PageIndex = $PageIndex
			})
			[pscustomobject]@{ result = 'success' }
		}
	}

	It 'forwards a valid POST body and adds the JSON content type' {
		$body = '{"Query":"DeviceProcessEvents | limit 2"}'
		$result = Invoke-ZtGraphRequest -RelativeUri 'security/runHuntingQuery' -Method POST -Body $body -GraphBaseUri 'https://graph.microsoft.com/'

		$result.result | Should -Be 'success'
		$script:requests | Should -HaveCount 1
		$script:requests[0].Method | Should -Be 'POST'
		$script:requests[0].Body | Should -Be $body
		$script:requests[0].Headers['Content-Type'] | Should -Be 'application/json'
	}

	It 'preserves a caller supplied content type for POST' {
		Invoke-ZtGraphRequest -RelativeUri 'security/runHuntingQuery' -Method POST -Body '{}' -Headers @{ 'Content-Type' = 'application/json; charset=utf-8' } -GraphBaseUri 'https://graph.microsoft.com/' | Out-Null

		$script:requests[0].Headers['Content-Type'] | Should -Be 'application/json; charset=utf-8'
	}

	It 'rejects a missing POST body before resolving Graph context' {
		{ Invoke-ZtGraphRequest -RelativeUri 'security/runHuntingQuery' -Method POST } | Should -Throw '*-Body is required*'
	}

	It 'rejects a non-object POST body before resolving Graph context' {
		{ Invoke-ZtGraphRequest -RelativeUri 'security/runHuntingQuery' -Method POST -Body '[]' } | Should -Throw '*JSON object*'
	}

	It 'rejects a body with GET before resolving Graph context' {
		{ Invoke-ZtGraphRequest -RelativeUri 'users' -Body '{}' } | Should -Throw '*only supported when -Method POST*'
	}

	It 'rejects POST-only incompatible parameters' {
		{ Invoke-ZtGraphRequest -RelativeUri 'security/runHuntingQuery' -Method POST -Body '{}' -DisableBatching } | Should -Throw '*DisableBatching*'
		{ Invoke-ZtGraphRequest -RelativeUri 'security/runHuntingQuery' -Method POST -Body '{}' -Select 'id' } | Should -Throw '*Select*'
		{ Invoke-ZtGraphRequest -RelativeUri 'security/runHuntingQuery' -Method POST -Body '{}' -Filter 'id ne null' } | Should -Throw '*Filter*'
		{ Invoke-ZtGraphRequest -RelativeUri 'security/runHuntingQuery' -Method POST -Body '{}' -Top 1 } | Should -Throw '*Top*'
	}

	It 'rejects multiple POST pipeline endpoints without issuing a request' {
		{ @('security/runHuntingQuery', 'directoryObjects/getByIds') | Invoke-ZtGraphRequest -Method POST -Body '{}' -GraphBaseUri 'https://graph.microsoft.com/' } | Should -Throw '*exactly one resolved endpoint*'
		Should -Invoke Invoke-ZtGraphRequestCache -Times 0 -Exactly
	}

	It 'uses GET without a body for a POST continuation link' {
		$script:callNumber = 0
		Mock Invoke-ZtGraphRequestCache {
			param($Method, $Uri, $Headers, $Body, $OutputType, $DisableCache, $OutputFilePath, $PageIndex)
			$script:requests.Add(@{ Method = $Method; Uri = $Uri; Body = $Body; PageIndex = $PageIndex })
			$script:callNumber++
			if ($script:callNumber -eq 1) {
				return [pscustomobject]@{ '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/security/runHuntingQuery?page=2'; result = 'first' }
			}
			return [pscustomobject]@{ result = 'second' }
		}

		$result = Invoke-ZtGraphRequest -RelativeUri 'security/runHuntingQuery' -Method POST -Body '{}' -GraphBaseUri 'https://graph.microsoft.com/'

		$result.result | Should -Be @('first', 'second')
		$script:requests | Should -HaveCount 2
		$script:requests[0].Method | Should -Be 'POST'
		$script:requests[0].Body | Should -Be '{}'
		$script:requests[1].Method | Should -Be 'GET'
		$script:requests[1].Body | Should -BeNullOrEmpty
		$script:requests[1].PageIndex | Should -Be 1
	}

	It 'uses the session-resolved Graph endpoint for GET batch requests' {
		$script:__ZtSession = [pscustomobject]@{ GraphBaseUri = $null }
		Mock Get-MgContext { [pscustomobject]@{ Environment = 'Global' } }
		Mock Get-MgEnvironment { [pscustomobject]@{ GraphEndpoint = 'https://graph.microsoft.com/' } }
		Mock Invoke-ZtGraphRequestCache {
			param($Method, $Uri, $Body)
			$script:requests.Add(@{ Method = $Method; Uri = $Uri; Body = $Body })
			[pscustomobject]@{ responses = @() }
		}

		Invoke-ZtGraphRequest -RelativeUri @('users', 'groups') | Out-Null

		$script:requests | Should -HaveCount 1
		$script:requests[0].Method | Should -Be 'POST'
		$script:requests[0].Uri.AbsoluteUri | Should -Be 'https://graph.microsoft.com/v1.0/$batch'
		Should -Invoke Get-MgContext -Times 1 -Exactly
		Should -Invoke Get-MgEnvironment -Times 1 -Exactly
	}
}

Describe 'Invoke-ZtGraphRequestCache non-GET output handling' {
	BeforeAll {
		$srcRoot = Join-Path $PSScriptRoot '../../src/powershell'

		function global:Write-PSFMessage { param($Message, $Level, $Tag) }
		function global:Get-PSFConfigValue { param($FullName) return $false }
		function global:Invoke-ZtRetry { param($ScriptBlock) & $ScriptBlock }
		function global:Get-ExportJsonFilePath { param($Path, $PageIndex) return (Join-Path $TestDrive 'post-response.json') }
		function global:Set-PSFFileContent { param($Path, $InputObject) }

		. (Join-Path $srcRoot 'private/core/Invoke-ZtGraphRequestCache.ps1')
	}

	BeforeEach {
		$script:__ZtSession = [pscustomobject]@{ GraphCache = [pscustomobject]@{ Value = @{} } }
		$script:__ZtThrottling = [pscustomobject]@{ Value = @{} }
		Mock Invoke-MgGraphRequest { '{"result":"success"}' }
		Mock Set-PSFFileContent {}
		Mock New-Item { [pscustomobject]@{ FullName = $Path } }
	}

	It 'does not read or write cache entries for POST' {
		$uri = [uri]'https://graph.microsoft.com/v1.0/security/runHuntingQuery'
		$script:__ZtSession.GraphCache.Value[$uri.AbsoluteUri] = [pscustomobject]@{ result = 'cached' }

		$result = Invoke-ZtGraphRequestCache -Uri $uri -Method POST -Body '{}' -OutputType PSObject

		$result | Should -Be '{"result":"success"}'
		Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' -and $Body -eq '{}' }
		$script:__ZtSession.GraphCache.Value[$uri.AbsoluteUri].result | Should -Be 'cached'
	}

	It 'writes and returns a parsed POST response when OutputFilePath is specified' {
		$result = Invoke-ZtGraphRequestCache -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Method POST -Body '{}' -OutputFilePath 'response.json'

		$result.result | Should -Be 'success'
		Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' -and $OutputType -eq 'Json' }
		Should -Invoke Set-PSFFileContent -Times 1 -Exactly
	}
}
