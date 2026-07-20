function Protect-ZtReportText {
	<#
	.SYNOPSIS
		Removes common HTTP credentials from report content.

	.DESCRIPTION
		Redacts credential-bearing HTTP headers and bearer/basic authorization
		values before text is persisted in assessment artifacts. This is a
		defense-in-depth control; callers should not serialize arbitrary request
		or response objects into report content.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param (
		[AllowNull()]
		[string]
		$Text
	)
	process {
		if ($null -eq $Text) {
			return $null
		}

		$credentialHeaderPattern = '(?im)(\b(?:proxy-)?authorization|\bcookie|\bset-cookie|\bx-api-key|\bapi-key|\bocp-apim-subscription-key)\s*[:=]\s*[^\r\n,;}\]]+'
		$sanitizedText = [regex]::Replace($Text, $credentialHeaderPattern, '$1: <redacted>')
		$bearerPattern = '(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*'

		return [regex]::Replace($sanitizedText, $bearerPattern, 'Bearer <redacted>')
	}
}
