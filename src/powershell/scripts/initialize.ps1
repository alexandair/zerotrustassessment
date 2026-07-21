# General Startup code

#region Configure In-Memory Log
$minSize = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Logging.InMemoryLog.MinSize' -Fallback 51200
$actualSize = Get-PSFConfigValue -FullName 'PSFramework.Logging.MaxMessageCount'
if ($actualSize -lt $minSize) {
	Set-PSFConfig -FullName 'PSFramework.Logging.MaxMessageCount' -Value $minSize
}
#endregion Configure In-Memory Log

#region Argument Transformers
<#
Override the default conversion by having plain numeric values be considered minutes, rather than seconds (int) or days (string).
Used for the TestTimeout parameter on Invoke-ZtaAssessment and applied to the "ZeroTrustAssessment.Tests.Timeout" config setting.
#>
Register-PSFArgumentTransformationScriptblock -Name 'ZeroTrustAssessment.TimeSpanParameter' -Scriptblock {
	if ($_ -as [int]) { return [PsfTimeSpan][timespan]::new(0,$_,0) }
	[PsfTimeSpan]$_
}
#endregion Argument Transformers
