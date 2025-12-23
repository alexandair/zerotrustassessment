<#
.SYNOPSIS
   Helper method to disconnect from Microsoft Graph, Azure, and Security & Compliance Center.

.DESCRIPTION
   Use this cmdlet to disconnect from Microsoft Graph, Azure, and Security & Compliance Center services.

   This command will disconnect from:
   - Microsoft Graph (using Disconnect-MgGraph)
   - Azure (using Disconnect-AzAccount)
   - Security & Compliance Center (using Disconnect-ExchangeOnline)

.EXAMPLE
   Disconnect-ZtAssessment

   Disconnects from Microsoft Graph, Azure, and Security & Compliance Center.

#>

function Disconnect-ZtAssessment
{
    [CmdletBinding()]
    param()

    Write-Host "`nDisconnecting from Microsoft Graph" -ForegroundColor Yellow
    Write-PSFMessage 'Disconnecting from Microsoft Graph'
    try
    {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Successfully disconnected from Microsoft Graph" -ForegroundColor Green
    }
    catch [Management.Automation.CommandNotFoundException]
    {
        Write-PSFMessage "The Graph PowerShell module is not installed or Disconnect-MgGraph is not available." -Level Warning
    }
    catch
    {
        Write-PSFMessage "Error disconnecting from Microsoft Graph: $($_.Exception.Message)" -Level Warning
    }

    Write-Host "`nDisconnecting from Azure" -ForegroundColor Yellow
    Write-PSFMessage 'Disconnecting from Azure'
    try
    {
        Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Successfully disconnected from Azure" -ForegroundColor Green
    }
    catch [Management.Automation.CommandNotFoundException]
    {
        Write-PSFMessage "The Azure PowerShell module is not installed or Disconnect-AzAccount is not available." -Level Warning
    }
    catch
    {
        Write-PSFMessage "Error disconnecting from Azure: $($_.Exception.Message)" -Level Warning
    }

    Write-Host "`nDisconnecting from Security & Compliance Center" -ForegroundColor Yellow
    Write-PSFMessage 'Disconnecting from Security & Compliance Center'
    try
    {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Successfully disconnected from Security & Compliance Center" -ForegroundColor Green
    }
    catch [Management.Automation.CommandNotFoundException]
    {
        Write-PSFMessage "The ExchangeOnlineManagement module is not installed or Disconnect-ExchangeOnline is not available." -Level Warning
    }
    catch
    {
        Write-PSFMessage "Error disconnecting from Security & Compliance Center: $($_.Exception.Message)" -Level Warning
    }

    Write-Host "`nDisconnection complete" -ForegroundColor Green
}
