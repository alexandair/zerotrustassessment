# This script is executed before the module is imported.
# Its purpose is to enforce a specific load order for dependencies to avoid DLL conflicts.
# Specifically, ExchangeOnlineManagement and Az.Accounts/Graph both use Microsoft.Identity.Client.dll.
# We must ensure Exchange's version (or a compatible one) is loaded first.

Write-Host "Pre-loading dependencies to ensure correct assembly load order..." -ForegroundColor Cyan

try {
    # 1. Locate and Load MSAL from ExchangeOnlineManagement (Priority #1)
    # We target the netCore version since we are running in pwsh (Core).
    $exoModule = Get-Module -ListAvailable ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
    if ($exoModule) {
        $msalPath = Join-Path $exoModule.ModuleBase "netCore\Microsoft.Identity.Client.dll"
        if (Test-Path $msalPath) {
            Write-Verbose "Explicitly loading MSAL assembly from: $msalPath"
            try {
                [System.Reflection.Assembly]::LoadFrom($msalPath) | Out-Null
                Write-Host "Successfully loaded MSAL from ExchangeOnlineManagement." -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to load MSAL assembly from $msalPath. Error: $_"
            }
        } else {
            Write-Warning "Could not find Microsoft.Identity.Client.dll at $msalPath"
        }

        # 1b. Load MSAL Broker (Required for WithBroker method)
        $brokerPath = Join-Path $exoModule.ModuleBase "netCore\Microsoft.Identity.Client.Broker.dll"
        if (Test-Path $brokerPath) {
            Write-Verbose "Explicitly loading MSAL Broker assembly from: $brokerPath"
            try {
                [System.Reflection.Assembly]::LoadFrom($brokerPath) | Out-Null
                Write-Host "Successfully loaded MSAL Broker from ExchangeOnlineManagement." -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to load MSAL Broker assembly from $brokerPath. Error: $_"
            }
        }
    }

    # 2. Import Exchange Online (Must be first module)
    if (-not (Get-Module -Name ExchangeOnlineManagement)) {
        Write-Verbose "Importing ExchangeOnlineManagement..."
        Import-Module ExchangeOnlineManagement -MinimumVersion 3.8.0 -ErrorAction Stop
    }

    # 3. Import Az.Accounts (After Exchange)
    if (-not (Get-Module -Name Az.Accounts)) {
        Write-Verbose "Importing Az.Accounts..."
        Import-Module Az.Accounts -ErrorAction Stop
    }

    # 4. Import Graph Authentication (After Exchange)
    # We load this here to ensure it doesn't try to load its own MSAL first if accessed later.
    if (-not (Get-Module -Name Microsoft.Graph.Authentication)) {
        Write-Verbose "Importing Microsoft.Graph.Authentication..."
        Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.32.0 -ErrorAction Stop
    }
}
catch {
    Write-Warning "Failed to pre-load dependencies. This may cause connection errors. Error: $_"
    throw $_
}
