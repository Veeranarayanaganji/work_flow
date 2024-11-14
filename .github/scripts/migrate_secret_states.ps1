param (
    [string]$sourceOrg,  # Source organization name
    [string]$sourceRepo,  # Source repository name
    [string]$targetOrg,  # Target organization name
    [string]$targetRepo,  # Target repository name
    [string]$sourceToken,  # Source PAT token
    [string]$targetToken   # Target PAT token
)

# Function to check if secret scanning is enabled in the target repository
function Is-SecretScanningEnabled($token, $org, $repo) {
    $headers = @{
        Authorization = "token $token"
        Accept        = "application/vnd.github.v3+json"
    }

    $url = "https://api.github.com/repos/$org/$repo"
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        # Check if the security_and_analysis and secret_scanning properties exist
        if ($response.PSObject.Properties["security_and_analysis"] -and 
            $response.security_and_analysis.PSObject.Properties["secret_scanning"] -and 
            $response.security_and_analysis.secret_scanning.status -eq "enabled") {
            return $true
        } else {
            return $false
        }
    } catch {
        Write-Host ("Error checking if secret scanning is enabled: " + $_.Exception.Message)
        return $false
    }
}

# Function to get secret scanning alerts from a repository
function Get-SecretScanningAlerts($token, $org, $repo) {
    $headers = @{
        Authorization = "token $token"
        Accept        = "application/vnd.github.v3+json"
    }

    $url = "https://api.github.com/repos/$org/$repo/secret-scanning/alerts"
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        return $response
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Host ("Error fetching secret scanning alerts: " + $errorMessage)
        return $null
    }
}

# Function to check if a specific secret exists in the target repository alerts
function SecretExistsInTarget($sourceSecret, $targetAlerts) {
    $matchingAlert = $targetAlerts | Where-Object { $_.secret -eq $sourceSecret }
    if ($matchingAlert) {
        return $matchingAlert
    }
    return $null
}

# Function to update secret scanning alerts in the target repository
function Update-SecretScanningAlert($token, $org, $repo, $alertNumber, $newState) {
    $headers = @{
        Authorization = "token $token"
        Accept        = "application/vnd.github.v3+json"
    }

    if ($newState -eq "resolved") {
        $body = @{
            state = $newState
            resolution = "revoked"  # Add a default resolution
        } | ConvertTo-Json
    } else {
        $body = @{
            state = $newState
        } | ConvertTo-Json
    }

    $url = "https://api.github.com/repos/$org/$repo/secret-scanning/alerts/$alertNumber"

    try {
        Invoke-RestMethod -Uri $url -Headers $headers -Method Patch -Body $body
        Write-Host ("Alert #" + $alertNumber + " updated to state '" + $newState + "'.")
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Host ("Error updating alert #" + $alertNumber + ": " + $errorMessage)
    }
}

# Function to handle the migration of secret scanning remediation states
function Migrate-SecretScanningRemediationStates {
    param (
        [string]$sourceToken,
        [string]$targetToken,
        [string]$sourceOrg,
        [string]$sourceRepo,
        [string]$targetOrg,
        [string]$targetRepo
    )

    Write-Host ("Checking if secret scanning is enabled in the target repository ($targetOrg/$targetRepo)...")
    $isSecretScanningEnabled = Is-SecretScanningEnabled -token $targetToken -org $targetOrg -repo $targetRepo

    if (-not $isSecretScanningEnabled) {
        Write-Host "Secret scanning is not enabled in the target repository. Please enable it before migrating secrets."
        exit 1
    }

    Write-Host ("Fetching secret scanning alerts from source repository ($sourceOrg/$sourceRepo)...")
    $sourceAlerts = Get-SecretScanningAlerts -token $sourceToken -org $sourceOrg -repo $sourceRepo

    if ($sourceAlerts -eq $null -or $sourceAlerts.Count -eq 0) {
        Write-Host "No secret scanning alerts found in the source repository. Nothing to migrate."
        return
    }

    Write-Host ($sourceAlerts.Count.ToString() + " secret scanning alert(s) found in the source repository.")

    Write-Host ("Fetching secret scanning alerts from target repository ($targetOrg/$targetRepo)...")
    $targetAlerts = Get-SecretScanningAlerts -token $targetToken -org $targetOrg -repo $targetRepo

    # Loop through each alert and check if it exists in the target repository
    foreach ($alert in $sourceAlerts) {
        $alertNumber = $alert.number
        $alertState = $alert.state
        $alertSecret = $alert.secret

        $targetAlert = SecretExistsInTarget -sourceSecret $alertSecret -targetAlerts $targetAlerts

        if ($targetAlert -eq $null) {
            Write-Host ("Secret not found in target repository for alert #" + $alertNumber + ". GitHub needs to detect it. Consider triggering a re-scan.")
            continue
        } else {
            Write-Host ("Migrating secret alert #" + $targetAlert.number + " with state '" + $alertState + "'...")
            Update-SecretScanningAlert -token $targetToken -org $targetOrg -repo $targetRepo -alertNumber $targetAlert.number -newState $alertState
        }
    }

    Write-Host "Secret scanning remediation states migrated successfully."
}

# Print inputs for logging
Write-Host ("Source Organization: " + $sourceOrg)
Write-Host ("Source Repository: " + $sourceRepo)
Write-Host ("Target Organization: " + $targetOrg)
Write-Host ("Target Repository: " + $targetRepo)

# Call the migration function
Migrate-SecretScanningRemediationStates -sourceToken $sourceToken -targetToken $targetToken -sourceOrg $sourceOrg -sourceRepo $sourceRepo -targetOrg $targetOrg -targetRepo $targetRepo