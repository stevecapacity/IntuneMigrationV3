# Start and append post-migration log file
# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64")
{
    if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe")
    {
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"
        Exit $lastexitcode
    }
}

$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json
$hostname = $env:COMPUTERNAME

$localPath = $settings.localPath

$log = "$($localPath)\groupTag.log"
Start-Transcript -Path $log -Verbose
Write-Host "BEGIN LOGGING GROUP TAG..."

# Add Group Tag from Autopilot device in Tenant A to Azure AD object in Tenant B

# App reg info for tenant B
$clientId = $settings.targetTenant.clientID
$clientSecret = $settings.targetTenant.clientSecret
$tenant = $settings.targetTenant.tenantName

# Authenticate to graph
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/x-www-form-urlencoded")

$body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
$body += -join("&client_id=" , $clientId, "&client_secret=", $clientSecret)

$response = Invoke-RestMethod "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body

#Get Token form OAuth.
$token = -join("Bearer ", $response.access_token)

#Reinstantiate headers.
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", $token)
$headers.Add("Content-Type", "application/json")
Write-Host "MS Graph Authenticated"

#==============================================================================#

# Get tag and device info
Write-Host "Retrieving info from registry..."

$regPath = $settings.regPath
$key = "Registry::$regPath"

$oldTag = Get-ItemPropertyValue -Path $key -Name GroupTag
Write-Host "Group Tag is $($oldTag)"

$serialNumber = Get-WmiObject -Class Win32_Bios | Select-Object -ExpandProperty serialNumber

# Get graph info
Write-Host "Getting information from Microsoft Graph.  Looking for Azure device ID..."

try 
{
    $intuneObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers
    Write-Host "$($hostname) Intune object found."
    $aadDeviceId = $intuneObject.value.azureADDeviceId
    Write-Host "Azure device ID is $($aadDeviceId)"
}
catch 
{
    Write-Host "Could not retrieve AAD device ID for $($hostname)"
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
}


Write-Host "Getting Azure AD object..."

try
{
    $aadObject = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/devices?`$filter=deviceId eq '$($aadDeviceId)'" -Headers $headers
    $aadObjectId = $aadObject.value.id
    Write-Host "Azure AD object ID is $($aadObjectId)"
}
catch
{
    Write-Host "Could not retrieve AAD object ID for $($hostname)"
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
}

# Place group tag in correct format and add to existing physical IDs

$physicalIds = $aadObject.value.physicalIds
$groupTag = "[OrderID]:$($oldTag)"
$physicalIds += $groupTag

# Construct JSON body for graph post

$body = @{
	physicalIds = $physicalIds
} | ConvertTo-Json

# PATCH to graph
Write-Host "Adding Group Tag $($oldTag) to $($hostname) in $($tenant)..."
try 
{
    Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/devices/$($aadObjectId)" -Method Patch -Headers $headers -Body $body
    Start-Sleep -Seconds 2
    Write-Host "Successfully added Group Tag $($oldTag) to $($hostname) in $($tenant)"
}
catch 
{
    Write-Host "Could not add $($oldTag) to $($hostname)"
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
}


# Disable Task
Disable-ScheduledTask -TaskName "GroupTag"
Write-Host "Disabled GroupTag scheduled task"

Write-Host "END LOGGING FOR GROUPTAG..."
Stop-Transcript
