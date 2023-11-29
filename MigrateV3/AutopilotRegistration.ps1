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

$localPath = $settings.localPath

$log = "$($localPath)\autopilotRegistration.log"
Start-Transcript -Path $log -Verbose
Write-Host "BEGIN LOGGING AUTOPILOT REGISTRATION..."
# Install for NUGET
Install-PackageProvider -Name NuGet -Confirm:$false -Force

# Install and import required modules
$requiredModules = @(
    'Microsoft.Graph.Intune'
    'WindowsAutopilotIntune'
)

foreach($module in $requiredModules)
{
    Install-Module -Name $module -AllowClobber -Force
}

foreach($module in $requiredModules)
{
    Import-Module $module
}

# Tenant B App reg

<#PERMISSIONS NEEDED:
Device.ReadWrite.All
DeviceManagementApps.ReadWrite.All
DeviceManagementConfiguration.ReadWrite.All
DeviceManagementManagedDevices.PrivilegedOperations.All
DeviceManagementManagedDevices.ReadWrite.All
DeviceManagementServiceConfig.ReadWrite.All
#>

$clientId = $settings.targetTenant.clientID
$clientSecret = $settings.targetTenant.clientSecret
$clientSecureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$clientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientId, $clientSecureSecret
$tenantId = $settings.targetTenant.tenantID

# Authenticate to graph and add Autopilot device
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $clientSecretCredential

# Get Autopilot device info
$hwid = ((Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData)

$ser = (Get-WmiObject win32_bios).SerialNumber
if([string]::IsNullOrWhiteSpace($ser)) { $ser = $env:COMPUTERNAME}

# Retrieve group tag info
$regPath = $settings.regPath
$key = "Registry::$regPath"
$tag = Get-ItemPropertyValue -Path $key -Name GroupTag

Add-AutopilotImportedDevice -serialNumber $ser -hardwareIdentifier $hwid -groupTag $tag
Start-Sleep -Seconds 5

#now delete scheduled task
Disable-ScheduledTask -TaskName "AutopilotRegistration"
Write-Host "Disabled AutopilotRegistration scheduled task"

Write-Host "END LOGGING FOR AUTOPILOT REGISTRATION..."
Stop-Transcript
