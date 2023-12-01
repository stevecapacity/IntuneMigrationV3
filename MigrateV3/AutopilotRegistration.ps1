# Start and append post-migration log file
# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process


$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json
$hostname = $env:COMPUTERNAME


$localPath = $settings.localPath

$log = "$($localPath)\autopilotRegistration.log"
Start-Transcript -Path $log -Verbose
Write-Host "BEGIN LOGGING AUTOPILOT REGISTRATION..."
# Install for NUGET
Write-Host "Looking for NuGet package provider on $($hostname)..."
$nuget = Get-PackageProvider -Name NuGet -ErrorAction Ignore
if(-not($nuget))
{
    Write-Host "NuGet package provider not found- installing now..."
    try
    {
        Install-PackageProvider -Name NuGet -Confirm:$false -Force
        Write-Host "NuGet installed"
    }
    catch
    {
        $message = $_
        Write-Host "Error installing NuGet: $message"
    }
}
else
{
    Write-Host "NuGet already installed on $($hostname)"
}


# Install and import required modules
$requiredModules = @(
    'Microsoft.Graph.Intune'
    'WindowsAutopilotIntune'
)

foreach($module in $requiredModules)
{
    Write-Host "Checking $($hostname) for $($module) PowerShell module..."
    $installed = Get-InstalledModule -Name $module -ErrorAction Ignore
    if(-not($installed))
    {
        Write-Host "$($module) was not found- installing now..."
        try 
        {
            Install-Module -Name $module -AllowClobber -Force
            Import-Module $module
            Write-Host "$($module) was successfully installed on $($hostname)"        
        }
        catch 
        {
            $message = $_
            Write-Host "Error installing $($module): $message"
        }
    }
    else 
    {
        Write-Host "$($module) already installed on $($hostname)"
        Import-Module $module
    }
}


# Tenant B App reg

$clientId = $settings.targetTenant.clientID
$clientSecret = $settings.targetTenant.clientSecret
$clientSecureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$clientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientId, $clientSecureSecret
$tenantId = $settings.targetTenant.tenantID
$tenant = $settings.targetTenant.tenantName

# Authenticate to graph and add Autopilot device
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $clientSecretCredential

# Get Autopilot device info
Write-Host "Collecting hardware hash info for Autopilot..."
$hwid = ((Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData)
Write-Host "Hardware hash ID is $($hwid)"

$ser = (Get-WmiObject win32_bios).SerialNumber
if([string]::IsNullOrWhiteSpace($ser)) { $ser = $env:COMPUTERNAME}
Write-Host "Serial number is $($ser)"

Write-Host "Retrieving Group Tag from registry..."
# Retrieve group tag info
$regPath = $settings.regPath
$key = "Registry::$regPath"
$tag = Get-ItemPropertyValue -Path $key -Name GroupTag

if($tag -ne $null)
{
    $groupTag = $tag
    Write-Host "Group Tag is set to $($groupTag)"
}
else
{
    $groupTag = ""
    Write-Host "Group Tag not found- setting to $($groupTag)"
}

Write-Host "Registering $($hostname) to Autopilot in $($tenant) tenant..."
try
{
    Add-AutopilotImportedDevice -serialNumber $ser -hardwareIdentifier $hwid -groupTag $groupTag
    Start-Sleep -Seconds 3
    Write-Hosto "$($hostname) successfully registered to $($tenant) Autopilot."
}
catch
{
    Write-Host "Could not register $($hostname) in $($tenant) Autopilot"
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
}


#now delete scheduled task
Disable-ScheduledTask -TaskName "AutopilotRegistration"
Write-Host "Disabled AutopilotRegistration scheduled task"

Write-Host "END LOGGING FOR AUTOPILOT REGISTRATION..."
Stop-Transcript
