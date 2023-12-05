<# PRE MIGRATION BACKUP - SCRIPT FOR INTUNE TENANT TO TENANT MIGRATION #>
<# RUN AT T-10 DAYS BEFORE MIGRATION #>
<# WARNING: THIS MUST BE RUN AS SYSTEM CONTEXT #>
<#APP REG PERMISSIONS NEEDED:
Device.ReadWrite.All
DeviceManagementApps.ReadWrite.All
DeviceManagementConfiguration.ReadWrite.All
DeviceManagementManagedDevices.PrivilegedOperations.All
DeviceManagementManagedDevices.ReadWrite.All
DeviceManagementServiceConfig.ReadWrite.All
#>
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

#// PRE-MIGRATE BACKUP SCRIPT SHOULD RUN AT A MINIMUM OF 10 DAYS PRIOR TO TENANT MIGRATION
$ErrorActionPreference = 'SilentlyContinue'

<# =================================================================================================#>
#### LOCAL FILES AND LOGGING ####
<# =================================================================================================#>

# Create local path for files and logging

$localPath = $settings.localPath

if(!(Test-Path $localPath))
{
    mkdir $localPath
}

# Set detection flag for Intune install
$installFlag = "$($localPath)\preMigrateInstalled.txt"
New-Item $installFlag -Force
Set-Content -Path $installFlag -Value "Installed"

# Start logging
Start-Transcript -Path "$($localPath)\preMigrate.log" -Verbose

Write-Host "Starting Intune tenant to tenant migration pre-migrate backup process..."

<# =================================================================================================#>
#### AUTHENTICATE TO MS GRAPH ####
<# =================================================================================================#>

# SOURCE TENANT Application Registration Auth
Write-Host "Authenticating to MS Graph..."
$clientId = $settings.sourceTenant.clientID
$clientSecret = $settings.sourceTenant.clientSecret
$tenant = $settings.sourceTenant.tenantName

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/x-www-form-urlencoded")

$body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
$body += -join ("&client_id=" , $clientId, "&client_secret=", $clientSecret)

$response = Invoke-RestMethod "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body

#Get Token form OAuth.
$token = -join ("Bearer ", $response.access_token)

#Reinstantiate headers.
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", $token)
$headers.Add("Content-Type", "application/json")
Write-Host "MS Graph Authenticated"

<#=================================================================================================#>
#### GET CURRENT STATE INFO ####
<# =================================================================================================#>

# Get active username
$activeUsername = (Get-WMIObject Win32_ComputerSystem | Select-Object username).username
$user = $activeUsername -replace '.*\\'
Write-Host "Current active user is $($user)"
Write-Host "Getting current user SID..."
$objUser = New-Object System.Security.Principal.NTAccount("$activeUsername")
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
$activeUserSID = $strSID.Value
$currentDomain = (Get-WmiObject Win32_ComputerSystem | Select-Object Domain).Domain

# Get hostname
$hostname = $env:COMPUTERNAME
Write-Host "Device hostname is $($hostname)"

# Generate GUID
Write-Host "Generating Migration GUID..."
$guid = (New-Guid).Guid
Write-Host "Migration GUID for $($hostname) is $($guid)"

# Gather Autopilot and Intune Object details
Write-Host "Gathering device info from tenant $($tenant)"
$serialNumber = Get-WmiObject -Class Win32_Bios | Select-Object -ExpandProperty serialNumber
Write-Host "Serial number of $($hostname) is $($serialNumber)"

Write-Host "Retreiving $($hostname) Autopilot object in $($tenant)..."
try {
    $autopilotObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers
    Write-Host "$($hostname) Autopilot object found."
}
catch {
    Write-Host "Could not retrieve Autopilot object for $($hostname)"
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
}

Write-Host "Retreiving $($hostname) Intune object in $($tenant)..."
try {
    $intuneObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers
    Write-Host "$($hostname) Intune object found."
}
catch {
    Write-Host "Could not retrieve Intune object for $($hostname)"
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
}

if($autopilotObject -ne $null)
{
    $autopilotID = $autopilotObject.value.id
    Write-Host "Autopilot ID is $($autopilotID)"
    $groupTag = $autopilotObject.value.groupTag
    if($groupTag -ne $null)
    {
        Write-Host "Current Autopilot GroupTag is $($groupTag)"
    }
    else 
    {
        Write-Host "$($hostname) does not have a Group Tag in $($tenant)"
    }
}
else
{
    Write-Host "$($hostname) not enrolled in Autopilot in $($tenant)"
}

if($intuneObject -ne $null)
{
    $intuneID = $intuneObject.value.id
    Write-Host "Intune ID is $($intuneID)"
}
else
{
    Write-Host "$($hostname) not enrolled in Intune in $($tenant)"
}

<# =================================================================================================#>
#### DATA MIGRATION + BACKUP METHOD ####
<# =================================================================================================#>
$locations = $settings.locations

# Check user data size
$totalProfileSize = 0.0

foreach($location in $locations)
{
    $userLocation = "C:\Users\$($user)\$($location)"
    $size = (Get-ChildItem $userLocation -Recurse | Measure-Object Length -Sum).Sum
    $sizeGB = "{0:N2} GB" -f ($size / 1Gb)
    Write-Host "$userLocation is $($sizeGB)"
    $totalProfileSize += $size
}

$totalProfileSizeGB = "{0:N2} GB" -f ($totalProfileSize/ 1Gb)
Write-Host "The size of $($user) user data is $($totalProfileSizeGB)"

# Check disk space
$diskSize = Get-Volume -DriveLetter C | Select-Object -ExpandProperty size
$diskSizeGB = "{0:N2} GB" -f ($diskSize/ 1Gb)
$freeSpace = Get-Volume -DriveLetter C | Select-Object -ExpandProperty SizeRemaining
$freeSpaceGB = "{0:N2} GB" -f ($freeSpace/ 1Gb)
Write-Host "Disk has $($freeSpaceGB) free space available out of the total $($diskSizeGB)"

# Space needed for local migration vs blob storage
$localRequiredSpace = $totalProfileSize * 3
$localRequiredSpaceGB = "{0:N2} GB" -f ($localRequiredSpace/ 1Gb)
Write-Host "$($localRequiredSpaceGB) of free disk space is required to migrate data locally"

$blobRequiredSpace = $totalProfileSize * 2
$blobRequiredSpaceGB = "{0:N2} GB" -f ($blobRequiredSpace/ 1Gb)
Write-Host "$($blobRequiredSpaceGB) of free disk space is required to migrate data via blob storage"

# Attempt to backup data for migration
$migrateMethod = ""
# Try local backup 
# Exclude AAD.BrokerPlugin folder

if($freeSpace -gt $localRequiredSpace)
{
    $migrateMethod = "local"
    Write-Host "$($freeSpaceGB) of free space is sufficient to transfer $($totalProfileSizeGB) of $($user) data locally."
    foreach($location in $locations)
    {   
        $userLocation = "C:\Users\$($user)\$($location)"
        $backupLocation = "C:\Users\Public\Temp\$($location)"
        $aadBrokerFolder = Get-ChildItem -Path "$($userLocation)\Packages" -ErrorAction SilentlyContinue | Where-Object {$_.Name -match "Microsoft.AAD.BrokerPlugin_*"} | Select-Object -ExpandProperty Name
        $aadBrokerPath = "$($userLocation)\Packages\$($aadBrokerFolder)"
        if(!(Test-Path $backupLocation))
        {
            mkdir $backupLocation
        }
        Write-Host "Initiating backup of $($userLocation)"
        try 
        {
            robocopy $userLocation $backupLocation /E /ZB /R:0 /W:0 /V /XJ /FFT /XD $aadBrokerPath
            Write-Host "$($userLocation) backed up to $($backupLocation)"    
        }
        catch 
        {
            $message = $_
            Write-Host "Error copying $($userLocation) to $($backupLocation): $message"
        }
    }
}
# Try blob backup
elseif($freeSpace -gt $blobRequiredSpace) 
{
    Write-Host "$($freeSpaceGB) of free space is sufficient to transfer $($totalProfileSizeGB) of $($user) data via blob storage."
    # Install Az Storage module for blob
    Write-Host "Checking for NuGet Package Provider..."
    $nuget = Get-PackageProvider -Name NuGet -ErrorAction Ignore

    if(-not($nuget))
    {
        try
        {
            Write-Host "Package Provider NuGet not found. Installing now..."
            Install-PackageProvider -Name NuGet -Confirm:$false -Force
            Write-Host "NuGet installed."
        }
        catch
        {
            $message = $_
            Write-Host "Error installing NuGet: $message"
        }
    }
    else 
    {
        Write-Host "Package Provider NuGet already installed"
    }

    $azStorage = Get-InstalledModule -Name Az.Storage -ErrorAction Ignore

    if(-not($azStorage))
    {
        try 
        {
            Write-Host "Az.Storage module not found. Installing now..."
            Install-Module -Name Az.Storage -Force
            Import-Module Az.Storage
            Write-Host "Az.Storage module installed"    
        }
        catch 
        {
            $message = $_
            Write-Host "Error installing Az.Storage module: $message"
        }
    }
    else
    {
        Write-Host "Az.Storage module already installed"
        Import-Module Az.Storage
    }

    # Connect to blob storage
    $storageAccountName = $settings.storageAccountName
    $storageAccountKey = $settings.storageAccountKey
    $context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey

    Write-Host "Connecting to Azure blob storage account $($storageAccountName)"
    $migrateMethod = "blob"
    # Create user container
    $containerName = $guid
    try 
    {
        Write-Host "Creating $($containerName) container in $($azStorage) Azure storage..."
        New-AzStorageContainer -Name $containerName -Context $context
        Write-Host "Successfully created $($containerName) in $($azStorage) Azure storage"
    }
    catch 
    {
        $message = $_
        Write-Host "Error creating $($containerName) in $($azStorage) Azure storage: $message"
    }
    foreach($location in $locations)
    {
        $userLocation = "C:\Users\$($user)\$($location)"
        $blobLocation = $location
        if($blobLocation -match '[^a-zA-Z0-9]')
        {
            Write-Host "$($blobLocation) contains special character.  Removing..."
            $blobName = $blobLocation -replace '\\'
            Write-Host "Removed special character from $($blobName)"
            $backupLocation = "$($localPath)\$($blobName)"
            $aadBrokerFolder = Get-ChildItem -Path "$($userLocation)\Packages" -ErrorAction SilentlyContinue | Where-Object {$_.Name -match "Microsoft.AAD.BrokerPlugin_*"} | Select-Object -ExpandProperty Name
            $aadBrokerPath = "$($userLocation)\Packages\$($aadBrokerFolder)"
            if(!(Test-Path $backupLocation))
            {
                mkdir $backupLocation
            }
            Write-Host "Initiating backup of $($userLocation)"
            try 
            {
                robocopy $userLocation $backupLocation /E /ZB /R:0 /W:0 /V /XJ /FFT /XD $aadBrokerPath
                Write-Host "$($userLocation) coppied to $($backupLocation)"    
            }
            catch 
            {
                $message = $_
                Write-Host "Error copying $($userLocation) to $($backupLocation): $message"
            }
            Write-Host "Compressing $($backupLocation) for blob storage..."
            try 
            {
                Start-Process "$($PSScriptRoot)\7zr.exe" -ArgumentList "a $($localPath)\$($blobName).zip $($backupLocation)\* -r" -Wait
                Write-Host "Compressed $($backupLocation) to $($localPath)\$($blobName).zip"
            }
            catch 
            {
                $message = $_
                Write-Host "Error compressing $($backupLocation) to $($localPath)\$($blobName).zip: $message"
            }
            Write-Host "Uploading $($localPath)\$($blobName).zip to $($azStorage) blob storage..."
            try 
            {
                Set-AzStorageBlobContent -File "$($localPath)\$($blobName).zip" -Container $containerName -Blob "$($blobName).zip" -Context $context -Force | Out-Null
                Write-Host "$($blobName).zip uploaded to $($storageAccountName) blob storage"
                Write-Host "Removing temporary locations $($backupLocation) and $($localPath)\$($blobName).zip..."
                try 
                {
                    Remove-Item -Path "$($backupLocation)" -Recurse -Force
                    Remove-Item -Path "$($localPath)\$($blobName).zip" -Recurse -Force
                    Write-Host "Successfully removed temporary locations $($backupLocation) and $($localPath)\$($blobName).zip"
                }
                catch 
                {
                    Write-Host "Could not remove temporary locations $($backupLocation) and $($localPath)\$($blobName).zip"
                }
            }
            catch 
            {
                $message = $_
                Write-Host "Error uploading $($localPath)\$($blobName).zip to $($azStorage) blob storage: $message"
            }
            
        }
        else 
        {
            Write-Host "$($blobLocation) does not contain special chearacters."
            $blobName = $blobLocation
            Write-Host "Compressing $($userLocation) to $($localPath)\$($blobName).zip..."
            try 
            {
                Start-Process "$($PSScriptRoot)\7zr.exe" -ArgumentList "a $($localPath)\$($blobName).zip $($userLocation)\* -r" -Wait
                Write-Host "Compressed $($userLocation) to $($localPath)\$($blobName).zip"
            }
            catch 
            {
                $message = $_
                Write-Host "Error compressing $($userLocation) to $($localPath)\$($blobName).zip: $message"
            }
            Write-Host "Uploading $($localPath)\$($blobName).zip to $($azStorage) blob storage..."
            try 
            {
                Set-AzStorageBlobContent -File "$($localPath)\$($blobName).zip" -Container $containerName -Blob "$($blobName).zip" -Context $context -Force | Out-Null
                Write-Host "$($blobName).zip uploaded to $($storageAccountName) blob storage"
                Write-Host "Removing temporary location $($localPath)\$($blobName).zip..."
                try 
                {
                    Remove-Item -Path "$($localPath)\$($blobName).zip" -Recurse -Force
                    Write-Host "Successfully removed temporary location $($localPath)\$($blobName).zip"
                }
                catch 
                {
                    Write-Host "Could not remove temporary location $($localPath)\$($blobName).zip"
                }
            }
            catch 
            {
                $message = $_
                Write-Host "Error uploading $($localPath)\$($blobName).zip to $($azStorage) blob storage: $message"
            }
        }
    }
}
else
{
    # cannot migrate data
    $migrateMethod = "none"
    Write-Host "Not enough local space to migrate user data."
}

<# =================================================================================================#>
#### WRITE VARIABLES TO REGISTRY
<# =================================================================================================#>



$regPath = $settings.regPath
Write-Host "Setting registry values to $($regPath)..."

reg.exe add $regPath /v GUID /t REG_SZ /d $guid /f | Out-Host
Write-Host "Set GUID to $($guid) at $($regPath)"

reg.exe add $regPath /v MigrateMethod /t REG_SZ /d $migrateMethod /f | Out-Host
Write-Host "Set MigrateMethod to $($migrateMethod) at $($regPath)"

reg.exe add $regPath /v Username /t REG_SZ /d $user /f | Out-Host
Write-Host "Set Username to $($user) at $($regPath)"

reg.exe add $regPath /v UserSID /t REG_SZ /d $activeUserSID /f | Out-Host
Write-Host "Set UserSID to $($activeUserSID) at $($regPath)"


if($intuneID -ne $null)
{
    reg.exe add $regPath /v IntuneID /t REG_SZ /d $intuneID /f | Out-Host
    Write-Host "Set IntuneID to $($intuneID) at $($regPath)"
}

if($autopilotID -ne $null)
{
    reg.exe add $regPath /v AutopilotID /t REG_SZ /d $autopilotID /f | Out-Host
    Write-Host "Set AutopilotID to $($autopilotID) at $($regPath)"
}

if($groupTag -ne $null)
{
    reg.exe add $regPath /v GroupTag /t REG_SZ /d $groupTag /f | Out-Host
    Write-Host "Set GroupTag to $($groupTag) at $($regPath)"
}

if($currentDomain -ne $null)
{
    reg.exe add $regPath /v CurrentDomain /t REG_SZ /d $currentDomain /f | Out-Host
    Write-Host "Set CurrentDomain to $($currentDomain) at $($regPath)"
}

Write-Host "End of PreMigrate... stopping log..."

Stop-Transcript
