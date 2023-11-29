# Start log file
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

$log = "$($localPath)\restoreProfile.log"
Start-Transcript -Path $log -Verbose
Write-Host "BEGIN LOGGING RESTORE PROFILE..."

$ErrorActionPreference = 'SilentlyContinue'
# Check if migrating data
Write-Host "Checking migration method..."

# Get values from registry
$regPath = $settings.regPath
$key = "Registry::$regPath"
$migrateMethod = Get-ItemPropertyValue -Path $key -Name MigrateMethod
$guid = Get-ItemPropertyValue -Path $key -Name GUID
$locations = $settings.locations

# Get current username
$activeUsername = (Get-WMIObject Win32_ComputerSystem | Select-Object username).username
$currentUser = $activeUsername -replace '.*\\'

# Migrate data based on MigrateMethod data point
if($migrateMethod -eq "local")
{
	Write-Host "Migration method is local.  Migrating from Public directory..."
	foreach($location in $locations)
	{
		$userPath = "C:\Users\$($currentUser)\$($location)"
		$publicPath = "C:\Users\Public\Temp\$($location)"
		Write-Host "Initiating data restore of $($location)"
		robocopy $publicPath $userPath /E /ZB /R:0 /W:0 /V /XJ /FFT
  		Remove-Item -Path $publicPath -Recurse -Force
	}
	Write-Host "$($currentUser) data is restored"
}
elseif ($migrateMethod -eq "blob") 
{
	Write-Host "Migration method is blob storage.  Connecting to AzBlob storage account..."
	$storageAccountName = $settings.storageAccountName
	$storageAccountKey = $settings.storageAccountKey
	$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey
	$containerName = $guid
	# Check for temp data path
	$tempDataPath = "$($localPath)\TempData"
	Write-Host "Checking for $tempDataPath..."
	if(!(Test-Path $tempDataPath))
	{
		Write-Host "Creating $($tempDataPath)"
		mkdir $tempDataPath
	}
	else
	{
		Write-Host "$($tempDataPath) exists"
	}
	foreach($location in $locations)
	{
		if($location -match '[^a-zA-Z0-9]')
		{
			$blobName = $location
			$blobName = $blobName -replace '\\'
			$blob = "$($blobName).zip"	
			$userPath = "C:\Users\$($currentUser)\$($location)"
			$blobDownload = @{
				Blob = $blob
				Container = $containerName
				Destination = $tempDataPath
				Context = $context
			}
			Write-Host "Downloading $($blob) from $($azStorage) blob storage..."
			try 
			{
				Get-AzStorageBlobContent @blobDownload | Out-Null
				Write-Host "Successfully downloaded $($blob) from $($azStorage) blob storage"
			}
			catch 
			{
				$message = $_
				Write-Host "Error downloading $($blob) from $($azStorage) blob storage: $message"	
			}
			$publicPath = "C:\Users\Public\Temp"
			if(!(Test-Path $publicPath))
			{
				mkdir $publicPath
			}
			Write-Host "Extracting data from $($tempDataPath)\$($blob) to $($publicPath)..."
			try 
			{
				Expand-Archive -Path "$($tempDataPath)\$($blob)" -DestinationPath $publicPath -Force | Out-Null
				Write-Host "Extracted $($tempDataPath)\$($blob) to $($publicPath) folder"
			}
			catch 
			{
				Write-Host "Could not extract $($tempDataPath)\$($blob) to $($publicPath)"
			}
			$newPublicPath = "$($publicPath)\$($blobName)"
			Write-Host "Copying data from $($newPublicPath) to $($userPath)..."
			try 
			{
				robocopy $newPublicPath $userPath /E /ZB /R:0 /W:0 /V /XJ /FFT
				Write-Host "Coppied contents of $($newPublicPath) to $($userPath)"
				Write-Host "Removing $($tempDataPath)\$($blob) and $($newPublicPath) directories..."
				try 
				{
					Remove-Item -Path "$($tempDataPath)\$($blob)" -Recurse -Force
					Remove-Item -Path $newPublicPath -Recurse -Force
					Write-Host "Successfully removed $($tempDataPath)\$($blob) and $($newPublicPath) directories"	
				}
				catch 
				{
					Write-Host "Could not remove $($tempDataPath)\$($blob) and $($newPublicPath) directories"
				}
			}
			catch 
			{
				Write-Host "Could not copy contents of $($newPublicPath) to $($userPath)"
			}
		}
		else 
		{
			$blobName = "$($location).zip"
			$userPath = "C:\Users\$($currentUser)"
			$blobDownload = @{
				Blob = $blobName
				Container = $containerName
				Destination = $tempDataPath
				Context = $context
			}
			Write-Host "Downloading $($blob) from $($azStorage) blob storage..."
			try 
			{
				Get-AzStorageBlobContent @blobDownload | Out-Null
				Write-Host "Successfully downloaded $($blob) from $($azStorage) blob storage"
			}
			catch 
			{
				$message = $_
				Write-Host "Error downloading $($blob) from $($azStorage) blob storage: $message"	
			}
			Write-Host "Extracting data from $($tempDataPath)\$($blob) to $($publicPath)..."
			try 
			{
				Expand-Archive -Path "$($tempDataPath)\$($blob)" -DestinationPath $publicPath -Force | Out-Null
				Write-Host "Extracted $($tempDataPath)\$($blob) to $($publicPath) folder"
				Write-Host "Removing $($tempDataPath)\$($blob)..."
				try 
				{
					Remove-Item -Path "$($tempDataPath)\$($blob)" -Recurse -Force
					Write-Host "Successfully removed $($tempDataPath)\$($blob)"	
				}
				catch 
				{
					Write-Host "Could not remove $($tempDataPath)\$($blob)"
				}
			}
			catch 
			{
				Write-Host "Could not extract $($tempDataPath)\$($blob) to $($publicPath)"
			}
		}
	}
	Write-Host "User data restored from blob storage"
}
else
{
	Write-Host "User data will not be migrated"
}

Start-Sleep -Seconds 3

# Renable the GPO so the user can see the last signed-in user on logon screen
try {
	Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name dontdisplaylastusername -Value 0 -Type DWORD
	Write-Host "$(Get-TimeStamp) - Disable Interactive Logon GPO"
} 
catch {
	Write-Host "$(Get-TimeStamp) - Failed to disable GPO"
}

# Disable RestoreProfile Task
Disable-ScheduledTask -TaskName "RestoreProfile"
Write-Host "Disabled RestoreProfile scheduled task"

Write-Host "Rebooting machine in 30 seconds"
Shutdown -r -t 30

Write-Host "END LOGGING FOR RESTORE PROFILE..."
Stop-Transcript
