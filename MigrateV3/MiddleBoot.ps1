# Create and start log file

$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json

$localPath = $settings.localPath

$log = "$($localPath)\middleBoot.log"
Start-Transcript -Path $log -Verbose
Write-Host "BEGIN LOGGING MIDDLEBOOT..."


# Rename the Tenant A user profile, disable the MiddleBoot task, and reboot

# Get Tenant A user profile directory name from registry file
Write-Host "Getting Tenant A user profile name"
$regPath = $settings.regPath
$key = "Registry::$regPath"

$user = Get-ItemPropertyValue -Path $key -Name Username
Write-Host "Current user directory name is C:\Users\$($user)"
$userSID = Get-ItemPropertyValue -Path $key -Name UserSID
Write-Host "Current userSID is $($userSID)"

# Remove directory
$currentDirectory = "C:\Users\$($user)"
if($user -ne $null)
{
	if(Test-Path $currentDirectory)
	{
		Remove-Item -Path $currentDirectory -Recurse -Force
		Write-Host "Removed $($currentDirectory)"
	}
	else 
	{
		Write-Host "Path $($currentDirectory) not found"
	}
}
else
{
	Write-Host "$($currentDirectory) could not be removed"
}

if($userSID -ne $null)
{
	$userSIDPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($userSID)"
	Remove-Item -Path $($userSIDPath) -Force
	Write-Host "Successfully removed $($userSIDPath)"
}
else 
{
	Write-Host "Could not delete $($userSIDPath) from registry"
}




# Disable MiddleBoot task
Disable-ScheduledTask -TaskName "MiddleBoot"
Write-Host "Disabled MiddleBoot scheduled task"

Start-Sleep -Seconds 2

# Reboot in 30 seconds
shutdown -r -t 30

Write-Host "END LOGGING FOR MIDDLEBOOT..."
Stop-Transcript

