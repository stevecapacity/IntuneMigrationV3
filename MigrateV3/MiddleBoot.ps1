
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

$cacheRegPaths = @(
	"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
	"HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache",
	"HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\S-1-5-18\IdentityCache",
	"HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\S-1-5-19\IdentityCache",
	"HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\S-1-5-20\IdentityCache",
	"HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\S-1-5-90-0-2\IdentityCache"
)

foreach($path in $cacheRegPaths)
{
	$deletePath = "$($path)\$($userSID)"
	if($deletePath -ne $null)
	{
		Write-Host "Removing $($deletePath) registry path..."
		try 
		{
			Remove-Item -Path $deletePath -Force -Recurse
			Write-Host "Successfully removed $($deletePath)"
		}
		catch 
		{
			$message = $_
			Write-Host "Error removing $($deletePath): $message"
		}
	}
	else
	{
		Write-Host "$($deletePath) not found."
	}
}

# Remove logon cache
$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache"
if($logonCache -ne $null)
{
	Write-Host "Removing $($logonCache) from registry..."
	try 
	{
		Remove-Item -Path $logonCache -Force -Recurse
		Write-Host "Successfully removed $($logonCache)"
	}
	catch 
	{
		$message = $_
		Write-Host "Error removing $($logonCache): $message"
	}
}
else
{
	Write-Host "$($logonCache) not found in registry."
}

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

# Disable MiddleBoot task
Disable-ScheduledTask -TaskName "MiddleBoot"
Write-Host "Disabled MiddleBoot scheduled task"

Start-Sleep -Seconds 2

# Reboot in 30 seconds
shutdown -r -t 30

Write-Host "END LOGGING FOR MIDDLEBOOT..."
Stop-Transcript

