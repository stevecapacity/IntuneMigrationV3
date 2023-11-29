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

$log = "$($localPath)\migrateBitlocker.log"
Start-Transcript -Path $log -Verbose
Write-Host "BEGIN LOGGING MIGRATE BITLOCKER..."

# Write BDE Key to AAD

$BLV = Get-BitLockerVolume -MountPoint "C:"
Write-Host "Retrieving BitLocker Volume $($BLV)"
BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BLV.KeyProtector[1].KeyProtectorId
Write-Host "Backing up BitLocker Key to AAD"

#now delete scheduled task
Disable-ScheduledTask -TaskName "MigrateBitlockerKey"
Write-Host "Disabled MigrateBitlockerKey scheduled task"

Stop-Transcript