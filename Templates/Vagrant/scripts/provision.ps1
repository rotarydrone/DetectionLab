# Purpose: Sets timezone to UTC, sets hostname, creates/joins domain.
# Source: https://github.com/StefanScherer/adfs2

$box = Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName -Name "ComputerName"
$box = $box.ComputerName.ToString().ToLower()

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Setting timezone to UTC..."
c:\windows\system32\tzutil.exe /s "UTC"

if ($env:COMPUTERNAME -imatch 'vagrant') {

  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Hostname is still the original one, skip provisioning for reboot..."

  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing bginfo..."
  . c:\vagrant\scripts\install-bginfo.ps1

  Write-Host -fore red 'Hint: vagrant reload' $box '--provision'

} elseif ((gwmi win32_computersystem).partofdomain -eq $false) {

  Write-Host -fore red "$('[{0:HH:mm}]' -f (Get-Date)) Current domain is set to 'workgroup'. Time to join the domain!"

  if (!(Test-Path 'c:\Program Files\sysinternals\bginfo.exe')) {
    Write-Host 'Install bginfo'
    . c:\vagrant\scripts\install-bginfo.ps1
    # Set background to be "fitted" instead of "tiled"
    Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name TileWallpaper -Value '0'
    Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name WallpaperStyle -Value '6'
    # Set Task Manager prefs
    reg import "c:\vagrant\resources\windows\TaskManager.reg" 2>&1 | out-null
  }

  if ($env:COMPUTERNAME -imatch 'dc') {
    . c:\vagrant\scripts\create-domain.ps1 DC_IP_ADDRESS
  } else {
    . c:\vagrant\scripts\join-domain.ps1
  }
  Write-Host -fore red 'Hint: vagrant reload' $box '--provision'

} else {

  Write-Host -fore green "$('[{0:HH:mm}]' -f (Get-Date)) I am domain joined!"

  if (!(Test-Path 'c:\Program Files\sysinternals\bginfo.exe')) {
    Write-Host 'Install bginfo'
    . c:\vagrant\scripts\install-bginfo.ps1
  }

  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Provisioning after joining domain..."
}
