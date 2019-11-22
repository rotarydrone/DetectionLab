# Purpose: Joins a Windows host to the DOMAIN_NAME domain which was created with "create-domain.ps1".
# Source: https://github.com/StefanScherer/adfs2

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Joining the domain..."

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) First, set DNS to DC to join the domain..."
$newDNSServers = "DC_IP_ADDRESS"
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPAddress -match "LAB_IP_PREFIX"}
$adapters | ForEach-Object {$_.SetDNSServerSearchOrder($newDNSServers)}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Now join the domain..."
$hostname = $(hostname)
$user = "DOMAIN_NAME\PROVISION_USER"
$pass = ConvertTo-SecureString "PROVISION_PASSWORD" -AsPlainText -Force
$DomainCred = New-Object System.Management.Automation.PSCredential $user, $pass

# Place the computer in the correct OU based on hostname
If ($hostname -eq "wef") {
  Add-Computer -DomainName "DOMAIN_NAME" -credential $DomainCred -OUPath "ou=Servers,DOMAIN_DN" -PassThru
} ElseIf ($hostname -eq "win10") {
  Write-Host "Adding Win10 to the domain. Sometimes this step times out. If that happens, just run 'vagrant reload win10 --provision'" #debug
  Add-Computer -DomainName "DOMAIN_NAME" -credential $DomainCred -OUPath "ou=Workstations,DOMAIN_DN"
} Else {
  Add-Computer -DomainName "DOMAIN_NAME" -credential $DomainCred -PassThru
}

Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value 1
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value "PROVISION_USER"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value "PROVISION_PASSWORD"

# Stop Windows Update
Write-Host "Disabling Windows Updates and Windows Module Services"
Set-Service wuauserv -StartupType Disabled
Stop-Service wuauserv
Set-Service TrustedInstaller -StartupType Disabled
Stop-Service TrustedInstaller
