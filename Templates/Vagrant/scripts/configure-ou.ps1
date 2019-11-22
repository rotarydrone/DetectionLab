# Purpose: Sets up OUs and Basic AD Schema

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Checking AD services status..."
$svcs = "adws","dns","kdc","netlogon"
Get-Service -name $svcs -ComputerName localhost | Select Machinename,Name,Status

# Hardcoding DC hostname in hosts file
Add-Content "c:\windows\system32\drivers\etc\hosts" "        DC_IP_ADDRESS    dc.DOMAIN_NAME"

# Force DNS resolution of the domain
ping /n 1 dc.DOMAIN_NAME
ping /n 1 DOMAIN_NAME

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Creating Server and Workstation OUs..."
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Creating Servers OU..."

if (!([ADSI]::Exists("LDAP://OU=Servers,DOMAIN_DN")))
{
  New-ADOrganizationalUnit -Name "Servers" -Server "dc.DOMAIN_NAME"
}
else
{
    Write-Host "Servers OU already exists. Moving On."
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Creating Workstations OU"
if (!([ADSI]::Exists("LDAP://OU=Workstations,DOMAIN_DN")))
{
  New-ADOrganizationalUnit -Name "Workstations" -Server "dc.DOMAIN_NAME"
}
else
{
  Write-Host "Workstations OU already exists. Moving On."
}

# Sysprep breaks auto-login. Let's restore it here:
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value 1
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value "PROVISION_USER"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value "PROVISION_PASSWORD"
