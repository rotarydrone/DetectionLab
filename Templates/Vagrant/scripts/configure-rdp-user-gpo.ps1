# Purpose: Install the GPO that allows DOMAIN_NETBIOS\PROVISION_USER to RDP
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Importing the GPO to allow DOMAIN_NETBIOS/PROVISION_USER to RDP..."
Import-GPO -BackupGpoName 'Allow Domain Users RDP' -Path "c:\vagrant\resources\GPO\rdp_users" -TargetName 'Allow Domain Users RDP' -CreateIfNeeded

$OU = "ou=Workstations,DOMAIN_DN"
$gPLinks = $null
$gPLinks = Get-ADOrganizationalUnit -Identity $OU -Properties name,distinguishedName, gPLink, gPOptions
$GPO = Get-GPO -Name 'Allow Domain Users RDP'
If ($gPLinks.LinkedGroupPolicyObjects -notcontains $gpo.path)
{
  New-GPLink -Name 'Allow Domain Users RDP' -Target $OU -Enforced yes
}
else
{
  Write-Host "Allow Domain Users RDP GPO was already linked at $OU. Moving On."
}
$OU = "ou=Servers,DOMAIN_DN"
$gPLinks = $null
$gPLinks = Get-ADOrganizationalUnit -Identity $OU -Properties name,distinguishedName, gPLink, gPOptions
$GPO = Get-GPO -Name 'Allow Domain Users RDP'
If ($gPLinks.LinkedGroupPolicyObjects -notcontains $gpo.path)
{
    New-GPLink -Name 'Allow Domain Users RDP' -Target $OU -Enforced yes
}
else
{
  Write-Host "Allow Domain Users RDP GPO was already linked at $OU. Moving On."
}
gpupdate /force
