# Purpose: Installs the GPOs for the custom WinEventLog auditing policy.
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Configuring auditing policy GPOs..."
$GPOName = 'Domain Controllers Enhanced Auditing Policy'
$OU = "ou=Domain Controllers,DOMAIN_DN"
Write-Host "Importing $GPOName..."
Import-GPO -BackupGpoName $GPOName -Path "c:\vagrant\resources\GPO\Domain_Controllers_Enhanced_Auditing_Policy" -TargetName $GPOName -CreateIfNeeded
$gpLinks = $null
$gPLinks = Get-ADOrganizationalUnit -Identity $OU -Properties name,distinguishedName, gPLink, gPOptions
$GPO = Get-GPO -Name $GPOName
If ($gPLinks.LinkedGroupPolicyObjects -notcontains $gpo.path)
{
    New-GPLink -Name $GPOName -Target $OU -Enforced yes
}
else
{
    Write-Host "GpLink $GPOName already linked on $OU. Moving On."
}
$GPOName = 'Servers Enhanced Auditing Policy'
$OU = "ou=Servers,DOMAIN_DN"
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Importing $GPOName..."
Import-GPO -BackupGpoName $GPOName -Path "c:\vagrant\resources\GPO\Servers_Enhanced_Auditing_Policy" -TargetName $GPOName -CreateIfNeeded
$gpLinks = $null
$gPLinks = Get-ADOrganizationalUnit -Identity $OU -Properties name,distinguishedName, gPLink, gPOptions
$GPO = Get-GPO -Name $GPOName
If ($gPLinks.LinkedGroupPolicyObjects -notcontains $gpo.path)
{
    New-GPLink -Name $GPOName -Target $OU -Enforced yes
}
else
{
    Write-Host "GpLink $GPOName already linked on $OU. Moving On."
}

$GPOName = 'Workstations Enhanced Auditing Policy'
$OU = "ou=Workstations,DOMAIN_DN"
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Importing $GPOName..."
Import-GPO -BackupGpoName $GPOName -Path "c:\vagrant\resources\GPO\Workstations_Enhanced_Auditing_Policy" -TargetName $GPOName -CreateIfNeeded
$gpLinks = $null
$gPLinks = Get-ADOrganizationalUnit -Identity $OU -Properties name,distinguishedName, gPLink, gPOptions
$GPO = Get-GPO -Name $GPOName
If ($gPLinks.LinkedGroupPolicyObjects -notcontains $gpo.path)
{
    New-GPLink -Name $GPOName -Target $OU -Enforced yes
}
else
{
    Write-Host "GpLink $GPOName already linked on $OU. Moving On."
}
