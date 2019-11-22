# Purpose : Create Active Directory user and service accounts and OU structure 


Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Checking AD services status..."
$svcs = "adws","dns","kdc","netlogon"
Get-Service -name $svcs -ComputerName localhost | Select Machinename,Name,Status

# Force AdminSDHolder to propogate more frequently... otherwise AdminCount flag will not be set in a timely fashion (once a minute)
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters -Value 60 -Name AdminSDProtectFrequency


# OUs
New-ADOrganizationalUnit -Name "User Accounts" -Path "DOMAIN_DN" 
New-ADOrganizationalUnit -Name "Service Accounts" -Path "DOMAIN_DN" 
New-ADOrganizationalUnit -Name "Groups" -Path "DOMAIN_DN" 

New-ADOrganizationalUnit -Name "Finance" -Path "OU=User Accounts,DOMAIN_DN" 
New-ADOrganizationalUnit -Name "Marketing" -Path "OU=User Accounts,DOMAIN_DN"
New-ADOrganizationalUnit -Name "Sales" -Path "OU=User Accounts,DOMAIN_DN" 
New-ADOrganizationalUnit -Name "Information Technology" -Path "OU=User Accounts,DOMAIN_DN"

# Groups 
New-ADGroup -Name "sg-it-helpdesk" -SamAccountName sg-it-helpdesk -GroupCategory Security -GroupScope Global -DisplayName "sg-it-helpdesk" -Path "OU=Groups,DOMAIN_DN" -Description "IT Helpdesk Team Members"
New-ADGroup -Name "sg-infosec" -SamAccountName sg-infosec -GroupCategory Security -GroupScope Global -DisplayName "sg-infosec" -Path "OU=Groups,DOMAIN_DN" -Description "Information Security Team Members"
New-ADGroup -Name "sg-finance" -SamAccountName sg-finance -GroupCategory Security -GroupScope Global -DisplayName "sg-finance" -Path "OU=Groups,DOMAIN_DN" -Description "Finance Team Members"
New-ADGroup -Name "sg-marketing" -SamAccountName sg-marketing -GroupCategory Security -GroupScope Global -DisplayName "sg-marketing" -Path "OU=Groups,DOMAIN_DN" -Description "Marketing Team Members"
New-ADGroup -Name "sg-sales" -SamAccountName sg-sales -GroupCategory Security -GroupScope Global -DisplayName "sg-sales" -Path "OU=Groups,DOMAIN_DN" -Description "Sales Team Members"

Add-ADGroupMember -Identity "Administrators" -Members "sg-infosec"

# Service Accounts 

## svcsql service account 
## kerberoastable
New-ADUser -Name "svcsql" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "MSSQL Service Account" -ServicePrincipalNames "MSSQLSvc/sql.rotary.lab:1433" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
Add-ADGroupMember -Identity "Administrators" -Members "svcsql"

## misc service accounts
New-ADUser -Name "svciis" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "IIS Service Account" -ServicePrincipalNames "HTTP/web.rotary.lab" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "svcftp" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "FTP Transfer Account" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "svcwebapp" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "WebApp Service Account" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)

## Backup Operator Account
New-ADUser -Name "svcbackup" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "Backup Admin Service Account" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
Add-ADGroupMember -Identity "Backup Operators" -Members "svcbackup"

## Account Operator Account
## AS-REP Roastable
New-ADUser -Name "svciam" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "Identity Admin Service Account" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
Add-ADGroupMember -Identity "Account Operators" -Members "svciam"
Set-ADAccountControl -Identity "svciam" -doesnotrequirepreauth $true

# Finance Users
New-ADUser -Name "andy.dufresne" -PasswordNeverExpires $true -Enabled $true -Path "OU=Finance,OU=User Accounts,DOMAIN_DN"  -DisplayName "Andy Dufresne" -GivenName "Andy" -SurName "Dufresne" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "skyler.white" -PasswordNeverExpires $true -Enabled $true -Path "OU=Finance,OU=User Accounts,DOMAIN_DN"  -DisplayName "Skyler White" -GivenName "Skyler" -SurName "White" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
Add-ADGroupMember -Identity "sg-finance" -Members andy.dufresne,skyler.white

# Marketing Users
New-ADUser -Name "don.draper" -PasswordNeverExpires $true -Enabled $true -Path "OU=Marketing,OU=User Accounts,DOMAIN_DN"  -DisplayName "Don Draper" -GivenName "Dick" -SurName "Whitman" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "peggy.olson" -PasswordNeverExpires $true -Enabled $true -Path "OU=Marketing,OU=User Accounts,DOMAIN_DN"  -DisplayName "Peggy Olson" -GivenName "Peggy" -SurName "Olson" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "ted.chaugh" -PasswordNeverExpires $true -Enabled $true -Path "OU=Marketing,OU=User Accounts,DOMAIN_DN"  -DisplayName "Ted Chaugh" -GivenName "Ted" -SurName "Chaugh" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
Add-ADGroupMember -Identity "sg-marketing" -Members don.draper, peggy.olson, ted.chaugh

# Sales Users
New-ADUser -Name "andy.bernard" -PasswordNeverExpires $true -Enabled $true -Path "OU=Sales,OU=User Accounts,DOMAIN_DN"  -DisplayName "Andy Bernard" -GivenName "Andy" -SurName "Bernard" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "jim.halpert" -PasswordNeverExpires $true -Enabled $true -Path "OU=Sales,OU=User Accounts,DOMAIN_DN"  -DisplayName "Jim Halpert" -GivenName "Jim" -SurName "Halpert" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "dwight.schrute" -PasswordNeverExpires $true -Enabled $true -Path "OU=Sales,OU=User Accounts,DOMAIN_DN"  -DisplayName "Dwight Schrute" -GivenName "Dwight" -SurName "Schrute" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
Add-ADGroupMember -Identity "sg-sales" -Members andy.bernard, jim.halpert, dwight.schrute

# IT Users
New-ADUser -Name "roy" -PasswordNeverExpires $true -Enabled $true -Path "OU=Information Technology,OU=User Accounts,DOMAIN_DN"  -DisplayName "Roy" -GivenName "Roy" -SurName "" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "moss" -PasswordNeverExpires $true -Enabled $true -Path "OU=Information Technology,OU=User Accounts,DOMAIN_DN"  -DisplayName "Moss" -GivenName "Maurice" -SurName "Moss" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "richmond" -PasswordNeverExpires $true -Enabled $true -Path "OU=Information Technology,OU=User Accounts,DOMAIN_DN"  -DisplayName "Richmond" -GivenName "Richmond" -SurName "Avenal" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "jen" -PasswordNeverExpires $true -Enabled $true -Path "OU=Information Technology,OU=User Accounts,DOMAIN_DN"  -DisplayName "Jen" -GivenName "Jen" -SurName "Barber" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
Add-ADGroupMember -Identity "sg-it-helpdesk" -Members roy, moss, jen
Add-ADGroupMember -Identity "sg-infosec" -Members richmond, roy


# Make some vulnerable ACLs

# Delegate Password Reset Group Control to sg-it-helpdesk Group"
New-PSDrive -Name "DOMAIN_NETBIOS" -PSProvider ActiveDirectory -Root "//RootDSE/" -server "DC.DOMAIN_NAME"
$acl = Get-ACL "DOMAIN_NETBIOS:\DOMAIN_DN"
$s = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Server "DC.DOMAIN_NAME" "sg-it-helpdesk").SID
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$s,"ExtendedRight","Allow",([GUID]("00299570-246d-11d0-a768-00aa006e0529")).guid,"Descendents",([GUID]("bf967aba-0de6-11d0-a285-00aa003049e2")).guid))
Set-ACL "DOMAIN_NETBIOS:\DOMAIN_DN" $acl
Remove-PSDrive -Name "DOMAIN_NETBIOS"

# Delegate AD Group Management rights to sg-it-helpdesk Group
New-PSDrive -Name "DOMAIN_NETBIOS" -PSProvider ActiveDirectory -Root "//RootDSE/" -server "DC.DOMAIN_NAME"
$acl = Get-ACL "DOMAIN_NETBIOS:\DOMAIN_DN"
$s = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Server "DC.DOMAIN_NAME" "sg-it-helpdesk").SID
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$s,"GenericAll","Allow",([GUID]("00000000-0000-0000-0000-000000000000")).guid,"Descendents",([GUID]("bf967a9c-0de6-11d0-a285-00aa003049e2")).guid))
Set-ACL "DOMAIN_NETBIOS:\DOMAIN_DN" $acl
Remove-PSDrive -Name "DOMAIN_NETBIOS"

# Delegate writeOwner privileges to svciam user to User Accounts"
New-PSDrive -Name "DOMAIN_NETBIOS" -PSProvider ActiveDirectory -Root "//RootDSE/" -server "DC.DOMAIN_NAME"
$acl = Get-ACL "DOMAIN_NETBIOS:\OU=User Accounts,DOMAIN_DN"
$s = New-Object System.Security.Principal.SecurityIdentifier (Get-ADUser -Server "DC.DOMAIN_NAME" "svciam").SID
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$s,"writeOwner","Allow",([GUID]("bf967aba-0de6-11d0-a285-00aa003049e2")).guid,"Descendents",([GUID]("bf967a9c-0de6-11d0-a285-00aa003049e2")).guid))
Set-ACL "DOMAIN_NETBIOS:\OU=User Accounts,DOMAIN_DN" $acl
Remove-PSDrive -Name "DOMAIN_NETBIOS"

# Delegate writeOwner privileges to tsvciam user to Service Accounts"
New-PSDrive -Name "DOMAIN_NETBIOS" -PSProvider ActiveDirectory -Root "//RootDSE/" -server "DC.DOMAIN_NAME"
$acl = Get-ACL "DOMAIN_NETBIOS:\OU=Service Accounts,DOMAIN_DN"
$s = New-Object System.Security.Principal.SecurityIdentifier (Get-ADUser -Server "DC.DOMAIN_NAME" "svciam").SID
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$s,"writeOwner","Allow",([GUID]("bf967aba-0de6-11d0-a285-00aa003049e2")).guid,"Descendents",([GUID]("bf967aba-0de6-11d0-a285-00aa003049e2")).guid))
Set-ACL "DOMAIN_NETBIOS:\OU=Service Accounts,DOMAIN_DN" $acl
Remove-PSDrive -Name "DOMAIN_NETBIOS"

# Delegate writeOwner privileges to svciam user to Groups"
New-PSDrive -Name "DOMAIN_NETBIOS" -PSProvider ActiveDirectory -Root "//RootDSE/" -server "DC.DOMAIN_NAME"
$acl = Get-ACL "DOMAIN_NETBIOS:\OU=Groups,DOMAIN_DN"
$s = New-Object System.Security.Principal.SecurityIdentifier (Get-ADUser -Server "DC.DOMAIN_NAME" "svciam").SID
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$s,"writeOwner","Allow",([GUID]("bf967a9c-0de6-11d0-a285-00aa003049e2")).guid,"Descendents",([GUID]("bf967a9c-0de6-11d0-a285-00aa003049e2")).guid))
Set-ACL "DOMAIN_NETBIOS:\OU=Groups,DOMAIN_DN" $acl
Remove-PSDrive -Name "DOMAIN_NETBIOS"