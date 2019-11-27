# Purpose : Create Active Directory user and service accounts and OU structure 

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Checking AD services status..."
$svcs = "adws","dns","kdc","netlogon"
Get-Service -name $svcs -ComputerName localhost | Select Machinename,Name,Status

# Force AdminSDHolder to propogate more frequently... otherwise AdminCount flag will not be set in a timely fashion (once a minute)
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters -Value 60 -Name AdminSDProtectFrequency

# Create OUs
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

# Import Fake Users to domain from CSV template
$FakeUsers = Import-CSV "C:\vagrant\resources\windows\fakenamegenerator.csv"

foreach ($fakeuser in $FakeUsers){
    $username = -join($fakeuser.GivenName[0], $fakeuser.Surname)
    $username = $username.ToLower()

    Write-Host $username $fakeuser.OUPath
    
    New-ADUser -Name $username -Path $fakeuser.OUPath.Replace('"', '') -PasswordNeverExpires $true -Enabled $true -DisplayName $username -GivenName $fakeuser.GivenName -SurName $fakeuser.SurName -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
    Add-ADGroupMember -Identity $fakeuser.Group -Members $username
}


# Add marketing user for Gaucamole autologon
New-ADUser -Name "unprivileged" -Path "OU=Sales,OU=User Accounts,DOMAIN_DN"  -PasswordNeverExpires $true -Enabled $true -DisplayName "unprivileged" -GivenName "Unprivileged" -SurName "User" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
Add-ADGroupMember -Identity "sg-sales" -Members "unprivileged"

# Add Service Accounts

## svcsql service account 
## kerberoastable + Admin
New-ADUser -Name "svcsql" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "MSSQL Service Account" -ServicePrincipalNames "MSSQLSvc/sql.rotary.lab:1433" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
Add-ADGroupMember -Identity "Administrators" -Members "svcsql"

## Account Operator Account
## AS-REP Roastable
New-ADUser -Name "svciam" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "Identity Admin Service Account" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
Add-ADGroupMember -Identity "Account Operators" -Members "svciam"
Set-ADAccountControl -Identity "svciam" -doesnotrequirepreauth $true

## Backup Operator Account
New-ADUser -Name "svcbackup" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "Backup Admin Service Account" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
Add-ADGroupMember -Identity "Backup Operators" -Members "svcbackup"

## misc service accounts
New-ADUser -Name "svciis" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "IIS Service Account" -ServicePrincipalNames "HTTP/web.rotary.lab" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "svcftp" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "FTP Transfer Account" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
New-ADUser -Name "svcwebapp" -PasswordNeverExpires $true -Enabled $true -Path "OU=Service Accounts,DOMAIN_DN"  -Description "WebApp Service Account" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)

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
