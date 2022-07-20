---
title: "THM - # Enumerating Active Directory"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # Enumerating Active Directory"
categories:
  - THM
---

The given box ```Enumerating Active Directory``` is a AD machine with an IP address of ```10.10.135.22```

- [TryHackMe- Enumerating Active Directory](#tryhackme---Enumerating-Active-Directory)
  - [Recon](#recon)
    - [Nmap Scan Result](#nmap-scan-result)
  - [Enumeration](#enumeration)
	  - [Redis](#redis)
	  - [SMB](#smb)
  - [Post Escalation](#post-escalation)
	  - [SMB Reverse-Shell](#smb-reverse-shell)
  - [Privilege Escalation](#privilege-escalation)
	  - [BloodHound Enumeration](#bloodhound-enumeration)
	  - [Exploiting the GPO](#exploiting-the-gpo)

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/attacking-ad.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/network-diagram.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/dns.png" />
</center>


```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/adenumeration# sudo systemctl restart NetworkManager

root@rE3oN:~/enum-more/obsidian_vault/thm/adenumeration# nslookup thmdc.za.tryhackme.com
Server:         10.200.68.101
Address:        10.200.68.101#53

Name:   thmdc.za.tryhackme.com
Address: 10.200.68.101
```

![[ad_creds.png]]

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/adenumeration# cat ad_credentials.txt
Username: tony.holland
Password: Mhvn2334
```

```cmd
Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

za\tony.holland@THMJMP1 C:\Users\tony.holland>dir \\za.tryhackme.com\SYSVOL\
 Volume in drive \\za.tryhackme.com\SYSVOL is Windows
 Volume Serial Number is 1634-22A9

 Directory of \\za.tryhackme.com\SYSVOL

02/24/2022  10:57 PM    <DIR>          .
02/24/2022  10:57 PM    <DIR>          ..
02/24/2022  10:57 PM    <JUNCTION>     za.tryhackme.com [C:\Windows\SYSVOL\domain]
               0 File(s)              0 bytes
               3 Dir(s)  51,574,280,192 bytes free
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/adenumeration# xfreerdp /u:tony.holland /p:Mhvn2334 /v:thmjmp1.za.tryhackme.com /dynamic-resolution
[21:49:07:554] [4816:4817] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[21:49:07:554] [4816:4817] [WARN][com.freerdp.crypto] - CN = THMJMP1.za.tryhackme.com
Certificate details for thmjmp1.za.tryhackme.com:3389 (RDP-Server):
        Common Name: THMJMP1.za.tryhackme.com
        Subject:     CN = THMJMP1.za.tryhackme.com
        Issuer:      CN = THMJMP1.za.tryhackme.com
        Thumbprint:  67:fe:05:1b:5b:a3:59:2a:c1:f5:e4:db:fc:ca:a2:31:39:b0:35:0c:c8:29:f7:ce:5d:d4:f0:b9:fa:1b:14:df
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) y
```

![[app&features.png]]

![[Pasted image 20220720215612.png]]

![[Pasted image 20220720221658.png]]

![[change_forest.png]]

![[sites&service.png]]

![[Pasted image 20220720221758.png]]

![[user&computer.png]]

![[change_domain.png]]

![[advanced_feature.png]]

![[groups.png]]

![[detailed_view.png]]

```powershell
PS C:\Users\tony.holland> net user /domain
The request will be processed at a domain controller for domain za.tryhackme.com.


User accounts for \\THMDC.za.tryhackme.com

-------------------------------------------------------------------------------
aaron.conway             aaron.hancock            aaron.harris
aaron.johnson            aaron.lewis              aaron.moore
aaron.patel              aaron.smith              abbie.joyce
abbie.robertson          abbie.taylor             abbie.walker
abdul.akhtar             abdul.bates              abdul.holt
abdul.jones              abdul.wall               abdul.west
abdul.wilson             abigail.cox              abigail.cox1
abigail.smith            abigail.ward             abigail.wheeler
adam.heath               adam.jones               adam.parker
adam.pugh                adam.reynolds            adam.woodward
Administrator            adrian.blake             adrian.chapman
adrian.foster            adrian.wilson            aimee.ball
aimee.dean               aimee.humphries          aimee.jones
aimee.potter             aimee.robinson           alan.brown
alan.jones               albert.elliott           albert.harrison
[..]

PS C:\Users\tony.holland> net user zoe.marshall /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

User name                    zoe.marshall
Full Name                    Zoe Marshall
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/24/2022 11:06:06 PM
Password expires             Never
Password changeable          2/24/2022 11:06:06 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Internet Access
The command completed successfully.

PS C:\Users\tony.holland> net group /domain
The request will be processed at a domain controller for domain za.tryhackme.com.


Group Accounts for \\THMDC.za.tryhackme.com

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*HR Share RW
*Internet Access
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Schema Admins
*Server Admins
*Tier 0 Admins
*Tier 1 Admins
*Tier 2 Admins
The command completed successfully.

PS C:\Users\tony.holland> net group "Tier 1 Admins" /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

Group name     Tier 1 Admins
Comment

Members

-------------------------------------------------------------------------------
t1_arthur.tyler          t1_gary.moss             t1_henry.miller
t1_jill.wallis           t1_joel.stephenson       t1_marian.yates
t1_rosie.bryant
The command completed successfully.

PS C:\Users\tony.holland> net accounts /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          Unlimited
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        PRIMARY
The command completed successfully.

PS C:\Users\tony.holland> net user aaron.harris /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

User name                    aaron.harris
Full Name                    Aaron Harris
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/24/2022 11:05:11 PM
Password expires             Never
Password changeable          2/24/2022 11:05:11 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Internet Access
The command completed successfully.

PS C:\Users\tony.holland> net user guest /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

User name                    Guest
Full Name
Comment                      Built-in account for guest access to the computer/domain
User's comment
Country/region code          000 (System Default)
Account active               No
Account expires              Never

Password last set            7/20/2022 6:09:17 PM
Password expires             Never
Password changeable          7/20/2022 6:09:17 PM
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Guests
Global Group memberships     *Domain Guests
The command completed successfully.
```

```powershell
PS C:\Users\tony.holland> Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *


AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
AccountNotDelegated                  : False
AllowReversiblePasswordEncryption    : False
AuthenticationPolicy                 : {}
AuthenticationPolicySilo             : {}
BadLogonCount                        : 0
badPasswordTime                      : 0
badPwdCount                          : 0
CannotChangePassword                 : False
CanonicalName                        : za.tryhackme.com/People/Consulting/gordon.stevens
Certificates                         : {}
City                                 :
CN                                   : gordon.stevens
codePage                             : 0
Company                              :
CompoundIdentitySupported            : {}
Country                              :
countryCode                          : 0
Created                              : 2/24/2022 10:06:44 PM
createTimeStamp                      : 2/24/2022 10:06:44 PM
Deleted                              :
Department                           : Consulting
Description                          :
DisplayName                          : Gordon Stevens
DistinguishedName                    : CN=gordon.stevens,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com
Division                             :
DoesNotRequirePreAuth                : False
dSCorePropagationData                : {1/1/1601 12:00:00 AM}
EmailAddress                         :
EmployeeID                           :
EmployeeNumber                       :
Enabled                              : True
Fax                                  :
GivenName                            : Gordon
HomeDirectory                        :
HomedirRequired                      : False
HomeDrive                            :
HomePage                             :
HomePhone                            :
Initials                             :
instanceType                         : 4
isDeleted                            :
KerberosEncryptionType               : {}
LastBadPasswordAttempt               :
LastKnownParent                      :
lastLogoff                           : 0
lastLogon                            : 132908987618422496
LastLogonDate                        : 4/29/2022 11:13:07 PM
lastLogonTimestamp                   : 132957439878817675
LockedOut                            : False
logonCount                           : 4
LogonWorkstations                    :
Manager                              :
MemberOf                             : {CN=Internet Access,OU=Groups,DC=za,DC=tryhackme,DC=com}
MNSLogonAccount                      : False
MobilePhone                          :
Modified                             : 4/29/2022 11:13:07 PM
modifyTimeStamp                      : 4/29/2022 11:13:07 PM
msDS-User-Account-Control-Computed   : 0
Name                                 : gordon.stevens
nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                       : CN=Person,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                          : user
ObjectGUID                           : 48ddd5f1-37ae-4040-a281-47dd58313fcb
objectSid                            : S-1-5-21-3330634377-1326264276-632209373-3058
Office                               :
OfficePhone                          :
Organization                         :
OtherName                            :
PasswordExpired                      : False
PasswordLastSet                      : 2/24/2022 10:06:44 PM
PasswordNeverExpires                 : False
PasswordNotRequired                  : False
POBox                                :
PostalCode                           :
PrimaryGroup                         : CN=Domain Users,CN=Users,DC=za,DC=tryhackme,DC=com
primaryGroupID                       : 513
PrincipalsAllowedToDelegateToAccount : {}
ProfilePath                          :
ProtectedFromAccidentalDeletion      : False
pwdLastSet                           : 132902140043901058
SamAccountName                       : gordon.stevens
sAMAccountType                       : 805306368
ScriptPath                           :
sDRightsEffective                    : 0
ServicePrincipalNames                : {}
SID                                  : S-1-5-21-3330634377-1326264276-632209373-3058
SIDHistory                           : {}
SmartcardLogonRequired               : False
sn                                   : Stevens
State                                :
StreetAddress                        :
Surname                              : Stevens
Title                                : Mid-level
TrustedForDelegation                 : False
TrustedToAuthForDelegation           : False
UseDESKeyOnly                        : False
userAccountControl                   : 512
userCertificate                      : {}
UserPrincipalName                    :
uSNChanged                           : 103860
uSNCreated                           : 30825
whenChanged                          : 4/29/2022 11:13:07 PM
whenCreated                          : 2/24/2022 10:06:44 PM



PS C:\Users\tony.holland> Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table Name,SamAccountName -A

Name             SamAccountName
----             --------------
chloe.stevens    chloe.stevens
samantha.stevens samantha.stevens
mohammed.stevens mohammed.stevens
jacob.stevens    jacob.stevens
timothy.stevens  timothy.stevens
trevor.stevens   trevor.stevens
owen.stevens     owen.stevens
jane.stevens     jane.stevens
janice.stevens   janice.stevens
gordon.stevens   gordon.stevens


PS C:\Users\tony.holland> Get-ADGroup -Identity Administrators -Server za.tryhackme.com


DistinguishedName : CN=Administrators,CN=Builtin,DC=za,DC=tryhackme,DC=com
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Administrators
ObjectClass       : group
ObjectGUID        : f4d1cbcd-4a6f-4531-8550-0394c3273c4f
SamAccountName    : Administrators
SID               : S-1-5-32-544



PS C:\Users\tony.holland> Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com


distinguishedName : CN=Domain Admins,CN=Users,DC=za,DC=tryhackme,DC=com
name              : Domain Admins
objectClass       : group
objectGUID        : 8a6186e5-e20f-4f13-b1b0-067f3326f67c
SamAccountName    : Domain Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-512

distinguishedName : CN=Enterprise Admins,CN=Users,DC=za,DC=tryhackme,DC=com
name              : Enterprise Admins
objectClass       : group
objectGUID        : 93846b04-25b9-4915-baca-e98cce4541c6
SamAccountName    : Enterprise Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-519

distinguishedName : CN=vagrant,CN=Users,DC=za,DC=tryhackme,DC=com
name              : vagrant
objectClass       : user
objectGUID        : ed901eff-9ec0-4851-ba32-7a26a8f0858f
SamAccountName    : vagrant
SID               : S-1-5-21-3330634377-1326264276-632209373-1000

distinguishedName : CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com
name              : Administrator
objectClass       : user
objectGUID        : b10fe384-bcce-450b-85c8-218e3c79b30f
SamAccountName    : Administrator
SID               : S-1-5-21-3330634377-1326264276-632209373-500



PS C:\Users\tony.holland>  $ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
PS C:\Users\tony.holland> Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com


Deleted           :
DistinguishedName : DC=za,DC=tryhackme,DC=com
Name              : za
ObjectClass       : domainDNS
ObjectGUID        : 518ee1e7-f427-4e91-a081-bb75e655ce7a

Deleted           :
DistinguishedName : CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com
Name              : Administrator
ObjectClass       : user
ObjectGUID        : b10fe384-bcce-450b-85c8-218e3c79b30f

Deleted           :
DistinguishedName : CN=vagrant,CN=Users,DC=za,DC=tryhackme,DC=com
Name              : vagrant
ObjectClass       : user
ObjectGUID        : ed901eff-9ec0-4851-ba32-7a26a8f0858f

Deleted           :
DistinguishedName : CN=THMDC,OU=Domain Controllers,DC=za,DC=tryhackme,DC=com
Name              : THMDC
ObjectClass       : computer
ObjectGUID        : 910d503f-f1ba-428c-b5ea-14fc2b6972a0

Deleted           :
DistinguishedName : CN=Domain Admins,CN=Users,DC=za,DC=tryhackme,DC=com
Name              : Domain Admins
ObjectClass       : group
ObjectGUID        : 8a6186e5-e20f-4f13-b1b0-067f3326f67c

Deleted           :
DistinguishedName : CN=RID Manager$,CN=System,DC=za,DC=tryhackme,DC=com
Name              : RID Manager$
ObjectClass       : rIDManager
ObjectGUID        : 2fc1c4ed-1d56-491f-a293-26032ed3fe5c

Deleted           :
DistinguishedName : CN=RID Set,CN=THMDC,OU=Domain Controllers,DC=za,DC=tryhackme,DC=com
Name              : RID Set
ObjectClass       : rIDSet
ObjectGUID        : 98604f43-623e-409c-948d-b6e31c3749f2

Deleted           :
DistinguishedName : OU=Servers,DC=za,DC=tryhackme,DC=com
Name              : Servers
ObjectClass       : organizationalUnit
ObjectGUID        : e1bd8860-0730-41bd-9c2a-c3037c4e7aa7

Deleted           :
DistinguishedName : OU=Workstations,DC=za,DC=tryhackme,DC=com
Name              : Workstations
ObjectClass       : organizationalUnit
ObjectGUID        : c49b0279-e36a-4f25-862d-b8f8326c940e

Deleted           :
DistinguishedName : OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : Admins
ObjectClass       : organizationalUnit
ObjectGUID        : 44828fce-e037-4cd3-96f6-20edc4bcd8fc

Deleted           :
DistinguishedName : CN=Tier 0 Admins,OU=Groups,DC=za,DC=tryhackme,DC=com
Name              : Tier 0 Admins
ObjectClass       : group
ObjectGUID        : ce3298cf-bf26-479f-a053-9b993e5a6e55

Deleted           :
DistinguishedName : CN=roy.perry,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com
Name              : roy.perry
ObjectClass       : user
ObjectGUID        : fa25d286-ff1f-4125-bae0-29acac3ed63a

Deleted           :
DistinguishedName : CN=denise.jenkins,OU=Finance,OU=People,DC=za,DC=tryhackme,DC=com
Name              : denise.jenkins
ObjectClass       : user
ObjectGUID        : 4fe20438-e4c8-417b-aa87-5ae140386a30

Deleted           :
DistinguishedName : CN=gemma.lyons,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com
Name              : gemma.lyons
ObjectClass       : user
ObjectGUID        : 6d1115e6-d085-4f25-b453-28cb4b6a96f6

Deleted           :
DistinguishedName : CN=kerry.murray,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com
Name              : kerry.murray
ObjectClass       : user
ObjectGUID        : f0bb8993-f32e-4ebe-8383-9823d72e7b07

Deleted           :
DistinguishedName : CN=darren.davis,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com
Name              : darren.davis
ObjectClass       : user
ObjectGUID        : a9190d98-2fc6-48f1-803a-103a7207f57b

Deleted           :
DistinguishedName : CN=kenneth.davies,OU=Sales,OU=People,DC=za,DC=tryhackme,DC=com
Name              : kenneth.davies
ObjectClass       : user
ObjectGUID        : 9e8e905e-384f-4acf-bf40-3fbf640981e8

Deleted           :
DistinguishedName : CN=graeme.williams,OU=IT,OU=People,DC=za,DC=tryhackme,DC=com
Name              : graeme.williams
ObjectClass       : user
ObjectGUID        : 9d79da0b-f510-4cad-bfc5-15353ba6989e

Deleted           :
DistinguishedName : CN=lynda.franklin,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com
Name              : lynda.franklin
ObjectClass       : user
ObjectGUID        : 746bfc1d-5b7d-4529-94aa-df37580a231b

Deleted           :
DistinguishedName : CN=rachel.dunn,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com
Name              : rachel.dunn
ObjectClass       : user
ObjectGUID        : 806db00b-7887-4737-b98f-83875cc93bc2

Deleted           :
DistinguishedName : CN=mandy.bryan,OU=IT,OU=People,DC=za,DC=tryhackme,DC=com
Name              : mandy.bryan
ObjectClass       : user
ObjectGUID        : 5e12031a-2501-42c5-9088-cb40263f66be

Deleted           :
DistinguishedName : CN=kimberley.smith,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com
Name              : kimberley.smith
ObjectClass       : user
ObjectGUID        : cef07387-1b1c-43fe-9667-5ece32758021

Deleted           :
DistinguishedName : CN=joel.pearce,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com
Name              : joel.pearce
ObjectClass       : user
ObjectGUID        : 77a78d58-d4e0-4f02-a987-ea11811d8e99

Deleted           :
DistinguishedName : CN=ricky.barker,OU=Sales,OU=People,DC=za,DC=tryhackme,DC=com
Name              : ricky.barker
ObjectClass       : user
ObjectGUID        : 7b694eb9-7876-4525-ae76-f6b116d7e699

Deleted           :
DistinguishedName : CN=maurice.palmer,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com
Name              : maurice.palmer
ObjectClass       : user
ObjectGUID        : 152c3bd1-5490-4e02-9811-2edaf6d2973b

Deleted           :
DistinguishedName : CN=leslie.young,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com
Name              : leslie.young
ObjectClass       : user
ObjectGUID        : 3ab61eba-0cee-4c14-870c-9eba80d46481

Deleted           :
DistinguishedName : CN=david.cook,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com
Name              : david.cook
ObjectClass       : user
ObjectGUID        : fc4db1bb-a5c5-4044-83b9-5fb858a13eed

Deleted           :
DistinguishedName : CN=elliott.allen,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com
Name              : elliott.allen
ObjectClass       : user
ObjectGUID        : b293b522-e062-4345-87f6-8f94e483669d

Deleted           :
DistinguishedName : CN=kathryn.dickinson,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com
Name              : kathryn.dickinson
ObjectClass       : user
ObjectGUID        : 8c70aaaa-751f-4741-afc0-c32de7ae1dba

Deleted           :
DistinguishedName : CN=arthur.campbell,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com
Name              : arthur.campbell
ObjectClass       : user
ObjectGUID        : c77a6fc9-0f93-4432-a87e-59b74b995b46

Deleted           :
DistinguishedName : CN=jenna.field,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com
Name              : jenna.field
ObjectClass       : user
ObjectGUID        : bee824a1-cefe-4029-b304-7e31c0bc2d40

Deleted           :
DistinguishedName : CN=tony.holland,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com
Name              : tony.holland
ObjectClass       : user
ObjectGUID        : 87a8f74d-5115-4015-b48b-97f00050a862

Deleted           :
DistinguishedName : CN=t2_henry.taylor,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_henry.taylor
ObjectClass       : user
ObjectGUID        : 3694f78c-9eca-433b-b8b9-25490efd1a88

Deleted           :
DistinguishedName : CN=declan.clarke,OU=Sales,OU=People,DC=za,DC=tryhackme,DC=com
Name              : declan.clarke
ObjectClass       : user
ObjectGUID        : 4a31ca0d-1ef6-477a-9d03-fadb9b2dac91

Deleted           :
DistinguishedName : CN=t2_sophie.davies,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_sophie.davies
ObjectClass       : user
ObjectGUID        : a4571ce7-379f-40bd-afa8-ee07ddd817de

Deleted           :
DistinguishedName : CN=t2_brian.wilson,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_brian.wilson
ObjectClass       : user
ObjectGUID        : 26379709-3acd-4d54-8d9e-e0596800c474

Deleted           :
DistinguishedName : CN=t2_christian.goodwin,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_christian.goodwin
ObjectClass       : user
ObjectGUID        : 11c5d432-3067-44ce-afbd-40966f970ee1

Deleted           :
DistinguishedName : CN=t2_chloe.carter,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_chloe.carter
ObjectClass       : user
ObjectGUID        : 94b6f97a-1939-4fdb-bea2-2e18f752989c

Deleted           :
DistinguishedName : CN=t2_victor.fisher,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_victor.fisher
ObjectClass       : user
ObjectGUID        : ef283309-56a5-4506-b227-c0f673cc6ec1

Deleted           :
DistinguishedName : CN=t1_arthur.tyler,OU=T1,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t1_arthur.tyler
ObjectClass       : user
ObjectGUID        : 77f38ece-c0dd-4991-b02b-3365f64ff539

Deleted           :
DistinguishedName : CN=philip.clements,OU=IT,OU=People,DC=za,DC=tryhackme,DC=com
Name              : philip.clements
ObjectClass       : user
ObjectGUID        : fa0d43e1-7e1c-4d2c-be18-fedfcbae9931

Deleted           :
DistinguishedName : CN=t2_philip.clements,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_philip.clements
ObjectClass       : user
ObjectGUID        : 7fa9d895-7933-4bd6-a605-4f57abee8fb5

Deleted           :
DistinguishedName : CN=t2_jane.oneill,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_jane.oneill
ObjectClass       : user
ObjectGUID        : 0c04f516-d52c-4211-b961-517c6e4cb666

Deleted           :
DistinguishedName : CN=t1_henry.miller,OU=T1,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t1_henry.miller
ObjectClass       : user
ObjectGUID        : d15c1146-6fef-40f5-82d3-beed3aad89bc

Deleted           :
DistinguishedName : CN=t2_natasha.scott,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_natasha.scott
ObjectClass       : user
ObjectGUID        : eb050fba-2275-4074-86ab-7ba46ae702cc

Deleted           :
DistinguishedName : CN=t2_craig.iqbal,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_craig.iqbal
ObjectClass       : user
ObjectGUID        : 7dea6022-9877-43c7-93a5-de24add0745c

Deleted           :
DistinguishedName : CN=t1_gary.moss,OU=T1,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t1_gary.moss
ObjectClass       : user
ObjectGUID        : 7de2e387-b70f-4c78-9709-2b3d13be159a

Deleted           :
DistinguishedName : CN=t2_gerard.davis,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_gerard.davis
ObjectClass       : user
ObjectGUID        : 749c77fe-fa54-4c3c-9191-2a2503cc38c0

Deleted           :
DistinguishedName : CN=t2_zoe.watson,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_zoe.watson
ObjectClass       : user
ObjectGUID        : 94d1c24d-a83a-448f-b193-9721b72ba2bc

Deleted           :
DistinguishedName : CN=t1_jill.wallis,OU=T1,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t1_jill.wallis
ObjectClass       : user
ObjectGUID        : 5267ea24-623e-4dd4-91aa-50c936b576fb

Deleted           :
DistinguishedName : CN=t2_tom.bray,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_tom.bray
ObjectClass       : user
ObjectGUID        : 45f6cf25-3b4d-4cef-a9c0-dec3a81a0272

Deleted           :
DistinguishedName : CN=t2_marian.yates,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_marian.yates
ObjectClass       : user
ObjectGUID        : 44c3b9c3-9374-45aa-abff-7684ca1b9251

Deleted           :
DistinguishedName : CN=t1_marian.yates,OU=T1,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t1_marian.yates
ObjectClass       : user
ObjectGUID        : c150fdff-2de0-4a8d-ae2f-b335b442e272

Deleted           :
DistinguishedName : CN=t2_jeremy.leonard,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t2_jeremy.leonard
ObjectClass       : user
ObjectGUID        : de51ba44-1949-4873-9d15-1fa7b952bc2b

Deleted           :
DistinguishedName : CN=t1_rosie.bryant,OU=T1,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t1_rosie.bryant
ObjectClass       : user
ObjectGUID        : 8f5e9057-0e9c-4d74-b8af-0d4fe1b25219

Deleted           :
DistinguishedName : CN=georgina.edwards,OU=Sales,OU=People,DC=za,DC=tryhackme,DC=com
Name              : georgina.edwards
ObjectClass       : user
ObjectGUID        : 65c5a0d4-d9ee-4d86-8a40-c3e3d872f6a7

Deleted           :
DistinguishedName : CN=t1_joel.stephenson,OU=T1,OU=Admins,DC=za,DC=tryhackme,DC=com
Name              : t1_joel.stephenson
ObjectClass       : user
ObjectGUID        : 2d6bea54-92f7-4b3a-adbc-c5668ef76d98

Deleted           :
DistinguishedName : CN=gordon.stevens,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com
Name              : gordon.stevens
ObjectClass       : user
ObjectGUID        : 48ddd5f1-37ae-4040-a281-47dd58313fcb

Deleted           :
DistinguishedName : CN=hollie.powell,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com
Name              : hollie.powell
ObjectClass       : user
ObjectGUID        : 4efd3e8d-7cf0-47ff-886d-f1c3272352c5

Deleted           :
DistinguishedName : CN=heather.smith,OU=Finance,OU=People,DC=za,DC=tryhackme,DC=com
Name              : heather.smith
ObjectClass       : user
ObjectGUID        : faba5407-bc02-40f8-b38e-769c6f937df2

Deleted           :
DistinguishedName : CN=THMIIS,OU=Servers,DC=za,DC=tryhackme,DC=com
Name              : THMIIS
ObjectClass       : computer
ObjectGUID        : 7c2e5818-c919-4445-8e7a-28471db7ec68

Deleted           :
DistinguishedName : CN=THMMDT,OU=Servers,DC=za,DC=tryhackme,DC=com
Name              : THMMDT
ObjectClass       : computer
ObjectGUID        : 0eee4895-630f-4c92-8876-aac054fa869a

Deleted           :
DistinguishedName : CN=THMMDT-Remote-Installation-Services,CN=THMMDT,OU=Servers,DC=za,DC=tryhackme,DC=com
Name              : THMMDT-Remote-Installation-Services
ObjectClass       : intellimirrorSCP
ObjectGUID        : 86c9991e-ff39-4f49-b40e-780477d8e7f4

Deleted           :
DistinguishedName : OU=Contoso,DC=za,DC=tryhackme,DC=com
Name              : Contoso
ObjectClass       : organizationalUnit
ObjectGUID        : e4db5c03-a2ed-4901-bae4-0a3073bdaa23

Deleted           :
DistinguishedName : OU=ZA,DC=za,DC=tryhackme,DC=com
Name              : ZA
ObjectClass       : organizationalUnit
ObjectGUID        : a79a2fc8-924a-4b63-a9d6-87fb6c048bd7

Deleted           :
DistinguishedName : OU=Accounts,OU=ZA,DC=za,DC=tryhackme,DC=com
Name              : Accounts
ObjectClass       : organizationalUnit
ObjectGUID        : d4aa1a43-0a97-4989-ae26-dbaa9b0009e1

Deleted           :
DistinguishedName : OU=Computers,OU=ZA,DC=za,DC=tryhackme,DC=com
Name              : Computers
ObjectClass       : organizationalUnit
ObjectGUID        : af9a241c-25c8-4858-a73c-add4c1e30cb7

Deleted           :
DistinguishedName : OU=Groups,OU=ZA,DC=za,DC=tryhackme,DC=com
Name              : Groups
ObjectClass       : organizationalUnit
ObjectGUID        : a7b9169b-1c00-49ed-9ad2-624c088ff399

Deleted           :
DistinguishedName : OU=Admins,OU=Accounts,OU=ZA,DC=za,DC=tryhackme,DC=com
Name              : Admins
ObjectClass       : organizationalUnit
ObjectGUID        : be9e8635-f448-452a-afe1-39e0393bb310

Deleted           :
DistinguishedName : OU=Service Accounts,OU=Accounts,OU=ZA,DC=za,DC=tryhackme,DC=com
Name              : Service Accounts
ObjectClass       : organizationalUnit
ObjectGUID        : ee0d86b4-846c-444d-822c-94126c92b743

Deleted           :
DistinguishedName : OU=Users,OU=Accounts,OU=ZA,DC=za,DC=tryhackme,DC=com
Name              : Users
ObjectClass       : organizationalUnit
ObjectGUID        : c8390136-c7f3-4466-abbd-ef47be17d9b3

Deleted           :
DistinguishedName : OU=Servers,OU=Computers,OU=ZA,DC=za,DC=tryhackme,DC=com
Name              : Servers
ObjectClass       : organizationalUnit
ObjectGUID        : 2b074e78-8bea-43fa-962e-77c3f7f786a3

Deleted           :
DistinguishedName : OU=Workstations,OU=Computers,OU=ZA,DC=za,DC=tryhackme,DC=com
Name              : Workstations
ObjectClass       : organizationalUnit
ObjectGUID        : b540f93f-9966-457e-a26b-f02844affcfe

Deleted           :
DistinguishedName : OU=Security Groups,OU=Groups,OU=ZA,DC=za,DC=tryhackme,DC=com
Name              : Security Groups
ObjectClass       : organizationalUnit
ObjectGUID        : 30df9cd3-ddf8-4459-b736-c874bbf7be43

Deleted           :
DistinguishedName : CN=svcMDT,CN=Users,DC=za,DC=tryhackme,DC=com
Name              : svcMDT
ObjectClass       : user
ObjectGUID        : 79afaf43-e9a8-4cd9-81ea-51a3b0e7b2b3

Deleted           :
DistinguishedName : CN=svcLDAP,CN=Users,DC=za,DC=tryhackme,DC=com
Name              : svcLDAP
ObjectClass       : user
ObjectGUID        : 1bcdaea3-0725-4974-b5be-55b3e17418ae
          
PS C:\Users\tony.holland> Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com

DistinguishedName                                                        Name              ObjectClass ObjectGUID
-----------------                                                        ----              ----------- ----------
CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com                      Administrator     user        b10fe384-bcce-450b-85c8-218e3c79b30f
CN=maurice.palmer,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com      maurice.palmer    user        152c3bd1-5490-4e02-9811-2edaf6d2973b
CN=henry.taylor,OU=IT,OU=People,DC=za,DC=tryhackme,DC=com                henry.taylor      user        154e4541-219e-4fa9-a5bf-ec5a367c5e21
CN=frank.fletcher,OU=IT,OU=People,DC=za,DC=tryhackme,DC=com              frank.fletcher    user        3dd92645-4b2d-4ba0-957c-9f6c20421d54
CN=henry.black,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com        henry.black       user        379df099-f89b-47fa-886d-ae915e2f8d32
CN=mark.oconnor,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com       mark.oconnor      user        e0bb6195-9f2e-4de1-83a5-0f9613a28e8f
CN=dawn.hughes,OU=Finance,OU=People,DC=za,DC=tryhackme,DC=com            dawn.hughes       user        fed968f3-3e5e-4d36-b66a-289ddb6e8db2
CN=joanne.davies,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com        joanne.davies     user        81b8d2ab-d3e1-4316-8115-9d305a0824b8
CN=alan.jones,OU=Human Resources,OU=People,DC=za,DC=tryhackme,DC=com     alan.jones        user        88922cf5-828b-48f4-ab30-86d37381233c
CN=maria.sheppard,OU=Human Resources,OU=People,DC=za,DC=tryhackme,DC=com maria.sheppard    user        edeffae5-eb5c-4c4a-8ba1-64e750e84fbe
CN=sophie.blackburn,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com    sophie.blackburn  user        e2854343-659c-4b90-94ac-111af7c60ce3
CN=dominic.elliott,OU=Finance,OU=People,DC=za,DC=tryhackme,DC=com        dominic.elliott   user        2a5eabcc-0bff-4341-a2ce-f14fc1621894
CN=louise.talbot,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com       louise.talbot     user        b5fe09ec-935d-4158-8413-3b596da9e11c
CN=jennifer.wood,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com      jennifer.wood     user        90d6e815-5260-4a26-b5c3-b3fb6a28f192
CN=frances.chapman,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com    frances.chapman   user        26616091-bb69-4182-99e7-41d61e578034
CN=dawn.turner,OU=Finance,OU=People,DC=za,DC=tryhackme,DC=com            dawn.turner       user        178cb599-6a57-41cb-94b6-30415f04a008
CN=samantha.thompson,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com  samantha.thompson user        f78decbb-6ec8-40bb-9190-af2193a23ee5
CN=anthony.reynolds,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com     anthony.reynolds  user        ab44469f-8752-4bb7-bd36-10e6705028e4


PS C:\Users\tony.holland> Get-ADDomain -Server za.tryhackme.com


AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=za,DC=tryhackme,DC=com
DeletedObjectsContainer            : CN=Deleted Objects,DC=za,DC=tryhackme,DC=com
DistinguishedName                  : DC=za,DC=tryhackme,DC=com
DNSRoot                            : za.tryhackme.com
DomainControllersContainer         : OU=Domain Controllers,DC=za,DC=tryhackme,DC=com
DomainMode                         : Windows2012R2Domain
DomainSID                          : S-1-5-21-3330634377-1326264276-632209373
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=za,DC=tryhackme,DC=com
Forest                             : za.tryhackme.com
InfrastructureMaster               : THMDC.za.tryhackme.com
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=za,DC=tryhackme,DC=com}
LostAndFoundContainer              : CN=LostAndFound,DC=za,DC=tryhackme,DC=com
ManagedBy                          :
Name                               : za
NetBIOSName                        : ZA
ObjectClass                        : domainDNS
ObjectGUID                         : 518ee1e7-f427-4e91-a081-bb75e655ce7a
ParentDomain                       :
PDCEmulator                        : THMDC.za.tryhackme.com
PublicKeyRequiredPasswordRolling   :
QuotasContainer                    : CN=NTDS Quotas,DC=za,DC=tryhackme,DC=com
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {THMDC.za.tryhackme.com}
RIDMaster                          : THMDC.za.tryhackme.com
SubordinateReferences              : {DC=ForestDnsZones,DC=za,DC=tryhackme,DC=com, DC=DomainDnsZones,DC=za,DC=tryhackme,DC=com, CN=Configuration,DC=za,DC=tryhackme,DC=com}
SystemsContainer                   : CN=System,DC=za,DC=tryhackme,DC=com
UsersContainer                     : CN=Users,DC=za,DC=tryhackme,DC=com



PS C:\Users\tony.holland> Set-ADAccountPassword -Identity gordon.stevens -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)
Set-ADAccountPassword : The specified network password is not correct
At line:1 char:1
+ Set-ADAccountPassword -Identity gordon.stevens -Server za.tryhackme.c ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidData: (gordon.stevens:ADAccount) [Set-ADAccountPassword], ADInvalidPasswordException
    + FullyQualifiedErrorId : ActiveDirectoryServer:86,Microsoft.ActiveDirectory.Management.Commands.SetADAccountPassword

PS C:\Users\tony.holland> Set-ADAccountPassword -Identity tony.holland -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "Mhvn2334" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "ajith123" -Force)
Set-ADAccountPassword : The password does not meet the length, complexity, or history requirement of the domain.
At line:1 char:1
+ Set-ADAccountPassword -Identity tony.holland -Server za.tryhackme.com ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidData: (tony.holland:ADAccount) [Set-ADAccountPassword], ADPasswordComplexityException
    + FullyQualifiedErrorId : ActiveDirectoryServer:1325,Microsoft.ActiveDirectory.Management.Commands.SetADAccountPassword

PS C:\Users\tony.holland> Set-ADAccountPassword -Identity tony.holland -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "Mhvn2334" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "ajith12345" -Force)
Set-ADAccountPassword : The password does not meet the length, complexity, or history requirement of the domain.
At line:1 char:1
+ Set-ADAccountPassword -Identity tony.holland -Server za.tryhackme.com ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidData: (tony.holland:ADAccount) [Set-ADAccountPassword], ADPasswordComplexityException
    + FullyQualifiedErrorId : ActiveDirectoryServer:1325,Microsoft.ActiveDirectory.Management.Commands.SetADAccountPassword

PS C:\Users\tony.holland> Get-ADUser -Identity beth.nolan -Server za.tryhackme.com -Properties *


AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
AccountNotDelegated                  : False
AllowReversiblePasswordEncryption    : False
AuthenticationPolicy                 : {}
AuthenticationPolicySilo             : {}
BadLogonCount                        : 0
badPasswordTime                      : 0
badPwdCount                          : 0
CannotChangePassword                 : False
CanonicalName                        : za.tryhackme.com/People/Sales/beth.nolan
Certificates                         : {}
City                                 :
CN                                   : beth.nolan
codePage                             : 0
Company                              :
CompoundIdentitySupported            : {}
Country                              :
countryCode                          : 0
Created                              : 2/24/2022 10:06:25 PM
createTimeStamp                      : 2/24/2022 10:06:25 PM
Deleted                              :
Department                           : Sales
Description                          :
DisplayName                          : Beth Nolan
DistinguishedName                    : CN=beth.nolan,OU=Sales,OU=People,DC=za,DC=tryhackme,DC=com
Division                             :
DoesNotRequirePreAuth                : False
dSCorePropagationData                : {1/1/1601 12:00:00 AM}
EmailAddress                         :
EmployeeID                           :
EmployeeNumber                       :
Enabled                              : True
Fax                                  :
GivenName                            : Beth
HomeDirectory                        :
HomedirRequired                      : False
HomeDrive                            :
HomePage                             :
HomePhone                            :
Initials                             :
instanceType                         : 4
isDeleted                            :
KerberosEncryptionType               : {}
LastBadPasswordAttempt               :
LastKnownParent                      :
lastLogoff                           : 0
lastLogon                            : 0
LastLogonDate                        :
LockedOut                            : False
logonCount                           : 0
LogonWorkstations                    :
Manager                              :
MemberOf                             : {CN=Internet Access,OU=Groups,DC=za,DC=tryhackme,DC=com}
MNSLogonAccount                      : False
MobilePhone                          :
Modified                             : 2/24/2022 10:06:25 PM
modifyTimeStamp                      : 2/24/2022 10:06:25 PM
msDS-User-Account-Control-Computed   : 0
Name                                 : beth.nolan
nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                       : CN=Person,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                          : user
ObjectGUID                           : c4ae7c4c-4f98-4366-b3a1-c57debe3256f
objectSid                            : S-1-5-21-3330634377-1326264276-632209373-2760
Office                               :
OfficePhone                          :
Organization                         :
OtherName                            :
PasswordExpired                      : False
PasswordLastSet                      : 2/24/2022 10:06:25 PM
PasswordNeverExpires                 : False
PasswordNotRequired                  : False
POBox                                :
PostalCode                           :
PrimaryGroup                         : CN=Domain Users,CN=Users,DC=za,DC=tryhackme,DC=com
primaryGroupID                       : 513
PrincipalsAllowedToDelegateToAccount : {}
ProfilePath                          :
ProtectedFromAccidentalDeletion      : False
pwdLastSet                           : 132902139856391082
SamAccountName                       : beth.nolan
sAMAccountType                       : 805306368
ScriptPath                           :
sDRightsEffective                    : 0
ServicePrincipalNames                : {}
SID                                  : S-1-5-21-3330634377-1326264276-632209373-2760
SIDHistory                           : {}
SmartcardLogonRequired               : False
sn                                   : Nolan
State                                :
StreetAddress                        :
Surname                              : Nolan
Title                                : Senior
TrustedForDelegation                 : False
TrustedToAuthForDelegation           : False
UseDESKeyOnly                        : False
userAccountControl                   : 512
userCertificate                      : {}
UserPrincipalName                    :
uSNChanged                           : 28070
uSNCreated                           : 28066
whenChanged                          : 2/24/2022 10:06:25 PM
whenCreated                          : 2/24/2022 10:06:25 PM



PS C:\Users\tony.holland> Get-ADUser -Identity annette.manning -Server za.tryhackme.com -Properties *


AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
AccountNotDelegated                  : False
AllowReversiblePasswordEncryption    : False
AuthenticationPolicy                 : {}
AuthenticationPolicySilo             : {}
BadLogonCount                        : 0
badPasswordTime                      : 0
badPwdCount                          : 0
CannotChangePassword                 : False
CanonicalName                        : za.tryhackme.com/People/Marketing/annette.manning
Certificates                         : {}
City                                 :
CN                                   : annette.manning
codePage                             : 0
Company                              :
CompoundIdentitySupported            : {}
Country                              :
countryCode                          : 0
Created                              : 2/24/2022 10:04:50 PM
createTimeStamp                      : 2/24/2022 10:04:50 PM
Deleted                              :
Department                           : Marketing
Description                          :
DisplayName                          : Annette Manning
DistinguishedName                    : CN=annette.manning,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com
Division                             :
DoesNotRequirePreAuth                : False
dSCorePropagationData                : {1/1/1601 12:00:00 AM}
EmailAddress                         :
EmployeeID                           :
EmployeeNumber                       :
Enabled                              : True
Fax                                  :
GivenName                            : Annette
HomeDirectory                        :
HomedirRequired                      : False
HomeDrive                            :
HomePage                             :
HomePhone                            :
Initials                             :
instanceType                         : 4
isDeleted                            :
KerberosEncryptionType               : {}
LastBadPasswordAttempt               :
LastKnownParent                      :
lastLogoff                           : 0
lastLogon                            : 0
LastLogonDate                        :
LockedOut                            : False
logonCount                           : 0
LogonWorkstations                    :
Manager                              :
MemberOf                             : {CN=Internet Access,OU=Groups,DC=za,DC=tryhackme,DC=com}
MNSLogonAccount                      : False
MobilePhone                          :
Modified                             : 2/24/2022 10:04:50 PM
modifyTimeStamp                      : 2/24/2022 10:04:50 PM
msDS-User-Account-Control-Computed   : 0
Name                                 : annette.manning
nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                       : CN=Person,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                          : user
ObjectGUID                           : 57069bf6-db28-4988-ac9e-0254ca51bb2f
objectSid                            : S-1-5-21-3330634377-1326264276-632209373-1257
Office                               :
OfficePhone                          :
Organization                         :
OtherName                            :
PasswordExpired                      : False
PasswordLastSet                      : 2/24/2022 10:04:50 PM
PasswordNeverExpires                 : False
PasswordNotRequired                  : False
POBox                                :
PostalCode                           :
PrimaryGroup                         : CN=Domain Users,CN=Users,DC=za,DC=tryhackme,DC=com
primaryGroupID                       : 513
PrincipalsAllowedToDelegateToAccount : {}
ProfilePath                          :
ProtectedFromAccidentalDeletion      : False
pwdLastSet                           : 132902138902335915
SamAccountName                       : annette.manning
sAMAccountType                       : 805306368
ScriptPath                           :
sDRightsEffective                    : 0
ServicePrincipalNames                : {}
SID                                  : S-1-5-21-3330634377-1326264276-632209373-1257
SIDHistory                           : {}
SmartcardLogonRequired               : False
sn                                   : Manning
State                                :
StreetAddress                        :
Surname                              : Manning
Title                                : Associate
TrustedForDelegation                 : False
TrustedToAuthForDelegation           : False
UseDESKeyOnly                        : False
userAccountControl                   : 512
userCertificate                      : {}
UserPrincipalName                    :
uSNChanged                           : 14150
uSNCreated                           : 14146
whenChanged                          : 2/24/2022 10:04:50 PM
whenCreated                          : 2/24/2022 10:04:50 PM



PS C:\Users\tony.holland> Get-ADGroup -Identity Administrators -Server za.tryhackme.com -Properties *


adminCount                      : 1
CanonicalName                   : za.tryhackme.com/Builtin/Administrators
CN                              : Administrators
Created                         : 2/24/2022 9:57:34 PM
createTimeStamp                 : 2/24/2022 9:57:34 PM
Deleted                         :
Description                     : Administrators have complete and unrestricted access to the computer/domain
DisplayName                     :
DistinguishedName               : CN=Administrators,CN=Builtin,DC=za,DC=tryhackme,DC=com
dSCorePropagationData           : {2/24/2022 10:13:48 PM, 2/24/2022 9:58:38 PM, 1/1/1601 12:04:16 AM}
GroupCategory                   : Security
GroupScope                      : DomainLocal
groupType                       : -2147483643
HomePage                        :
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       :
LastKnownParent                 :
ManagedBy                       :
member                          : {CN=Domain Admins,CN=Users,DC=za,DC=tryhackme,DC=com, CN=Enterprise Admins,CN=Users,DC=za,DC=tryhackme,DC=com, CN=vagrant,CN=Users,DC=za,DC=tryhackme,DC=com,
                                  CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com}
MemberOf                        : {}
Members                         : {CN=Domain Admins,CN=Users,DC=za,DC=tryhackme,DC=com, CN=Enterprise Admins,CN=Users,DC=za,DC=tryhackme,DC=com, CN=vagrant,CN=Users,DC=za,DC=tryhackme,DC=com,
                                  CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com}
Modified                        : 2/24/2022 10:13:48 PM
modifyTimeStamp                 : 2/24/2022 10:13:48 PM
Name                            : Administrators
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                     : group
ObjectGUID                      : f4d1cbcd-4a6f-4531-8550-0394c3273c4f
objectSid                       : S-1-5-32-544
ProtectedFromAccidentalDeletion : False
SamAccountName                  : Administrators
sAMAccountType                  : 536870912
sDRightsEffective               : 0
SID                             : S-1-5-32-544
SIDHistory                      : {}
systemFlags                     : -1946157056
uSNChanged                      : 31686
uSNCreated                      : 8200
whenChanged                     : 2/24/2022 10:13:48 PM
whenCreated                     : 2/24/2022 9:57:34 PM



PS C:\Users\tony.holland> Get-ADGroup -Identity Tier 2 Admins  -Server za.tryhackme.com -Properties *
Get-ADGroup : A positional parameter cannot be found that accepts argument '2'.
At line:1 char:1
+ Get-ADGroup -Identity Tier 2 Admins  -Server za.tryhackme.com -Proper ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (:) [Get-ADGroup], ParameterBindingException
    + FullyQualifiedErrorId : PositionalParameterNotFound,Microsoft.ActiveDirectory.Management.Commands.GetADGroup

PS C:\Users\tony.holland> Get-ADGroup -Identity "Tier 2 Admins" -Server za.tryhackme.com -Properties *


CanonicalName                   : za.tryhackme.com/Groups/Tier 2 Admins
CN                              : Tier 2 Admins
Created                         : 2/24/2022 10:04:41 PM
createTimeStamp                 : 2/24/2022 10:04:41 PM
Deleted                         :
Description                     :
DisplayName                     : Tier 2 Admins
DistinguishedName               : CN=Tier 2 Admins,OU=Groups,DC=za,DC=tryhackme,DC=com
dSCorePropagationData           : {1/1/1601 12:00:00 AM}
GroupCategory                   : Security
GroupScope                      : Global
groupType                       : -2147483646
HomePage                        :
instanceType                    : 4
isDeleted                       :
LastKnownParent                 :
ManagedBy                       :
member                          : {CN=t2_jeremy.leonard,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com, CN=t2_marian.yates,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com,
                                  CN=t2_tom.bray,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com, CN=t2_zoe.watson,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com...}
MemberOf                        : {}
Members                         : {CN=t2_jeremy.leonard,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com, CN=t2_marian.yates,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com,
                                  CN=t2_tom.bray,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com, CN=t2_zoe.watson,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com...}
Modified                        : 2/24/2022 10:06:21 PM
modifyTimeStamp                 : 2/24/2022 10:06:21 PM
Name                            : Tier 2 Admins
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                     : group
ObjectGUID                      : 6edab731-c305-4959-bd34-4ca1eefe2b3f
objectSid                       : S-1-5-21-3330634377-1326264276-632209373-1104
ProtectedFromAccidentalDeletion : False
SamAccountName                  : Tier 2 Admins
sAMAccountType                  : 268435456
sDRightsEffective               : 0
SID                             : S-1-5-21-3330634377-1326264276-632209373-1104
SIDHistory                      : {}
uSNChanged                      : 27391
uSNCreated                      : 12781
whenChanged                     : 2/24/2022 10:06:21 PM
whenCreated                     : 2/24/2022 10:04:41 PM



PS C:\Users\tony.holland> Get-ADGroup -Identity "Enterprise Admins" -Server za.tryhackme.com -Properties *


adminCount                      : 1
CanonicalName                   : za.tryhackme.com/Users/Enterprise Admins
CN                              : Enterprise Admins
Created                         : 2/24/2022 9:58:38 PM
createTimeStamp                 : 2/24/2022 9:58:38 PM
Deleted                         :
Description                     : Designated administrators of the enterprise
DisplayName                     :
DistinguishedName               : CN=Enterprise Admins,CN=Users,DC=za,DC=tryhackme,DC=com
dSCorePropagationData           : {2/24/2022 10:13:48 PM, 2/24/2022 9:58:38 PM, 1/1/1601 12:04:16 AM}
GroupCategory                   : Security
GroupScope                      : Universal
groupType                       : -2147483640
HomePage                        :
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       :
LastKnownParent                 :
ManagedBy                       :
member                          : {CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com}
MemberOf                        : {CN=Denied RODC Password Replication Group,CN=Users,DC=za,DC=tryhackme,DC=com, CN=Administrators,CN=Builtin,DC=za,DC=tryhackme,DC=com}
Members                         : {CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com}
Modified                        : 2/24/2022 10:13:48 PM
modifyTimeStamp                 : 2/24/2022 10:13:48 PM
Name                            : Enterprise Admins
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                     : group
ObjectGUID                      : 93846b04-25b9-4915-baca-e98cce4541c6
objectSid                       : S-1-5-21-3330634377-1326264276-632209373-519
ProtectedFromAccidentalDeletion : False
SamAccountName                  : Enterprise Admins
sAMAccountType                  : 268435456
sDRightsEffective               : 0
SID                             : S-1-5-21-3330634377-1326264276-632209373-519
SIDHistory                      : {}
uSNChanged                      : 31668
uSNCreated                      : 12339
whenChanged                     : 2/24/2022 10:13:48 PM
whenCreated                     : 2/24/2022 9:58:38 PM

```

