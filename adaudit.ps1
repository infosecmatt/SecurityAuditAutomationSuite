<#
.SYNOPSIS
    This script/function does - What?
    This script is designed to supplement IT security audits within the Windows AD environment. It collects a variety of information that is needed for PCI, SOX, SOC, internal audit, etc. and exports it into easy-to-use formats. The topics covered include: AD environment information, GPO, AD users, AD groups, and possibly more in the future.

.PARAMETER Credential
    The parameter 'Credential' is used to provide credentials that would allow access to a domain that the user device is not connected to. This is useful if a particular engagement involves multiple AD environments. If you use this parameter, you must also use '-Server' in order to identify the server to authenticate against.

.PARAMETER Server
    The parameter Server is used to identify the server to authenticate against using the credentials provided via the 'Credential' parameter. Both are required if you want to test an environment where the user device is not-joined. 

.NOTES
    Author: Matt Johnson
    Last Edit: 2020-05-23
    Version 1.0 - initial release

#>


<#
Parameters for non-domain test machines 
If the machine running the script is not-joined, specifying these parameters
will allow the script to authenticate to an LDAP server to run its queries.
No special administrative privileges are required for the credentials used to connect. 
#>
param( $Server, $Credential)

#For obvious reasons, the ActiveDirectory module is required by this script
if ( -not (Get-Module -ListAvailable -Name ActiveDirectory))
{
    Write-Host "Active Directory module not found. Exiting."
    return
}
Import-Module ActiveDirectory

#Script output location
New-Item -Path $PSScriptRoot -Name 'AuditScript-Output' -ItemType "directory"
$outpath = "$PSScriptRoot\AuditScript-Output"
New-Item -Path $outpath -Name 'report.txt' -ItemType "file"
$report = "$outpath\report.txt"
Write-Output "Script output is located within the $outpath directory."
Write-Output "The script report is located at $report."

AuditAD | Tee-Object -FilePath $report

function AuditAD() {
        Write-Output "AD Audit Script Results"  
        Write-Output "Date: $(Get-Date)"  

      #Only use the alternative connection parameters if they were supplied
      if( $Server -and $Credential )
      {
        $ServerPort = $Server.ToString() + ":389" #append ldap port to server
        New-PSDrive -name "ADAudit" -PSProvider ActiveDirectory -Root "" -Server $ServerPort -Credential $Credential | Out-Null #mount to provided server
        Push-Location ADAudit: | Out-Null
        NewReportSection #formatting the report
        "Server used: $Server"  
      }

      #Current User Information
      NewReportSection
      Write-Output "Current User Information"  
      Write-Output "-------------------------------------------------"  
      Write-Output "Current User: $env:USERNAME"  
      Write-Output "User Domain: $env:USERDOMAIN"  
      Write-Output "Computer Name: $env:COMPUTERNAME"  
      Write-Output "Logon Server: $env:LOGONSERVER"  

      #AD Domain Information
      NewReportSection
      Write-Output "Active Directory Domain Information"  
      Write-Output "-------------------------------------------------"  

      $ADDomain = Get-ADDomain
      $ADDomain
      Write-Output "NetBIOSName: $(($ADDomain | Select-Object NetBIOSName).NetBIOSName)"  
      Write-Output "DNSRoot: $(($ADDomain | Select-Object DNSRoot).DNSRoot)"  
      Write-Output "AD Forest: $(($ADDomain | Select-Object Forest).Forest)"  
      Write-Output "AD Functional Level: $(($ADDomain | Select-Object DomainMode).DomainMode.ToString())"  
      Write-Output "Root of directory information server tree:"  
      Get-ADRootDSE
      Write-Output "List of trusted objects for the domain:"
      Get-ADTrust -Filter *


      #Password and Group Policies
      NewReportSection
      Write-Output "Password and Group Policies"
      Write-Output "-------------------------------------------------"  
      Write-Output "Default Domain Password Policy: "  
      Get-ADDefaultDomainPasswordPolicy
      Get-GPOReport -All -ReportType HTML -Path "$outpath\GPOReportsAll.html"
      Get-GPOReport -All -ReportType XML -Path "$outpath\GPOReportsAll.xml"
      Write-Output "Group policies exported to $outpath\GPOReportsAll.html."

      #All AD Users
      NewReportSection
      Write-Output "Active Directory User Information"
      Write-Output "-------------------------------------------------"  
      $TotalUserList = Get-ADUser -filter *
      $TotalUserCount = ($TotalUserList | Measure-Object).Count
      Write-Output "Total User Count: $TotalUserCount"
      if ($TotalUserCount -gt 0) {
        $filename = $outpath + "\" + "AllUsers.csv"
        $TotalUserList | ConvertTo-Csv | Out-File $filename
      }
      $EnabledUserList = $TotalUserList | Where-Object {$_.Enabled -eq $true}
      $EnabledUserCount = ($EnabledUserList | Measure-Object).Count
      Write-Output "Enabled User Count: $EnabledUserCount"
      if ($EnabledUserCount -gt 0) {
        $filename = $outpath + "\" + "EnabledUsers.csv"
        $EnabledUserList | ConvertTo-Csv | Out-File $filename
      }
      $DisabledUserList = $TotalUserList | Where-Object {$_.Enabled -eq $false}
      $DisabledUserCount = ($TotalUserList | Where-Object {$_.Enabled -eq $false | Measure-Object}).Count
      Write-Output "Disabled User Count: $DisabledUserCount"
      if ($DisabledUserCount -gt 0) {
        $filename = $outpath + "\" + "DisabledUsers.csv"
        $DisabledUserList | ConvertTo-Csv | Out-File $filename
      }

      #Inactive Users (Users who have not authenticated within the last 90, 180, or 365 days) and Stale Passwords (Users who have not changed their password in 90, 180, or 365 days)
      $ActivityPeriods = 90, 180, 365

      foreach ($Period in $ActivityPeriods) {
        $InactiveUserList = ($EnabledUserList | Where-Object { ($_.LastLogonDate -lt (Get-Date).AddDays(-$Period)) } )
        $InactiveUserCount = ($InactiveUserList | Measure-Object).Count
        Write-Output "Number of users that have not logged in for $Period days: $InactiveUserCount"
        if ($InactiveUserCount -gt 0) {
          $filename = $outpath + "\" + $Period + "DaysInactive.csv"
          $InactiveUserList | ConvertTo-Csv | Out-File $filename
        }

        $StalePasswordList = ($EnabledUserList | Where-Object { ($_.WhenCreated -lt (Get-Date).AddDays( -$Period )) -and ($_.passwordLastSet -lt (Get-Date).AddDays( -$Period )) } )
        $StalePasswordCount = ($StalePasswordList | Measure-Object).Count
        Write-Output "Number of users that have not changed their password for $Period days: $StalePasswordCount"
        if ($StalePasswordCount -gt 0) {
          $filename = $outpath + "\" + $Period + "DaysNoPassChange.csv"
          $StalePasswordList | ConvertTo-Csv | Out-File $filename
        }
      }

      #Members of sensitive groups
      $SensitiveGroups = "administrators", "Domain Admins", "Schema Admins", "Enterprise Admins"

      foreach ($SensitiveGroup in $SensitiveGroups) {
        $MemberCount = 0
        $Members = ""

        $Members = (Get-ADGroupMember -Recursive -Identity $SensitiveGroup | Get-ADUser -Properties * | Select-Object Name, DistinguishedName, Enabled, whenCreated, whenChanged, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired,@{Name="Group Membership"; Expression = {Get-ADPrincipalGroupMembership $_.DistinguishedName | Select-Object Name | convertto-csv -NoTypeInformation | Select-Object -Skip 1}})
        $MemberCount = ($Members | Measure-Object).Count
        Write-Output "Number of members in the $SensitiveGroup group: $MemberCount"
        if ($MemberCount -gt 0) {
          $filename = $outpath + "\" + $SensitiveGroup.replace(' ', '-') + "Members.csv"
          $Members | ConvertTo-Csv | Out-File $filename
        }
      }

      #Members of all non-builtin groups
      $CustomGroups = (Get-ADGroup -Filter { GroupCategory -eq "Security" -and GroupScope -eq "Global"  } -Properties isCriticalSystemObject | Where-Object { !($_.IsCriticalSystemObject)})
      $CustomGroupCount = ($CustomGroups | Measure-Object).Count
      Write-Output "Number of custom groups: $CustomGroupCount"
      $invalidChars = [io.path]::GetInvalidFileNameChars()
      foreach ($Group in $CustomGroups) {
          $GroupMembers = $null
          $MemberCount = $null
          $filename = $null

          $GroupMembers = (Get-ADGroupMember -Identity $Group.DistinguishedName | Select-Object distinguishedname, name,@{Name="Group Membership"; Expression = {Get-ADPrincipalGroupMembership $_.DistinguishedName | Select-Object Name | convertto-csv -NoTypeInformation | Select-Object -Skip 1}})
          $MemberCount = ($GroupMembers | Measure-Object).Count
          Write-Output "Number of members in the $($Group.Name) group: $MemberCount"
          if ($MemberCount -gt 0) {
              $filename = $outpath + "\" + (($Group.Name).ToString() -replace "[$invalidChars]","-") + "Members" + ".csv"
              $GroupMembers | ConvertTo-Csv | Out-File $filename
          }
      }

      #Enabled users with password which never expires
      $PasswordNeverExpiresList = ($EnabledUserList | Where-Object {$_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true})
      $PasswordNeverExpiresCount = ($PasswordNeverExpiresList| Measure-Object).Count
      Write-Output "Number of users whose password never expires: $PasswordNeverExpiresCount"
      if ($PasswordNeverExpiresCount -gt 0) {
          $filename = $outpath + "\" + "PassNeverExpiresUsers" + ".csv"
          $PasswordNeverExpiresList | ConvertTo-Csv | Out-File $filename
      }

      #Enabled users with password which was never set
      $PasswordNeverSetList = $EnabledUserList | Where-Object { ($_.PasswordLastSet -eq $null) -and ($_.Created -lt (Get-Date).AddDays( -14 )) }
      $PasswordNeverSetCount = ($PasswordNeverSetList | Measure-Object).Count
      Write-Output "Number of users whose password was never set: $PasswordNeverSetCount"
      if ($PasswordNeverSetCount -gt 0) {
          $filename = $outpath + "\" + "PassNeverSetUsers" + ".csv"
          $PasswordNeverSetList | ConvertTo-Csv | Out-File $filename
      }

      #Enabled users with no password required
      $PasswordNotRequiredList = ($EnabledUserList | Where-Object {$_.PasswordNotRequired -eq $true})
      $PasswordNotRequiredCount = ( $PasswordNotRequiredList | Measure-Object).Count
      Write-Output "Number of users with no password required: $PasswordNotRequiredCount"
      if ($PasswordNotRequiredCount -gt 0) {
          $filename = $outpath + "\" + "PassNotRequiredUsers" + ".csv"
          $PasswordNotRequiredList | ConvertTo-Csv | Out-File $filename
      }

      #If the alternate connection was used, then get back to the original location and remove the PS drive
      #before exiting
      if( $Server -and $Credential )
      {
        Pop-Location
        Remove-PSDrive -name "ADAudit"
      }
}
function NewReportSection() {
        Write-Output "-------------------------------------------------"  
        Write-Output ""
        Write-Output ""
        Write-Output "-------------------------------------------------"  
      }