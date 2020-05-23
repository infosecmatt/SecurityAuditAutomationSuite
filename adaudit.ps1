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


#Parameters for non-domain test machines 
#If the machine running the script is not-joined, specifying these parameters
#will allow the script to authenticate to an LDAP server to run its queries.
#No special administrative privileges are required for the credentials used to connect.
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
echo "Script output is located within the $outpath directory."
echo "The script report is located at $report."

AuditAD | Tee-Object -FilePath $report

function AuditAD() {
        echo "AD Audit Script Results"  
        echo "Date: $(Get-Date)"  

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
      echo "Current User Information"  
      echo "-------------------------------------------------"  
      echo "Current User: $env:USERNAME"  
      echo "User Domain: $env:USERDOMAIN"  
      echo "Computer Name: $env:COMPUTERNAME"  
      echo "Logon Server: $env:LOGONSERVER"  

      #AD Domain Information
      NewReportSection
      echo "Active Directory Domain Information"  
      echo "-------------------------------------------------"  

      $ADDomain = Get-ADDomain
      $ADDomain  
      $NetBIOSName = ($ADDomain | Select-Object NetBIOSName).NetBIOSName
      echo "NetBIOSName: $NetBIOSName"  
      $DNSRoot = ($ADDomain | Select-Object DNSRoot).DNSRoot
      echo "DNSRoot: $DNSRoot"  
      $Forest = ($ADDomain | Select-Object Forest).Forest
      echo "AD Forest: $Forest"  
      $ADFunctionalLevel = ($ADDomain | Select-Object DomainMode).DomainMode.ToString()
      echo "AD Functional Level: $ADFunctionalLevel"  
      $ADRootDSE = Get-ADRootDSE
      echo "Root of directory information server tree:"  
      $ADRootDSE  
      $ADTrust = Get-ADTrust -Filter *

      #Group Policies
      echo "Default Domain Password Policy: "  
      Get-ADDefaultDomainPasswordPolicy  
      echo ""  
      echo "Password Policy for the Current User: "  
      Get-ADUserResultantPasswordPolicy -Identity $env:USERDOMAIN + '\' + $env:USERNAME  
      echo ''  
      Get-GPOReport -All -ReportType HTML -Path "$outpath\GPOReportsAll.html"
      Get-GPOReport -All -ReportType XML -Path "$outpath\GPOReportsAll.xml"

      #All AD Users
      $TotalUserList = Get-ADUser -filter *
      $TotalUserCount = ($TotalUserList | Measure-Object).Count
      $EnabledUserList = $TotalUserList | where {$_.Enabled -eq $true}
      $EnabledUserCount = ($EnabledUserList | Measure-Object).Count
      $DisabledUserList = $TotalUserList | where {$_.Enabled -eq $false}
      $DisableUserCount = ($TotalUserList | where {$_.Enabled -eq $false | Measure-Object}).Count

      #Inactive Users (Users who have not authenticated within the last 90, 180, or 365 days) and Stale Passwords (Users who have not changed their password in 90, 180, or 365 days)
      $ActivityPeriods = 90, 180, 365

      foreach ($Period in $ActivityPeriods) {
        $InactiveUsersList = ($EnabledUserList | where { ($_.LastLogonDate -lt (Get-Date).AddDays(-$Period)) } )
        Set-Variable -Name $Period'DaysInactiveUsers' -Value $InactiveUsersList
        Set-Variable -Name $Period'DaysInactiveCount' -Value ($InactiveUsersList | MeasureObject).Count

        $StalePasswordList = ($EnabledUserList | Where-Object { ($_.WhenCreated -lt (Get-Date).AddDays( -$InactiveDays )) -and ($_.passwordLastSet -lt (Get-Date).AddDays( -$InactiveDays )) } )
        Set-Variable -Name $Period'DaysStalePasswordUsers' -Value $StalePasswordList
        Set-Variable -Name $Period'DaysStalePasswordCount' -Value ($StalePasswordList | Measure-Object).Count
      }

      #Members of sensitive groups
      $SensitiveGroups = "administrators", "Domain Admins", "Schema Admins", "Enterprise Admins"

      foreach ($SensitiveGroup in $SensitiveGroups) {
        $Members = (Get-ADGroupMember -Recursive -Identity $SensitiveGroup | Get-ADUser -Properties * | select Name, DistinguishedName, Enabled, whenCreated, whenChanged, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired,@{Name="Group Membership"; Expression = {Get-ADPrincipalGroupMembership $_.DistinguishedName | select Name | convertto-csv -NoTypeInformation | select -Skip 1}})
        $SensitiveGroup.replace(' ', '-')
        Set-Variable -Name $SensitiveGroup'GroupMembers' -Value $Members
        Set-Variable -Name $SensitiveGroup'MemberCount' -Value ($Members | Measure-Object).Count
      }

      #Members of all non-builtin groups
      $CustomGroups = (Get-ADGroup -Filter { GroupCategory -eq "Security" -and GroupScope -eq "Global"  } -Properties isCriticalSystemObject | Where-Object { !($_.IsCriticalSystemObject)})
      $CustomGroupCount = ($CustomGroups | Measure-Object).Count
      $GroupNames = @()

      $invalidChars = [io.path]::GetInvalidFileNameChars()
      foreach ($Group in $CustomGroups) {
          $GroupMembers = $null
          $filename = $null
          $GroupMembers = (Get-ADGroupMember -Identity $Group.DistinguishedName | select distinguishedname, name,@{Name="Group Membership"; Expression = {Get-ADPrincipalGroupMembership $_.DistinguishedName | select Name | convertto-csv -NoTypeInformation | select -Skip 1}})
          if (($GroupMembers | Measure-Object).Count -gt 0) {
              $GroupNames += $Group.Name
              $filename = (($Group.Name).ToString() -replace "[$invalidChars]","-") + ".csv"
              $GroupMembers | ConvertTo-Csv | Out-File "$PSScriptRoot\$filename"
          }
      }

      #Enabled users with password which never expires
      $PasswordNeverExpiresList = ($TotalUserList | where {PasswordNeverExpires -eq $true -and Enabled -eq $true})
      $PasswordNeverExpires = ($PasswordNeverExpiresList| Measure-Object).Count

      #Enabled users with password which was never set
      $PasswordNeverSetList = $EnabledUserList | where { ($_.PasswordLastSet -eq $null) -and ($_.Created -lt (Get-Date).AddDays( -14 )) }
      $PasswordNeverSet = ($PasswordNeverSetList | Measure-Object).Count

      #Enabled users with no password required
      $PasswordNotRequiredList = ($EnabledUserList | where {$_.PasswordNotRequired -eq $true})
      $PasswordNotRequiredCount = ( $PasswordNotRequiredList | Measure-Object).Count


      $adAuditResults = [PSCustomObject]@{
          NetBIOSName = $NetBIOSName
          DNSRoot = $DNSRoot
          Forest = $Forest
          ADFunctionalLevel = $ADFunctionalLevel
          EnabledUserCount = $EnabledUserCount
          DisableUserCount = $DisabledUserCount
          TotalUserCount = $TotalUserCount
          StalePasswordUsers = $StalePasswordUsers
          InactiveUsers = $InactiveUsers
          ActiveUsers = $ActiveUsers
          DomainAdmins = $DomainAdmins     
          SchemaAdmins = $SchemaAdmins
          EnterpriseAdmins = $EnterpriseAdmins
          CustomGroupCount = $CustomGroupCount
          CustomGroupNames = $GroupNames
          PasswordNeverExpires = $PasswordNeverExpires
          PasswordNeverSet = $PasswordNeverSet     
          PasswordNotRequired = $PasswordNotRequiredCount
      }

      #Output the object to the pipeline. The user might want to pipe these results through something like
      #ConvertTo-CSV or ConvertTo-JSON
      $adAuditResults

      #For each of the measured objects, if it has >0 members, output it to a CSV in the original script directory
      if($DisableUserCount -gt 0)
      {
        $DisableUserList | ConvertTo-Csv | Out-File "$PSScriptRoot\DisabledUsers.csv"
      }
      if( $StalePasswordUsers -gt 0 )
      {
        $StalePasswordUsersList | ConvertTo-Csv | Out-File "$PSScriptRoot\StalePasswordUsers.csv"
      }
      if( $InactiveUsers -gt 0 )
      {
        $InactiveUsersList | ConvertTo-Csv | Out-File "$PSScriptRoot\InactiveUsers.csv"
      }
      if( $DomainAdmins -gt 0 )
      {
        $DomainAdminsList | ConvertTo-Csv | Out-File "$PSScriptRoot\DomainAdmins.csv"
      }
      if( $SchemaAdmins -gt 0 )
      {
        $SchemaAdminsList | ConvertTo-Csv | Out-File "$PSScriptRoot\SchemaAdmins.csv"
      }
      if( $EnterpriseAdmins -gt 0 )
      {
        $EnterpriseAdminsList | ConvertTo-Csv | Out-File "$PSScriptRoot\EnterpriseAdmins.csv"
      }
      if( $PasswordNeverExpires -gt 0 )
      {
        $PasswordNeverExpiresList | ConvertTo-Csv | Out-File "$PSScriptRoot\NonExpiringPwdUsers.csv"
      }
      if( $PasswordNeverSet -gt 0 )
      {
        $PasswordNeverSetList | ConvertTo-Csv | Out-File "$PSScriptRoot\PwdNotSetUsers.csv"
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
        echo "-------------------------------------------------"  
        echo ""
        echo ""
        echo "-------------------------------------------------"  
      }