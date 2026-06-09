
Import-Module ActiveDirectory

<#
#Active Directory User Audit Tool
#This script will audit Active Directory users and report on various attributes such as last logon time, password last set, Inactive accounts, account status, and more. 

Audit Categories:
1. Disabled Accounts
2. Inactive Accounts (not logged in for 30 days)
3. Password Last Set (Not changed in 180+ days)
4. Locked Accounts
5. Privileged Accounts (Members of Domain Admins, Enterprise Admins, etc.)

Collects: Name, Username, Status, Last Logon Time, Password Last Set, Department, Title, OU

#>

$ErrorActionPreference = "Stop"

function Get-ADUserLastLogon {
    param (
        [string]$Username
    )
    $user = Get-ADUser -Identity $Username -Properties LastLogonDate
    return $user.LastLogonDate
}

function Get-ADUserPasswordLastSet {
    param (
        [string]$Username
    )
    $user = Get-ADUser -Identity $Username -Properties PasswordLastSet
    return $user.PasswordLastSet
}

function Get-ADUserAccountStatus {
    param (
        [string]$Username
    )
    $user = Get-ADUser -Identity $Username -Properties Enabled
    if ($user.Enabled) { 
        return "Enabled" } 
    else { 
        return "Disabled" 
    }
}

function Get-ADUserTitle {
    param (
        [string]$Username
    )
    $user = Get-ADUser -Identity $Username -Properties Title
    return $user.Title
}

function Get-ADUserOU {
    param (
        [string]$Username
    )
    $user = Get-ADUser -Identity $Username -Properties DistinguishedName
    $ouList = Get-OU
    return $ouList[$user.DistinguishedName]
}

function Get-ADUserGroupMembership {
    param (
        [string]$Username
    )
    $groups = Get-ADUser -Identity $Username -Properties MemberOf
    return $groups.MemberOf
}

function Get-ADUserLockedStatus {
    param (
        [string]$Username
    )
    $user = Get-ADUser -Identity $Username -Properties LockedOut
    if ($user.LockedOut) { 
        return "Locked" } 
    else { 
        return "Not Locked" 
        }
}

function Get-ADUserPrivilegedStatus {
    param (
        [string]$Username
    )
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Administrators")
    $userGroups = Get-ADUserGroupMembership -Username $Username
    foreach ($group in $userGroups) {
        if ($privilegedGroups -contains (Get-ADGroup -Identity $group).Name) {
            return "Privileged"
        }
    }
    return "Standard"
}

function Get-ADUserInactiveStatus {
    param (
        [string]$Username,
        [int]$DaysInactive = 30
    )
    $lastLogon = Get-ADUserLastLogon -Username $Username
    if ($null -ne $lastLogon) {
        $inactiveThreshold = (Get-Date).AddDays(-$DaysInactive)
        
        if ($lastLogon -lt $inactiveThreshold) { 
            return "Inactive" } 
        else { 
            return "Active" 
        }
    }
    return "No Logon Data"
}

function Get-ADUserPasswordAgeStatus {
    param (
        [string]$Username,
        [int]$DaysPasswordAge = 180
    )
    $passwordLastSet = Get-ADUserPasswordLastSet -Username $Username
    if ($null -ne $passwordLastSet) {
        $passwordAgeThreshold = (Get-Date).AddDays(-$DaysPasswordAge)
        if ($passwordLastSet -lt $passwordAgeThreshold) { 
            return "Password Older than 180 Days" } 
        else { 
            return "Password Valid" 
        }
    }
    return "No Password Data"
}

function Get-ADUserDisabledStatus {
    param (
        [string]$Username
    )
    return Get-ADUserAccountStatus -Username $Username
}

function Get-ADUserAuditReport {
    $users = Get-ADUser -Filter * -Properties Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, Department, Title, DistinguishedName
    $report = @()
    foreach ($user in $users) {
        $report += [PSCustomObject]@{
            Name             = $user.Name
            Username         = $user.SamAccountName
            Status           = if ($user.Enabled) { "Enabled" } else { "Disabled" }
            LastLogonTime    = $user.LastLogonDate
            PasswordLastSet  = $user.PasswordLastSet
            Department       = $user.Department
            Title            = $user.Title
            OU               = ($user.DistinguishedName -split ",",2)[1]
            LockedStatus     = Get-ADUserLockedStatus -Username $user.SamAccountName
            PrivilegedStatus = Get-ADUserPrivilegedStatus -Username $user.SamAccountName
            InactiveStatus   = Get-ADUserInactiveStatus -Username $user.SamAccountName
            PasswordAgeStatus= Get-ADUserPasswordAgeStatus -Username $user.SamAccountName
        }
    }
    return $report
}

Get-ADUserAuditReport | Format-Table -AutoSize