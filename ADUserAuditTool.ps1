
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
    return ($user.DistinguishedName -split ",",2)[1]
}

function Get-ADUserGroupMembership {
    param (
        [string]$Username
    )
    $groups = Get-ADUser -Identity $Username -Properties MemberOf
    return $groups.MemberOf
}

function Get-ADUserLockedStatus {
    param ($User)
    if ($user.LockedOut) { 
        return "Locked" } 
    else { 
        return "Not Locked" 
        }
}

function Get-PrivilegedUserSet {
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Administrators")
    $privilegedUsers = @()
    foreach ($groupName in $privilegedGroups) {
        try {
            Get-ADGroupMember -Identity $groupName -Recursive |
                Where-Object { $_.objectClass -eq "user" } |
                ForEach-Object {$privilegedUsers[$_.SamAccountName] = $true}
        } 
        catch {
            Write-Warning "Could not retrieve members of group '$groupName'. Error: $_"
            }
        }
    return $privilegedUsers
}

function Get-ADUserInactiveStatus {
    param (
        $User,
        [int]$DaysInactive = 30
    )
    if ($null -ne $User.LastLogonDate) {
        $inactiveThreshold = (Get-Date).AddDays(-$DaysInactive)
        if ($User.LastLogonDate -lt $inactiveThreshold) { 
            return "Inactive" } 
        else { 
            return "Active" 
        }
    }
    return "No Logon Data"
}

function Get-ADUserPasswordAgeStatus {
    param (
        $User,
        [int]$DaysPasswordAge = 180
    )
    if ($null -ne $User.PasswordLastSet) {
        $passwordAgeThreshold = (Get-Date).AddDays(-$DaysPasswordAge)
        if ($User.PasswordLastSet -lt $passwordAgeThreshold) { 
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
    $users = Get-ADUser -Filter * -Properties Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, Department, Title, DistinguishedName, LockedOut

    $privilegedUsers = Get-PrivilegedUserSet

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
            LockedStatus     = Get-ADUserLockedStatus -User $user
            PrivilegedStatus = if ($privilegedUsers.ContainsKey($user.SamAccountName)) { "Privileged" } else { "Standard" }
            InactiveStatus   = Get-ADUserInactiveStatus -User $user
            PasswordAgeStatus= Get-ADUserPasswordAgeStatus -User $user
        }
    }
    return $report
}

Get-ADUserAuditReport | Format-Table -AutoSize