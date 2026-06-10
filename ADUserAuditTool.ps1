
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

$ErrorActionPreference = "Stop" # Treat all errors as terminating to ensure we catch and handle them properly


function Get-ADUserLockedStatus { # Checks if the user account is locked out
    param ($User) # Takes an AD user object as input
    if ($User.LockedOut) { # If the LockedOut property is true, return "Locked"
        return "Locked" } # Return "Locked" if the account is locked out
    else { # Otherwise, return "Not Locked"
        return "Not Locked" # Return "Not Locked" if the account is not locked out
        }
}

function Get-PrivilegedUserSet { # Retrieves members of privileged groups and stores them in a hash table for quick lookup
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Administrators") # List of privileged groups to check
    $privilegedUsers = @{} # Initialize an empty hash table to store privileged users
    foreach ($groupName in $privilegedGroups) { # Loop through each privileged group
        try { # Attempt to retrieve members of the current group
            Get-ADGroupMember -Identity $groupName -Recursive | # Get members of the group recursively to include nested group members
                Where-Object { $_.objectClass -eq "user" } | # Filter to include only user objects
                ForEach-Object {$privilegedUsers[$_.SamAccountName] = $true} # Add each privileged user's SamAccountName to the hash table with a value of $true
        } 
        catch { # If an error occurs (e.g., group not found), catch the exception and write a warning message
            Write-Warning "Could not retrieve members of group '$groupName'. Error: $_" # Log a warning if the group cannot be accessed, but continue processing other groups
            }
        }
    return $privilegedUsers # Return the hash table containing privileged users for use in the main report generation
}

function Get-ADUserInactiveStatus { # Determines if a user is inactive based on their last logon date
    param ( # Takes an AD user object and an optional number of days to consider for inactivity
        $User, # The AD user object to evaluate
        [int]$DaysInactive = 30 # Default threshold for inactivity is 30 days
    )
    if ($null -ne $User.LastLogonDate) { # If the LastLogonDate property is not null, proceed to check inactivity
        $inactiveThreshold = (Get-Date).AddDays(-$DaysInactive) # Calculate the threshold date for inactivity by subtracting the specified number of days from the current date
        if ($User.LastLogonDate -lt $inactiveThreshold) { # If the user's last logon date is older than the threshold, return "Inactive"
            return "Inactive" } # Return "Inactive" if the user has not logged in within the specified number of days
        else { # Otherwise, return "Active"
            return "Active" # Return "Active" if the user has logged in within the specified number of days
        }
    }
    return "No Logon Data" # If the LastLogonDate property is null, return "No Logon Data" to indicate that there is no information available about the user's logon activity
}

function Get-ADUserPasswordAgeStatus { # Evaluates the age of the user's password and determines if it is older than a specified number of days
    param ( # Takes an AD user object and an optional number of days to consider for password age
        $User, # The AD user object to evaluate
        [int]$DaysPasswordAge = 180 # Default threshold for password age is 180 days
    )
    if ($null -ne $User.PasswordLastSet) { # If the PasswordLastSet property is not null, proceed to check password age
        $passwordAgeThreshold = (Get-Date).AddDays(-$DaysPasswordAge) # Calculate the threshold date for password age by subtracting the specified number of days from the current date
        if ($User.PasswordLastSet -lt $passwordAgeThreshold) { # If the user's password last set date is older than the threshold, return "Password Older than X Days"
            return "Password Older than $DaysPasswordAge Days" } # Return a message indicating that the password is older than the specified number of days if it has not been changed within that time frame
        else { # Otherwise, return "Password Valid"
            return "Password Valid" # Return "Password Valid" if the password has been changed within the specified number of days, indicating that it is not considered old
        }
    }
    return "No Password Data" # If the PasswordLastSet property is null, return "No Password Data" to indicate that there is no information available about the user's password age
}

function Get-ADUserAuditReport { # Main function to generate the Active Directory user audit report
    $users = Get-ADUser -Filter * -Properties Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, Department, Title, DistinguishedName, LockedOut # Retrieve all AD users and select the necessary properties for the report

    $privilegedUsers = Get-PrivilegedUserSet # Get the set of privileged users to determine their status in the report

    foreach ($user in $users) { # Loop through each user and create a custom object with the relevant information for the report
        [PSCustomObject]@{ # Create a custom object for each user with the following properties:
            Name             = $user.Name # The full name of the user
            Username         = $user.SamAccountName # The SamAccountName (username) of the user
            Status           = if ($user.Enabled) { "Enabled" } else { "Disabled" } # Determine if the account is enabled or disabled based on the Enabled property
            LastLogonTime    = $user.LastLogonDate # The last logon time of the user, which may be null if the user has never logged in
            PasswordLastSet  = $user.PasswordLastSet # The date and time when the user's password was last set, which may be null if the password has never been set
            Department       = $user.Department # The department to which the user belongs
            Title            = $user.Title # The job title of the user
            OU               = ($user.DistinguishedName -split ",",2)[1] # The organizational unit to which the user belongs
            LockedStatus     = Get-ADUserLockedStatus -User $user # Determine if the user's account is locked out
            PrivilegedStatus = if ($privilegedUsers.ContainsKey($user.SamAccountName)) { "Privileged" } else { "Standard" } # Determine if the user is privileged
            InactiveStatus   = Get-ADUserInactiveStatus -User $user # Determine if the user is inactive based on their last logon time
            PasswordAgeStatus= Get-ADUserPasswordAgeStatus -User $user # Determine the age of the user's password and whether it is older than the specified threshold
        }
    }
}

$report = Get-ADUserAuditReport # Generate the Active Directory user audit report by calling the main function

$report | Format-List # Output the report in a formatted list for better readability in the console