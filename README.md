Active Directory User Audit Tool

Overview

This PowerShell script audits Active Directory user accounts and generates a report containing account status, activity, password age, and privilege information.

The tool is designed to help administrators quickly identify:
- Disabled accounts
- Inactive accounts
- Locked accounts
- Privileged accounts
- Accounts with passwords older than 180 days

Features
- Audits all Active Directory users
- Detects locked accounts
- Identifies inactive users (30+ days)
- Flags passwords older than 180 days
- Identifies members of privileged administrative groups
- Displays results in a formatted PowerShell table
- Uses custom PowerShell functions for modular and reusable code

How does this help?
- This tool helps Active Directory administrators quickly identify potential security and account management issues across their environment. By highlighting disabled accounts, inactive users, locked accounts, privileged users, and aging passwords, administrators can reduce manual auditing efforts, improve security visibility, and support compliance and account lifecycle management processes.



Functions

Get-ADUserLockedStatus

- Checks whether a user account is currently locked out.

Returns:
- Locked
- Not Locked

Get-PrivilegedUserSet

- Builds a list of users who belong to privileged groups.

Groups checked:

- Domain Admins
- Enterprise Admins
- Administrators

Uses a hash table for fast lookups during report generation.

Get-ADUserInactiveStatus

- Determines whether a user has logged in within the last 30 days.

Returns:

- Active
- Inactive
- No Logon Data

Get-ADUserPasswordAgeStatus

- Determines whether a user's password is older than 180 days.

Returns:
- Password Valid
- Password Older than 180 Days
- No Password Data

Get-ADUserAuditReport

- Main reporting function.

Performs the following actions:
- Retrieves Active Directory users.
- Builds the privileged user list.
- Processes each user account.
- Creates a custom PowerShell object containing audit information.
- Returns the completed report.
- Output

Example fields included in the report:

Field	Description
- Name:	User's full name
- Username:	SAM Account Name
- Status:	Enabled or Disabled
- LastLogonTime:	Last successful logon
- PasswordLastSet:	Date password was last changed
- Department: User department
- Title:	User job title
- OU:	Organizational Unit
- LockedStatus:	Locked or Not Locked
- PrivilegedStatus:	Privileged or Standard
- InactiveStatus:	Active or Inactive
- PasswordAgeStatus:	Password age status

Technologies Used
- PowerShell
- Active Directory Module
