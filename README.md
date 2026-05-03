# Why?

<img width="1349" height="423" alt="image" src="https://github.com/user-attachments/assets/58ea19f0-edc8-4d22-a8fa-9bf9f923d0e4" />

<br>

A PowerShell script to analyze Active Directory account lockouts.  
It displays all currently locked accounts with details (lockout time, bad password count, etc.) and can investigate a specific user by querying security event 4740 from the PDC emulator for the last 8 hours.

## Features

- **Show all locked users** – Displays a table with:
  - `SamAccountName`
  - `LockoutTime` (local time)
  - `BadPwdCount`
  - `LastBadPasswordAttempt`
  - `LastLogonDate`
- **Check a specific user** – Searches for event ID 4740 on the PDC emulator (last 8 hours) and shows:
  - Event time (local)
  - Source computer (extracted from event message)
  - Username as reported in the event
- Interactive menu for easy selection.
- Progress indicator when processing many locked accounts.

## Prerequisites

- **Active Directory module** for PowerShell (RSAT tools or domain controller with AD PowerShell).
- Read access to Active Directory.
- Access to the **Security log** on the PDC emulator (requires appropriate permissions, often admin rights).
- The script must be run on a machine that can reach the PDC emulator (e.g., domain-joined workstation or a DC itself).

## Usage

1. Download or copy the `Why.ps1` script.
2. Open **PowerShell as administrator** (recommended for event log access).
3. Run the script:
   ```powershell
   .\Why.ps1
