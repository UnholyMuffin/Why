<#

.SYNOPSIS

    Active Directory account lockout analysis tool.

.DESCRIPTION

    - Show all locked users (table).

    - Check a specific user: search for event 4740 on the PDC for the last 8 hours,

      display a table with time and source computer for all found events.

.NOTES

    Requires Active Directory read permissions and access to the PDC security log.

#>


# Load Active Directory module

if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {

    try {

        Import-Module ActiveDirectory -ErrorAction Stop

    } catch {

        Write-Host "Error: Active Directory module not found." -ForegroundColor Red

        exit 1

    }

}


# Function to get PDC Emulator

function Get-PDCEmulator {

    try {

        return (Get-ADDomain).PDCEmulator

    } catch {

        Write-Host "Failed to determine PDC Emulator." -ForegroundColor Red

        exit 1

    }

}


# Function to show all locked users

function Show-AllLockedUsers {

    $pdc = Get-PDCEmulator

    Write-Host "`n=== Searching for all locked accounts (PDC: $pdc) ===" -ForegroundColor Green

    try {

        $lockedAccounts = Search-ADAccount -LockedOut -UsersOnly -Server $pdc -ErrorAction Stop

    } catch {

        Write-Host "Error: $_" -ForegroundColor Red

        return

    }


    if ($lockedAccounts.Count -eq 0) {

        Write-Host "No locked accounts found." -ForegroundColor Yellow

        return

    }


    Write-Host "Locked users found: $($lockedAccounts.Count)`n" -ForegroundColor Cyan


    $output = @()

    $totalAccounts = $lockedAccounts.Count

    $currentAccount = 0

   

    foreach ($account in $lockedAccounts | Sort-Object SamAccountName) {

        $currentAccount++

        Write-Progress -Activity "Processing users" -Status "Processing: $($account.SamAccountName)" -PercentComplete (($currentAccount / $totalAccounts) * 100)

       

        $user = Get-ADUser -Identity $account.DistinguishedName -Properties LockoutTime, BadPwdCount, LastBadPasswordAttempt, LastLogonDate -Server $pdc -ErrorAction SilentlyContinue

        if (-not $user) { continue }


        $lockoutTimeLocal = if ($user.LockoutTime -gt 0) { [DateTime]::FromFileTime($user.LockoutTime).ToLocalTime() } else { $null }

        $lastBadLocal = if ($user.LastBadPasswordAttempt) { $user.LastBadPasswordAttempt.ToLocalTime() } else { $null }


        $output += [PSCustomObject]@{

            SamAccountName         = $user.SamAccountName

            LockoutTime            = $lockoutTimeLocal

            BadPwdCount            = $user.BadPwdCount

            LastBadPasswordAttempt = $lastBadLocal

            LastLogonDate          = $user.LastLogonDate

        }

    }

   

    Write-Progress -Activity "Processing users" -Completed


    $output | Format-Table -AutoSize -Property SamAccountName, LockoutTime, BadPwdCount, LastBadPasswordAttempt, LastLogonDate

}


# Function to extract Caller Computer Name from event 4740 (via message text)

function Get-CallerComputerNameFromEvent {

    param($Event)

    if ($Event.Message -match 'Caller Computer Name:\s*(\S+)') {

        return $Matches[1]

    }

    return "Not determined"

}


# Function to analyze a specific user (TABLE of all events for last 8 hours)

function Analyze-User {

    param([string]$UserName)


    $pdc = Get-PDCEmulator

    $cutoffTime = (Get-Date).AddHours(-8)

    $filterHash = @{

        LogName   = 'Security'

        ID        = 4740

        StartTime = $cutoffTime

    }


    try {

        Write-Host "`nSearching for event 4740 for user '$UserName' on PDC $pdc for the last 8 hours..." -ForegroundColor Cyan

        $events = Get-WinEvent -FilterHashtable $filterHash -ComputerName $pdc -ErrorAction Stop |

                  Where-Object { $_.Properties[0].Value -like "*$UserName*" } |

                  Sort-Object TimeCreated -Descending

    } catch {

        Write-Host "Error accessing event log: $_" -ForegroundColor Red

        return

    }


    if ($events.Count -eq 0) {

        Write-Host "No event 4740 found for the last 8 hours." -ForegroundColor Yellow

        return

    }


    Write-Host "Events found: $($events.Count)`n" -ForegroundColor Green


    $result = foreach ($event in $events) {

        $eventTime = $event.TimeCreated.ToLocalTime()

        $callerComputer = Get-CallerComputerNameFromEvent -Event $event

       

        [PSCustomObject]@{

            "Event Time"       = $eventTime.ToString("yyyy-MM-dd HH:mm:ss")

            "Source Computer"  = $callerComputer

            "Username"         = $event.Properties[0].Value   # SamAccountName from event

        }

    }


    $result | Format-Table -AutoSize

}


# ------------------------------------------------------------

# MAIN PROGRAM

# ------------------------------------------------------------

Clear-Host

Write-Host "=====================================================" -ForegroundColor Magenta

Write-Host "       Account Lockout Analysis Tool" -ForegroundColor White

Write-Host "=====================================================" -ForegroundColor Magenta


do {

    Write-Host "`nSelect an action:" -ForegroundColor Cyan

    Write-Host "  1 - Show all locked users"

    Write-Host "  2 - Check a specific user (all event 4740 for last 8 hours, table)"

    Write-Host "  0 - Exit"

    $choice = Read-Host "Your choice"


    switch ($choice) {

        '1' { Show-AllLockedUsers }

        '2' {

            $userName = Read-Host "Enter username (sAMAccountName)"

            if ([string]::IsNullOrWhiteSpace($userName)) {

                Write-Host "Username cannot be empty." -ForegroundColor Red

                continue

            }

            Analyze-User -UserName $userName

        }

        '0' { Write-Host "Exiting." -ForegroundColor Yellow }

        default { Write-Host "Invalid choice, please try again." -ForegroundColor Red }

    }

} while ($choice -ne '0')