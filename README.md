# 🔐 Privileged Access Weekly Digest
### Microsoft Entra ID | PowerShell | Microsoft Graph API

> Combines five privileged access security checks into a single weekly
> digest — total role assignments, admins with no MFA, inactive admins,
> disabled accounts still holding roles, and over-privileged admins.
> Prints a clean formatted dashboard and exports a full CSV report.

---

### Why Privileged Access is the Highest Priority

A compromised regular user account gives an attacker access to
one person's files and email. A compromised Global Admin account
gives them access to everything — all users, all data, all
applications, the entire tenant.

This script monitors the five most critical privileged access
risk factors every week:

No MFA on admin accounts → single password away from full tenant breach
Inactive admin accounts → forgotten accounts nobody is watching
Disabled accounts with roles → should have been cleaned up — still a risk
Over-privileged admins → principle of least privilege violated

---

## 📄 Executive Summary

**Problem:** Organizations assign admin roles and never review them.
Accounts accumulate privileges over time. Some admins never sign in.
Some have no MFA. Some left the company but their accounts remain.
Nobody has a weekly view of privileged access health without manual
portal browsing across multiple screens.

**Solution:** This script pulls every high risk role assignment,
checks five security properties per admin, and produces a one-page
digest and detailed CSV — all in a single run.

**Result:** Complete privileged access health picture in under
10 minutes — ready to share with the security team every Friday.

---

## 🔍 Real Findings From Lab Tenant

| Metric | Result |
|---|---|
| Total privileged assignments | 3 |
| Admins with no MFA | 0 ✅ |
| Admins inactive 90+ days | 1 🔴 |
| Disabled accounts with roles | 0 ✅ |
| Over-privileged admins | 0 ✅ |
| Overall risk | HIGH |

---

## 📊 Digest Output

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRIVILEGED ACCESS WEEKLY DIGEST
Week of: October 12 2026
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total privileged assignments : 3
Admins with no MFA : 0 ✅
Admins inactive 90+ days : 1 🔴
Disabled accounts with roles : 0 ✅
Over-privileged admins : 0 ✅
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OVERALL RISK: HIGH
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


---

## 🔍 Overall Risk Calculation

| Findings Flagged | Risk Level |
|---|---|
| 3 or more | CRITICAL |
| 1 or 2 | HIGH |
| 0 | LOW |

A finding is flagged when:

noMFACount -gt 0 → at least one admin has no MFA
inactiveCount -gt 0 → at least one admin inactive 90+ days
disabledCount -gt 0 → at least one disabled account holds a role
overPrivCount -gt 0 → at least one admin has multiple roles


---

## 🎯 High Risk Roles Monitored

Global Administrator
Privileged Role Administrator
Security Administrator
User Administrator
Application Administrator
Exchange Administrator
SharePoint Administrator


---

## ✅ Step by Step Breakdown

**Step 1 — Connected to Microsoft Graph**
```powershell
Connect-MgGraph -Scopes "User.Read.All","RoleManagement.Read.All","AuditLog.Read.All","UserAuthenticationMethod.Read.All" -NoWelcome
```
- Four scopes required for all five checks
- `RoleManagement.Read.All` — read directory roles and members
- `User.Read.All` — read user properties and sign-in activity
- `AuditLog.Read.All` — read sign-in activity timestamps
- `UserAuthenticationMethod.Read.All` — read MFA methods per user

---

**Step 2 — Initialized counters and hashtable**
```powershell
$totalAssignments = 0
$noMFACount       = 0
$inactiveCount    = 0
$disabledCount    = 0
$userRoles        = @{}
```
- Five counters track each security finding
- `$userRoles` hashtable tracks which roles each admin holds
- Hashtable declared before all loops — must persist across iterations
- Counters incremented with `++` — not set as booleans

---

**Step 3 — Pulled all directory roles**
```powershell
$roles = Get-MgDirectoryRole
```
- Returns all active directory roles in the tenant
- Typically 30+ roles — most are low risk
- Skip non-high-risk roles immediately at top of loop to avoid unnecessary API calls

---

**Step 4 — Skipped non-high-risk roles**
```powershell
if (-not ($highRiskRoles -contains $role.DisplayName)) { continue }
```
- `continue` skips to next role immediately
- Only the seven high risk roles proceed past this point
- Saves 20+ unnecessary `Get-MgDirectoryRoleMember` calls

---

**Step 5 — Got members per role**
```powershell
$members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
```
- Returns all members assigned to this role
- Members come back as generic directory objects — not full user objects
- UPN and display name available in `AdditionalProperties`
- Full user details require a second `Get-MgUser` call

---

**Step 6 — Got full user details per member**
```powershell
$memberId   = $member.Id
$memberName = $member.AdditionalProperties["displayName"]
$memberUPN  = $member.AdditionalProperties["userPrincipalName"]

$user = Get-MgUser -UserId $memberId -Property "Id,DisplayName,UserPrincipalName,Department,AccountEnabled,SignInActivity"
```
- Two step pattern — identity from member object then details from Get-MgUser
- `SignInActivity` requires `AuditLog.Read.All` scope to populate
- `AccountEnabled` used for disabled account check

---

**Step 7 — Ran five checks per admin**
```powershell
$totalAssignments++
if ($user.AccountEnabled -eq $false) { $disabledCount++ }
if ($daysSinceSignIn -ge 90)         { $inactiveCount++ }
if (-not $hasMFA)                    { $noMFACount++ }
```
- Each check increments the relevant counter
- `++` adds 1 to the running total
- All five checks run for every admin on every role

---

**Step 8 — Checked MFA per admin**
```powershell
$methods = Get-MgUserAuthenticationMethod -UserId $memberId
$hasMFA  = $methods.Count -gt 1
if (-not $hasMFA) { $noMFACount++ }
```
- `Get-MgUserAuthenticationMethod` returns all registered methods per user
- Every user always has at least one method — their password
- Count greater than 1 means at least one MFA method is registered
- Count of 1 means password only — no MFA — counter incremented
- Requires `UserAuthenticationMethod.Read.All` scope
- One API call per admin — on large tenants this is the slowest part of the script

---

**Step 9 — Stored MFA status in hashtable entry**
```powershell
$userRoles[$memberId].HasMFA = if ($hasMFA) { "Yes" } else { "No" }
```
- MFA status stored on the user's hashtable entry
- Reused when building the CSV — no second MFA call needed
- Existing entries updated when user appears in additional roles

---

**Step 10 — Built hashtable for over-privileged detection**
```powershell
if ($userRoles.ContainsKey($memberId)) {
    $userRoles[$memberId].Roles.Add($role.DisplayName)
} else {
    $userRoles[$memberId] = [PSCustomObject]@{ ... }
    $userRoles[$memberId].Roles.Add($role.DisplayName)
}
```
- Hashtable key is the user's unique ID
- First time seeing a user — create their entry
- Subsequent times — add the new role to their existing list
- After all loops each user has a complete list of their roles

---

**Step 11 — Counted over-privileged admins**
```powershell
$overPrivCount = 0
foreach ($entry in $userRoles.Values) {
    if ($entry.Roles.Count -gt 1) { $overPrivCount++ }
}
```
- Runs AFTER both main loops close — not inside them
- `.Values` gives every entry in the hashtable
- Anyone with more than one role is over-privileged

---

**Step 12 — Built CSV from hashtable**
```powershell
foreach ($entry in $userRoles.Values) {
    $results.Add([PSCustomObject]@{
        DisplayName     = $entry.DisplayName
        RolesAssigned   = $entry.Roles -join ", "
        RoleCount       = $entry.Roles.Count
        OverPrivileged  = if ($entry.Roles.Count -gt 1) { "Yes" } else { "No" }
        ...
    })
}
```
- One row per unique admin — no duplicates
- `$entry.Roles -join ", "` combines role list into readable string
- Built from hashtable so each admin appears exactly once

---

**Step 13 — Calculated overall risk**
```powershell
$highFindings = 0
if ($noMFACount -gt 0)    { $highFindings++ }
if ($inactiveCount -gt 0) { $highFindings++ }
if ($disabledCount -gt 0) { $highFindings++ }
if ($overPrivCount -gt 0) { $highFindings++ }

$overallRisk = if ($highFindings -ge 3)    { "CRITICAL" }
               elseif ($highFindings -ge 1) { "HIGH" }
               else                         { "LOW" }
```
- Each finding category counts as one point
- Risk level based on how many categories have findings
- Calculated once after all loops — not per user

---

**Step 14 — Printed digest and exported CSV**
- Digest printed to screen with dynamic colors
- Green when count is zero — red or yellow when flagged
- CSV exported with full admin details for deeper investigation

---

## Results in PowerShell

<img width="327" height="153" alt="Screenshot 2026-10-12 at 18 31 46" src="https://github.com/user-attachments/assets/7daecf90-f341-4d1d-80eb-c515980bc6bf" />

## Results in Excel 

<img width="1079" height="87" alt="Screenshot 2026-10-12 at 18 32 57" src="https://github.com/user-attachments/assets/1d9e49c9-2d1a-41cb-89ca-8eabc79594a6" />

## Script 

```powershell
Connect-MgGraph -Scopes "User.Read.All","RoleManagement.Read.All","AuditLog.Read.All","UserAuthenticationMethod.Read.All" -NoWelcome
Write-Host "Connected to Graph" -ForegroundColor Green

$today     = Get-Date
$userRoles = @{}

# Counters for digest
$totalAssignments = 0
$noMFACount       = 0
$inactiveCount    = 0
$disabledCount    = 0

# Results for CSV
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

$highRiskRoles = @(
    "Global Administrator"
    "Privileged Role Administrator"
    "Security Administrator"
    "User Administrator"
    "Application Administrator"
    "Exchange Administrator"
    "SharePoint Administrator"
)

$roles = Get-MgDirectoryRole
Write-Host "Scanning privileged access..." -ForegroundColor Cyan

foreach ($role in $roles) {
    if (-not ($highRiskRoles -contains $role.DisplayName)) { continue }

    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id

    foreach ($member in $members) {

        $memberId   = $member.Id
        $memberName = $member.AdditionalProperties["displayName"]
        $memberUPN  = $member.AdditionalProperties["userPrincipalName"]

        $totalAssignments++

        $user = Get-MgUser -UserId $memberId -Property "Id,DisplayName,UserPrincipalName,Department,AccountEnabled,SignInActivity"

        if ($user.AccountEnabled -eq $false) { $disabledCount++ }

        $lastSignIn      = $user.SignInActivity.LastSignInDateTime
        $daysSinceSignIn = if ($lastSignIn) { [int]($today - $lastSignIn).TotalDays } else { 999 }
        if ($daysSinceSignIn -ge 90) { $inactiveCount++ }

        $methods = Get-MgUserAuthenticationMethod -UserId $memberId
        $hasMFA  = $methods.Count -gt 1
        if (-not $hasMFA) { $noMFACount++ }

        if ($userRoles.ContainsKey($memberId)) {
            $userRoles[$memberId].Roles.Add($role.DisplayName)
            # Update existing entry with latest details
            $userRoles[$memberId].HasMFA           = if ($hasMFA) { "Yes" } else { "No" }
            $userRoles[$memberId].LastSignInDate    = if ($lastSignIn) { $lastSignIn.ToString("yyyy-MM-dd") } else { "Never" }
            $userRoles[$memberId].DaysSinceSignIn   = if ($daysSinceSignIn -eq 999) { "Never" } else { $daysSinceSignIn }
            $userRoles[$memberId].AccountEnabled    = $user.AccountEnabled
            $userRoles[$memberId].Department        = $user.Department
        } else {
            $userRoles[$memberId] = [PSCustomObject]@{
                DisplayName     = $memberName
                UPN             = $memberUPN
                Department      = $user.Department
                AccountEnabled  = $user.AccountEnabled
                HasMFA          = if ($hasMFA) { "Yes" } else { "No" }
                LastSignInDate  = if ($lastSignIn) { $lastSignIn.ToString("yyyy-MM-dd") } else { "Never" }
                DaysSinceSignIn = if ($daysSinceSignIn -eq 999) { "Never" } else { $daysSinceSignIn }
                Roles           = [System.Collections.Generic.List[string]]::new()
            }
            $userRoles[$memberId].Roles.Add($role.DisplayName)
        }
    }
}

$overPrivCount = 0
foreach ($entry in $userRoles.Values) {
    if ($entry.Roles.Count -gt 1) { $overPrivCount++ }
}

foreach ($entry in $userRoles.Values) {
    $results.Add([PSCustomObject]@{
        DisplayName     = $entry.DisplayName
        UPN             = $entry.UPN
        Department      = $entry.Department
        AccountEnabled  = $entry.AccountEnabled
        RolesAssigned   = $entry.Roles -join ", "
        RoleCount       = $entry.Roles.Count
        HasMFA          = $entry.HasMFA
        LastSignInDate  = $entry.LastSignInDate
        DaysSinceSignIn = $entry.DaysSinceSignIn
        OverPrivileged  = if ($entry.Roles.Count -gt 1) { "Yes" } else { "No" }
    })
}

$results | Export-Csv -Path "$HOME/Desktop/PrivilegedAccessDigest.csv" -NoTypeInformation
Write-Host "CSV exported to Desktop" -ForegroundColor Green

$highFindings = 0
if ($noMFACount -gt 0)    { $highFindings++ }
if ($inactiveCount -gt 0) { $highFindings++ }
if ($disabledCount -gt 0) { $highFindings++ }
if ($overPrivCount -gt 0) { $highFindings++ }

$overallRisk = if ($highFindings -ge 3)    { "CRITICAL" }
               elseif ($highFindings -ge 1) { "HIGH" }
               else                         { "LOW" }

$riskColor = if ($overallRisk -eq "CRITICAL") { "Red" }
             elseif ($overallRisk -eq "HIGH")   { "Yellow" }
             else                               { "Green" }

Write-Host "  PRIVILEGED ACCESS WEEKLY DIGEST" -ForegroundColor White
Write-Host "  Week of: $(Get-Date -Format 'MMMM dd yyyy')" -ForegroundColor DarkGray
Write-Host "  Total privileged assignments : $totalAssignments" -ForegroundColor White
Write-Host "  Admins with no MFA           : $noMFACount $(if ($noMFACount -gt 0) { '🔴' } else { '✅' })" -ForegroundColor $(if ($noMFACount -gt 0) { "Red" } else { "Green" })
Write-Host "  Admins inactive 90+ days     : $inactiveCount $(if ($inactiveCount -gt 0) { '🔴' } else { '✅' })" -ForegroundColor $(if ($inactiveCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Disabled accounts with roles : $disabledCount $(if ($disabledCount -gt 0) { '🔴' } else { '✅' })" -ForegroundColor $(if ($disabledCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Over-privileged admins       : $overPrivCount $(if ($overPrivCount -gt 0) { '🟡' } else { '✅' })" -ForegroundColor $(if ($overPrivCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  OVERALL RISK: $overallRisk" -ForegroundColor $riskColor
```
## 📋 Compliance Relevance

| Framework | Control |
|---|---|
| NIST 800-53 | AC-6 — Least Privilege |
| SOC 2 Type II | CC6.3 — Access Removal |
| ISO 27001 | A.9.2.3 — Management of Privileged Access Rights |
| CIS Controls | Control 5 — Account Management |
| Microsoft Secure Score | Review privileged role assignments |

---

## 🎯 Use Cases

**Weekly Security Review**
Run every Friday to give the security team a one-page
view of privileged access health.

**Incident Response**
Run immediately after a suspected breach to understand
the current privileged access exposure.

**M&A Tenant Discovery**
Run on day one of an acquisition to immediately understand
admin account posture in the acquired tenant.

**Audit Preparation**
Run before an audit to identify and remediate privileged
access gaps before auditors find them.
