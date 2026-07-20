<#
.SYNOPSIS
    Scans a Windows PC for common indicators of Roblox cheat/exploit tools
    (executors, injectors, DLL exploits) and produces a "suspects" report.

.DESCRIPTION
    This is a READ-ONLY detection script. It does not delete, quarantine, or
    modify anything — it only reports what it finds so you can review and
    decide what to do next.

    Checks performed:
      1. Running processes matched against known cheat-tool names
      2. Known install/cache folders for popular exploit executors
      3. Suspicious files in Downloads / Desktop / Temp matching known
         naming patterns
      4. Startup entries (registry Run keys + Startup folder)
      5. Recently created/modified .dll and .exe files in common
         injection-prone locations
      6. Browser download history folders (filenames only, not content)

.OUTPUTS
    A table printed to screen, plus a CSV report saved next to the script:
    RobloxCheatScan_<timestamp>.csv

.NOTES
    Run in an elevated PowerShell window (Run as Administrator) for the
    most complete results — some folders/registry keys need admin rights
    to read fully.
#>

[CmdletBinding()]
param(
    [string]$ReportPath = "$PSScriptRoot\RobloxCheatScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'SilentlyContinue'
$suspects = New-Object System.Collections.Generic.List[Object]

function Add-Suspect {
    param($Category, $Name, $Path, $Detail)
    $suspects.Add([PSCustomObject]@{
        Category = $Category
        Name     = $Name
        Path     = $Path
        Detail   = $Detail
        Found    = (Get-Date)
    })
}

# --- Known names associated with Roblox cheat/exploit tools ---
# (executors, injectors, script hubs commonly flagged by Roblox anti-cheat)
$knownNames = @(
    'synapse', 'synapsex', 'krnl', 'fluxus', 'electron', 'wave',
    'jjsploit', 'codex', 'comet', 'hydrogen', 'sirhurt', 'sentinel',
    'evon', 'arceusx', 'scriptware', 'protosmasher', 'oxygenu',
    'valyse', 'trigon', 'cryptic', 'awp', 'delta-executor', 'vega-x',
    'solara', 'seliware', 'zorara', 'nihon', 'celery', 'temple',
    'exoline', 'calamari'
)

$namePattern = ($knownNames -join '|')

Write-Host "=== Roblox Cheat Scanner ===" -ForegroundColor Cyan
Write-Host "This is read-only: nothing will be modified or deleted.`n"

# 1. Running processes
Write-Host "[1/6] Checking running processes..." -ForegroundColor Yellow
Get-Process | Where-Object { $_.ProcessName -match $namePattern } | ForEach-Object {
    Add-Suspect "Process" $_.ProcessName $_.Path "Matches known cheat-tool name (running now)"
}

# 2. Known install/cache folders
Write-Host "[2/6] Checking common install locations..." -ForegroundColor Yellow
$commonRoots = @(
    "$env:APPDATA", "$env:LOCALAPPDATA", "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop", "$env:PUBLIC\Desktop", "$env:TEMP",
    "$env:USERPROFILE\AppData\LocalLow"
)
foreach ($root in $commonRoots) {
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $namePattern } |
            ForEach-Object { Add-Suspect "Folder" $_.Name $_.FullName "Folder name matches known cheat tool" }
    }
}

# 3. Downloads / Desktop / Temp files by name pattern
Write-Host "[3/6] Checking Downloads, Desktop, and Temp for suspicious files..." -ForegroundColor Yellow
$fileRoots = @(
    "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP"
)
foreach ($root in $fileRoots) {
    if (Test-Path $root) {
        Get-ChildItem -Path $root -File -Recurse -ErrorAction SilentlyContinue -Depth 2 |
            Where-Object { $_.Name -match $namePattern -and $_.Extension -match '\.(exe|dll|zip|rar|7z)$' } |
            ForEach-Object { Add-Suspect "File" $_.Name $_.FullName "Filename matches known cheat tool ($($_.Extension))" }
    }
}

# 4. Startup entries (Run keys + Startup folder)
Write-Host "[4/6] Checking startup entries..." -ForegroundColor Yellow
$runKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $props = Get-ItemProperty -Path $key
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -notmatch '^PS' -and ($prop.Name -match $namePattern -or $prop.Value -match $namePattern)) {
                Add-Suspect "Startup (Registry)" $prop.Name $prop.Value "Matches known cheat tool in Run key: $key"
            }
        }
    }
}
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -File | Where-Object { $_.Name -match $namePattern } |
            ForEach-Object { Add-Suspect "Startup (Folder)" $_.Name $_.FullName "Shortcut/file in Startup folder" }
    }
}

# 5. Recently modified DLL/EXE in injection-prone locations (last 14 days)
Write-Host "[5/6] Checking for recently modified DLL/EXE files (last 14 days)..." -ForegroundColor Yellow
$cutoff = (Get-Date).AddDays(-14)
$scanRoots = @("$env:LOCALAPPDATA", "$env:APPDATA", "$env:TEMP")
foreach ($root in $scanRoots) {
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Include *.dll,*.exe -File -Recurse -ErrorAction SilentlyContinue -Depth 3 |
            Where-Object { $_.LastWriteTime -gt $cutoff -and $_.Name -match $namePattern } |
            ForEach-Object { Add-Suspect "Recent Binary" $_.Name $_.FullName "Recently modified ($($_.LastWriteTime)), name matches known tool" }
    }
}

# 6. Browser download history folders (filenames only)
Write-Host "[6/6] Checking browser download folders for filenames..." -ForegroundColor Yellow
$browserDownloadDbs = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
)
foreach ($db in $browserDownloadDbs) {
    if (Test-Path $db) {
        # Browser history files are SQLite and locked while browser is open;
        # we just do a raw string scan for matching filenames as a lightweight check.
        try {
            $bytes = [System.IO.File]::ReadAllText($db, [System.Text.Encoding]::Latin1)
            if ($bytes -match $namePattern) {
                Add-Suspect "Browser History" (Split-Path $db -Leaf) $db "Possible reference to known cheat tool found in browser history file"
            }
        } catch {
            # File locked (browser running) — skip silently
        }
    }
}

# --- Results ---
Write-Host "`n=== Scan Complete ===" -ForegroundColor Cyan
if ($suspects.Count -eq 0) {
    Write-Host "No matches found against the known cheat-tool list." -ForegroundColor Green
} else {
    Write-Host "$($suspects.Count) potential match(es) found:`n" -ForegroundColor Red
    $suspects | Sort-Object Category | Format-Table -AutoSize
    $suspects | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nFull report saved to: $ReportPath" -ForegroundColor Yellow
}

Write-Host "`nNote: This scan matches against a fixed list of publicly-known tool" -ForegroundColor DarkGray
Write-Host "names/patterns. It can produce false positives (e.g. unrelated files" -ForegroundColor DarkGray
Write-Host "that happen to share a name) and can miss newer or renamed tools." -ForegroundColor DarkGray
Write-Host "Review each result manually before taking any action." -ForegroundColor DarkGray
