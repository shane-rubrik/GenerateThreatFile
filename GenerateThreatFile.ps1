<#
.SYNOPSIS
    Cybersecurity Threat Hunting Simulator for Rubrik Security Cloud.

.DESCRIPTION
    PURPOSE:
    This script generates harmless, random executable files to simulate a malware outbreak.
    It is designed for security teams to practice threat hunting, detection, and mitigation
    using Rubrik Security Cloud (RSC).

    FEATURES:
    1. Generates unique .exe files with valid PE headers but non-functional logic.
    2. Calculates SHA256 hashes for "Indicator of Compromise" (IoC) tracking.
    3. Supports distribution to multiple network paths to simulate lateral movement.
    4. Integrates with Rubrik Security Cloud to automatically create/update Threat Feeds.
    5. Provides a robust cleanup mechanism to reset the environment.

.PARAMETER OutputDirectory
    The folder where the fake malware should be created. Defaults to a 'Threats' subfolder.
.PARAMETER Count
    Number of unique files to generate.
.PARAMETER RubrikConfigPath
    Path to the JSON service account credentials file from RSC.
.PARAMETER CreateThreatFeed
    Switch to automatically upload generated hashes to Rubrik as a Threat Feed.
.PARAMETER NetworkPaths
    Array of UNC paths to copy files to (e.g., "\\Server\Share").
.PARAMETER Cleanup
    Switch to delete all generated files and tracking logs in the target directory.

.EXAMPLE
    .\GenerateThreatFile.ps1 -Count 5 -OutputDirectory "C:\SafetyLab"
    Creates 5 files in C:\SafetyLab.

.EXAMPLE
    .\GenerateThreatFile.ps1 -RubrikConfigPath ".\rsc-creds.json" -CreateThreatFeed
    Creates a file and uploads its hash to Rubrik Security Cloud.
#>

param(
    [string]$OutputDirectory,
    [int]$Count = 1,
    [string]$RubrikConfigPath,
    [switch]$CreateThreatFeed,
    [switch]$Verbose,
    [string[]]$NetworkPaths,
    [switch]$Cleanup
)

# ---------------------------------------------------------
# SECTION 1: RUBRIK CLOUD CONNECTION TOOLS
# ---------------------------------------------------------

function rscConnect {
    param ([string]$path)
    if (-not (Test-Path $path)) { throw "Config file not found at $path" }
    
    $config = Get-Content -Raw -Path $path | ConvertFrom-Json
    
    # Validation check for required JSON fields
    if (-not $config.client_id -or -not $config.client_secret -or -not $config.access_token_uri) {
        throw "The provided JSON config is missing required RSC credentials (client_id, client_secret, or access_token_uri)."
    }

    $body = @{
        client_id     = $config.client_id
        client_secret = $config.client_secret
        grant_type    = "client_credentials"
    }
    
    $response = Invoke-RestMethod -Uri $config.access_token_uri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
    return @{
        access_token = $response.access_token
        graphql_url  = $config.access_token_uri -replace "/api/client_token$", "/api/graphql"
    }
}

function Invoke-GraphQLQuery {
    param ($query, $variables, $url, $token, $maxRetries = 3, $retryDelaySeconds = 5)
    $body = @{ query = $query; variables = $variables } | ConvertTo-Json -Depth 10
    $headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

    $attempt = 1
    while ($attempt -le $maxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
            return $response.data
        } catch {
            if ($attempt -eq $maxRetries) { throw }
            Start-Sleep -Seconds $retryDelaySeconds
            $attempt++
        }
    }
}

# ---------------------------------------------------------
# SECTION 2: THREAT FEED MANAGEMENT
# ---------------------------------------------------------

function New-RubrikThreatFeed {
    param ($feedName, $description, $hashes, $url, $token)
    $entries = foreach ($hash in $hashes) {
        @{ iocType = "HASH"; threatFamily = "Lab Simulation"; iocString = $hash }
    }
    $mutation = "mutation AddCustomIntelFeedMutation(`$input: AddCustomIntelFeedInput!) { addCustomIntelFeed(input: `$input) { providerId } }"
    $variables = @{ input = @{ name = $feedName; description = $description; entries = $entries } } | ConvertTo-Json -Depth 10
    return Invoke-GraphQLQuery -query $mutation -variables $variables -url $url -token $token
}

# ---------------------------------------------------------
# SECTION 3: FILE GENERATION
# ---------------------------------------------------------

function New-MinimalExecutable {
    param([string]$FilePath)
    try {
        # Minimal PE Header bytes
        $peHeader = @(
            0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
            0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        )
        $randomBytes = New-Object byte[] (Get-Random -Minimum 2048 -Maximum 8192)
        (New-Object System.Random).NextBytes($randomBytes)
        [System.IO.File]::WriteAllBytes($FilePath, ([byte[]]$peHeader + $randomBytes))
        return $true
    } catch { return $false }
}

# ---------------------------------------------------------
# SECTION 4: MAIN SCRIPT LOGIC
# ---------------------------------------------------------

Clear-Host
Write-Host "=== Rubrik Threat Hunting Simulator ===" -ForegroundColor Cyan

$targetDir = if ($OutputDirectory) { $OutputDirectory } else { Join-Path $PSScriptRoot "Threats" }
$csvPath = Join-Path $targetDir "generated_executables.csv"

# CLEANUP LOGIC
if ($Cleanup) {
    Write-Host "--- Resetting Environment: $targetDir ---" -ForegroundColor Red
    
    if (Test-Path $csvPath) {
        try {
            $data = Import-Csv $csvPath -ErrorAction SilentlyContinue
            foreach ($item in $data) {
                if (Test-Path $item.Path) { Remove-Item $item.Path -Force -ErrorAction SilentlyContinue }
            }
        } catch {}
    }

    if (Test-Path $targetDir) {
        Get-ChildItem -Path $targetDir -Filter "*.exe" | Where-Object { $_.Name -match "^[A-Z]{10}\.exe$" } | ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $csvPath) { 
            $data = $null; [GC]::Collect(); [GC]::WaitForPendingFinalizers()
            Remove-Item $csvPath -Force -ErrorAction SilentlyContinue 
        }
    }
    Write-Host "Cleanup Complete." -ForegroundColor Green
    return
}

# GENERATION LOGIC
if (-not (Test-Path $targetDir)) { New-Item -Path $targetDir -ItemType Directory -Force | Out-Null }

$rubrikConnection = $null
if ($RubrikConfigPath) {
    try {
        $rubrikConnection = rscConnect -path $RubrikConfigPath
        Write-Host "Successfully authenticated with RSC." -ForegroundColor Green
    } catch {
        Write-Host "Authentication Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "Generating $Count files..." -ForegroundColor White
$generatedHashes = @()

for ($i = 1; $i -le $Count; $i++) {
    $fileName = "$( -join ((1..10) | % { "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[(Get-Random -Max 26)] }) ).exe"
    $fullPath = Join-Path $targetDir $fileName
    
    if (New-MinimalExecutable -FilePath $fullPath) {
        $hash = (Get-FileHash $fullPath -Algorithm SHA256).Hash
        $generatedHashes += $hash
        
        if ($NetworkPaths) {
            foreach ($netPath in $NetworkPaths) {
                if (Test-Path $netPath) { Copy-Item $fullPath -Destination $netPath }
            }
        }

        [PSCustomObject]@{
            Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            FileName = $fileName
            SHA256 = $hash
            Path = $fullPath
        } | Export-Csv $csvPath -Append -NoTypeInformation
        Write-Host "Created: $fileName" -ForegroundColor Green
    }
}

if ($rubrikConnection -and $CreateThreatFeed -and $generatedHashes.Count -gt 0) {
    Write-Host "Uploading Threat Feed to RSC..." -ForegroundColor Cyan
    $feedName = "Lab-Threat-$(Get-Date -Format 'yyyyMMdd-HHmm')"
    $result = New-RubrikThreatFeed -feedName $feedName -description "Generated by Threat Simulator" -hashes $generatedHashes -url $rubrikConnection.graphql_url -token $rubrikConnection.access_token
    if ($result) { Write-Host "Threat Feed '$feedName' active in RSC." -ForegroundColor Green }
}

Write-Host "`nSimulation Complete." -ForegroundColor White
