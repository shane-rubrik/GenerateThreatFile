<#
.SYNOPSIS
    Cybersecurity Threat Hunting Simulator for Rubrik Security Cloud.

.DESCRIPTION
    PURPOSE:
    This script generates harmless, random executable files to simulate a malware outbreak.
    It is designed for security teams to practice threat hunting, detection, and mitigation
    using Rubrik Security Cloud (RSC).

    CLEANUP FEATURE:
    When run with the -Cleanup switch and a valid RubrikConfigPath, the script will:
    1. Read the local tracking CSV to find the Rubrik Provider ID.
    2. Connect to RSC and delete the Intel Threat Source automatically.
    3. Delete all local .exe files and the tracking log.

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
    Switch to delete local files AND remove the Threat Source from Rubrik Security Cloud.
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
    param ($query, $variables, $url, $token)
    $body = @{ query = $query; variables = $variables } | ConvertTo-Json -Depth 10
    $headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
        return $response
    } catch {
        throw "GraphQL Request Failed: $($_.Exception.Message)"
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
    $result = Invoke-GraphQLQuery -query $mutation -variables $variables -url $url -token $token
    return $result.data.addCustomIntelFeed
}

function Remove-RubrikThreatFeed {
    param ($providerId, $url, $token)
    $mutation = "mutation DeleteIntelFeedMutation(`$input: DeleteIntelFeedInput!) { deleteIntelFeed(input: `$input) }"
    $variables = @{ input = @{ providerId = $providerId } } | ConvertTo-Json -Depth 10
    $result = Invoke-GraphQLQuery -query $mutation -variables $variables -url $url -token $token
    # Rubrik returns null on data.deleteIntelFeed if successful
    return $result
}

# ---------------------------------------------------------
# SECTION 3: FILE GENERATION
# ---------------------------------------------------------

function New-MinimalExecutable {
    param([string]$FilePath)
    try {
        $peHeader = @(0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00)
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

if ($Cleanup) {
    Write-Host "--- Performing Full Reset (Local & Rubrik) ---" -ForegroundColor Red
    
    if (Test-Path $csvPath) {
        try {
            $data = Import-Csv $csvPath -ErrorAction SilentlyContinue
            $providerIds = $data | Where-Object { $_.ProviderId -and $_.ProviderId -ne "" } | Select-Object -ExpandProperty ProviderId -Unique
            
            if ($providerIds -and $RubrikConfigPath) {
                Write-Host "Connecting to Rubrik to remove Threat Sources..." -ForegroundColor Yellow
                $conn = rscConnect -path $RubrikConfigPath
                foreach ($id in $providerIds) {
                    Write-Host "  Removing Threat Source ID: $id" -ForegroundColor Gray
                    $response = Remove-RubrikThreatFeed -providerId $id -url $conn.graphql_url -token $conn.access_token
                    if ($null -eq $response.errors) {
                         Write-Host "  ✓ Successfully removed from Rubrik." -ForegroundColor Green
                    }
                }
            }
        } catch {
            Write-Host "⚠ Note: Could not clean up Rubrik sources ($($_.Exception.Message))" -ForegroundColor Yellow
        }
    }

    if (Test-Path $targetDir) {
        if (Test-Path $csvPath) {
            foreach ($item in (Import-Csv $csvPath)) {
                if (Test-Path $item.Path) { Remove-Item $item.Path -Force -ErrorAction SilentlyContinue }
            }
        }
        Get-ChildItem -Path $targetDir -Filter "*.exe" | Where-Object { $_.Name -match "^[A-Z]{10}\.exe$" } | ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $csvPath) { 
            $data = $null; [GC]::Collect(); [GC]::WaitForPendingFinalizers()
            Remove-Item $csvPath -Force -ErrorAction SilentlyContinue 
        }
    }
    Write-Host "Local cleanup Complete." -ForegroundColor Green
    return
}

if (-not (Test-Path $targetDir)) { New-Item -Path $targetDir -ItemType Directory -Force | Out-Null }

$rubrikConnection = $null
$providerId = ""

if ($RubrikConfigPath) {
    try {
        $rubrikConnection = rscConnect -path $RubrikConfigPath
        Write-Host "Successfully authenticated with RSC." -ForegroundColor Green
    } catch {
        Write-Host "Authentication Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "Generating $Count files..." -ForegroundColor White
$batchData = @()
$hashes = @()

for ($i = 1; $i -le $Count; $i++) {
    $fileName = "$( -join ((1..10) | % { "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[(Get-Random -Max 26)] }) ).exe"
    $fullPath = Join-Path $targetDir $fileName
    
    if (New-MinimalExecutable -FilePath $fullPath) {
        $hash = (Get-FileHash $fullPath -Algorithm SHA256).Hash
        $hashes += $hash
        $batchData += @{ FileName = $fileName; Path = $fullPath; Hash = $hash }
        Write-Host "Created: $fileName" -ForegroundColor Green
    }
}

if ($rubrikConnection -and $CreateThreatFeed -and $hashes.Count -gt 0) {
    Write-Host "Uploading Threat Feed to RSC..." -ForegroundColor Cyan
    $feedName = "Lab-Threat-$(Get-Date -Format 'yyyyMMdd-HHmm')"
    $result = New-RubrikThreatFeed -feedName $feedName -description "Generated by Threat Simulator" -hashes $hashes -url $rubrikConnection.graphql_url -token $rubrikConnection.access_token
    if ($result.providerId) { 
        $providerId = $result.providerId
        Write-Host "Threat Feed '$feedName' active in RSC (ID: $providerId)." -ForegroundColor Green 
    }
}

foreach ($item in $batchData) {
    [PSCustomObject]@{
        Time       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        FileName   = $item.FileName
        SHA256     = $item.Hash
        Path       = $item.Path
        ProviderId = $providerId
    } | Export-Csv $csvPath -Append -NoTypeInformation
}

Write-Host "`nSimulation Complete." -ForegroundColor White
