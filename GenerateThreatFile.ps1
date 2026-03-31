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

[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [int]$Count = 1,
    [string]$RubrikConfigPath,
    [switch]$CreateThreatFeed,
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
    # $variables must be a hashtable — ConvertTo-Json handles serialization once here
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
    # Pass hashtable directly — Invoke-GraphQLQuery handles JSON serialization
    $variables = @{ input = @{ name = $feedName; description = $description; entries = $entries } }
    $result = Invoke-GraphQLQuery -query $mutation -variables $variables -url $url -token $token
    return $result.data.addCustomIntelFeed
}

function Remove-RubrikThreatFeed {
    param ($providerId, $url, $token)
    $mutation = "mutation DeleteIntelFeedMutation(`$input: DeleteIntelFeedInput!) { deleteIntelFeed(input: `$input) }"
    # Pass hashtable directly — Invoke-GraphQLQuery handles JSON serialization
    $variables = @{ input = @{ providerId = $providerId } }
    $result = Invoke-GraphQLQuery -query $mutation -variables $variables -url $url -token $token
    # Rubrik returns null on data.deleteIntelFeed if successful
    return $result
}

# ---------------------------------------------------------
# SECTION 3: FILE GENERATION
# ---------------------------------------------------------

function Get-RandomString {
    param([int]$Length = 10)
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function Get-CurrentIteration {
    param([string]$CsvPath)
    if (Test-Path $CsvPath) {
        try {
            $existingData = Import-Csv $CsvPath -ErrorAction SilentlyContinue
            if ($existingData -and $existingData.Count -gt 0) {
                $lastIteration = ($existingData | Measure-Object -Property Iteration -Maximum).Maximum
                return [int]$lastIteration + 1
            }
        } catch {
            Write-Warning "Could not read existing CSV file. Starting from iteration 1."
        }
    }
    return 1
}

function New-MinimalExecutable {
    param([string]$FilePath)
    try {
        $peHeader = @(
            # DOS Header
            0x4D, 0x5A,             # MZ signature
            0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
            0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,

            # DOS Stub (minimal)
            0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
            0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63,
            0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69,
            0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
            0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

            # PE Header
            0x50, 0x45, 0x00, 0x00, # PE signature
            0x4C, 0x01,             # Machine (i386)
            0x01, 0x00,             # Number of sections
            0x00, 0x00, 0x00, 0x00, # Timestamp (randomized below)
            0x00, 0x00, 0x00, 0x00, # Pointer to symbol table
            0x00, 0x00, 0x00, 0x00, # Number of symbols
            0xE0, 0x00,             # Size of optional header
            0x02, 0x01              # Characteristics
        )

        # Randomize the PE timestamp
        $unixEpoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        $timestamp = [BitConverter]::GetBytes([uint32](([DateTime]::UtcNow - $unixEpoch).TotalSeconds))
        $peHeader[136] = $timestamp[0]
        $peHeader[137] = $timestamp[1]
        $peHeader[138] = $timestamp[2]
        $peHeader[139] = $timestamp[3]

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

$scriptRoot  = if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }
$targetDir   = if ($OutputDirectory) { $OutputDirectory } else { Join-Path $scriptRoot "Threats" }
$csvPath     = Join-Path $targetDir "generated_executables.csv"

if ($Cleanup) {
    Write-Host "--- Performing Full Reset (Local & Rubrik) ---" -ForegroundColor Red

    if (Test-Path $csvPath) {
        try {
            # Read CSV once — reuse for both Rubrik cleanup and file deletion
            $data        = Import-Csv $csvPath -ErrorAction SilentlyContinue
            $providerIds = $data | Where-Object { $_.ProviderId -and $_.ProviderId -ne "" } |
                           Select-Object -ExpandProperty ProviderId -Unique

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

            foreach ($item in $data) {
                if (Test-Path $item.FullPath) { Remove-Item $item.FullPath -Force -ErrorAction SilentlyContinue }
                if ($item.NetworkPaths) {
                    $item.NetworkPaths -split ';' | Where-Object { $_.Trim() -ne "" } | ForEach-Object {
                        $networkFilePath = Join-Path $_.Trim() $item.FileName
                        if (Test-Path $networkFilePath) { Remove-Item $networkFilePath -Force -ErrorAction SilentlyContinue }
                    }
                }
            }
        } catch {
            Write-Host "⚠ Note: Could not complete cleanup ($($_.Exception.Message))" -ForegroundColor Yellow
        }
    }

    if (Test-Path $targetDir) {
        # Catch any generated files not recorded in the CSV
        Get-ChildItem -Path $targetDir -Filter "*.exe" |
            Where-Object { $_.Name -match "^[A-Za-z0-9]{8,14}\.exe$" } |
            ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }

        if (Test-Path $csvPath) {
            Remove-Item $csvPath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "Local cleanup Complete." -ForegroundColor Green
    return
}

if (-not (Test-Path $targetDir)) { New-Item -Path $targetDir -ItemType Directory -Force | Out-Null }

$rubrikConnection = $null
$providerId       = ""
$currentIteration = Get-CurrentIteration -CsvPath $csvPath

if ($RubrikConfigPath) {
    try {
        $rubrikConnection = rscConnect -path $RubrikConfigPath
        Write-Host "Successfully authenticated with RSC." -ForegroundColor Green
    } catch {
        Write-Host "Authentication Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "Generating $Count files..." -ForegroundColor White
$batchData = [System.Collections.Generic.List[hashtable]]::new()
$hashes    = [System.Collections.Generic.List[string]]::new()

for ($i = 1; $i -le $Count; $i++) {
    $iterationNumber = $currentIteration + ($i - 1)

    # Retry on the rare chance of a name collision
    do {
        $fileName = "$(Get-RandomString -Length (Get-Random -Minimum 8 -Maximum 15)).exe"
        $fullPath = Join-Path $targetDir $fileName
    } while (Test-Path $fullPath)

    if (New-MinimalExecutable -FilePath $fullPath) {
        $hash         = (Get-FileHash $fullPath -Algorithm SHA256).Hash
        $fileSize     = (Get-Item $fullPath).Length
        $creationTime = (Get-Item $fullPath).CreationTime
        $hashes.Add($hash)

        $networkPathsString = ""
        if ($NetworkPaths) {
            $successfulPaths = @()
            foreach ($netPath in $NetworkPaths) {
                try {
                    Copy-Item -Path $fullPath -Destination $netPath -Force -ErrorAction Stop
                    Write-Host "  Copied to: $netPath" -ForegroundColor Gray
                    $successfulPaths += $netPath
                } catch {
                    Write-Host "  ⚠ Could not copy to ${netPath}: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
            if ($successfulPaths.Count -gt 0) { $networkPathsString = $successfulPaths -join ';' }
        }

        $batchData.Add(@{
            Iteration    = $iterationNumber
            FileName     = $fileName
            FullPath     = $fullPath
            Hash         = $hash
            Size         = $fileSize
            Created      = $creationTime
            NetworkPaths = $networkPathsString
        })
        Write-Host "Created: $fileName" -ForegroundColor Green
    }
}

$feedName = ""
if ($rubrikConnection -and $CreateThreatFeed -and $hashes.Count -gt 0) {
    Write-Host "Uploading Threat Feed to RSC..." -ForegroundColor Cyan
    $feedName = "Lab-Threat-$(Get-Date -Format 'yyyyMMdd-HHmm')"
    $result = New-RubrikThreatFeed -feedName $feedName -description "Generated by Threat Simulator" -hashes $hashes -url $rubrikConnection.graphql_url -token $rubrikConnection.access_token
    if ($result.providerId) {
        $providerId = $result.providerId
        Write-Host "Threat Feed '$feedName' active in RSC (ID: $providerId)." -ForegroundColor Green
    }
}

$batchData | ForEach-Object {
    [PSCustomObject]@{
        Iteration    = $_.Iteration
        ThreatFeed   = $feedName
        FileName     = $_.FileName
        FullPath     = $_.FullPath
        SHA256       = $_.Hash
        Size         = $_.Size
        Created      = $_.Created
        ProviderId   = $providerId
        NetworkPaths = $_.NetworkPaths
    }
} | Export-Csv $csvPath -Append -NoTypeInformation

Write-Host "`nSimulation Complete." -ForegroundColor White
