<#
.SYNOPSIS
    Combines DNS blocklist URLs and synchronizes the resulting domain list to a GitHub file.

.DESCRIPTION
    Reads one URL per line from a text file. Supports plain domain lists and hosts-file
    format (for example, 0.0.0.0 ads.example.com). Ignores blank/comment lines,
    removes duplicates, compares against the existing GitHub file, and commits only
    when the domain list has changed.

    Requires PowerShell 5.1+ and a GitHub personal access token in $env:GITHUB_TOKEN.
    The token needs Contents: read and write access to the target repository.

.EXAMPLE
    $env:GITHUB_TOKEN = 'github_pat_...'
    .\Sync-DnsBlocklistsToGitHub.ps1 `
        -UrlListPath .\blocklist-urls.txt `
        -Owner 'your-account' `
        -Repository 'dns-lists' `
        -FilePath 'blocklists/combined-domains.txt' `
        -Branch 'main'

.PARAMETER UrlListPath
    Path to the list of the URL Text Files
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$UrlListPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Owner,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Repository,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$FilePath,

    [string]$Branch,

    [string]$CommitMessage = 'Update combined DNS blocklist',

    [switch]$AllowEmptyList
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-GitHubHeaders {
    param([Parameter(Mandatory)][string]$Token)

    return @{
        Accept                 = 'application/vnd.github+json'
        Authorization          = "Bearer $Token"
        'X-GitHub-Api-Version' = '2022-11-28'
        'User-Agent'            = 'PowerShell-DNS-Blocklist-Sync'
    }
}

function ConvertTo-GitHubContentsPath {
    param([Parameter(Mandatory)][string]$Path)

    $segments = $Path -split '/' | Where-Object { $_ -ne '' }
    if ($segments.Count -eq 0) {
        throw 'FilePath must identify a file inside the repository.'
    }

    return (($segments | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/')
}

function Get-BlocklistDomains {
    param([Parameter(Mandatory)][string[]]$Lines)

    $domains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $domainPattern = '^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
    $ignoredHosts = @('localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback')

    foreach ($line in $Lines) {
        $cleanLine = ($line -replace "`0", '').Trim().TrimStart([char]0xFEFF)
        if ([string]::IsNullOrWhiteSpace($cleanLine) -or $cleanLine -match '^[#!;]') {
            continue
        }

        # Strip trailing inline comments commonly used in hosts-style files.
        $cleanLine = ($cleanLine -split '\s+[#!;]', 2)[0].Trim()
        if (-not $cleanLine) { continue }

        $tokens = @($cleanLine -split '\s+')
        $ipAddress = $null
        $isHostsEntry = $tokens.Count -gt 1 -and [System.Net.IPAddress]::TryParse($tokens[0], [ref]$ipAddress)
        $candidateTokens = if ($isHostsEntry) { $tokens | Select-Object -Skip 1 } else { $tokens }

        foreach ($token in $candidateTokens) {
            $candidate = $token.Trim().TrimEnd('.')
            if ($candidate -match '^\*\.') { $candidate = $candidate.Substring(2) }
            $candidate = $candidate.ToLowerInvariant()

            if ($candidate -match $domainPattern -and $candidate -notin $ignoredHosts) {
                [void]$domains.Add($candidate)
            }
        }
    }

    return @($domains)
}

function Get-GitHubFile {
    param(
        [Parameter(Mandatory)][string]$ApiUrl,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    try {
        $response = Invoke-RestMethod -Method Get -Uri $ApiUrl -Headers $Headers
        if ($response.type -ne 'file') {
            throw "GitHub path is not a file: $($response.path)"
        }

        if ($response.encoding -eq 'base64' -and $response.content) {
            $base64 = ($response.content -replace '\s', '')
            $content = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64))
        }
        elseif ($response.download_url) {
            $content = (Invoke-RestMethod -Method Get -Uri $response.download_url -Headers @{ 'User-Agent' = 'PowerShell-DNS-Blocklist-Sync' })
        }
        else {
            throw 'GitHub returned no readable file content.'
        }

        return [pscustomobject]@{ Sha = $response.sha; Content = [string]$content }
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -eq 404) { return $null }
        throw
    }
}

function Set-GitHubFile {
    param(
        [Parameter(Mandatory)][string]$ApiUrl,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$Message,
        [string]$FileSha,
        [string]$TargetBranch
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $body = @{
        message = $Message
        content = [Convert]::ToBase64String($bytes)
    }
    if ($FileSha) { $body.sha = $FileSha }
    if ($TargetBranch) { $body.branch = $TargetBranch }

    return Invoke-RestMethod -Method Put -Uri $ApiUrl -Headers $Headers -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json; charset=utf-8'
}

$token = $env:GITHUB_TOKEN
if ([string]::IsNullOrWhiteSpace($token)) {
    throw 'Set the GITHUB_TOKEN environment variable before running this script.'
}

$urlLines = Get-Content -LiteralPath $UrlListPath -ErrorAction Stop
$sourceUrls = @(
    $urlLines |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') -and -not $_.StartsWith(';') } |
        Select-Object -Unique
)
if ($sourceUrls.Count -eq 0) {
    throw "No source URLs were found in '$UrlListPath'."
}

$allDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($sourceUrl in $sourceUrls) {
    $parsedUri = $null
    if (-not [uri]::TryCreate($sourceUrl, [System.UriKind]::Absolute, [ref]$parsedUri) -or $parsedUri.Scheme -notin @('http', 'https')) {
        throw "Invalid HTTP/HTTPS source URL in '$UrlListPath': $sourceUrl"
    }

    Write-Host "Downloading $sourceUrl"
    try {
        $sourceContent = Invoke-RestMethod -Method Get -Uri $parsedUri -TimeoutSec 60 -Headers @{ 'User-Agent' = 'PowerShell-DNS-Blocklist-Sync' }
    }
    catch {
        throw "Failed to download '$sourceUrl'. No GitHub changes were made. $($_.Exception.Message)"
    }

    $sourceLines = ([string]$sourceContent) -split "`r?`n"
    $sourceDomains = @(Get-BlocklistDomains -Lines $sourceLines)
    if ($sourceDomains.Count -eq 0) {
        throw "No valid domains were parsed from '$sourceUrl'. No GitHub changes were made."
    }

    foreach ($domain in $sourceDomains) { [void]$allDomains.Add($domain) }
    Write-Host "  Parsed $($sourceDomains.Count) domains"
}

if ($allDomains.Count -eq 0 -and -not $AllowEmptyList) {
    throw 'The combined list is empty. Use -AllowEmptyList only if an empty GitHub file is intentional.'
}

$newDomains = @($allDomains | Sort-Object)
$newContent = if ($newDomains.Count -gt 0) { ($newDomains -join "`n") + "`n" } else { '' }

$encodedPath = ConvertTo-GitHubContentsPath -Path $FilePath
$apiUrl = "https://api.github.com/repos/$Owner/$Repository/contents/$encodedPath"
$headers = Get-GitHubHeaders -Token $token
$githubFile = Get-GitHubFile -ApiUrl $apiUrl -Headers $headers
$oldDomains = @()
if ($null -ne $githubFile) {
    $oldDomains = @(Get-BlocklistDomains -Lines ($githubFile.Content -split "`r?`n"))
}

$oldSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$newSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($domain in $oldDomains) { [void]$oldSet.Add($domain) }
foreach ($domain in $newDomains) { [void]$newSet.Add($domain) }
$added = @($newDomains | Where-Object { -not $oldSet.Contains($_) } | Sort-Object)
$removed = @($oldDomains | Where-Object { -not $newSet.Contains($_) } | Sort-Object)

Write-Host "Current GitHub domains: $($oldSet.Count)"
Write-Host "Fetched domains:        $($newSet.Count)"
Write-Host "Added:                  $($added.Count)"
Write-Host "Removed:                $($removed.Count)"

if ($added.Count -eq 0 -and $removed.Count -eq 0) {
    Write-Host 'GitHub already has the current list. No commit was created.'
    return
}

if ($added.Count -gt 0) {
    Write-Host 'New domains:'
    $added | Select-Object -First 25 | ForEach-Object { Write-Host "  + $_" }
    if ($added.Count -gt 25) { Write-Host "  ... and $($added.Count - 25) more" }
}
if ($removed.Count -gt 0) {
    Write-Host 'Removed domains:'
    $removed | Select-Object -First 25 | ForEach-Object { Write-Host "  - $_" }
    if ($removed.Count -gt 25) { Write-Host "  ... and $($removed.Count - 25) more" }
}

$commit = Set-GitHubFile -ApiUrl $apiUrl -Headers $headers -Content $newContent -Message $CommitMessage -FileSha $(if ($githubFile) { $githubFile.Sha }) -TargetBranch $Branch
Write-Host "Updated GitHub: $($commit.content.html_url)"
Write-Host "Commit:         $($commit.commit.sha)"
