<#
.SYNOPSIS
  Read-only detector for the gemini-cli workflow_run artifact-poisoning chain.

.DESCRIPTION
  Fetches the two workflow files from the PUBLIC GitHub API at the current HEAD
  of the default branch and verifies each precondition of the vulnerability:

    1. trigger_e2e.yml runs on an UNPRIVILEGED trigger (pull_request)
    2. ...and persists attacker-controlled head.repo.full_name / head.sha to an artifact
    3. chained_e2e.yml runs on the PRIVILEGED workflow_run trigger
    4. ...downloads that artifact
    5. ...feeds the artifact-derived repo/ref into actions/checkout
    6. ...then executes npm scripts (ci/build/test) from the checked-out tree
    7. ...with secrets.GEMINI_API_KEY present in that job's environment

  It is 100% read-only against api.github.com. It does NOT contact Google
  infrastructure and performs no exploitation. Its purpose is to confirm the
  vulnerable configuration is still live and to emit evidence for a VRP report.

.PARAMETER Token
  Optional GitHub PAT (any classic/read token) to raise the 60/hr anonymous
  rate limit. No scopes required for public repos.

.EXAMPLE
  .\Detect-ArtifactPoisoning.ps1
  .\Detect-ArtifactPoisoning.ps1 -Token ghp_xxx
#>
[CmdletBinding()]
param(
  [string]$Owner  = 'google-gemini',
  [string]$Repo   = 'gemini-cli',
  [string]$Trigger= '.github/workflows/trigger_e2e.yml',
  [string]$Chained= '.github/workflows/chained_e2e.yml',
  [string]$Token
)

$ErrorActionPreference = 'Stop'
$api = "https://api.github.com"
$headers = @{ 'User-Agent' = 'vrp-static-detector'; 'Accept' = 'application/vnd.github+json' }
if ($Token) { $headers['Authorization'] = "Bearer $Token" }

function Get-File($path, $ref) {
  $u = "$api/repos/$Owner/$Repo/contents/$path`?ref=$ref"
  $r = Invoke-RestMethod -Uri $u -Headers $headers
  [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($r.content -replace '\s',''))
}

function Test-Chain($name, $regex, $text) {
  $m = [regex]::Match($text, $regex, 'IgnoreCase,Singleline')
  [pscustomobject]@{ Check = $name; Present = $m.Success; Evidence = ($m.Value -replace '\s+',' ').Trim() }
}

Write-Host "`n=== Live static detector: $Owner/$Repo ===" -ForegroundColor Cyan

# Pin to the exact commit the files currently live at (for the report).
$branch   = (Invoke-RestMethod -Uri "$api/repos/$Owner/$Repo" -Headers $headers).default_branch
$headSha  = (Invoke-RestMethod -Uri "$api/repos/$Owner/$Repo/commits/$branch" -Headers $headers).sha
Write-Host ("Default branch : {0}" -f $branch)
Write-Host ("HEAD commit    : {0}" -f $headSha)

$tText = Get-File $Trigger $headSha
$cText = Get-File $Chained $headSha

# Expression forms in these files are single-quoted, e.g.  key: '${{ ... }}'
$q = "['""]?"              # optional surrounding quote
$e = "$q\`$\{\{\s*"        # optional-quote + literal ${{ + whitespace

$results = @()
# --- trigger_e2e.yml (untrusted source) ---
$results += Test-Chain '1. trigger runs on pull_request (untrusted)' '(?m)^\s*pull_request\s*:' $tText
$results += Test-Chain '2. persists head.repo.full_name to artifact' 'pull_request\.head\.repo\.full_name' $tText
$results += Test-Chain '2b. persists head.sha to artifact'           'pull_request\.head\.sha'           $tText
$results += Test-Chain '2c. uploads the artifact'                    "uses:\s*${q}actions/upload-artifact" $tText
# --- chained_e2e.yml (privileged sink) ---
$results += Test-Chain '3. chained runs on workflow_run (privileged)' '(?m)^\s*workflow_run\s*:'          $cText
$results += Test-Chain '4. downloads the poisoned artifact'          "uses:\s*${q}actions/download-artifact" $cText
$results += Test-Chain '5. checkout uses artifact-derived repository' "repository:\s*${e}needs\.parse_run_context\.outputs\.repository" $cText
$results += Test-Chain '5b. checkout uses artifact-derived ref'       "ref:\s*${e}needs\.parse_run_context\.outputs\.sha"               $cText
$results += Test-Chain '6. executes npm scripts from checkout'        'npm run (build|test:integration)'   $cText
$results += Test-Chain '7. GEMINI_API_KEY present in that job env'    "GEMINI_API_KEY:\s*${e}secrets\.GEMINI_API_KEY" $cText

$results | Format-Table -AutoSize Check, Present

$all = ($results.Present -notcontains $false)
Write-Host ""
if ($all) {
  Write-Host "VERDICT: VULNERABLE CHAIN FULLY PRESENT on $headSha" -ForegroundColor Red
} else {
  Write-Host "VERDICT: chain incomplete - one or more links changed. Re-review before reporting." -ForegroundColor Yellow
}

Write-Host "`n--- Evidence block for the report ---" -ForegroundColor Cyan
Write-Host ("Repo        : https://github.com/$Owner/$Repo")
Write-Host ("Pinned SHA  : $headSha")
Write-Host ("Trigger file: https://github.com/$Owner/$Repo/blob/$headSha/$Trigger")
Write-Host ("Chained file: https://github.com/$Owner/$Repo/blob/$headSha/$Chained")
Write-Host ("Detected at : {0:u}" -f (Get-Date))
$results | Where-Object Present | ForEach-Object { Write-Host ("  [OK] {0} :: {1}" -f $_.Check, $_.Evidence) }
