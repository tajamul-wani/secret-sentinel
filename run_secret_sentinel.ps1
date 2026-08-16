param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args = @()
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

$pythonCommand = $null
foreach ($candidate in @("py", "python")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $pythonCommand = $candidate
        break
    }
}

if (-not $pythonCommand) {
    Write-Error "Python was not found. Install Python 3.10+ and try again."
    exit 1
}

if ($Args.Count -eq 0) {
    $Args = @("--staged")
}

Write-Host "Running Secret Sentinel with: $($Args -join ' ')"
& $pythonCommand -m pip install -e . --quiet
& $pythonCommand -m secret_sentinel.cli @Args
exit $LASTEXITCODE
