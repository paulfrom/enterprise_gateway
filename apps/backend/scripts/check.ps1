$ErrorActionPreference = 'Stop'
$BackendDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $BackendDirectory
try {
    uv sync --frozen --offline --group dev --no-editable --reinstall-package enterprise-privacy-gateway --cache-dir .uv-cache
    if ($LASTEXITCODE -ne 0) { throw 'Locked installation failed.' }
    uv run --frozen --offline --no-editable --group dev --cache-dir .uv-cache python scripts/export_admin_openapi.py --check
    if ($LASTEXITCODE -ne 0) { throw 'Backend OpenAPI drift check failed.' }
    uv run --frozen --offline --no-editable --group dev --cache-dir .uv-cache python scripts/check_package.py
    if ($LASTEXITCODE -ne 0) { throw 'Backend package verification failed.' }
    $testTimeoutSeconds = 1800
    if ($env:GATEWAY_TEST_TIMEOUT_SECONDS) { $testTimeoutSeconds = [int]$env:GATEWAY_TEST_TIMEOUT_SECONDS }
    if ($testTimeoutSeconds -lt 1 -or $testTimeoutSeconds -gt 86400) { throw 'Invalid test timeout.' }
    $testProcess = Start-Process -FilePath (Get-Command uv).Source -WorkingDirectory $BackendDirectory -NoNewWindow -PassThru -ArgumentList @(
        'run', '--frozen', '--offline', '--no-editable', '--group', 'dev', '--cache-dir', '.uv-cache',
        'python', '-m', 'unittest', 'discover', '-s', 'tests', '-t', '.', '-v'
    )
    try {
        if (-not $testProcess.WaitForExit($testTimeoutSeconds * 1000)) {
            $testProcess.Kill($true)
            $null = $testProcess.WaitForExit(10000)
            throw 'Framework verification timed out; incomplete tests are not a pass.'
        }
        if ($testProcess.ExitCode -ne 0) { throw "Framework verification failed with exit code $($testProcess.ExitCode)." }
    } finally {
        $testProcess.Dispose()
    }
} finally {
    Pop-Location
}


