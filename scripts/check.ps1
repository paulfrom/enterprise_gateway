$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    uv sync --frozen --offline --group dev --no-editable --reinstall-package enterprise-privacy-gateway --cache-dir .uv-cache
    if ($LASTEXITCODE -ne 0) { throw 'Locked installation failed.' }
    uv run --frozen --offline --no-editable --group dev --cache-dir .uv-cache python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Framework verification failed.' }
} finally {
    Pop-Location
}


