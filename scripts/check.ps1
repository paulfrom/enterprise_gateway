$ErrorActionPreference = 'Stop'

# 1. 定位项目根
# 使用 $PSScriptRoot 确定仓库根目录，支持从任意当前目录（cwd）调用均能唯一定位到项目根，
# 且严禁覆盖 $HOME / $CODEX_HOME 等系统变量。
if (-not $PSScriptRoot) {
    throw 'Unable to determine script root ($PSScriptRoot is not set).'
}
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

Push-Location $RepoRoot
try {
    # 结构纯洁性与关键文件核验
    $rootPyproject = Join-Path $RepoRoot 'pyproject.toml'
    if (Test-Path $rootPyproject) {
        throw "Purity check failed: Root directory must not contain pyproject.toml ($rootPyproject exists)."
    }

    $subLock = Join-Path $RepoRoot 'apps/admin-web/package-lock.json'
    if (Test-Path $subLock) {
        throw "Purity check failed: apps/admin-web must not contain a standalone package-lock.json ($subLock exists)."
    }

    $rootPkg = Join-Path $RepoRoot 'package.json'
    if (-not (Test-Path $rootPkg)) {
        throw "Root package.json is missing: $rootPkg"
    }

    $rootLock = Join-Path $RepoRoot 'package-lock.json'
    if (-not (Test-Path $rootLock)) {
        throw "Root package-lock.json is missing: $rootLock"
    }

    $contractPath = Join-Path $RepoRoot 'contracts/admin.openapi.json'
    if (-not (Test-Path $contractPath)) {
        throw "Admin OpenAPI contract is missing: $contractPath"
    }

    # 2. 工具版本/环境前置核验：检查 Node (v22)、npm、Python/uv 等必需 CLI 环境
    Write-Host '==> [1/4] Verifying CLI tools and environment...'

    # Node.js (v22)
    if (-not (Get-Command 'node' -ErrorAction SilentlyContinue)) {
        throw 'Required CLI tool "node" is not found in PATH.'
    }
    $nodeVersion = (& node --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to execute "node --version".'
    }
    if ($nodeVersion -notmatch '^v?22(\.|$)') {
        throw "Node.js version v22 is required, but found: $nodeVersion"
    }
    Write-Host "    Node: $nodeVersion (verified v22)"

    # npm
    if (-not (Get-Command 'npm' -ErrorAction SilentlyContinue)) {
        throw 'Required CLI tool "npm" is not found in PATH.'
    }
    $npmVersion = (& npm --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to execute "npm --version".'
    }
    Write-Host "    npm: $npmVersion"

    # uv
    if (-not (Get-Command 'uv' -ErrorAction SilentlyContinue)) {
        throw 'Required CLI tool "uv" is not found in PATH.'
    }
    $uvVersion = (& uv --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to execute "uv --version".'
    }
    Write-Host "    uv: $uvVersion"

    # Python
    $pythonCmd = $null
    if (Get-Command 'python' -ErrorAction SilentlyContinue) {
        $pythonCmd = 'python'
    } elseif (Get-Command 'python3' -ErrorAction SilentlyContinue) {
        $pythonCmd = 'python3'
    } else {
        throw 'Required CLI tool "python" (or python3) is not found in PATH.'
    }
    $pythonVersion = (& $pythonCmd --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to execute '$pythonCmd --version'."
    }
    Write-Host "    Python: $pythonVersion ($pythonCmd)"

    # 3. 串联后端检查：调用 check.ps1 执行后端冻结离线依赖安装与 unittest 门禁
    Write-Host '==> [2/4] Calling backend check (apps/backend/scripts/check.ps1)...'
    $backendCheckScript = Join-Path $RepoRoot 'apps/backend/scripts/check.ps1'
    if (-not (Test-Path $backendCheckScript)) {
        throw "Backend check script not found: $backendCheckScript"
    }
    & $backendCheckScript
    if ($LASTEXITCODE -ne 0) {
        throw "Backend check failed with exit code $LASTEXITCODE."
    }

    # 4. 串联前端与契约检查
    # 从根执行 npm ci
    Write-Host '==> [3/4] Installing frontend dependencies (npm ci)...'
    & npm ci
    if ($LASTEXITCODE -ne 0) {
        throw "npm ci failed with exit code $LASTEXITCODE."
    }

    Write-Host '==> [4/4] Running frontend gates and contract checks...'

    # 执行 npm run check:api --workspace apps/admin-web（契约漂移门禁）
    Write-Host '    -> check:api (Contract drift gate)...'
    & npm run check:api --workspace apps/admin-web
    if ($LASTEXITCODE -ne 0) {
        throw "Contract check (npm run check:api) failed with exit code $LASTEXITCODE."
    }

    # 执行 npm run typecheck --workspace apps/admin-web（类型检查）
    Write-Host '    -> typecheck (TypeScript typecheck)...'
    & npm run typecheck --workspace apps/admin-web
    if ($LASTEXITCODE -ne 0) {
        throw "Typecheck (npm run typecheck) failed with exit code $LASTEXITCODE."
    }

    # 执行 npm run lint --workspace apps/admin-web（代码质量检查）
    Write-Host '    -> lint (ESLint code quality)...'
    & npm run lint --workspace apps/admin-web
    if ($LASTEXITCODE -ne 0) {
        throw "Linter (npm run lint) failed with exit code $LASTEXITCODE."
    }

    # 执行 npm run test --workspace apps/admin-web（单元测试）
    Write-Host '    -> test (Vitest unit tests)...'
    & npm run test --workspace apps/admin-web
    if ($LASTEXITCODE -ne 0) {
        throw "Unit tests (npm run test) failed with exit code $LASTEXITCODE."
    }

    # 执行 npm run build --workspace apps/admin-web（生产静态编译）
    Write-Host '    -> build (Vite production build)...'
    & npm run build --workspace apps/admin-web
    if ($LASTEXITCODE -ne 0) {
        throw "Production build (npm run build) failed with exit code $LASTEXITCODE."
    }

    Write-Host '==> All checks completed successfully.'
} finally {
    Pop-Location
}
