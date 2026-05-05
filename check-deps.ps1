# Simple dependency check script

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Dependency Check Tool" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

function Test-Tool {
    param($Name, $Command)

    Write-Host "Checking $Name..." -ForegroundColor Yellow
    try {
        if (Get-Command $Command -ErrorAction Stop) {
            Write-Host "[OK] $Name is installed" -ForegroundColor Green
            $version = & $Command --version 2>&1 | Select-Object -First 1
            Write-Host "    $version" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[  ] $Name is NOT installed" -ForegroundColor Red
    }
    Write-Host ""
}

Test-Tool "Node.js" "node"
Test-Tool "Git" "git"
Test-Tool "Python" "python"
Test-Tool "pip" "pip"
Test-Tool "Chocolatey" "choco"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Check complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

Read-Host "Press Enter to exit"
