# Code Audit Platform - Dependency Installation Script (Windows PowerShell)
# Purpose: Automatically detect and install required external tools

# Requires Administrator privileges
#Requires -RunAsAdministrator

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Code Audit Platform - Dependency Installer" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if command exists
function Test-Command {
    param($Command)
    try {
        if (Get-Command $Command -ErrorAction Stop) {
            return $true
        }
    }
    catch {
        return $false
    }
}

# Check tool and display status
function Check-Tool {
    param(
        [string]$Name,
        [string]$Command,
        [string]$VersionArg = "--version"
    )

    if (Test-Command $Command) {
        Write-Host "[OK] $Name is installed" -ForegroundColor Green
        try {
            $version = & $Command $VersionArg 2>&1 | Select-Object -First 1
            Write-Host "    $version" -ForegroundColor Gray
        }
        catch {
            # Ignore version check errors
        }
        return $true
    }
    else {
        Write-Host "[  ] $Name is not installed" -ForegroundColor Yellow
        return $false
    }
}

# Install Chocolatey
function Install-Chocolatey {
    Write-Host ""
    Write-Host "Installing Chocolatey..." -ForegroundColor Cyan

    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

    try {
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Host "[OK] Chocolatey installed successfully" -ForegroundColor Green

        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

        return $true
    }
    catch {
        Write-Host "[ERROR] Chocolatey installation failed: $_" -ForegroundColor Red
        return $false
    }
}

# Install tool with Chocolatey
function Install-WithChoco {
    param(
        [string]$Name,
        [string]$Package
    )

    Write-Host ""
    Write-Host "Installing $Name..." -ForegroundColor Cyan

    try {
        choco install $Package -y --no-progress
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] $Name installed successfully" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "[ERROR] $Name installation failed" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "[ERROR] $Name installation failed: $_" -ForegroundColor Red
        return $false
    }
}

# Install tool with pip
function Install-WithPip {
    param(
        [string]$Name,
        [string]$Package
    )

    Write-Host ""
    Write-Host "Installing $Name..." -ForegroundColor Cyan

    try {
        pip install $Package
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] $Name installed successfully" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "[ERROR] $Name installation failed" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "[ERROR] $Name installation failed: $_" -ForegroundColor Red
        return $false
    }
}

# Main function
function Main {
    Write-Host "Checking dependencies..." -ForegroundColor Cyan
    Write-Host ""

    # Check required tools
    Write-Host "Checking required tools..." -ForegroundColor Cyan
    $needNodejs = -not (Check-Tool "Node.js" "node")
    $needGit = -not (Check-Tool "Git" "git")
    $needPython = -not (Check-Tool "Python" "python")
    $needPip = -not (Check-Tool "pip" "pip")

    Write-Host ""
    Write-Host "Checking optional tools (for enhanced scanning)..." -ForegroundColor Cyan
    $needGitleaks = -not (Check-Tool "Gitleaks" "gitleaks" "version")
    $needBandit = -not (Check-Tool "Bandit" "bandit")
    $needSemgrep = -not (Check-Tool "Semgrep" "semgrep")

    Write-Host ""

    # Count tools to install
    $needInstall = $needNodejs -or $needGit -or $needPython -or $needPip -or $needGitleaks -or $needBandit -or $needSemgrep

    if ($needInstall) {
        Write-Host "==========================================" -ForegroundColor Yellow
        Write-Host "Tools to install:" -ForegroundColor Yellow
        if ($needNodejs) { Write-Host "  - Node.js (required)" -ForegroundColor White }
        if ($needGit) { Write-Host "  - Git (required)" -ForegroundColor White }
        if ($needPython) { Write-Host "  - Python (required)" -ForegroundColor White }
        if ($needPip) { Write-Host "  - pip (required)" -ForegroundColor White }
        if ($needGitleaks) { Write-Host "  - Gitleaks (optional)" -ForegroundColor Gray }
        if ($needBandit) { Write-Host "  - Bandit (optional)" -ForegroundColor Gray }
        if ($needSemgrep) { Write-Host "  - Semgrep (optional)" -ForegroundColor Gray }
        Write-Host "==========================================" -ForegroundColor Yellow
        Write-Host ""

        $confirm = Read-Host "Continue with installation? (Y/N)"
        if ($confirm -ne "Y" -and $confirm -ne "y") {
            Write-Host "Installation cancelled" -ForegroundColor Yellow
            return
        }

        # Check Chocolatey
        $hasChoco = Test-Command "choco"
        if (-not $hasChoco) {
            Write-Host ""
            Write-Host "[!] Chocolatey is not installed" -ForegroundColor Yellow
            Write-Host "Chocolatey is a package manager for Windows." -ForegroundColor Gray
            $installChoco = Read-Host "Install Chocolatey? (Y/N)"

            if ($installChoco -eq "Y" -or $installChoco -eq "y") {
                if (Install-Chocolatey) {
                    $hasChoco = $true
                    Write-Host ""
                    Write-Host "Please restart this script to continue" -ForegroundColor Cyan
                    Read-Host "Press Enter to exit"
                    return
                }
                else {
                    Write-Host ""
                    Write-Host "Cannot install tools without Chocolatey" -ForegroundColor Red
                    Write-Host "Please install manually:" -ForegroundColor Yellow
                    if ($needNodejs) { Write-Host "  - Node.js: https://nodejs.org/" }
                    if ($needGit) { Write-Host "  - Git: https://git-scm.com/" }
                    if ($needPython) { Write-Host "  - Python: https://www.python.org/" }
                    if ($needGitleaks) { Write-Host "  - Gitleaks: https://github.com/gitleaks/gitleaks/releases" }
                    Read-Host "Press Enter to exit"
                    return
                }
            }
            else {
                Write-Host "Skipping Chocolatey installation" -ForegroundColor Yellow
                Write-Host "Please install tools manually" -ForegroundColor Yellow
                Read-Host "Press Enter to exit"
                return
            }
        }

        Write-Host ""
        Write-Host "Starting installation..." -ForegroundColor Cyan

        # Install required tools
        if ($needNodejs) { Install-WithChoco "Node.js" "nodejs" }
        if ($needGit) { Install-WithChoco "Git" "git" }
        if ($needPython) { Install-WithChoco "Python" "python" }

        # Refresh environment variables
        Write-Host ""
        Write-Host "Refreshing environment variables..." -ForegroundColor Cyan
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

        # Install optional tools
        if ($needGitleaks) { Install-WithChoco "Gitleaks" "gitleaks" }
        if ($needBandit) { Install-WithPip "Bandit" "bandit" }
        if ($needSemgrep) { Install-WithPip "Semgrep" "semgrep" }

        Write-Host ""
        Write-Host "==========================================" -ForegroundColor Green
        Write-Host "[OK] Installation complete!" -ForegroundColor Green
        Write-Host "==========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Note: Some tools may require terminal restart" -ForegroundColor Yellow
    }
    else {
        Write-Host "==========================================" -ForegroundColor Green
        Write-Host "[OK] All dependencies are installed!" -ForegroundColor Green
        Write-Host "==========================================" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "You can now run the project:" -ForegroundColor Cyan
    Write-Host "  npm install" -ForegroundColor White
    Write-Host "  node server.js" -ForegroundColor White
    Write-Host ""
    Write-Host "Or use quick launch script:" -ForegroundColor Cyan
    Write-Host "  .\launch.ps1" -ForegroundColor White
    Write-Host ""
}

# Run main function
try {
    Main
}
catch {
    Write-Host ""
    Write-Host "[ERROR] An error occurred: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}

Read-Host "Press Enter to exit"
