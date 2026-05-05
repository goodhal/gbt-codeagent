@echo off
REM Code Audit Platform - Dependency Installation Script (Windows)
REM Purpose: Automatically detect and install required external tools

setlocal enabledelayedexpansion

echo ==========================================
echo   Code Audit Platform - Dependency Installer
echo ==========================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Recommended to run as Administrator
    echo.
)

REM Check if Chocolatey is installed
where choco >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Chocolatey is not installed
    echo.
    echo Chocolatey is a package manager for Windows.
    echo Install Chocolatey? (Y/N^)
    set /p INSTALL_CHOCO=
    if /i "!INSTALL_CHOCO!"=="Y" (
        echo.
        echo Installing Chocolatey...
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"

        if !errorLevel! equ 0 (
            echo [OK] Chocolatey installed successfully
            echo Please restart this script to continue
            pause
            exit /b 0
        ) else (
            echo [ERROR] Chocolatey installation failed
            echo Please visit https://chocolatey.org/install
            pause
            exit /b 1
        )
    ) else (
        echo Skipping Chocolatey installation
        echo Note: Without Chocolatey, tools must be installed manually
        echo.
    )
)

echo Checking dependencies...
echo.

REM Check required tools
echo Checking required tools...

REM Node.js
where node >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Node.js is installed
    node --version
) else (
    echo [  ] Node.js is not installed
    set NEED_NODEJS=1
)

REM Git
where git >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Git is installed
    git --version
) else (
    echo [  ] Git is not installed
    set NEED_GIT=1
)

REM Python
where python >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Python is installed
    python --version
) else (
    echo [  ] Python is not installed
    set NEED_PYTHON=1
)

REM pip
where pip >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] pip is installed
    pip --version
) else (
    echo [  ] pip is not installed
    set NEED_PIP=1
)

echo.
echo Checking optional tools (for enhanced scanning^)...

REM Gitleaks
where gitleaks >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Gitleaks is installed
    gitleaks version
) else (
    echo [  ] Gitleaks is not installed
    set NEED_GITLEAKS=1
)

REM Bandit
where bandit >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Bandit is installed
    bandit --version
) else (
    echo [  ] Bandit is not installed
    set NEED_BANDIT=1
)

REM Semgrep
where semgrep >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Semgrep is installed
    semgrep --version
) else (
    echo [  ] Semgrep is not installed
    set NEED_SEMGREP=1
)

echo.

REM If installation needed
if defined NEED_NODEJS (
    echo ==========================================
    echo Tools to install:
    if defined NEED_NODEJS echo   - Node.js (required^)
    if defined NEED_GIT echo   - Git (required^)
    if defined NEED_PYTHON echo   - Python (required^)
    if defined NEED_PIP echo   - pip (required^)
    if defined NEED_GITLEAKS echo   - Gitleaks (optional^)
    if defined NEED_BANDIT echo   - Bandit (optional^)
    if defined NEED_SEMGREP echo   - Semgrep (optional^)
    echo ==========================================
    echo.

    set /p CONFIRM=Continue with installation? (Y/N^)
    if /i "!CONFIRM!" neq "Y" (
        echo Installation cancelled
        pause
        exit /b 0
    )

    REM Check Chocolatey
    where choco >nul 2>&1
    if %errorLevel% neq 0 (
        echo.
        echo [ERROR] Chocolatey is required for automatic installation
        echo Please install Chocolatey: https://chocolatey.org/install
        echo.
        echo Or install tools manually:
        if defined NEED_NODEJS echo   - Node.js: https://nodejs.org/
        if defined NEED_GIT echo   - Git: https://git-scm.com/
        if defined NEED_PYTHON echo   - Python: https://www.python.org/
        if defined NEED_GITLEAKS echo   - Gitleaks: https://github.com/gitleaks/gitleaks/releases
        pause
        exit /b 1
    )

    echo.
    echo Starting installation...
    echo.

    REM Install Node.js
    if defined NEED_NODEJS (
        echo Installing Node.js...
        choco install nodejs -y
        if !errorLevel! equ 0 (
            echo [OK] Node.js installed successfully
        ) else (
            echo [ERROR] Node.js installation failed
        )
        echo.
    )

    REM Install Git
    if defined NEED_GIT (
        echo Installing Git...
        choco install git -y
        if !errorLevel! equ 0 (
            echo [OK] Git installed successfully
        ) else (
            echo [ERROR] Git installation failed
        )
        echo.
    )

    REM Install Python
    if defined NEED_PYTHON (
        echo Installing Python...
        choco install python -y
        if !errorLevel! equ 0 (
            echo [OK] Python installed successfully
        ) else (
            echo [ERROR] Python installation failed
        )
        echo.
    )

    REM Refresh environment variables
    echo Refreshing environment variables...
    call refreshenv
    echo.

    REM Install Gitleaks
    if defined NEED_GITLEAKS (
        echo Installing Gitleaks...
        choco install gitleaks -y
        if !errorLevel! equ 0 (
            echo [OK] Gitleaks installed successfully
        ) else (
            echo [ERROR] Gitleaks installation failed
            echo Download from: https://github.com/gitleaks/gitleaks/releases
        )
        echo.
    )

    REM Install Bandit
    if defined NEED_BANDIT (
        echo Installing Bandit...
        pip install bandit
        if !errorLevel! equ 0 (
            echo [OK] Bandit installed successfully
        ) else (
            echo [ERROR] Bandit installation failed
        )
        echo.
    )

    REM Install Semgrep
    if defined NEED_SEMGREP (
        echo Installing Semgrep...
        pip install semgrep
        if !errorLevel! equ 0 (
            echo [OK] Semgrep installed successfully
        ) else (
            echo [ERROR] Semgrep installation failed
        )
        echo.
    )

    echo ==========================================
    echo [OK] Installation complete!
    echo ==========================================
    echo.
    echo Note: Some tools may require terminal restart
    echo.
) else (
    echo ==========================================
    echo [OK] All dependencies are installed!
    echo ==========================================
    echo.
)

echo You can now run the project:
echo   npm install
echo   node server.js
echo.
echo Or use quick launch script:
echo   launch.cmd
echo.

pause
