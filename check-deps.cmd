@echo off
REM Simple test script to check dependencies

echo ==========================================
echo   Dependency Check Tool
echo ==========================================
echo.

echo Checking Node.js...
where node >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Node.js is installed
    node --version
) else (
    echo [  ] Node.js is NOT installed
)

echo.
echo Checking Git...
where git >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Git is installed
    git --version
) else (
    echo [  ] Git is NOT installed
)

echo.
echo Checking Python...
where python >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Python is installed
    python --version
) else (
    echo [  ] Python is NOT installed
)

echo.
echo Checking pip...
where pip >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] pip is installed
    pip --version
) else (
    echo [  ] pip is NOT installed
)

echo.
echo Checking Chocolatey...
where choco >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Chocolatey is installed
    choco --version
) else (
    echo [  ] Chocolatey is NOT installed
)

echo.
echo ==========================================
echo Check complete!
echo ==========================================
echo.

pause
