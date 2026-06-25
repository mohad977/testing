@echo off
echo ============================================
echo  NetScanner MSI Builder
echo ============================================

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.8+ and add to PATH.
    pause
    exit /b 1
)

:: Install cx_Freeze if missing
python -c "import cx_Freeze" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing cx_Freeze...
    pip install cx_Freeze
)

echo [*] Building MSI...
python setup.py bdist_msi

if errorlevel 1 (
    echo [ERROR] Build failed.
    pause
    exit /b 1
)

echo.
echo [+] Done! MSI is in the dist\ folder.
echo [+] Run it to install NetScanner to Program Files.
echo.
pause
