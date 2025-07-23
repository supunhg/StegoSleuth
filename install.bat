@echo off
REM Install script for StegoSleuth (Windows)

echo 🕵️‍♂️ Installing StegoSleuth...

REM Check Python version
python --version
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

REM Install Python dependencies
echo Installing Python dependencies...
pip install -r requirements.txt

REM Check if binwalk is available
binwalk --help >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ⚠️  binwalk is not installed
    echo For full functionality, install binwalk:
    echo   - Using chocolatey: choco install binwalk
    echo   - Or download from: https://github.com/ReFirmLabs/binwalk
    echo.
)

echo.
echo ✅ Installation complete!
echo.
echo Usage:
echo   python stegosleuth.py image.png
echo   python stegosleuth.py image.png --check lsb
echo   python stegosleuth.py image.png --verbose --output results.txt
echo.
echo Run tests:
echo   python -m pytest tests/
echo.
pause
