@echo off
title Locket Gold VIP Server 2099
cd /d "%~dp0"
echo ========================================================
echo       Khoi dong Locket Gold VIP Unified Server
echo ========================================================
echo.
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Khong tim thay Python! Vui long cai dat Python 3.8+ tren may.
    pause
    exit /b 1
)

echo [*] Kiem tra thu vien cryptography...
python -c "import cryptography" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Dang cai dat requirements.txt...
    pip install -r requirements.txt
)

echo [*] Dang mo giao dien web tren trinh duyet...
start http://localhost

echo [*] Bat dau chay server...
python server.py
pause
