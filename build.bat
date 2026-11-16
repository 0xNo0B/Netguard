@echo off
REM Builds dist\NetGuard.exe (single file; asks for admin through its UAC manifest).
cd /d "%~dp0"
if not exist .venv (
    py -3 -m venv .venv || python -m venv .venv
)
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install -r requirements.txt pyinstaller
.venv\Scripts\pyinstaller --noconfirm --clean --onefile --windowed --uac-admin ^
    --name NetGuard --icon assets\netguard.ico main.py
echo.
echo Done: dist\NetGuard.exe
pause
