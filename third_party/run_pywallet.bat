@echo off
cd /d "%~dp0"
if not exist "python\python.exe" (echo [E] python missing & exit /b 1)
if exist "pywallet\pywallet.py" ("python\python.exe" "pywallet\pywallet.py" %* & exit /b %ERRORLEVEL%)
echo [E] pywallet missing
exit /b 1
