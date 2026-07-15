@echo off
cd /d "%~dp0"
set "PYTHONPATH=%~dp0btcrecover"
if not exist "python\python.exe" (echo [E] python missing & exit /b 1)
if not exist "btcrecover\btcrecover.py" (echo [E] btcrecover missing & exit /b 1)
cd /d "%~dp0btcrecover"
"%~dp0python\python.exe" btcrecover.py %*
