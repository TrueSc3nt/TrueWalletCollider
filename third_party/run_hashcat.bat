@echo off
cd /d "%~dp0"
if exist "hashcat\hashcat.exe" ("hashcat\hashcat.exe" %* & exit /b %ERRORLEVEL%)
echo [E] hashcat missing — run setup_forensics.bat
exit /b 1
