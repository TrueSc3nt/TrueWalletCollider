@echo off
cd /d "%~dp0"
if exist "john\run\john.exe" ("john\run\john.exe" %* & exit /b %ERRORLEVEL%)
if exist "john\john.exe" ("john\john.exe" %* & exit /b %ERRORLEVEL%)
echo [E] john missing ? run setup_forensics.bat
exit /b 1
