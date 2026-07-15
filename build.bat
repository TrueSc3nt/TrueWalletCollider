@echo off
REM Alias — full build is CUDA+GUI (same as build_cuda.bat)
setlocal EnableExtensions
cd /d "%~dp0"
echo =============================================
echo  TrueWalletCollider — build.bat
echo  Delegates to build_cuda.bat
echo  Made by TrueScent — https://t.me/TrueScent
echo =============================================
call "%~dp0build_cuda.bat" %*
exit /b %ERRORLEVEL%
