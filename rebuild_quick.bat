@echo off
setlocal
cd /d "%~dp0"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
set "CUDA_PATH=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.8"
set "PATH=%CUDA_PATH%\bin;%PATH%"
set "CMAKE=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
"%CMAKE%" --build build -j
if errorlevel 1 exit /b 1
if exist build\TrueWalletCollider.exe copy /y build\TrueWalletCollider.exe TrueWalletCollider.exe >nul
TrueWalletCollider.exe --experiment secp
TrueWalletCollider.exe --experiment passphrase
TrueWalletCollider.exe --experiment force_rebuild
TrueWalletCollider.exe --partial-help
endlocal
