@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo =============================================
echo  TrueWalletCollider — automated CUDA+GUI build
echo =============================================

REM ---- Visual Studio / Build Tools ----
set "VCVARS="
for %%P in (
  "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
) do (
  if exist %%~P if not defined VCVARS set "VCVARS=%%~P"
)
if not defined VCVARS (
  echo [E] vcvars64.bat not found — install VS 2022 / VS 18 C++ tools
  exit /b 1
)
echo [+] MSVC: !VCVARS!
call "!VCVARS!"
if errorlevel 1 exit /b 1

REM ---- CUDA Toolkit ----
set "CUDA_PATH="
for %%V in (v12.8 v12.6 v12.5 v12.4 v12.3 v12.2 v12.1 v12.0 v13.3 v13.2 v13.1 v13.0) do (
  if exist "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\%%V\bin\nvcc.exe" (
    if not defined CUDA_PATH set "CUDA_PATH=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\%%V"
  )
)
if not defined CUDA_PATH if defined CUDA_PATH_V12_8 set "CUDA_PATH=!CUDA_PATH_V12_8!"
if not defined CUDA_PATH (
  echo [E] CUDA Toolkit not found
  exit /b 1
)
echo [+] CUDA_PATH=!CUDA_PATH!
"!CUDA_PATH!\bin\nvcc.exe" --version | findstr /C:"release"
set "PATH=!CUDA_PATH!\bin;!PATH!"

REM ---- CMake / Ninja ----
set "CMAKE="
for %%P in (
  "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
  "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
  "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
) do (
  if exist %%~P if not defined CMAKE set "CMAKE=%%~P"
)
where cmake >nul 2>&1 && if not defined CMAKE for /f "delims=" %%A in ('where cmake') do set "CMAKE=%%A"
if not defined CMAKE (
  echo [E] cmake not found
  exit /b 1
)
echo [+] cmake=!CMAKE!

set "NINJA="
for %%P in (
  "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
  "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
) do (
  if exist %%~P if not defined NINJA set "NINJA=%%~P"
)

set "BDIR=build"
if exist "!BDIR!" rd /s /q "!BDIR!"

set "ARCHS=75;80;86;89;90"

echo [+] Configuring...
if defined NINJA (
  "!CMAKE!" -S . -B "!BDIR!" -G Ninja -DCMAKE_MAKE_PROGRAM="!NINJA!" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=cl.exe "-DCMAKE_CUDA_COMPILER=!CUDA_PATH!\bin\nvcc.exe" -DCMAKE_CUDA_HOST_COMPILER=cl.exe "-DCMAKE_CUDA_ARCHITECTURES=!ARCHS!"
) else (
  "!CMAKE!" -S . -B "!BDIR!" -G "Visual Studio 17 2022" -A x64 -T host=x64 "-DCMAKE_CUDA_COMPILER=!CUDA_PATH!\bin\nvcc.exe" "-DCMAKE_CUDA_ARCHITECTURES=!ARCHS!"
)
if errorlevel 1 (
  echo [!] Primary generator failed — trying VS 2022...
  if exist "!BDIR!" rd /s /q "!BDIR!"
  "!CMAKE!" -S . -B "!BDIR!" -G "Visual Studio 17 2022" -A x64 -T host=x64 "-DCMAKE_CUDA_COMPILER=!CUDA_PATH!\bin\nvcc.exe" "-DCMAKE_CUDA_ARCHITECTURES=!ARCHS!"
  if errorlevel 1 exit /b 1
  echo [+] Building Release...
  "!CMAKE!" --build "!BDIR!" --config Release -j
  if errorlevel 1 exit /b 1
  if exist "!BDIR!\Release\TrueWalletCollider.exe" copy /y "!BDIR!\Release\TrueWalletCollider.exe" TrueWalletCollider.exe >nul
) else (
  echo [+] Building...
  "!CMAKE!" --build "!BDIR!" -j
  if errorlevel 1 exit /b 1
  if exist "!BDIR!\TrueWalletCollider.exe" copy /y "!BDIR!\TrueWalletCollider.exe" TrueWalletCollider.exe >nul
  if exist "!BDIR!\Release\TrueWalletCollider.exe" copy /y "!BDIR!\Release\TrueWalletCollider.exe" TrueWalletCollider.exe >nul
)

if not exist TrueWalletCollider.exe (
  echo [E] TrueWalletCollider.exe missing after build
  exit /b 1
)

echo.
echo [+] Build OK
dir TrueWalletCollider.exe
echo.
echo [+] Smoke: --selftest
TrueWalletCollider.exe --selftest
if errorlevel 1 (
  echo [E] selftest failed
  exit /b 1
)
echo [+] Smoke: --experiment passphrase
TrueWalletCollider.exe --experiment passphrase
if errorlevel 1 exit /b 1
echo [+] Smoke: --partial-help
TrueWalletCollider.exe --partial-help
echo.
echo [+] Done. Run TrueWalletCollider.exe for Recovery Lab GUI.
endlocal
